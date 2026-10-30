//! Secret delivery to one agent session (E2-07.2, P2.9).
//!
//! - **Redeemed by the runner itself**, once per lease, with its own signed request
//!   (`POST /api/v1/secret-leases/redeem`, [`http_redeem`]): the lease is only ever this runner's.
//! - **Delivered to that session's harness only**, never to the runner's own environment:
//!   `env` sets the variable on the harness's processes; `file` writes the value to a file
//!   created 0600 in the session's 0700 dir and sets the variable to its path; `askpass` does
//!   the same and adds a 0700 helper that prints the file (never the value itself), set as the
//!   variable and as `GIT_ASKPASS`. The value never goes on a command line.
//! - **Removed** when the session ends or is killed ([`Delivered`]'s drop), and, after a crash
//!   or `kill -9`, when the next driver starts ([`sweep`]).
//! - The plaintext is held in `Zeroizing` buffers here, best effort: the HTTP body, the JSON
//!   value and the harness's environment are not wiped (secrets review L2).

use std::fs::{DirBuilder, File, OpenOptions};
use std::future::Future;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use serde_json::json;
use zeroize::Zeroizing;

use crate::v2::client::{Client, Signer};
use crate::v2::key::{Enrolment, Key};

/// A redeemed secret. No `Debug`: nothing may print it.
pub struct Leased {
    pub name: String,
    /// `env`, `file` or `askpass`.
    pub delivery: String,
    pub value: Zeroizing<String>,
}

/// Redeems a lease: the secret, or why not (never holding the lease or a value).
pub type Redeem = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<Leased, String>> + Send>> + Send + Sync,
>;

pub use ainkrad_proto::v2::valid_secret_var as valid_var;

/// A session's delivered secrets: the variables for its harness, and its dir, removed on drop.
pub struct Delivered {
    dir: Option<PathBuf>,
    pub env: Vec<(String, String)>,
}

impl Drop for Delivered {
    fn drop(&mut self) {
        if let Some(dir) = &self.dir
            && let Err(e) = std::fs::remove_dir_all(dir)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::error!(dir = %dir.display(), error = %e, "removing delivered secrets failed");
        }
    }
}

/// A directory only this user can enter (created, or narrowed if it exists).
pub fn private_dir(dir: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// A file only this user can read, 0600 from its creation: appended to, or replaced.
pub fn private_file(path: &Path, append: bool) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.mode(0o600).create(true);
    if append {
        o.append(true);
    } else {
        o.write(true).truncate(true);
    }
    o.open(path)
}

/// Empties `root` (what a crashed runner left) and leaves it 0700.
pub fn sweep(root: &Path) -> io::Result<()> {
    match std::fs::remove_dir_all(root) {
        Ok(()) => tracing::info!(dir = %root.display(), "removed secrets a previous runner left"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    private_dir(root)
}

/// Writes `value` to a new file, 0600 at its creation (never widened, never truncated over).
fn write_new(path: &Path, value: &[u8], mode: u32) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    f.write_all(value)?;
    f.sync_all()
}

/// Delivers `leased` (variable, secret) for `session` under `root/<session>`.
pub fn deliver(root: &Path, session: &str, leased: Vec<(String, Leased)>) -> io::Result<Delivered> {
    if leased.is_empty() {
        return Ok(Delivered {
            dir: None,
            env: vec![],
        });
    }
    let dir = root.join(session);
    // A dir left by an earlier run of the session goes first: create_new below must not fail.
    let _ = std::fs::remove_dir_all(&dir);
    private_dir(root)?;
    private_dir(&dir)?;
    let mut out = Delivered {
        dir: Some(dir.clone()),
        env: vec![],
    };
    for (i, (var, secret)) in leased.into_iter().enumerate() {
        // Named by position: a secret's name never becomes a path.
        let file = dir.join(format!("s{i}"));
        match secret.delivery.as_str() {
            "env" => out.env.push((var, secret.value.to_string())),
            "file" => {
                write_new(&file, secret.value.as_bytes(), 0o600)?;
                out.env.push((var, path_str(&file)?));
            }
            "askpass" => {
                write_new(&file, secret.value.as_bytes(), 0o600)?;
                let helper = dir.join(format!("s{i}.askpass"));
                let script = format!("#!/bin/sh\nexec cat '{}'\n", path_str(&file)?);
                write_new(&helper, script.as_bytes(), 0o700)?;
                let helper = path_str(&helper)?;
                out.env.push((var, helper.clone()));
                out.env.push(("GIT_ASKPASS".to_owned(), helper));
                out.env
                    .push(("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()));
            }
            other => {
                return Err(io::Error::other(format!(
                    "secret {}: unknown delivery {other}",
                    secret.name
                )));
            }
        }
    }
    Ok(out)
}

/// A path as UTF-8 with no quote, so it is safe inside the helper's single quotes.
fn path_str(p: &Path) -> io::Result<String> {
    p.to_str()
        .filter(|s| !s.contains('\''))
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("the secrets dir's path is not plain UTF-8"))
}

/// Redeems leases against the Core with this runner's own signed requests.
pub fn http_redeem(client: Arc<Client>, key: Arc<Key>, enrolment: Arc<Mutex<Enrolment>>) -> Redeem {
    Arc::new(move |lease: String| {
        let (client, key, enrolment) = (
            Arc::clone(&client),
            Arc::clone(&key),
            Arc::clone(&enrolment),
        );
        Box::pin(async move {
            let (device, core_fp) = {
                let e = enrolment.lock().unwrap();
                (e.device_id.clone(), e.core_fp.clone())
            };
            let signer = Signer {
                key: &key,
                device: &device,
                core_fp: &core_fp,
            };
            let why = |e: super::super::client::LinkError| format!("redeeming a lease: {e}");
            let session = client.session(signer).await.map_err(why)?;
            let body = json!({"lease": lease});
            let (_, mut v) = client
                .call(
                    "POST",
                    "/api/v1/secret-leases/redeem",
                    Some(&body),
                    Some((signer, Some(&session))),
                )
                .await
                .map_err(why)?;
            let value = match v.get_mut("value").map(serde_json::Value::take) {
                Some(serde_json::Value::String(s)) => Zeroizing::new(s),
                _ => return Err("the Core's answer has no value".to_owned()),
            };
            let text = |k: &str| v[k].as_str().unwrap_or_default().to_owned();
            Ok(Leased {
                name: text("name"),
                delivery: text("delivery"),
                value,
            })
        })
    })
}
