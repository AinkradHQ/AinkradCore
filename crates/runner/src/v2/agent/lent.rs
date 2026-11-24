//! A Core-held plan's login lent for one session (2026-11-23, accounts on the Core). The Core keeps
//! a Codex or OpenCode login in its vault and leases it to the runner that runs the session
//! (`AgentStart::home_lease`). Here it becomes a home of this session alone,
//! `<config>/bound/lent-<run>`, which the harness's per-session copy (`bound_session`) reads like
//! any bound home. When the session ends, a credential the harness rotated (the same account only)
//! is sent back to the Core (`POST /api/v1/runner/sessions/{id}/credential`), and the home is
//! wiped. Nothing of it outlives the session on disk: a runner start also sweeps any `lent-*`
//! home a crash left. A failed send is retried in memory only, then dropped.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::{Bundle, same_account};
use serde_json::json;
use zeroize::Zeroize;

use crate::harness::bound_session::{read_credential, wipe, write_credential};
use crate::v2::client::{Client, Signer};
use crate::v2::key::{Enrolment, Key};

/// Hands a rotated login back to the Core: `(session, files)`.
pub type GiveBack = Arc<
    dyn Fn(String, Bundle) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        + Send
        + Sync,
>;

/// How often a give-back is tried before the rotation is dropped (the vault keeps the old one).
const TRIES: u32 = 5;
const PREFIX: &str = "lent-";

/// Removes every lent home a runner that died mid-session left under `homes`.
pub fn sweep(homes: &Path) {
    let Ok(rd) = std::fs::read_dir(homes) else {
        return;
    };
    for e in rd.flatten() {
        if e.file_name().to_string_lossy().starts_with(PREFIX) {
            wipe(&e.path());
        }
    }
}

/// One session's lent home. Dropping it sends a rotation back and wipes the home.
pub struct LentHome {
    dir: PathBuf,
    key: String,
    session: String,
    sent: Bundle,
    give_back: Option<GiveBack>,
}

impl LentHome {
    /// Writes `bundle` (checked by the caller with `parse_bundle`) into `<homes>/lent-<run>`.
    pub fn make(
        homes: &Path,
        run: i64,
        session: &str,
        bundle: Bundle,
        give_back: Option<GiveBack>,
    ) -> std::io::Result<Self> {
        let key = format!("{PREFIX}{run}");
        let dir = homes.join(&key);
        wipe(&dir);
        crate::v2::agent::secrets::private_dir(homes)?;
        // Built first, so a failure below wipes what was written.
        let home = Self {
            dir,
            key,
            session: session.to_owned(),
            sent: bundle,
            give_back,
        };
        crate::v2::agent::secrets::private_dir(&home.dir)?;
        for (rel, text) in &home.sent {
            write_credential(&home.dir, rel, text.as_bytes())?;
        }
        Ok(home)
    }

    /// The home key the harness runs with (`bound/<key>`).
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Every value of the lent login that a redactor should never let through: each JSON string.
    pub fn secrets(&self) -> Vec<String> {
        fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
            match v {
                serde_json::Value::String(s) => out.push(s.clone()),
                serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
                serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, out)),
                _ => {}
            }
        }
        let mut out = Vec::new();
        for text in self.sent.values() {
            if let Ok(v) = serde_json::from_str(text) {
                walk(&v, &mut out);
            }
        }
        out
    }

    /// The files the harness changed since the start, the same account's only (the copy-back into
    /// this home already refused another account's; checked again here, and by the Core).
    pub fn rotated(&self) -> Option<Bundle> {
        let mut out = Bundle::new();
        for (rel, old) in &self.sent {
            let Some(new) = read_credential(&self.dir, rel) else {
                continue;
            };
            if new != old.as_bytes() && same_account(old.as_bytes(), &new) {
                out.insert(rel.clone(), String::from_utf8_lossy(&new).into_owned());
            }
        }
        (!out.is_empty()).then_some(out)
    }
}

impl Drop for LentHome {
    fn drop(&mut self) {
        let rotated = self.rotated();
        wipe(&self.dir);
        self.sent.values_mut().for_each(Zeroize::zeroize);
        let (Some(files), Some(give)) = (rotated, self.give_back.clone()) else {
            return;
        };
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            tracing::warn!("a rotated login could not be sent back: no runtime");
            return;
        };
        let session = self.session.clone();
        rt.spawn(async move {
            let mut wait = Duration::from_secs(2);
            for n in 1..=TRIES {
                match give(session.clone(), files.clone()).await {
                    Ok(()) => return,
                    // The reason never holds a value (`http_give_back`).
                    Err(why) if n == TRIES => {
                        tracing::warn!(%why, "a rotated login was not taken back by the Core")
                    }
                    Err(_) => {
                        tokio::time::sleep(wait).await;
                        wait *= 2;
                    }
                }
            }
        });
    }
}

/// Sends a rotated login to the Core with this runner's own signed request.
pub fn http_give_back(
    client: Arc<Client>,
    key: Arc<Key>,
    enrolment: Arc<Mutex<Enrolment>>,
) -> GiveBack {
    Arc::new(move |session: String, files: Bundle| {
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
            let why = |e: crate::v2::client::LinkError| format!("returning a rotated login: {e}");
            let s = client.session(signer).await.map_err(why)?;
            let body = json!({ "files": files });
            let path = format!("/api/v1/runner/sessions/{session}/credential");
            client
                .call("POST", &path, Some(&body), Some((signer, Some(&s))))
                .await
                .map(drop)
                .map_err(why)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ainkrad-lent-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn bundle(v: &str) -> Bundle {
        Bundle::from([("auth.json".to_owned(), v.to_owned())])
    }

    type Got = Arc<Mutex<Vec<(String, Bundle)>>>;

    fn catcher() -> (GiveBack, Got) {
        let got: Got = Arc::default();
        let g = Arc::clone(&got);
        let give: GiveBack = Arc::new(move |s, b| {
            g.lock().unwrap().push((s, b));
            Box::pin(async { Ok(()) })
        });
        (give, got)
    }

    async fn settle() {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn a_lent_home_holds_only_the_login_and_is_gone_after_the_session() {
        let d = scratch("gone");
        let (give, got) = catcher();
        let h = LentHome::make(&d, 7, "as_x", bundle(r#"{"t":"dummy-a"}"#), Some(give)).unwrap();
        let dir = d.join(h.key());
        assert_eq!(h.key(), "lent-7");
        assert_eq!(
            std::fs::read(dir.join("auth.json")).unwrap(),
            br#"{"t":"dummy-a"}"#
        );
        assert_eq!(h.secrets(), vec!["dummy-a".to_owned()]);
        drop(h);
        settle().await;
        assert!(!dir.exists(), "the runner keeps nothing after the session");
        assert!(
            got.lock().unwrap().is_empty(),
            "nothing changed: nothing sent"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_token_refreshed_during_the_session_goes_back_to_the_core_and_another_account_does_not()
     {
        let d = scratch("back");
        let (give, got) = catcher();
        let h =
            LentHome::make(&d, 8, "as_y", bundle(r#"{"t":"old"}"#), Some(give.clone())).unwrap();
        std::fs::write(d.join("lent-8/auth.json"), br#"{"t":"new"}"#).unwrap();
        drop(h);
        settle().await;
        let sent = got.lock().unwrap().clone();
        assert_eq!(sent, vec![("as_y".to_owned(), bundle(r#"{"t":"new"}"#))]);
        assert!(!d.join("lent-8").exists());
        // Another account's login swapped in is never sent.
        got.lock().unwrap().clear();
        let h = LentHome::make(&d, 9, "as_z", bundle(r#"{"t":"old"}"#), Some(give)).unwrap();
        std::fs::write(d.join("lent-9/auth.json"), br#"{"other":"x"}"#).unwrap();
        drop(h);
        settle().await;
        assert!(got.lock().unwrap().is_empty());
        assert!(!d.join("lent-9").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_runner_start_sweeps_lent_homes_and_leaves_bound_ones() {
        let d = scratch("sweep");
        std::fs::create_dir_all(d.join("lent-3")).unwrap();
        std::fs::write(d.join("lent-3/auth.json"), b"{}").unwrap();
        std::fs::create_dir_all(d.join("lg_1")).unwrap();
        sweep(&d);
        assert!(!d.join("lent-3").exists() && d.join("lg_1").exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
