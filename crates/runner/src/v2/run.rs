//! The `run` driver (P5-02): `run.start`, `run.stop` and `run.status` for the Core. The runner redeems
//! the run's secret leases itself, fills `${secret:NAME}` in the env, bundles each checkout with git,
//! and hands the rest to the run helper (`crate::run::helper`), which drives Podman as `ainkrad-run`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ainkrad_proto::v2::{
    Command, DRIVER_RUN, DriverInfo, ErrorCode, OP_RUN_START, OP_RUN_STATUS, OP_RUN_STOP, Reply,
    RunStart, StreamError,
};
use zeroize::Zeroizing;

use super::agent::secrets::{Form, Redeem};
use crate::run::helper::{self, Request};

pub struct RunDriver {
    socket: PathBuf,
    redeem: Redeem,
    /// Where this runner's own checkouts live; a run's `checkouts.dir` must resolve under it.
    checkouts: PathBuf,
}

/// The unit that loads `deploy/run-egress.nft` (and re-loads it with nftables.service).
pub const EGRESS_UNIT: &str = "ainkrad-run-egress.service";

/// Whether the egress block is up. The runner cannot read nftables itself (no `CAP_NET_ADMIN`), so it
/// asks systemd; the helper unit re-loads the table as root before every op and does not start
/// without it (`ExecStartPre=+nft -f`), which is the check that holds at the moment of a start.
pub fn egress_active() -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", EGRESS_UNIT])
        .stdin(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// `dir`, resolved, when it lies under `root` (also resolved); `Err` otherwise.
pub(super) fn checkout_dir(root: &Path, dir: &str) -> Result<PathBuf, String> {
    let bad = || format!("the checkout {dir} is not one of this runner's");
    let root = root.canonicalize().map_err(|_| bad())?;
    let d = Path::new(dir).canonicalize().map_err(|_| bad())?;
    if d.starts_with(&root) && d != root {
        Ok(d)
    } else {
        Err(bad())
    }
}

/// Fills every `${secret:NAME}` in `v` from `values`; `Err` names a secret it does not have.
pub(super) fn fill(
    v: &str,
    values: &BTreeMap<String, Zeroizing<String>>,
) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = v;
    while let Some(i) = rest.find("${secret:") {
        let after = &rest[i + 9..];
        let end = after.find('}').ok_or("an unterminated ${secret:...}")?;
        let value = values
            .get(&after[..end])
            .ok_or_else(|| format!("no lease for the secret {}", &after[..end]))?;
        out.push_str(&rest[..i]);
        out.push_str(value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

impl RunDriver {
    pub fn new(socket: impl Into<PathBuf>, redeem: Redeem, checkouts: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            redeem,
            checkouts: checkouts.into(),
        }
    }

    /// Offered where the run helper is installed (`--with-run`); the Core places runs only on a
    /// runner that also reports `run_caps`.
    pub fn info(&self) -> Option<DriverInfo> {
        self.socket.exists().then(|| DriverInfo {
            name: DRIVER_RUN.to_owned(),
            commands: [OP_RUN_START, OP_RUN_STOP, OP_RUN_STATUS]
                .map(str::to_owned)
                .into(),
            capacity: 4,
            ..DriverInfo::default()
        })
    }

    pub async fn handle(&self, command: Command) -> Result<Reply, StreamError> {
        let internal = |e: String| StreamError::new(ErrorCode::Internal, e);
        fn de<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, StreamError> {
            serde_json::from_value(v)
                .map_err(|e| StreamError::new(ErrorCode::Internal, e.to_string()))
        }
        match command {
            Command::RunStart(req) => {
                // Fail closed: no egress block, no run.
                if !egress_active() {
                    return Err(StreamError::new(
                        ErrorCode::Internal,
                        format!("{EGRESS_UNIT} is not active; refusing to start a run"),
                    ));
                }
                let req = self.prepare(req).await?;
                let tmp = tempdir()?;
                let mut bundles = Vec::new();
                for c in &req.checkouts {
                    let dir = checkout_dir(&self.checkouts, &c.dir)
                        .map_err(|e| StreamError::new(ErrorCode::InvalidArgs, e))?;
                    bundles.push(bundle(&dir, &tmp.0.join(&c.repo)).await?);
                }
                let lens = bundles.iter().map(|b| b.1).collect();
                let paths: Vec<PathBuf> = bundles.into_iter().map(|b| b.0).collect();
                let start = Request::Start {
                    start: req,
                    bundles: lens,
                };
                let v = helper::call(&self.socket, &start, &paths)
                    .await
                    .map_err(internal)?;
                Ok(Reply::RunStart(de(v)?))
            }
            Command::RunStop(req) => {
                let v = helper::call(&self.socket, &Request::Stop { run: req.run }, &[]).await;
                Ok(Reply::RunStop(de(v.map_err(internal)?)?))
            }
            Command::RunStatus(req) => {
                let v = helper::call(&self.socket, &Request::Status { run: req.run }, &[]).await;
                Ok(Reply::RunStatus(de(v.map_err(internal)?)?))
            }
            _ => Err(StreamError::new(
                ErrorCode::UnsupportedCommand,
                "not a run op",
            )),
        }
    }

    /// Checks the request, redeems its leases and fills the env; the secrets list leaves it empty.
    async fn prepare(&self, mut req: RunStart) -> Result<RunStart, StreamError> {
        let invalid = |e: String| StreamError::new(ErrorCode::InvalidArgs, e);
        if let Some(p) = req.problem() {
            return Err(invalid(p));
        }
        let mut values = BTreeMap::new();
        for s in std::mem::take(&mut req.secrets) {
            let leased = (self.redeem)(s.lease)
                .await
                .map_err(|e| invalid(format!("cannot redeem the lease of {}: {e}", s.name)))?;
            // ponytail: text secrets only; `file` ones (T7: read-only tmpfs mounts) come with a need.
            if leased.form != Form::Text || leased.value.contains(['\n', '\r', '\0']) {
                return Err(invalid(format!("{} is not a one-line text secret", s.name)));
            }
            values.insert(s.name, leased.value);
        }
        for svc in req.spec.services.values_mut() {
            for v in svc.env.values_mut() {
                *v = fill(v, &values).map_err(invalid)?;
            }
        }
        Ok(req)
    }
}

/// A private scratch dir, removed when dropped.
struct Tmp(PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir() -> Result<Tmp, StreamError> {
    use std::os::unix::fs::DirBuilderExt;
    let p = std::env::temp_dir().join(format!(
        "ainkrad-run-{}",
        super::key::b64(&super::key::random::<9>())
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&p)
        .map_err(|e| StreamError::new(ErrorCode::Internal, e.to_string()))?;
    Ok(Tmp(p))
}

/// `git bundle create <to> HEAD` of a checkout: the file and its length.
async fn bundle(dir: &Path, to: &Path) -> Result<(PathBuf, u64), StreamError> {
    let bad = |e: String| StreamError::new(ErrorCode::InvalidArgs, e);
    let out = tokio::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["bundle", "create", "-q"])
        .arg(to)
        .arg("HEAD")
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .output()
        .await
        .map_err(|e| bad(format!("git: {e}")))?;
    if !out.status.success() {
        return Err(bad(format!(
            "bundling the checkout {}: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let len = std::fs::metadata(to).map_err(|e| bad(e.to_string()))?.len();
    Ok((to.to_path_buf(), len))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn secrets_fill_the_env_and_a_missing_one_is_named() {
        let mut values = BTreeMap::new();
        values.insert("db".to_owned(), Zeroizing::new("s3cret".to_owned()));
        assert_eq!(
            fill("postgres://u:${secret:db}@db/x", &values).unwrap(),
            "postgres://u:s3cret@db/x"
        );
        assert_eq!(fill("plain", &values).unwrap(), "plain");
        assert!(
            fill("${secret:other}", &values)
                .unwrap_err()
                .contains("other")
        );
        assert!(fill("${secret:db", &values).is_err());
    }

    #[tokio::test]
    async fn without_the_helper_the_driver_is_not_offered() {
        let redeem: Redeem = Arc::new(|_| Box::pin(async { Err("none".to_owned()) }));
        assert!(
            RunDriver::new("/nonexistent/run.sock", redeem, "/nonexistent")
                .info()
                .is_none()
        );
    }

    #[test]
    fn a_checkout_must_resolve_under_the_runners_root() {
        let base = std::env::temp_dir().join(format!("run-checkouts-{}", std::process::id()));
        let (root, other) = (base.join("root"), base.join("other"));
        std::fs::create_dir_all(root.join("s1/web")).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::os::unix::fs::symlink(&other, root.join("s1/link")).unwrap();
        let ok = checkout_dir(&root, root.join("s1/web").to_str().unwrap()).unwrap();
        assert_eq!(ok, root.canonicalize().unwrap().join("s1/web"));
        for bad in [
            root.join("s1/link"),
            root.join("s1/web/../../../other"),
            root.clone(),
            other.clone(),
            PathBuf::from("/etc"),
            root.join("missing"),
        ] {
            assert!(
                checkout_dir(&root, bad.to_str().unwrap()).is_err(),
                "{}",
                bad.display()
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
