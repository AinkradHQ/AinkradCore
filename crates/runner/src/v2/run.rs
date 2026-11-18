//! The `run` driver (P5-02): `run.start`, `run.stop` and `run.status` for the Core. The runner redeems
//! the run's secret leases itself, fills `${secret:NAME}` in the env, bundles each checkout with git,
//! and hands the rest to the run helper (`crate::run::helper`), which drives Podman as `ainkrad-run`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ainkrad_proto::runner::Workspace;
use ainkrad_proto::v2::{
    Command, DRIVER_RUN, DriverInfo, ErrorCode, OP_PORT_OPEN, OP_RUN_START, OP_RUN_STATUS,
    OP_RUN_STOP, PortOpen, Reply, RunList, RunStart, StreamError,
};
use zeroize::Zeroizing;

use super::agent::RUN_SESSION_PREFIX;
use super::agent::secrets::{Form, Redeem};
use crate::run::helper::{self, Request};

pub struct RunDriver {
    socket: PathBuf,
    redeem: Redeem,
    /// Where this runner's own checkouts live; a run's `checkouts.dir` must resolve under it.
    checkouts: PathBuf,
    /// Clones a run's repos from the Core's copies (the agent driver's mirror path); without it a
    /// run that builds from a repo cannot start here.
    clones: Option<Arc<super::agent::AgentDriver>>,
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
            clones: None,
        }
    }

    pub fn with_clones(mut self, agents: Arc<super::agent::AgentDriver>) -> Self {
        self.clones = Some(agents);
        self
    }

    /// Whether this runner can clone a start's `from_core` checkouts; checked before anything
    /// else is spent on the start (a secret lease is redeemed only once).
    fn can_clone(&self, req: &RunStart) -> Result<(), StreamError> {
        match (
            &self.clones,
            req.checkouts.iter().any(|c| c.from_core.is_some()),
        ) {
            (None, true) => Err(StreamError::new(
                ErrorCode::InvalidArgs,
                "this runner cannot clone from the Core",
            )),
            _ => Ok(()),
        }
    }

    /// Clones every checkout that names a Core copy (`from_core`) into one private dir and fills
    /// in its `dir`; the Core serves each copy only while it holds a lease for this runner. `Some`
    /// is a guard that deletes the clone when dropped (done, failed or cancelled).
    async fn clone_all(&self, req: &mut RunStart) -> Result<Option<CloneGuard>, StreamError> {
        let bad = |e: String| StreamError::new(ErrorCode::InvalidArgs, e);
        let trees: Vec<Workspace> = req
            .checkouts
            .iter()
            .filter_map(|c| {
                c.from_core.as_ref().map(|f| Workspace {
                    repo: f.remote.clone(),
                    base: f.base.clone(),
                    branch: f.base.clone(),
                    push: false,
                    name: c.repo.clone(),
                    also: Vec::new(),
                    expected_head: None,
                    mirror: Some(f.mirror),
                })
            })
            .collect();
        let Some((first, rest)) = trees.split_first() else {
            return Ok(None);
        };
        let agents = self
            .clones
            .as_ref()
            .ok_or_else(|| bad("this runner cannot clone from the Core".into()))?;
        if let Some(why) = first
            .problem()
            .or_else(|| rest.iter().find_map(Workspace::problem))
        {
            return Err(bad(why));
        }
        let mut head = first.clone();
        head.also = rest.to_vec();
        // `as_` + the run's letters and digits: a valid session id, one per run.
        let alnum: String = req
            .run
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect();
        let session = format!("{RUN_SESSION_PREFIX}{alnum}");
        // Armed before the clone: a failed or cancelled clone leaves nothing either.
        let guard = CloneGuard(Arc::clone(agents), session.clone());
        let root = agents.run_workspace(&session, &head).await.map_err(bad)?;
        for c in req.checkouts.iter_mut().filter(|c| c.from_core.is_some()) {
            let dir = match trees.len() {
                1 => root.clone(),
                _ => root.join(&c.repo),
            };
            c.dir = dir.to_string_lossy().into_owned();
            c.from_core = None;
        }
        Ok(Some(guard))
    }

    /// Offered where the run helper is installed (`--with-run`); the Core places runs only on a
    /// runner that also reports `run_caps`.
    pub fn info(&self) -> Option<DriverInfo> {
        self.socket.exists().then(|| DriverInfo {
            name: DRIVER_RUN.to_owned(),
            commands: [OP_RUN_START, OP_RUN_STOP, OP_RUN_STATUS, OP_PORT_OPEN]
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
                self.can_clone(&req)?;
                let mut req = self.prepare(req).await?;
                // Held to the end: dropped (and the clone deleted) on success, error or cancel.
                let _held = self.clone_all(&mut req).await?;
                self.start_bundled(req).await
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

    /// `port.open` (P6-01): resolves the request against the run's live containers (`port::resolve`),
    /// then bridges the stream until it or the run ends. The last frame is returned.
    pub async fn port(
        self: Arc<Self>,
        req: PortOpen,
        stream: u64,
        inbox: tokio::sync::mpsc::UnboundedReceiver<ainkrad_proto::v2::Body>,
        cancel: tokio::sync::oneshot::Receiver<()>,
        out: tokio::sync::mpsc::UnboundedSender<(u64, ainkrad_proto::v2::Body)>,
    ) -> ainkrad_proto::v2::Body {
        use ainkrad_proto::v2::Body;
        let refuse = |c, m: String| Body::Error(StreamError::new(c, m));
        if let Some(p) = req.problem() {
            return refuse(ErrorCode::InvalidArgs, p);
        }
        let host_port = match self
            .runs(&req.run)
            .await
            .and_then(|l| super::port::resolve(&l, &req))
        {
            Ok(p) => p,
            Err(e) => return refuse(ErrorCode::InvalidArgs, e),
        };
        let (me, asked) = (&*self, &req);
        let alive = move || async move {
            me.runs(&asked.run)
                .await
                .and_then(|l| super::port::resolve(&l, asked))
                == Ok(host_port)
        };
        super::port::bridge(host_port, alive, stream, inbox, cancel, out).await
    }

    /// The helper's view of run `run`.
    async fn runs(&self, run: &str) -> Result<RunList, String> {
        let req = Request::Status {
            run: Some(run.to_owned()),
        };
        let v = helper::call(&self.socket, &req, &[]).await?;
        serde_json::from_value(v).map_err(|e| e.to_string())
    }

    /// Bundles each checkout and hands the start to the run helper.
    async fn start_bundled(&self, req: RunStart) -> Result<Reply, StreamError> {
        let internal = |e: String| StreamError::new(ErrorCode::Internal, e);
        fn de<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, StreamError> {
            serde_json::from_value(v)
                .map_err(|e| StreamError::new(ErrorCode::Internal, e.to_string()))
        }
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

/// Deletes a run's clone (the session it was made under) when dropped. Not `cleanup_session`: that
/// saves the work under `session-wip`, which nothing ever cleans.
struct CloneGuard(Arc<super::agent::AgentDriver>, String);

impl Drop for CloneGuard {
    fn drop(&mut self) {
        self.0.discard_run_workspace(&self.1);
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
mod review_tests;

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
