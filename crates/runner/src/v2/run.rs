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
    /// One `run.status` per run per [`STATUS_TTL`], shared by all of the run's port streams.
    status: tokio::sync::Mutex<BTreeMap<String, (std::time::Instant, Result<RunList, String>)>>,
}

/// How long a run's `run.status` answers its port streams' liveness checks.
const STATUS_TTL: std::time::Duration = std::time::Duration::from_secs(1);
/// The most simultaneous `port.open` streams, counted by the Core apart from run control so port
/// traffic cannot starve `run.stop` and `run.status`. Below the session's `MAX_HELD`.
pub const PORT_STREAMS: u32 = 32;
/// The driver name `port.open` is offered under.
pub const DRIVER_PORT: &str = "run.port";

/// A fixed refusal for a failure inside the helper link; the detail goes to the log only.
fn helper_failed(what: &str, detail: impl std::fmt::Display) -> StreamError {
    tracing::warn!(%detail, "{what}");
    StreamError::new(ErrorCode::Internal, "the run helper failed")
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
            status: Default::default(),
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
            commands: [OP_RUN_START, OP_RUN_STOP, OP_RUN_STATUS]
                .map(str::to_owned)
                .into(),
            capacity: 4,
            ..DriverInfo::default()
        })
    }

    /// `port.open`, a driver of its own so the Core counts its streams apart from run control.
    pub fn port_info(&self) -> Option<DriverInfo> {
        self.info().map(|_| DriverInfo {
            name: DRIVER_PORT.to_owned(),
            commands: vec![OP_PORT_OPEN.to_owned()],
            capacity: PORT_STREAMS,
            streams: Some(PORT_STREAMS),
            ..DriverInfo::default()
        })
    }

    pub async fn handle(&self, command: Command) -> Result<Reply, StreamError> {
        let internal = |e: String| helper_failed("run helper call failed", e);
        fn de<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, StreamError> {
            serde_json::from_value(v)
                .map_err(|e| helper_failed("run helper reply did not parse", e))
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
        let host_port = match self.runs(&req.run).await {
            Ok(l) => super::port::resolve(&l, &req),
            Err(e) => return Body::Error(helper_failed("port.open status failed", e)),
        };
        let host_port = match host_port {
            Ok(p) => p,
            Err(e) => return refuse(ErrorCode::InvalidArgs, e),
        };
        let (me, asked) = (&*self, &req);
        let alive = move || async move {
            me.runs_cached(&asked.run)
                .await
                .and_then(|l| super::port::resolve(&l, asked))
                == Ok(host_port)
        };
        super::port::bridge(host_port, alive, stream, inbox, cancel, out).await
    }

    /// The helper's view of run `run`. `Err` holds the detail, for the log only.
    async fn runs(&self, run: &str) -> Result<RunList, String> {
        let req = Request::Status {
            run: Some(run.to_owned()),
        };
        let v = helper::call(&self.socket, &req, &[]).await?;
        serde_json::from_value(v).map_err(|e| e.to_string())
    }

    /// [`Self::runs`], at most once per [`STATUS_TTL`] per run: the lock is held across the fetch, so
    /// the streams of a run that ask together share one `podman ps`.
    async fn runs_cached(&self, run: &str) -> Result<RunList, String> {
        let mut cache = self.status.lock().await;
        if let Some((_, got)) = cache.get(run).filter(|(at, _)| at.elapsed() < STATUS_TTL) {
            return got.clone();
        }
        let got = self.runs(run).await;
        cache.retain(|_, (at, _)| at.elapsed() < STATUS_TTL * 10);
        cache.insert(run.to_owned(), (std::time::Instant::now(), got.clone()));
        got
    }

    /// Bundles each checkout and hands the start to the run helper.
    async fn start_bundled(&self, req: RunStart) -> Result<Reply, StreamError> {
        let internal = |e: String| helper_failed("run helper call failed", e);
        fn de<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, StreamError> {
            serde_json::from_value(v)
                .map_err(|e| helper_failed("run helper reply did not parse", e))
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

/// Refuses a `.git` that holds any symlink (a session could point one at a file outside the
/// checkout) or `objects/info/alternates` (the same, for objects); `Err` names the first.
pub(super) fn git_dir_clean(dir: &Path) -> Result<(), String> {
    let git = dir.join(".git");
    let is_dir = std::fs::symlink_metadata(&git).is_ok_and(|m| m.file_type().is_dir());
    if !is_dir {
        return Err(format!("{} is not a plain .git directory", git.display()));
    }
    let mut todo = vec![git.clone()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))? {
            let e = e.map_err(|e| e.to_string())?;
            let t = e.file_type().map_err(|e| e.to_string())?;
            if t.is_symlink() {
                return Err(format!("{} is a symlink", e.path().display()));
            }
            if t.is_dir() {
                todo.push(e.path());
            }
        }
    }
    if git.join("objects/info/alternates").exists() {
        return Err("the checkout borrows objects from elsewhere".to_owned());
    }
    Ok(())
}

/// `git` for the runner's own use on a checkout a session may have written: no system or global
/// config, no replace refs, no fsmonitor, no hooks.
fn safe_git() -> tokio::process::Command {
    let mut c = tokio::process::Command::new("git");
    c.args([
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
    ])
    .env_clear()
    .env("PATH", "/usr/local/bin:/usr/bin:/bin")
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("GIT_CONFIG_GLOBAL", "/dev/null")
    .env("GIT_NO_REPLACE_OBJECTS", "1")
    .env("GIT_TERMINAL_PROMPT", "0");
    c
}

/// `git bundle create <to> HEAD` of a checkout: the file and its length. The checkout's `.git` is
/// checked for symlinks, copied (`--mirror --no-local`, no hardlinks, no templates) into a private
/// dir beside `to`, and the bundle is made from that copy: nothing a session wrote is read by the
/// bundling itself.
async fn bundle(dir: &Path, to: &Path) -> Result<(PathBuf, u64), StreamError> {
    let bad = |e: String| StreamError::new(ErrorCode::InvalidArgs, e);
    let d = dir.to_path_buf();
    tokio::task::spawn_blocking(move || git_dir_clean(&d))
        .await
        .map_err(|e| bad(e.to_string()))?
        .map_err(|e| bad(format!("the checkout {}: {e}", dir.display())))?;
    let mut mirror = to.as_os_str().to_owned();
    mirror.push(".mirror");
    let mirror = PathBuf::from(mirror);
    let run = |mut c: tokio::process::Command, what: &'static str| async move {
        let out = c.output().await.map_err(|e| bad(format!("git: {e}")))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(bad(format!(
                "{what} the checkout: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    };
    let mut clone = safe_git();
    clone
        .args(["clone", "--mirror", "--no-local", "--template=", "-q"])
        .arg(dir)
        .arg(&mirror);
    run(clone, "copying").await?;
    let mut b = safe_git();
    b.arg("-C")
        .arg(&mirror)
        .args(["bundle", "create", "-q"])
        .arg(to)
        .arg("HEAD");
    run(b, "bundling").await?;
    let len = std::fs::metadata(to).map_err(|e| bad(e.to_string()))?.len();
    Ok((to.to_path_buf(), len))
}

#[cfg(test)]
mod port_review_tests;
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

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("run-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join(".git/objects/info")).unwrap();
        p
    }

    #[test]
    fn a_git_dir_with_a_symlink_or_alternates_is_refused() {
        let ok = scratch("git-ok");
        assert!(git_dir_clean(&ok).is_ok());
        let deep = scratch("git-deep");
        std::os::unix::fs::symlink("/etc/passwd", deep.join(".git/objects/info/x")).unwrap();
        assert!(git_dir_clean(&deep).unwrap_err().contains("symlink"));
        let alt = scratch("git-alt");
        std::fs::write(alt.join(".git/objects/info/alternates"), "/elsewhere\n").unwrap();
        assert!(git_dir_clean(&alt).unwrap_err().contains("borrows"));
        // `.git` itself a symlink, or a gitfile, is not a plain directory.
        let link = scratch("git-link");
        std::fs::remove_dir_all(link.join(".git")).unwrap();
        std::os::unix::fs::symlink(&ok, link.join(".git")).unwrap();
        assert!(git_dir_clean(&link).is_err());
        for p in [ok, deep, alt, link] {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn the_bundling_git_ignores_every_config_but_the_repos_own_safe_ones() {
        let c = safe_git();
        let c = c.as_std();
        let args: Vec<_> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args.join(" "),
            "-c core.fsmonitor=false -c core.hooksPath=/dev/null"
        );
        let env: BTreeMap<_, _> = c
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(env["GIT_CONFIG_NOSYSTEM"].as_deref(), Some("1"));
        assert_eq!(env["GIT_NO_REPLACE_OBJECTS"].as_deref(), Some("1"));
    }
}
