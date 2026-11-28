//! The Core's copy of every project repo (Core 0.9, P3-01): `<data>/mirrors/<repo id>.git`, a bare
//! repository the Core fetches from the remote (every 15 minutes while the project is active, on
//! demand, and when a session or run starts) and serves read-only to runners, which clone from it.
//! Pushes go to the remote, never into this copy.
//!
//! Security model:
//! - Serving is `git upload-pack` only, behind the signed gate with the `runner` scope
//!   (`api::v1::mirrors`): a runner is trusted compute of this Core, served only what it was leased,
//!   which holds only what the remote holds. `git receive-pack` is never run, so a runner cannot
//!   write the Core's copy; the route that names it answers 403. Nothing a runner sends reaches
//!   a shell: the repo is a number, the rest is the pack protocol on stdin.
//!   Only a runner holding a lease for the repo is served, and only while its project is
//!   active (P3-02; the model is at the top of `lease`).
//! - A mirror is only served while its repo row exists and its project and remote are the ones
//!   the mirror was made from (a marker file in it): removing a repo deletes its copy (in a task
//!   a dropped request cannot cancel), and a recycled repo id of another project or remote starts
//!   from nothing, never from the old objects.
//! - Protocol v2 lets a client ask for any object the copy holds, referenced or not. So after a
//!   fetch that dropped or rewrote refs (a force push, a deleted branch) the copy runs
//!   `git gc --prune=now` under the repo lock, and nothing unreferenced stays fetchable. A flag
//!   file is set before every fetch and cleared once no collection is owed, so a crash or a
//!   failed gc is made up at the next fetch.
//!   ponytail: gc rewrites packs while a stream may read them; an open file survives that, a
//!   stream that loses the race fails and the runner retries. Only a force push costs that.
//! - The Core's copy has no remote configured and no credential in it: the URL is a command
//!   argument (never one with a secret, `repo_url_problem`), and a token reaches git only in the
//!   environment of that one process, read by a fixed askpass script. It is never in argv, in a
//!   URL, in the repo config or in a log; git's own stderr is scrubbed of it before it is kept.
//! - git runs from a cleared environment: no global or system config, no hooks, no prompts, no
//!   redirects, only https and ssh, objects checked as they arrive (`transfer.fsckObjects`). ssh
//!   uses no key, no agent and the Core's own `known_hosts` (`StrictHostKeyChecking=accept-new`:
//!   trust on first use, a changed key is refused), so ssh remotes only work where no key is
//!   needed. `core.sshCommand` goes through `sh -c`, so ssh is only allowed when the mirrors
//!   path is plain (`[A-Za-z0-9/._-]`); otherwise `GIT_ALLOW_PROTOCOL` is `https` alone, which
//!   (unlike `protocol.ssh.allow`) nothing in the config can widen. Only a github.com https remote gets a token, found through
//!   the connections broker (`resolve` with the project owner's grants), so a repo no connection
//!   covers is fetched anonymously.
//! - Every git command runs in its own process group, killed when its output ends (before it is
//!   waited for) or when it times out; a pack stream has a total limit of 30 minutes. One
//!   fetch per repo at a time (an in-process lock); reads never take it, since git's own ref
//!   updates are atomic (`fetch --atomic`): a failed fetch leaves the older refs. Pack streams
//!   and advertisements share four slots, taken before anything is inflated or spawned.

use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::runner::{branch_name_ok, repo_url_problem};
use sqlx::{Row, SqlitePool};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::{OwnedMutexGuard, Semaphore};
use zeroize::Zeroizing;

use crate::api::App;
use crate::connections::adapter::Registry;
use crate::ops::secretbox::SecretBox;
use crate::store::connections::{resolve, secret};
use crate::store::projects as store;

/// How often a project's repos are fetched unless it picks another interval.
pub const INTERVAL: Duration = Duration::from_secs(15 * 60);

/// The file in a mirror naming the project and remote it was made from (`key`).
const MARKER: &str = "ainkrad-remote";

/// The file in a mirror while a collection of dropped objects may be owed.
const GC_FLAG: &str = "ainkrad-gc-owed";

/// What a mirror is made for: its project (a recycled repo id may land in another) and remote.
pub(crate) fn key(project: i64, remote: &str) -> String {
    format!("{project}\n{remote}")
}

/// The most a request to `upload-pack` may be once decompressed.
const REQUEST_MAX: usize = 8 << 20;

/// The fixed askpass: git asks for a user name, then a password; GitHub takes any user name with
/// a token as the password.
const ASKPASS: &str = "#!/bin/sh\ncase \"$1\" in\n  Username*) printf '%s\\n' x-access-token ;;\n  *) printf '%s\\n' \"$AINKRAD_GIT_TOKEN\" ;;\nesac\n";

/// Fetches at once unless `AINKRAD_MIRROR_FETCHES` says otherwise.
const FETCHES: usize = 2;

pub struct Mirrors {
    root: PathBuf,
    git: PathBuf,
    timeout: Duration,
    locks: Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>,
    /// Pack streams in flight; the Core machine runs other things too.
    serving: Arc<Semaphore>,
    /// Fetches running at once (`AINKRAD_MIRROR_FETCHES`, default [`FETCHES`]): a project made from
    /// twenty repos starts twenty, and a small Core machine must still answer its other requests.
    fetching: Arc<Semaphore>,
    /// Who may read which copy, until when (unix seconds) and for which project and remote (`key`);
    /// see `lease`.
    leases: Mutex<HashMap<(String, i64), (i64, String)>>,
}

mod insight;
mod lease;
mod main_copy;
mod read;
mod serve;
pub use insight::{CodeInfo, Commit};
#[cfg(test)]
pub(crate) use lease::grant_now;
pub use lease::{LEASE_SECS, for_session, release_run, release_session, servable};
pub use main_copy::ensure_main;
#[cfg(test)]
pub(crate) use main_copy::ensure_main_in as main_copy_for_test;
pub use read::path_ok;

/// Why a mirror cannot be served.
#[derive(Debug, PartialEq, Eq)]
pub enum ServeError {
    /// No fetch has succeeded yet.
    NotReady,
    Bad(&'static str),
    Failed(String),
}

/// A repo to fetch and who owns its project.
struct Target {
    id: i64,
    project: i64,
    remote: String,
    branch: String,
    owner: i64,
    active: bool,
}

impl Target {
    fn key(&self) -> String {
        key(self.project, &self.remote)
    }
}

fn key_of_target(t: &Target) -> String {
    t.key()
}

impl Mirrors {
    pub fn new(root: PathBuf) -> Self {
        // git runs with the mirrors dir as its working directory: every path must be absolute.
        let root = std::path::absolute(&root).unwrap_or(root);
        Self {
            root,
            git: PathBuf::from("git"),
            timeout: Duration::from_secs(300),
            locks: Mutex::default(),
            serving: Arc::new(Semaphore::new(4)),
            fetching: Arc::new(Semaphore::new(
                std::env::var("AINKRAD_MIRROR_FETCHES")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .filter(|n| *n > 0)
                    .unwrap_or(FETCHES),
            )),
            leases: Mutex::default(),
        }
    }

    /// Another git executable (tests).
    pub fn with_git(mut self, git: PathBuf) -> Self {
        self.git = git;
        self
    }

    pub fn dir(&self, repo: i64) -> PathBuf {
        self.root.join(format!("{repo}.git"))
    }

    async fn lock(&self, repo: i64) -> OwnedMutexGuard<()> {
        let lock = self
            .locks
            .lock()
            .expect("locks")
            .entry(repo)
            .or_default()
            .clone();
        lock.lock_owned().await
    }

    /// The repo's lock if no fetch holds it.
    fn try_lock(&self, repo: i64) -> Option<OwnedMutexGuard<()>> {
        let lock = self
            .locks
            .lock()
            .expect("locks")
            .entry(repo)
            .or_default()
            .clone();
        lock.try_lock_owned().ok()
    }

    /// Deletes the repo's copy, once nothing is fetching it (the repo was removed).
    pub async fn forget(&self, repo: i64) {
        let _one = self.lock(repo).await;
        for dir in [self.dir(repo), self.dir(repo).with_extension("cloning")] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// `git args…` as every git here runs (see the module docs); `token` only in its environment.
    fn command(&self, args: &[&str], token: Option<&str>) -> Command {
        let mut cmd = Command::new(&self.git);
        // `core.sshCommand` is run by `sh -c`: only a plain path may go into it.
        let known_hosts = self.root.join("known_hosts");
        let plain = |p: &str| {
            p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        };
        let ssh = known_hosts.to_str().filter(|p| plain(p));
        let sshconf = match ssh {
            Some(p) => format!(
                "core.sshCommand=ssh -F /dev/null -oBatchMode=yes -oIdentitiesOnly=yes \
                 -oIdentityFile=none -oUserKnownHostsFile={p} -oStrictHostKeyChecking=accept-new"
            ),
            None => "protocol.ssh.allow=never".to_owned(),
        };
        let fixed = [
            "core.hooksPath=/dev/null",
            "core.fsmonitor=false",
            "protocol.allow=never",
            "protocol.https.allow=always",
            "http.followRedirects=false",
            "http.lowSpeedLimit=1024",
            "http.lowSpeedTime=20",
            "init.templateDir=",
            "credential.helper=",
            "gc.auto=0",
            "transfer.fsckObjects=true",
            sshconf.as_str(),
        ];
        for c in fixed {
            cmd.args(["-c", c]);
        }
        if cfg!(test) {
            cmd.args(["-c", "protocol.file.allow=always"]);
        }
        cmd.args(args)
            .current_dir(&self.root)
            .env_clear()
            .env("HOME", "/dev/null")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_TEMPLATE_DIR", "")
            .env(
                "GIT_ALLOW_PROTOCOL",
                match (ssh.is_some(), cfg!(test)) {
                    (true, true) => "https:ssh:file",
                    (true, false) => "https:ssh",
                    (false, true) => "https:file",
                    (false, false) => "https",
                },
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd.as_std_mut().process_group(0);
        for name in ["PATH", "LANG"] {
            if let Some(v) = std::env::var_os(name) {
                cmd.env(name, v);
            }
        }
        if let Some(token) = token {
            cmd.env("GIT_ASKPASS", self.root.join("askpass"))
                .env("AINKRAD_GIT_TOKEN", token);
        }
        cmd
    }

    /// Runs `args` to the end within the timeout; stdout, or git's scrubbed last words.
    async fn run(&self, args: &[&str], token: Option<&str>) -> Result<String, String> {
        self.run_for(args, token, self.timeout).await
    }

    async fn run_for(
        &self,
        args: &[&str],
        token: Option<&str>,
        limit: Duration,
    ) -> Result<String, String> {
        self.run_command(self.command(args, token), token, limit)
            .await
    }

    /// `cmd` (made by `command`) run as `run_for` runs it.
    async fn run_command(
        &self,
        mut cmd: Command,
        token: Option<&str>,
        limit: Duration,
    ) -> Result<String, String> {
        let mut child = cmd.spawn().map_err(|e| format!("git: {e}"))?;
        let mut group = Group::new(child.id().ok_or("git has no pid")?);
        let (out, err) = (child.stdout.take(), child.stderr.take());
        let read = async {
            let (mut a, mut b) = (Vec::new(), Vec::new());
            tokio::join!(
                async {
                    if let Some(s) = out {
                        s.take(16 << 20).read_to_end(&mut a).await.ok();
                    }
                },
                async {
                    if let Some(e) = err {
                        e.take(1 << 20).read_to_end(&mut b).await.ok();
                    }
                }
            );
            (a, b)
        };
        let Ok((out, err)) = tokio::time::timeout(limit, read).await else {
            return Err("git timed out".into());
        };
        // Both pipes are closed: whatever is left (ssh, helpers) is killed before the wait.
        group.kill();
        let status = child.wait().await;
        group.reaped();
        match status {
            Ok(s) if s.success() => Ok(String::from_utf8_lossy(&out).into_owned()),
            _ => Err(scrub(&String::from_utf8_lossy(&err), token)),
        }
    }

    /// Makes `dir` hold the remote's branches and tags, and HEAD the default branch; its head.
    async fn sync(&self, t: &Target, token: Option<&str>) -> Result<String, String> {
        if !cfg!(test)
            && let Some(why) = repo_url_problem(&t.remote)
        {
            return Err(why);
        }
        if !branch_name_ok(&t.branch) {
            return Err("the default branch name is not valid".into());
        }
        std::fs::create_dir_all(&self.root).map_err(|e| format!("mirrors: {e}"))?;
        let askpass = self.root.join("askpass");
        if !askpass.exists() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&askpass, ASKPASS)
                .and_then(|()| {
                    std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700))
                })
                .map_err(|e| format!("mirrors: {e}"))?;
        }
        let dir = self.dir(t.id);
        // A copy made from another remote (a recycled repo id) is not this repo's: start over.
        if dir.exists() && self.ready(t.id, &t.key()).is_err() {
            std::fs::remove_dir_all(&dir).map_err(|e| format!("mirrors: {e}"))?;
        }
        // A first fetch is made aside and moved in, so a failed one leaves no half-made mirror.
        let fresh = !dir.join("HEAD").exists();
        let work = if fresh {
            dir.with_extension("cloning")
        } else {
            dir.clone()
        };
        let w = work.to_str().ok_or("path is not UTF-8")?;
        if fresh {
            let _ = std::fs::remove_dir_all(&work);
            self.run(&["init", "--bare", "-q", "--", w], None).await?;
            std::fs::write(work.join(MARKER), t.key()).map_err(|e| format!("mirrors: {e}"))?;
        }
        // Set before the fetch and cleared once no collection is owed: whatever stops this
        // short (a crash, a failed gc) leaves it for the next fetch.
        let flag = work.join(GC_FLAG);
        let owed = flag.exists();
        if !fresh {
            std::fs::write(&flag, "").map_err(|e| format!("mirrors: {e}"))?;
        }
        let before = match fresh {
            true => Vec::new(),
            false => self.refs(w).await?,
        };
        let branch = format!("refs/heads/{}", t.branch);
        let fetch = [
            "-C",
            w,
            "fetch",
            "--prune",
            "--atomic",
            "--no-auto-gc",
            "--",
            &t.remote,
            "+refs/heads/*:refs/heads/*",
            "+refs/tags/*:refs/tags/*",
        ];
        let head = async {
            self.run(&fetch, token).await?;
            self.forget_dropped(w, before, owed).await;
            self.run(&["-C", w, "symbolic-ref", "HEAD", &branch], None)
                .await?;
            let sha = self
                .run(
                    &[
                        "-C",
                        w,
                        "rev-parse",
                        "--verify",
                        "-q",
                        &format!("{branch}^{{commit}}"),
                    ],
                    None,
                )
                .await;
            sha.map(|s| s.trim().to_owned())
                .map_err(|_| format!("the remote has no branch {}", t.branch))
        }
        .await;
        match (&head, fresh) {
            (Ok(_), true) => std::fs::rename(&work, &dir).map_err(|e| format!("mirrors: {e}"))?,
            (Err(_), true) => drop(std::fs::remove_dir_all(&work)),
            _ => {}
        }
        head
    }

    /// The mirror to serve: made by a fetch, for `key`.
    fn ready(&self, repo: i64, key: &str) -> Result<String, ServeError> {
        let dir = self.dir(repo);
        let made = std::fs::read_to_string(dir.join(MARKER)).is_ok_and(|m| m == key);
        match dir.join("HEAD").exists() && made {
            true => dir
                .into_os_string()
                .into_string()
                .map_err(|_| ServeError::NotReady),
            false => Err(ServeError::NotReady),
        }
    }

    /// Every ref and what it points at.
    async fn refs(&self, w: &str) -> Result<Vec<(String, String)>, String> {
        let out = self
            .run(
                &["-C", w, "for-each-ref", "--format=%(objectname) %(refname)"],
                None,
            )
            .await?;
        let pair = |l: &str| l.split_once(' ').map(|(o, r)| (r.to_owned(), o.to_owned()));
        Ok(out.lines().filter_map(pair).collect())
    }

    /// After a fetch: if a ref was deleted or moved to a commit that does not contain what it
    /// held, objects no ref reaches are left, and protocol v2 would hand them out: collect them
    /// now (also when an earlier one was owed and not done: `owed`). A failure here is logged and
    /// leaves the flag; the fetch itself succeeded.
    async fn forget_dropped(&self, w: &str, before: Vec<(String, String)>, owed: bool) {
        let Ok(after) = self.refs(w).await else {
            return;
        };
        let mut dropped = owed;
        for (name, old) in &before {
            dropped |= match after.iter().find(|(n, _)| n == name) {
                None => true,
                Some((_, new)) if new == old => false,
                Some((_, new)) => self
                    .run(&["-C", w, "merge-base", "--is-ancestor", old, new], None)
                    .await
                    .is_err(),
            };
            if dropped {
                break;
            }
        }
        let flag = std::path::Path::new(w).join(GC_FLAG);
        if !dropped {
            let _ = std::fs::remove_file(flag);
            return;
        }
        let gc = ["-C", w, "gc", "--prune=now", "--quiet"];
        match self.run_for(&gc, None, Duration::from_secs(30 * 60)).await {
            Ok(_) => drop(std::fs::remove_file(flag)),
            Err(why) => tracing::warn!(why, "collecting a mirror's dropped objects failed"),
        }
    }
}

/// The `Git-Protocol` values passed on: `version=0` to `version=2`, nothing else.
fn protocol_of(header: Option<&str>) -> Option<&str> {
    header.filter(|h| matches!(*h, "version=0" | "version=1" | "version=2"))
}

/// A git process group: killed by `kill`, when dropped, and when its deadline (if any) passes,
/// so also what git started (ssh, remote helpers).
struct Group {
    pgid: u32,
    deadline: Option<tokio::task::AbortHandle>,
    /// The leader was waited for: its id may be anyone's now, so nothing is signalled.
    reaped: bool,
}

impl Group {
    fn new(pgid: u32) -> Self {
        Self {
            pgid,
            deadline: None,
            reaped: false,
        }
    }

    fn with_deadline(pgid: u32, limit: Duration) -> Self {
        let watchdog = tokio::spawn(async move {
            tokio::time::sleep(limit).await;
            let _ = ainkrad_sys::killpg(pgid, 9);
        });
        Self {
            pgid,
            deadline: Some(watchdog.abort_handle()),
            reaped: false,
        }
    }

    fn kill(&self) {
        if !self.reaped {
            let _ = ainkrad_sys::killpg(self.pgid, 9);
        }
    }

    /// Call right after the wait: no later kill (or the watchdog) may reach a reused id.
    fn reaped(&mut self) {
        self.reaped = true;
        if let Some(w) = &self.deadline {
            w.abort();
        }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        // The watchdog first: the id may be reused once this group is gone.
        if let Some(w) = &self.deadline {
            w.abort();
        }
        self.kill();
    }
}

/// The last 300 bytes of git's words, on one line, without the token.
fn scrub(text: &str, token: Option<&str>) -> String {
    let mut s = text.trim().to_owned();
    if let Some(t) = token.filter(|t| !t.is_empty()) {
        s = s.replace(t, "***");
    }
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let from = s.ceil_char_boundary(s.len().saturating_sub(300));
    s[from..].to_owned()
}

/// `owner/name` of a `https://github.com/owner/name(.git)` remote: the only kind that gets a token.
fn github_repo(url: &str) -> Option<String> {
    let rest = url
        .get(..19)
        .filter(|p| p.eq_ignore_ascii_case("https://github.com/"))
        .map(|_| &url[19..])?;
    let rest = rest.trim_end_matches('/');
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let (owner, name) = rest.split_once('/')?;
    let ok = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    };
    (ok(owner) && ok(name)).then(|| format!("{owner}/{name}"))
}

/// The token of the GitHub connection the project's owner may read `url`'s repo with, through
/// the broker's routing and grants; `None` for any other remote or when no connection covers it
/// (the fetch is then anonymous, and a private repo's error says so).
pub(crate) async fn token_for(
    pool: &SqlitePool,
    reg: &Registry,
    sealer: &SecretBox,
    owner: i64,
    url: &str,
    now: &str,
) -> Option<Zeroizing<String>> {
    let repo = github_repo(url)?;
    let cx = resolve::Context {
        workspace: owner,
        user: owner,
        role: "admin",
        agent: None,
        session: None,
        capability: "read_repo",
        operation: None,
        resource: Some(("repos", &repo)),
        allowlist: None,
    };
    let found = resolve::resolve(pool, reg, "github", &cx, now).await.ok()?;
    let (m, _) = secret::open(pool, sealer, owner, found.connection.id)
        .await
        .ok()?;
    Some(Zeroizing::new(m.access().to_owned()))
}

async fn target(pool: &SqlitePool, repo: i64) -> Result<Option<Target>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT r.id, r.project_id, r.remote_url, r.default_branch, p.user_id, p.state FROM core_project_repos r \
         JOIN core_projects p ON p.id = r.project_id WHERE r.id = ?",
    )
    .bind(repo)
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        Ok(Target {
            id: r.try_get("id")?,
            project: r.try_get("project_id")?,
            remote: r.try_get("remote_url")?,
            branch: r.try_get("default_branch")?,
            owner: r.try_get("user_id")?,
            active: r.try_get::<String, _>("state")? == "active",
        })
    })
    .transpose()
}

/// Why a fetch was not tried.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The Core has no mirrors directory (a test or a Core started without one).
    Off,
    NoRepo,
    Archived,
    Db(String),
}

/// Fetches one repo's remote into the Core's copy, waiting its turn, and records the outcome: the
/// new head, or the reason it failed with the older head and time kept. A failed fetch is a
/// recorded state, not an `Err`; `Err` is only for a fetch that could not be tried. Call it when
/// a session or run starts.
pub async fn refresh(app: &App, repo: i64) -> Result<store::Mirror, Refused> {
    let mirrors = app.mirrors.as_ref().ok_or(Refused::Off)?;
    let one = mirrors.lock(repo).await;
    fetch(app, mirrors, repo, one).await
}

/// "Fetch now": as `refresh`, but a fetch already under way for the repo is not queued behind or
/// started again; the state as it is comes back (the caller sees the running fetch's result
/// when it reads the state again).
pub async fn fetch_now(app: &App, repo: i64) -> Result<store::Mirror, Refused> {
    let mirrors = app.mirrors.as_ref().ok_or(Refused::Off)?;
    match mirrors.try_lock(repo) {
        Some(one) => fetch(app, mirrors, repo, one).await,
        None => {
            let db = |e: sqlx::Error| Refused::Db(e.to_string());
            let m = store::mirror(&app.pool, repo).await.map_err(db)?;
            Ok(m.unwrap_or(store::Mirror {
                repo_id: repo,
                head: None,
                fetched_at: None,
                error: None,
                state: "fetching".into(),
                reason: None,
                started_at: None,
            }))
        }
    }
}

/// The fetch itself, holding the repo's lock. The repo is looked up only now: it may have been
/// removed while this waited.
async fn fetch(
    app: &App,
    mirrors: &Mirrors,
    repo: i64,
    _one: OwnedMutexGuard<()>,
) -> Result<store::Mirror, Refused> {
    let db = |e: sqlx::Error| Refused::Db(e.to_string());
    // Waiting for a turn holds nothing: no pool connection, only this repo's lock.
    let _turn = mirrors.fetching.clone().acquire_owned().await;
    let t = target(&app.pool, repo)
        .await
        .map_err(db)?
        .ok_or(Refused::NoRepo)?;
    if !t.active {
        return Err(Refused::Archived);
    }
    let now = app.clock.now();
    let token = match &app.secrets {
        Some(sealer) => {
            token_for(
                &app.pool,
                app.connections.registry(),
                sealer,
                t.owner,
                &t.remote,
                &now,
            )
            .await
        }
        None => None,
    };
    let before = store::mirror(&app.pool, repo).await.map_err(db)?;
    let keep = |m: &Option<store::Mirror>| {
        (
            m.as_ref().and_then(|m| m.head.clone()),
            m.as_ref().and_then(|m| m.fetched_at.clone()),
        )
    };
    // Said before the wait (the person sees it at once); `start` may have said it already.
    if before.as_ref().is_none_or(|m| m.state != "fetching") {
        let (h, f) = keep(&before);
        let state = ("fetching", Some(now.as_str()));
        let (h, f) = (h.as_deref(), f.as_deref());
        store::set_mirror_state(&app.pool, repo, state, (h, f), (None, None))
            .await
            .map_err(db)?;
    }
    let has_token = token.is_some();
    let outcome = mirrors.sync(&t, token.as_ref().map(|t| t.as_str())).await;
    // The older head is only kept while the copy it names is still there.
    let kept = mirrors
        .ready(repo, &t.key())
        .is_ok()
        .then_some(before)
        .flatten();
    match &outcome {
        Ok(h) => tracing::info!(repo, head = %h, "mirror fetched"),
        Err(why) => tracing::warn!(repo, why, "mirror fetch failed"),
    }
    // The repo may have been removed meanwhile: its row is gone with it, nothing to record.
    let saved = match &outcome {
        Ok(head) => {
            let at = Some(now.as_str());
            let state = ("ready", None);
            store::set_mirror_state(&app.pool, repo, state, (Some(head), at), (None, None)).await
        }
        Err(why) => {
            let reason = classify(why, &t.remote, has_token);
            let words = reason.sentence(why);
            let (h, f) = keep(&kept);
            let kept = (h.as_deref(), f.as_deref());
            let code = Some(reason.code());
            store::set_mirror_state(
                &app.pool,
                repo,
                ("failed", None),
                kept,
                (Some(&words), code),
            )
            .await
        }
    };
    saved.map_err(db)?;
    store::mirror(&app.pool, repo)
        .await
        .map_err(db)?
        .ok_or(Refused::NoRepo)
}

/// Why a fetch failed; `code` goes to the API, `sentence` to the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Private (or missing) on GitHub and no connection covers it.
    NeedsGithub,
    NotFoundOrPrivate,
    AuthFailed,
    Timeout,
    SshNotSupported,
    /// Anything else; git's own words are kept.
    Other,
}

impl Reason {
    pub fn code(self) -> &'static str {
        match self {
            Self::NeedsGithub => "needs_github",
            Self::NotFoundOrPrivate => "not_found_or_private",
            Self::AuthFailed => "auth_failed",
            Self::Timeout => "timeout",
            Self::SshNotSupported => "ssh_not_supported",
            Self::Other => "other",
        }
    }

    /// One plain sentence; `git` (already scrubbed) only for `Other`.
    pub fn sentence(self, git: &str) -> String {
        match self {
            Self::NeedsGithub => "This repo is private. Connect GitHub to copy it.".into(),
            Self::NotFoundOrPrivate => "The remote says this repo does not exist, or you cannot see it. Check the address and your access.".into(),
            Self::AuthFailed => "The remote refused the sign-in. Reconnect the account and try again.".into(),
            Self::Timeout => "The remote did not answer in time. Try again in a moment.".into(),
            Self::SshNotSupported => "SSH addresses are not supported yet. Use the https address of the repo.".into(),
            Self::Other => git.to_owned(),
        }
    }
}

/// An ssh remote: `ssh://…` or scp-style `user@host:path`.
fn is_ssh(remote: &str) -> bool {
    let l = remote.to_ascii_lowercase();
    l.starts_with("ssh://") || (!l.contains("://") && !l.starts_with('/') && l.contains(':'))
}

/// Why an ssh remote is refused when a repo is added (the Core holds no key for it).
pub fn ssh_problem(remote: &str) -> Option<String> {
    is_ssh(remote).then(|| Reason::SshNotSupported.sentence(""))
}

/// Sorts a failed fetch's words (`git`: git's scrubbed stderr, or `git timed out`) into a
/// [`Reason`]. `has_token`: a connection covered the repo. ponytail: substring matching on git's
/// English; git has no exit codes for these, upgrade if it ever gets machine-readable errors.
pub fn classify(git: &str, remote: &str, has_token: bool) -> Reason {
    let g = git.to_ascii_lowercase();
    let github = github_repo(remote).is_some();
    let private = |covered: Reason| match github && !has_token {
        true => Reason::NeedsGithub,
        false => covered,
    };
    if g.contains("timed out") {
        Reason::Timeout
    } else if is_ssh(remote) {
        Reason::SshNotSupported
    } else if [
        "could not read username",
        "terminal prompts disabled",
        "authentication failed",
        "invalid username",
        "bad credentials",
        "permission denied",
        "access denied",
        "error: 401",
        "error: 403",
    ]
    .iter()
    .any(|k| g.contains(k))
    {
        private(Reason::AuthFailed)
    } else if [
        "not found",
        "error: 404",
        "does not appear to be a git repository",
        "could not read from remote",
    ]
    .iter()
    .any(|k| g.contains(k))
    {
        private(Reason::NotFoundOrPrivate)
    } else {
        Reason::Other
    }
}

/// Marks a repo `fetching` and fetches it in the background: a new repo is copied at once, not
/// when the next sweep comes. Failure is a recorded state, so nothing is returned.
pub async fn start(app: &App, repo: i64) {
    if app.mirrors.is_none() {
        return;
    }
    let before = store::mirror(&app.pool, repo).await.ok().flatten();
    let now = app.clock.now();
    let (h, f) = (
        before.as_ref().and_then(|m| m.head.as_deref()),
        before.as_ref().and_then(|m| m.fetched_at.as_deref()),
    );
    let _ = store::set_mirror_state(
        &app.pool,
        repo,
        ("fetching", Some(&now)),
        (h, f),
        (None, None),
    )
    .await;
    let app = app.clone();
    tokio::spawn(async move {
        // A repo added (or a project made with one): its project folder is made right after.
        if refresh(&app, repo).await.is_ok_and(|m| m.state == "ready")
            && let Ok(Some(t)) = target(&app.pool, repo).await
            && let Err(why) = ensure_main(&app, t.project).await
        {
            tracing::debug!(repo, why, "the project folder was not made");
        }
    });
}

/// Whether a project's automatic fetch is due: its interval in minutes (0: only when asked) has
/// passed since `last`, or it was never fetched here.
pub fn due(
    interval_minutes: i64,
    last: Option<tokio::time::Instant>,
    now: tokio::time::Instant,
) -> bool {
    let wait = Duration::from_secs(u64::try_from(interval_minutes).unwrap_or(0) * 60);
    interval_minutes > 0 && last.is_none_or(|l| now.duration_since(l) >= wait)
}

/// Every active project's repos, one after the other (the Core machine is small).
pub async fn sweep(app: &App) {
    sweep_due(app, None).await;
}

/// The sweep, honouring each project's `fetch_interval_minutes` when `last` (when each project was
/// last swept) is given; without it every project is fetched.
async fn sweep_due(
    app: &App,
    mut last: Option<&mut std::collections::HashMap<i64, tokio::time::Instant>>,
) {
    let Ok(projects) = store::list(&app.pool, false).await else {
        return;
    };
    let now = tokio::time::Instant::now();
    for p in projects {
        if let Some(l) = last.as_deref_mut() {
            if !due(p.fetch_interval_minutes, l.get(&p.id).copied(), now) {
                continue;
            }
            l.insert(p.id, now);
        }
        let Ok(mut conn) = app.pool.acquire().await else {
            return;
        };
        let repos = store::repos(&mut conn, p.id).await.unwrap_or_default();
        drop(conn);
        for r in repos {
            // A failure is recorded on the mirror already.
            let _ = refresh(app, r.id).await;
        }
    }
}

/// Looks once a minute, after a short wait, and fetches each project whose own interval has
/// passed (default [`INTERVAL`]), until the Core stops.
pub async fn sweep_loop(app: App) {
    let mut closing = app.closing.subscribe();
    let start = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut tick = tokio::time::interval_at(start, Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last = std::collections::HashMap::new();
    loop {
        tokio::select! {
            _ = tick.tick() => sweep_due(&app, Some(&mut last)).await,
            () = crate::api::stopping(&mut closing) => return,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod due_tests {
    use super::due;
    use tokio::time::{Duration, Instant};

    #[test]
    fn a_project_is_due_after_its_own_interval_and_never_at_zero() {
        let t0 = Instant::now();
        let later = |m: u64| t0 + Duration::from_secs(m * 60);
        assert!(due(15, None, t0));
        assert!(!due(15, Some(t0), later(14)));
        assert!(due(15, Some(t0), later(15)));
        assert!(due(10, Some(t0), later(10)));
        assert!(!due(0, None, later(1000)));
    }
}
