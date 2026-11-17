//! The Core's copy of every project repo (Core 0.9, P3-01): `<data>/mirrors/<repo id>.git`, a bare
//! repository the Core fetches from the remote (every 15 minutes while the project is active, on
//! demand, and when a session or run starts) and serves read-only to runners, which clone from it.
//! Pushes go to the remote, never into this copy.
//!
//! Security model:
//! - Serving is `git upload-pack` only, behind the signed gate with the `runner` scope
//!   (`api::v1::mirrors`): a runner is trusted compute of this Core and may read any mirror,
//!   which holds only what the remote holds. `git receive-pack` is never run, so a runner cannot
//!   write the Core's copy; the route that names it answers 403. Nothing a runner sends reaches
//!   a shell: the repo is a number, the rest is the pack protocol on stdin.
//! - The Core's copy has no remote configured and no credential in it: the URL is a command
//!   argument (never one with a secret, `repo_url_problem`), and a token reaches git only in the
//!   environment of that one process, read by a fixed askpass script. It is never in argv, in a
//!   URL, in the repo config or in a log; git's own stderr is scrubbed of it before it is kept.
//! - git runs from a cleared environment: no global or system config, no hooks, no prompts, no
//!   redirects, only https and ssh. Only a github.com https remote gets a token, found through
//!   the connections broker (`resolve` with the project owner's grants), so a repo no connection
//!   covers is fetched anonymously.
//! - Every git command runs in its own process group, killed when it ends or times out. One
//!   fetch per repo at a time (an in-process lock); reads never take it, since git's own ref
//!   updates are atomic (`fetch --atomic`): a failed fetch leaves the older refs.

use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::runner::{branch_name_ok, repo_url_problem};
use axum::body::{Body, Bytes};
use sqlx::{Row, SqlitePool};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{OwnedMutexGuard, Semaphore};
use zeroize::Zeroizing;

use crate::api::App;
use crate::connections::adapter::Registry;
use crate::ops::secretbox::SecretBox;
use crate::store::connections::{resolve, secret};
use crate::store::projects as store;

/// How often every active project's repos are fetched.
pub const INTERVAL: Duration = Duration::from_secs(15 * 60);

/// The most a request to `upload-pack` may be once decompressed.
const REQUEST_MAX: usize = 8 << 20;

/// The fixed askpass: git asks for a user name, then a password; GitHub takes any user name with
/// a token as the password.
const ASKPASS: &str = "#!/bin/sh\ncase \"$1\" in\n  Username*) printf '%s\\n' x-access-token ;;\n  *) printf '%s\\n' \"$AINKRAD_GIT_TOKEN\" ;;\nesac\n";

pub struct Mirrors {
    root: PathBuf,
    git: PathBuf,
    timeout: Duration,
    locks: Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>,
    /// Pack streams in flight; the Core machine runs other things too.
    serving: Arc<Semaphore>,
}

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
    remote: String,
    branch: String,
    owner: i64,
    active: bool,
}

impl Mirrors {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            git: PathBuf::from("git"),
            timeout: Duration::from_secs(300),
            locks: Mutex::default(),
            serving: Arc::new(Semaphore::new(4)),
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

    /// `git args…` as every git here runs (see the module docs); `token` only in its environment.
    fn command(&self, args: &[&str], token: Option<&str>) -> Command {
        let mut cmd = Command::new(&self.git);
        let fixed = [
            "core.hooksPath=/dev/null",
            "core.fsmonitor=false",
            "protocol.allow=never",
            "protocol.https.allow=always",
            "protocol.ssh.allow=always",
            "http.followRedirects=false",
            "http.lowSpeedLimit=1024",
            "http.lowSpeedTime=20",
            "init.templateDir=",
            "credential.helper=",
            "gc.auto=0",
            "core.sshCommand=ssh -F /dev/null -oBatchMode=yes -oStrictHostKeyChecking=yes",
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
                if cfg!(test) {
                    "https:ssh:file"
                } else {
                    "https:ssh"
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
        let mut child = self
            .command(args, token)
            .spawn()
            .map_err(|e| format!("git: {e}"))?;
        let _group = Group(child.id().ok_or("git has no pid")?);
        let (out, err) = (child.stdout.take(), child.stderr.take());
        let read = |s: Option<tokio::process::ChildStdout>,
                    e: Option<tokio::process::ChildStderr>| async move {
            let (mut a, mut b) = (Vec::new(), Vec::new());
            if let Some(s) = s {
                s.take(16 << 20).read_to_end(&mut a).await.ok();
            }
            if let Some(e) = e {
                e.take(1 << 20).read_to_end(&mut b).await.ok();
            }
            (a, b)
        };
        let run = async { tokio::join!(child.wait(), read(out, None), read(None, err)) };
        let Ok((status, (out, _), (_, err))) = tokio::time::timeout(self.timeout, run).await else {
            return Err("git timed out".into());
        };
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
        }
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

    /// The mirror to serve, if a fetch has made one.
    fn ready(&self, repo: i64) -> Result<String, ServeError> {
        let dir = self.dir(repo);
        match dir.join("HEAD").exists() {
            true => dir
                .into_os_string()
                .into_string()
                .map_err(|_| ServeError::NotReady),
            false => Err(ServeError::NotReady),
        }
    }

    /// The reference advertisement of `git upload-pack` for smart HTTP. `protocol` is the
    /// client's `Git-Protocol` header (`version=2`), passed on only if it is that plain.
    pub async fn advertise(
        &self,
        repo: i64,
        protocol: Option<&str>,
    ) -> Result<Vec<u8>, ServeError> {
        let dir = self.ready(repo)?;
        let mut cmd = self.command(
            &[
                "upload-pack",
                "--stateless-rpc",
                "--advertise-refs",
                "--timeout=30",
                &dir,
            ],
            None,
        );
        let v2 = protocol_of(protocol).is_some_and(|p| p == "version=2");
        if let Some(p) = protocol_of(protocol) {
            cmd.env("GIT_PROTOCOL", p);
        }
        let mut child = cmd.spawn().map_err(|e| ServeError::Failed(e.to_string()))?;
        let _group = Group(
            child
                .id()
                .ok_or_else(|| ServeError::Failed("no pid".into()))?,
        );
        let (mut out, mut err) = (child.stdout.take(), child.stderr.take());
        let (mut a, mut b) = (Vec::new(), Vec::new());
        let io = async {
            tokio::join!(
                async {
                    if let Some(o) = out.as_mut() {
                        o.take(16 << 20).read_to_end(&mut a).await.ok();
                    }
                },
                async {
                    if let Some(e) = err.as_mut() {
                        e.take(1 << 16).read_to_end(&mut b).await.ok();
                    }
                },
            );
            child.wait().await
        };
        match tokio::time::timeout(Duration::from_secs(30), io).await {
            Ok(Ok(s)) if s.success() => {
                // Version 2 has no service line; version 0 and 1 have one and a flush.
                let mut body = if v2 {
                    vec![]
                } else {
                    b"001e# service=git-upload-pack\n0000".to_vec()
                };
                body.extend(a);
                Ok(body)
            }
            _ => Err(ServeError::Failed(scrub(
                &String::from_utf8_lossy(&b),
                None,
            ))),
        }
    }

    /// `git upload-pack` answering one request: its output as it is made. `gzip` says the
    /// request is gzip-compressed, as git sends a large one.
    pub async fn upload_pack(
        &self,
        repo: i64,
        protocol: Option<&str>,
        request: &[u8],
        gzip: bool,
    ) -> Result<Body, ServeError> {
        let dir = self.ready(repo)?;
        let request = match gzip {
            true => self.gunzip(request).await?,
            false => request.to_vec(),
        };
        let permit = self
            .serving
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ServeError::Bad("closed"))?;
        let mut cmd = self.command(
            &["upload-pack", "--stateless-rpc", "--timeout=60", &dir],
            None,
        );
        if let Some(p) = protocol_of(protocol) {
            cmd.env("GIT_PROTOCOL", p);
        }
        // Nobody reads its stderr: a full pipe would stall it.
        cmd.stdin(Stdio::piped()).stderr(Stdio::null());
        let mut child = cmd.spawn().map_err(|e| ServeError::Failed(e.to_string()))?;
        let group = Group(
            child
                .id()
                .ok_or_else(|| ServeError::Failed("no pid".into()))?,
        );
        let (stdin, stdout) = (child.stdin.take(), child.stdout.take());
        let (Some(mut stdin), Some(stdout)) = (stdin, stdout) else {
            return Err(ServeError::Failed("no pipes".into()));
        };
        tokio::spawn(async move {
            let _ = stdin.write_all(&request).await;
        });
        // The child, its group and the permit live as long as the stream.
        let stream = futures_util::stream::unfold(
            (stdout, child, group, permit),
            |(mut out, mut child, group, permit)| async move {
                let mut buf = vec![0; 64 << 10];
                match out.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        buf.truncate(n);
                        Some((
                            Ok::<_, std::io::Error>(Bytes::from(buf)),
                            (out, child, group, permit),
                        ))
                    }
                    _ => {
                        let _ = child.wait().await;
                        None
                    }
                }
            },
        );
        Ok(Body::from_stream(stream))
    }

    /// `request` decompressed, within `REQUEST_MAX`, by the system `gzip`.
    async fn gunzip(&self, request: &[u8]) -> Result<Vec<u8>, ServeError> {
        let mut cmd = Command::new("gzip");
        cmd.arg("-dc")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| ServeError::Failed(e.to_string()))?;
        let (mut stdin, stdout) = (child.stdin.take(), child.stdout.take());
        let (Some(stdin), Some(stdout)) = (stdin.take(), stdout) else {
            return Err(ServeError::Failed("no pipes".into()));
        };
        let input = request.to_vec();
        tokio::spawn(async move {
            let mut stdin = stdin;
            let _ = stdin.write_all(&input).await;
        });
        let mut out = Vec::new();
        stdout
            .take(REQUEST_MAX as u64 + 1)
            .read_to_end(&mut out)
            .await
            .map_err(|e| ServeError::Failed(e.to_string()))?;
        match out.len() <= REQUEST_MAX && child.wait().await.is_ok_and(|s| s.success()) {
            true => Ok(out),
            false => Err(ServeError::Bad(
                "the request is not valid gzip or is too large",
            )),
        }
    }
}

/// The `Git-Protocol` values passed on: `version=0` to `version=2`, nothing else.
fn protocol_of(header: Option<&str>) -> Option<&str> {
    header.filter(|h| matches!(*h, "version=0" | "version=1" | "version=2"))
}

/// Kills the git process group when dropped: also what git started (ssh, remote helpers).
struct Group(u32);

impl Drop for Group {
    fn drop(&mut self) {
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{}", self.0)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
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
        "SELECT r.id, r.remote_url, r.default_branch, p.user_id, p.state FROM core_project_repos r \
         JOIN core_projects p ON p.id = r.project_id WHERE r.id = ?",
    )
    .bind(repo)
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        Ok(Target {
            id: r.try_get("id")?,
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

/// Fetches one repo's remote into the Core's copy and records the outcome: the new head, or the
/// reason it failed with the older head and time kept. A failed fetch is a recorded state, not
/// an `Err`; `Err` is only for a fetch that could not be tried. Call it when a session or run
/// starts.
pub async fn refresh(app: &App, repo: i64) -> Result<store::Mirror, Refused> {
    let db = |e: sqlx::Error| Refused::Db(e.to_string());
    let mirrors = app.mirrors.as_ref().ok_or(Refused::Off)?;
    let t = target(&app.pool, repo)
        .await
        .map_err(db)?
        .ok_or(Refused::NoRepo)?;
    if !t.active {
        return Err(Refused::Archived);
    }
    let _one = mirrors.lock(repo).await;
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
    let outcome = mirrors.sync(&t, token.as_ref().map(|t| t.as_str())).await;
    let before = store::mirror(&app.pool, repo).await.map_err(db)?;
    let (head, at, error) = match &outcome {
        Ok(head) => (Some(head.clone()), Some(now), None),
        Err(why) => (
            before.as_ref().and_then(|m| m.head.clone()),
            before.and_then(|m| m.fetched_at),
            Some(why.clone()),
        ),
    };
    match &outcome {
        Ok(h) => tracing::info!(repo, head = %h, "mirror fetched"),
        Err(why) => tracing::warn!(repo, why, "mirror fetch failed"),
    }
    // The repo may have been removed meanwhile: its row is gone with it, nothing to record.
    store::set_mirror(
        &app.pool,
        repo,
        head.as_deref(),
        at.as_deref(),
        error.as_deref(),
    )
    .await
    .map_err(db)?;
    store::mirror(&app.pool, repo)
        .await
        .map_err(db)?
        .ok_or(Refused::NoRepo)
}

/// Every active project's repos, one after the other (the Core machine is small).
pub async fn sweep(app: &App) {
    let Ok(projects) = store::list(&app.pool, false).await else {
        return;
    };
    for p in projects {
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

/// Fetches everything after a short wait, then every [`INTERVAL`], until the Core stops.
pub async fn sweep_loop(app: App) {
    let mut closing = app.closing.subscribe();
    let start = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut tick = tokio::time::interval_at(start, INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => sweep(&app).await,
            () = crate::api::stopping(&mut closing) => return,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
