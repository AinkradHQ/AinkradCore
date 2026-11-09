//! Subscription sign-in on a runner (KAN-441 L2; plan `2026-11-05-claude-subscription-sign-in`,
//! spec 12e). The runner drives `claude setup-token` in a PTY for the Core, which never runs the
//! vendor CLI itself.
//!
//! - `login.start`: checks the CLI's version against [`PINNED`] (an unknown one is refused),
//!   starts it in a per-login scratch dir, and answers `login.url` with the first URL it prints.
//! - `login.code`: types the approval code the user pasted into the PTY and answers
//!   `login.result` with the token it prints (`sk-ant-oat01-…`), once, or why there is none.
//! - `login.cancel`: kills the PTY's process group and wipes the scratch dir.
//!
//! Secrets: the code and the token live in [`Zeroizing`] strings and a [`Screen`] that wipes
//! itself; nothing the child printed is logged, and any child text in an error goes through
//! [`parse::redact`]. The token is never written to disk: the child's own files go to the
//! scratch HOME, which is removed on every ending (done, failed, cancelled, timed out) and swept
//! at runner start. The one copy that is not wiped is the `login.result` frame itself, which the
//! session holds until the Core acknowledges it (resume), like any frame.
//!
//! The child is **not sandboxed**: the harness sandbox (`harness::sandbox`) is compiled from an
//! agent run's `Spec` and its network modes are `deny` (the code exchange could not reach
//! Anthropic), `allow` (any host, on TCP 443 on macOS; refused for a secret-holding run on
//! Linux) or `filtered` (Linux, one egress policy for the whole runner, not a claude.ai-only
//! list of its own). So the child runs as the runner's user with a scrubbed environment
//! ([`child_env`]), its own session and process group, and HOME/TMPDIR/XDG in the scratch dir.
//! It can read what the runner's user can read and reach whatever the host network reaches.
//!
//! Gaps, stated: the `login.code` and `login.result` frames carry the secrets as plain `String`s
//! (the wire types), which the session's frame buffer holds until acknowledged; the PTY read
//! chunks and the screen are wiped, the token and code copies made here are `Zeroizing`. The
//! runner does not set `RLIMIT_CORE` (no safe std call, and `unsafe` is forbidden outside
//! `crates/sys`): run it with core dumps off (`LimitCORE=0`, `ulimit -c 0`).

#[cfg(test)]
mod hardening_tests;
mod parse;
#[cfg(test)]
mod parse_tests;
#[cfg(test)]
mod redact_tests;
mod run;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::{
    Body, CAP_LOGIN, Command, DriverInfo, ErrorCode, LoginCancel, LoginCode, LoginResult,
    LoginStart, LoginUrl, Reply, Size, StreamError,
};
use ainkrad_ptyhost::pty;

use super::agent::AgentDriver;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

/// The `claude` versions whose `setup-token` output this driver was written against. Any other
/// is refused with a clear result (the CLI changes; a guess could type a code into the wrong
/// prompt). Seeded from `claude --version` on the build machine (2026-11-05).
pub const PINNED: &[&str] = &["2.1.318"];

/// The sign-in's whole life (the Core's login expires at the same time).
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(600);
/// How long the CLI may take to print its URL.
const URL_TIMEOUT: Duration = Duration::from_secs(60);
/// Output quiet this long ends the line being written (a prompt has no newline).
const QUIET: Duration = Duration::from_millis(300);
/// The code and its Enter are two writes this far apart: a raw-mode TUI reads one chunk holding
/// both as a paste, and the Enter in it does not submit.
const ENTER_DELAY: Duration = Duration::from_millis(150);
/// Once the code is in, a token must follow this soon (a wrong or expired code never gets one).
const ANSWER_TIMEOUT: Duration = Duration::from_secs(60);
/// With no recognisable prompt, a code is typed once the output has been quiet this long.
const PROMPT_QUIET: Duration = Duration::from_millis(750);
const TICK: Duration = Duration::from_millis(50);
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);
/// Wide, so the terminal never wraps a URL or the token.
const SIZE: Size = Size {
    rows: 50,
    cols: 500,
};
/// All the output one sign-in may produce.
const MAX_OUTPUT: usize = 1 << 20;
/// At most this many sign-ins at once on a runner.
const MAX_LOGINS: usize = 1;

pub struct LoginConfig {
    /// `<state>/logins`: one dir per sign-in, swept at start.
    pub root: PathBuf,
    /// The `claude` executable (absolute).
    pub program: PathBuf,
    /// Arguments before the CLI's own (a test runs a script through `/bin/sh`).
    pub args: Vec<String>,
    pub timeout: Duration,
    pub url_timeout: Duration,
    /// Per signal of the escalating kill.
    pub grace: Duration,
    /// Between typing the code and its Enter; zero sends both in one write (a test of the stand-in).
    pub enter_delay: Duration,
    /// From the code to the token.
    pub answer_timeout: Duration,
    /// Versions accepted (tests add a stand-in's).
    pub pinned: Vec<String>,
}

impl LoginConfig {
    pub fn new(root: PathBuf, program: PathBuf) -> Self {
        Self {
            root,
            program,
            args: Vec::new(),
            timeout: LOGIN_TIMEOUT,
            url_timeout: URL_TIMEOUT,
            grace: Duration::from_millis(500),
            enter_delay: ENTER_DELAY,
            answer_timeout: ANSWER_TIMEOUT,
            pinned: PINNED.iter().map(|v| (*v).to_owned()).collect(),
        }
    }
}

/// `claude` on the runner's PATH, as an absolute path.
fn find_claude() -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join("claude"))
        .find(|p| {
            p.is_absolute()
                && std::fs::metadata(p)
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

/// Removes every sign-in scratch dir an earlier runner left (`<state>/logins`). The runner does
/// this at start whatever else is enabled: a crash can leave a scratch HOME behind.
pub fn sweep(state: &Path) {
    let _ = std::fs::remove_dir_all(state.join("logins"));
}

/// The sign-in driver for this runner (`<state>/logins`), or `None` (with the reason logged)
/// when there is no `claude` on PATH. Its version is not judged here: [`advertise`] checks it
/// each time the runner connects, and `login.start` checks it again, because `claude` updates
/// itself.
pub async fn detect(state: &Path) -> Option<Arc<LoginDriver>> {
    let Some(program) = find_claude() else {
        tracing::info!("sign-in is not offered: no claude on PATH");
        return None;
    };
    let driver = match LoginDriver::new(LoginConfig::new(state.join("logins"), program)) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            tracing::warn!("sign-in is not offered: {e}");
            return None;
        }
    };
    match driver.supported().await {
        Ok(v) => tracing::info!(version = %v, "claude sign-in is offered"),
        Err(why) => tracing::warn!("sign-in is not offered while: {why}"),
    }
    Some(driver)
}

/// The agent driver's info for a hello, with the `login` command added when `claude` is, right
/// now, a pinned version. Called for each hello: a `claude` that updated itself off the pinned
/// list drops the capability at the next connection, and the Core places no sign-in here.
pub async fn advertise(
    agent: Option<&Arc<AgentDriver>>,
    login: Option<&Arc<LoginDriver>>,
) -> Option<DriverInfo> {
    let mut info = agent?.info();
    // This runner applies the subscription rules before it redeems a lease (KAN-434).
    info.commands
        .push(ainkrad_proto::v2::CAP_SUBSCRIPTION_ENV.to_owned());
    if let Some(l) = login {
        match l.supported().await {
            Ok(_) => info.commands.push(CAP_LOGIN.to_owned()),
            Err(why) => tracing::warn!("sign-in is not offered: {why}"),
        }
    }
    Some(info)
}

/// A `login.*` command, answered by a task (`None` now): the sign-in lives in the driver, not in
/// the command's stream.
pub fn dispatch(
    login: Option<&Arc<LoginDriver>>,
    stream: u64,
    command: Command,
    done: &mpsc::UnboundedSender<(u64, Body)>,
) -> Option<Body> {
    let (Some(login), true) = (login, command.op().starts_with("login.")) else {
        return Some(Body::Error(err(
            ErrorCode::UnsupportedCommand,
            "no driver of this runner takes that command",
        )));
    };
    let (login, done) = (Arc::clone(login), done.clone());
    tokio::spawn(async move {
        let answer = match command {
            Command::LoginStart(req) => login.start(req).await.map(Reply::LoginUrl),
            Command::LoginCode(req) => login.code(req).await.map(Reply::LoginResult),
            Command::LoginCancel(req) => login.cancel(req).await.map(Reply::LoginResult),
            _ => return,
        };
        let body = match answer {
            Ok(reply) => Body::Result(reply),
            Err(e) => Body::Error(e),
        };
        let _ = done.send((stream, body));
    });
    None
}

enum Msg {
    Code(Zeroizing<String>, oneshot::Sender<LoginResult>),
    Cancel(oneshot::Sender<()>),
}

pub struct LoginDriver {
    cfg: LoginConfig,
    /// The sign-ins running, by id.
    active: Mutex<HashMap<String, mpsc::UnboundedSender<Msg>>>,
}

fn err(code: ErrorCode, why: impl Into<String>) -> StreamError {
    StreamError::new(code, why)
}

fn id_ok(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// What gets typed into the PTY: the Core's shape check again (a newline here would be a second
/// line of input), and never something that is itself a token.
fn code_ok(code: &str) -> bool {
    (8..=512).contains(&code.len())
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.~#:+/=".contains(&b))
        && !code.starts_with("sk-ant-")
}

fn result(id: &str, error: Option<&str>) -> LoginResult {
    LoginResult {
        login_id: id.to_owned(),
        token: None,
        error: error.map(str::to_owned),
    }
}

/// The child's whole environment: the pty host's allow-list from the runner's own (so no
/// provider key or token), then HOME, TMPDIR and the XDG dirs in the scratch dir, and a fixed
/// PATH that starts with the scratch dir's browser stubs.
pub fn child_env(runner: &[(OsString, OsString)], scratch: &Path) -> BTreeMap<String, String> {
    let (home, tmp) = (scratch.join("home"), scratch.join("tmp"));
    let path = format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        scratch.join("bin").display()
    );
    let d = |p: &Path| p.display().to_string();
    let set = BTreeMap::from([
        ("HOME".to_owned(), d(&home)),
        ("TMPDIR".to_owned(), d(&tmp)),
        ("XDG_CONFIG_HOME".to_owned(), d(&home.join(".config"))),
        ("XDG_DATA_HOME".to_owned(), d(&home.join(".local/share"))),
        ("XDG_STATE_HOME".to_owned(), d(&home.join(".local/state"))),
        ("XDG_CACHE_HOME".to_owned(), d(&home.join(".cache"))),
        ("CLAUDE_CONFIG_DIR".to_owned(), d(&home.join(".claude"))),
        // Best effort: no browser on the runner's machine opens the URL. `BROWSER` is one way a
        // CLI looks; the stubs first on PATH (`make_stubs`) catch `open` and `xdg-open`.
        ("BROWSER".to_owned(), "/usr/bin/false".to_owned()),
        ("PATH".to_owned(), path),
        ("DISABLE_AUTOUPDATER".to_owned(), "1".to_owned()),
    ]);
    pty::environment(runner, &[], &[], &set)
}

/// Scripts named like the programs a CLI opens a browser with, in `<scratch>/bin`, that only fail.
fn make_stubs(scratch: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let bin = scratch.join("bin");
    private_dir(&bin)?;
    for name in [
        "open",
        "xdg-open",
        "sensible-browser",
        "x-www-browser",
        "www-browser",
        "gnome-open",
    ] {
        let p = bin.join(name);
        std::fs::write(&p, "#!/bin/sh\nexit 1\n")?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn runner_env() -> Vec<(OsString, OsString)> {
    std::env::vars_os().collect()
}

fn private_dir(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
}

/// The first `x.y.z` word of `claude --version` output.
fn version_of(out: &str) -> Option<String> {
    let w = out.split_whitespace().next()?;
    let ok = w.split('.').count() == 3
        && w.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    ok.then(|| w.to_owned())
}

impl LoginDriver {
    /// A driver over `cfg`; sign-ins an earlier runner left behind are removed now.
    pub fn new(mut cfg: LoginConfig) -> std::io::Result<Self> {
        cfg.root = std::path::absolute(&cfg.root)?;
        let _ = std::fs::remove_dir_all(&cfg.root);
        private_dir(&cfg.root)?;
        Ok(Self {
            cfg,
            active: Mutex::new(HashMap::new()),
        })
    }

    /// `claude`'s version, read with the scrubbed environment from `scratch`.
    async fn version(&self, scratch: &Path) -> Result<String, String> {
        let mut cmd = tokio::process::Command::new(&self.cfg.program);
        cmd.args(&self.cfg.args)
            .arg("--version")
            .env_clear()
            .envs(child_env(&runner_env(), scratch))
            .current_dir(scratch.join("home"))
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let out = tokio::time::timeout(VERSION_TIMEOUT, cmd.output())
            .await
            .map_err(|_| "claude --version did not answer".to_owned())?
            .map_err(|_| "claude could not be started".to_owned())?;
        let v = version_of(&String::from_utf8_lossy(&out.stdout))
            .ok_or_else(|| "claude did not report a version".to_owned())?;
        match self.cfg.pinned.contains(&v) {
            true => Ok(v),
            false => Err(format!(
                "claude {v} is not a version this runner can sign in with (supported: {})",
                self.cfg.pinned.join(", ")
            )),
        }
    }

    /// Whether the installed `claude` is a pinned version (the runner advertises sign-in only then).
    pub async fn supported(&self) -> Result<String, String> {
        let scratch = self.cfg.root.join(".probe");
        for d in ["home", "tmp"] {
            private_dir(&scratch.join(d)).map_err(|e| e.to_string())?;
        }
        let v = self.version(&scratch).await;
        let _ = std::fs::remove_dir_all(&scratch);
        v
    }

    /// `login.start`.
    pub async fn start(self: &Arc<Self>, req: LoginStart) -> Result<LoginUrl, StreamError> {
        if !id_ok(&req.login_id) || req.harness != "claude" {
            return Err(err(
                ErrorCode::InvalidArgs,
                "a sign-in is for `claude`, with a plain id",
            ));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut a = self.active.lock().unwrap();
            if a.len() >= MAX_LOGINS || a.contains_key(&req.login_id) {
                return Err(err(
                    ErrorCode::Busy,
                    "another sign-in is already running on this runner",
                ));
            }
            a.insert(req.login_id.clone(), tx);
        }
        let (url_tx, url_rx) = oneshot::channel();
        tokio::spawn(Arc::clone(self).run(req.login_id, rx, url_tx));
        url_rx
            .await
            .unwrap_or_else(|_| Err(err(ErrorCode::Internal, "the sign-in ended")))
    }

    /// `login.code`: the token, or why there is none.
    pub async fn code(&self, req: LoginCode) -> Result<LoginResult, StreamError> {
        let code = Zeroizing::new(req.code);
        if !code_ok(&code) {
            return Err(err(
                ErrorCode::InvalidArgs,
                "that is not the shape of an approval code",
            ));
        }
        let tx = self.active.lock().unwrap().get(&req.login_id).cloned();
        let Some(tx) = tx else {
            return Err(err(ErrorCode::InvalidArgs, "no such sign-in is running"));
        };
        let (rtx, rrx) = oneshot::channel();
        tx.send(Msg::Code(code, rtx))
            .map_err(|_| err(ErrorCode::Internal, "the sign-in ended"))?;
        rrx.await
            .map_err(|_| err(ErrorCode::Internal, "the sign-in ended"))
    }

    /// `login.cancel`: answers once the process group is gone and the scratch dir removed.
    pub async fn cancel(&self, req: LoginCancel) -> Result<LoginResult, StreamError> {
        let tx = self.active.lock().unwrap().get(&req.login_id).cloned();
        let Some(tx) = tx else {
            return Ok(result(&req.login_id, Some("no such sign-in is running")));
        };
        let (rtx, rrx) = oneshot::channel();
        if tx.send(Msg::Cancel(rtx)).is_ok() {
            let _ = rrx.await;
        }
        Ok(result(&req.login_id, Some("cancelled")))
    }
}
