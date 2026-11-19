//! Runner-bound sign-in (E7-4 Codex, E7-5 OpenCode; plan 2026-11-19 D-20). The vendor login runs
//! in a PTY on this runner and writes its credential into the account's own home,
//! `<config root>/bound/<key>`. That credential rotates or is not portable, so it **never leaves
//! this runner**: the Core gets the sign-in URL and the one-time device code (shown to the user),
//! then a success flag, and no token. A session later runs the harness with that home as its
//! config dir (`AgentStart::home`).
//!
//! - `login.start` with a `home` key: version check, then the CLI starts with a scrubbed
//!   environment, its home variables pointing at the account home, and the URL (and code) it
//!   prints are answered as `login.url`.
//! - `login.wait`: answered when the CLI exits: `done` on exit 0, else why not.
//! - `login.cancel`, a failure, a timeout or a panic: the account home is wiped, with the scratch.
//!
//! Output passes [`parse::redact`] before any of it leaves; nothing child-written is logged.
//! Like the claude sign-in, the Codex and OpenCode children are not sandboxed (see the module doc of
//! `login`); the Antigravity one, an agent fed by typed lines, runs in the session sandbox (`agy`).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{
    BOUND_HOME_DIR, ErrorCode, LOGIN_INPUT_MAX, LoginInput, LoginResult, LoginScreen,
    LoginScreenReq, LoginStart, LoginUrl, LoginWait, LoginWipe, StreamError, bound_key_ok,
};
use ainkrad_ptyhost::pty::{self, Pty, Spec};
use std::io::Write;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::agy;
use super::parse::{self, Screen};
use super::run::{Guard, type_code};
use super::{
    LoginDriver, MAX_OUTPUT, Msg, QUIET, SIZE, TICK, child_env, err, make_stubs, private_dir,
    result, runner_env,
};

/// A vendor CLI this runner can sign in with, bound to the runner.
pub struct BoundCli {
    pub harness: &'static str,
    /// The executable (absolute).
    pub program: PathBuf,
    /// Arguments before the CLI's own (a test runs a script through `/bin/sh`).
    pub args: Vec<String>,
    /// Versions whose login output this driver was written against.
    pub pinned: Vec<String>,
}

/// The arguments of the harness's own login, in a PTY.
fn login_args(harness: &str) -> &'static [&'static str] {
    match harness {
        "codex" => &["login", "--device-auth"],
        "opencode" => &["auth", "login"],
        // agy has no login subcommand: its first run asks to sign in (E7-5b, unverified per CLI version).
        _ => &[],
    }
}

/// The variables that point the harness at the account home. Names are the harness's own
/// (`harness::{codex,opencode}` set the same ones for a session).
fn home_env(harness: &str, home: &Path) -> Vec<(String, String)> {
    let d = |p: PathBuf| p.display().to_string();
    match harness {
        "codex" => vec![("CODEX_HOME".to_owned(), d(home.to_owned()))],
        "opencode" => ["config", "data", "cache", "state"]
            .iter()
            .map(|n| {
                (
                    format!("XDG_{}_HOME", n.to_ascii_uppercase()),
                    d(home.join(n)),
                )
            })
            .collect(),
        // agy reads `~/.gemini/...` and keeps its login in the runner user's OS keyring (E7-5b):
        // HOME is the account's private home for its settings; the login itself is the runner's.
        "agy" => vec![("HOME".to_owned(), d(home.to_owned()))],
        _ => vec![],
    }
}

/// Whether the CLI says, in so many words, that the sign-in worked. A TUI like agy's does not
/// exit when it is signed in, so this is what ends its sign-in; nothing else counts.
pub(super) fn signed_in(lines: &[String]) -> bool {
    const SAID: [&str; 5] = [
        "logged in as",
        "signed in as",
        "successfully signed in",
        "successfully logged in",
        "login successful",
    ];
    lines.iter().any(|l| {
        let l = l.to_ascii_lowercase();
        !l.contains("not ") && SAID.iter().any(|s| l.contains(s))
    })
}

/// What the home needs before the CLI runs: Codex keeps its login in `auth.json`, never the OS
/// keyring (a keyring entry is not in the home and a session could not find it).
fn seed(harness: &str, home: &Path) -> std::io::Result<()> {
    private_dir(home)?;
    if harness == "codex" {
        std::fs::write(
            home.join("config.toml"),
            "cli_auth_credentials_store = \"file\"\n",
        )?;
    }
    if harness == "opencode" {
        for n in ["config", "data", "cache", "state"] {
            private_dir(&home.join(n))?;
        }
    }
    Ok(())
}

/// The first `x.y.z` word anywhere in `--version` output (`codex-cli 0.154.0`).
fn version_in(out: &str) -> Option<String> {
    out.split_whitespace()
        .find(|w| {
            w.split('.').count() == 3
                && w.split('.')
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(str::to_owned)
}

/// A device code as Codex prints it: two upper-case/digit groups with a dash, at least one digit.
pub(super) fn find_device_code(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .flat_map(|l| l.split_whitespace())
        .map(|w| w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-'))
        .find(|w| {
            let mut g = w.split('-');
            let (a, b, rest) = (g.next(), g.next(), g.next());
            let ok = |s: &str| {
                (3..=8).contains(&s.len())
                    && s.bytes()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            };
            matches!((a, b, rest), (Some(a), Some(b), None) if ok(a) && ok(b))
                && w.bytes().any(|c| c.is_ascii_digit())
        })
        .map(str::to_owned)
}

/// The first `https://` word: the page the user opens. Whether the host is the vendor's is the
/// Core's call (`agents::login::url_ok`); the runner never opens it.
pub(super) fn find_page(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .flat_map(|l| l.split_whitespace())
        .find(|w| w.starts_with("https://"))
        .map(str::to_owned)
}

/// Harnesses whose sign-in is a guided terminal: the CLI asks questions (a provider to choose, a
/// code to paste) that the user answers through `login.input`, reading `login.screen`. Codex's
/// device flow needs no answer: the page and the code are enough.
fn guided(harness: &str) -> bool {
    harness != "codex"
}

/// A typed line: printable, one line, bounded. Never a control character (a second line of input).
fn input_ok(text: &str) -> bool {
    text.len() <= LOGIN_INPUT_MAX && !text.chars().any(char::is_control)
}

/// How many of the last lines a screen answer carries.
const SCREEN_LINES: usize = 30;

enum End {
    Done,
    Fail(String),
    Unsupported(String),
    Cancelled,
}

impl LoginDriver {
    fn bound_cli(&self, harness: &str) -> Option<&BoundCli> {
        self.cfg.bound.iter().find(|c| c.harness == harness)
    }

    /// Whether the installed CLI of `harness` is a pinned version (a runner lists
    /// `login-bound:<harness>` only then).
    pub async fn bound_supported(&self, harness: &str) -> Result<String, String> {
        let cli = self
            .bound_cli(harness)
            .ok_or_else(|| format!("{harness} is not installed here"))?;
        let scratch = self.cfg.root.join(format!(".probe-{harness}"));
        for d in ["home", "tmp"] {
            private_dir(&scratch.join(d)).map_err(|e| e.to_string())?;
        }
        let v = self.bound_version(cli, &scratch).await;
        let _ = std::fs::remove_dir_all(&scratch);
        v
    }

    async fn bound_version(&self, cli: &BoundCli, scratch: &Path) -> Result<String, String> {
        let mut cmd = tokio::process::Command::new(&cli.program);
        cmd.args(&cli.args)
            .arg("--version")
            .env_clear()
            .envs(child_env(&runner_env(), scratch))
            .current_dir(scratch.join("home"))
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let h = cli.harness;
        let out = tokio::time::timeout(super::VERSION_TIMEOUT, cmd.output())
            .await
            .map_err(|_| format!("{h} --version did not answer"))?
            .map_err(|_| format!("{h} could not be started"))?;
        let v = version_in(&String::from_utf8_lossy(&out.stdout))
            .ok_or_else(|| format!("{h} did not report a version"))?;
        match cli.pinned.contains(&v) {
            true => Ok(v),
            false => Err(format!(
                "{h} {v} is not a version this runner can sign in with (supported: {})",
                cli.pinned.join(", ")
            )),
        }
    }

    /// `login.start` with a `home`.
    pub(super) async fn start_bound(
        self: &Arc<Self>,
        req: LoginStart,
        key: String,
    ) -> Result<LoginUrl, StreamError> {
        if !bound_key_ok(&key) || self.bound_cli(&req.harness).is_none() {
            return Err(err(
                ErrorCode::InvalidArgs,
                "a runner-bound sign-in is for an installed harness, with a plain home key",
            ));
        }
        // One Antigravity account per runner: its login is in the runner user's OS keyring, shared by
        // every home, so a second account could not be told apart from the first (or wiped alone).
        if req.harness == "agy" && agy::exists(&self.cfg.homes) {
            return Err(err(
                ErrorCode::Busy,
                "this runner already has an Antigravity account; remove it before signing in another",
            ));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut a = self.active.lock().unwrap();
            if a.len() >= super::MAX_LOGINS || a.contains_key(&req.login_id) {
                return Err(err(
                    ErrorCode::Busy,
                    "another sign-in is already running on this runner",
                ));
            }
            a.insert(req.login_id.clone(), tx);
        }
        let (url_tx, url_rx) = oneshot::channel();
        tokio::spawn(Arc::clone(self).run_bound(req.harness, req.login_id, key, rx, url_tx));
        url_rx
            .await
            .unwrap_or_else(|_| Err(err(ErrorCode::Internal, "the sign-in ended")))
    }

    /// `login.wait`: the end of a runner-bound sign-in.
    pub async fn wait(&self, req: LoginWait) -> Result<LoginResult, StreamError> {
        let tx = self.active.lock().unwrap().get(&req.login_id).cloned();
        let Some(tx) = tx else {
            return Err(err(ErrorCode::InvalidArgs, "no such sign-in is running"));
        };
        let (rtx, rrx) = oneshot::channel();
        tx.send(Msg::Wait(rtx))
            .map_err(|_| err(ErrorCode::Internal, "the sign-in ended"))?;
        rrx.await
            .map_err(|_| err(ErrorCode::Internal, "the sign-in ended"))
    }

    /// `login.wipe`: deletes a removed account's home from this runner. Idempotent: a home that is not
    /// there is already wiped.
    pub async fn wipe(&self, req: LoginWipe) -> Result<LoginResult, StreamError> {
        // Read before the home goes: an agy home's login also lives in the OS keyring, which no
        // tool here clears per account. The files are wiped; the answer says the keyring is not.
        let agy = agy::is_agy(&self.cfg.homes, &req.home);
        match wipe_home(&self.cfg.homes, &req.home) {
            Ok(()) => {
                if agy {
                    agy::unmark(&self.cfg.homes, &req.home);
                }
                Ok(LoginResult {
                    done: true,
                    ..result(&req.home, agy.then_some(agy::KEYRING_NOT_CLEARED))
                })
            }
            Err(why) => Err(err(ErrorCode::InvalidArgs, why)),
        }
    }

    /// `login.input`: one typed line, with Enter, into the sign-in's terminal.
    pub async fn input(&self, req: LoginInput) -> Result<LoginResult, StreamError> {
        let text = Zeroizing::new(req.text);
        if !input_ok(&text) {
            return Err(err(
                ErrorCode::InvalidArgs,
                "that is not one line of printable text",
            ));
        }
        let tx = self.active.lock().unwrap().get(&req.login_id).cloned();
        let Some(tx) = tx else {
            return Err(err(ErrorCode::InvalidArgs, "no such sign-in is running"));
        };
        let (rtx, rrx) = oneshot::channel();
        tx.send(Msg::Input(text, rtx))
            .map_err(|_| err(ErrorCode::Internal, "the sign-in ended"))?;
        rrx.await
            .map_err(|_| err(ErrorCode::Internal, "the sign-in ended"))
    }

    /// `login.screen`: what the CLI shows now, redacted.
    pub async fn screen(&self, req: LoginScreenReq) -> Result<LoginScreen, StreamError> {
        let tx = self.active.lock().unwrap().get(&req.login_id).cloned();
        let Some(tx) = tx else {
            return Err(err(ErrorCode::InvalidArgs, "no such sign-in is running"));
        };
        let (rtx, rrx) = oneshot::channel();
        tx.send(Msg::Screen(rtx))
            .map_err(|_| err(ErrorCode::Internal, "the sign-in ended"))?;
        rrx.await
            .map_err(|_| err(ErrorCode::Internal, "the sign-in ended"))
    }

    async fn run_bound(
        self: Arc<Self>,
        harness: String,
        id: String,
        key: String,
        mut rx: mpsc::UnboundedReceiver<Msg>,
        url_tx: oneshot::Sender<Result<LoginUrl, StreamError>>,
    ) {
        let scratch = self.cfg.root.join(&id);
        let home = self.cfg.homes.join(&key);
        // The home is wiped with the scratch unless the sign-in ends `done` (cleared below).
        let mut guard = Guard {
            driver: Arc::clone(&self),
            id: id.clone(),
            scratch: scratch.clone(),
            // A home that already exists is another sign-in's: never wiped, never reused.
            home: (!home.exists()).then(|| home.clone()),
        };
        let mut url_tx = Some(url_tx);
        let mut waiters: Vec<oneshot::Sender<LoginResult>> = Vec::new();
        let mut acks: Vec<oneshot::Sender<()>> = Vec::new();
        let end = self
            .drive_bound(
                &harness,
                &id,
                &scratch,
                &home,
                &mut rx,
                &mut url_tx,
                &mut waiters,
                &mut acks,
            )
            .await;
        if matches!(end, End::Done) {
            guard.home = None;
        }
        drop(guard);
        rx.close();
        // Whoever waits for the URL, then whoever waits for the end.
        if let Some(tx) = url_tx.take() {
            let (code, why) = match &end {
                End::Cancelled => (ErrorCode::Cancelled, "the sign-in was cancelled".to_owned()),
                End::Fail(w) => (ErrorCode::Internal, w.clone()),
                End::Unsupported(w) => (ErrorCode::UnsupportedCommand, w.clone()),
                End::Done => (ErrorCode::Internal, "the sign-in ended".to_owned()),
            };
            let _ = tx.send(Err(err(code, why)));
        }
        for w in waiters {
            let _ = w.send(match &end {
                End::Done => LoginResult {
                    done: true,
                    ..result(&id, None)
                },
                End::Fail(m) | End::Unsupported(m) => result(&id, Some(m)),
                End::Cancelled => result(&id, Some("cancelled")),
            });
        }
        for a in acks {
            let _ = a.send(());
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn drive_bound(
        &self,
        harness: &str,
        id: &str,
        scratch: &Path,
        home: &Path,
        rx: &mut mpsc::UnboundedReceiver<Msg>,
        url_tx: &mut Option<oneshot::Sender<Result<LoginUrl, StreamError>>>,
        waiters: &mut Vec<oneshot::Sender<LoginResult>>,
        acks: &mut Vec<oneshot::Sender<()>>,
    ) -> End {
        let Some(cli) = self.bound_cli(harness) else {
            return End::Fail("that harness is not installed here".to_owned());
        };
        for d in ["home", "tmp"] {
            if private_dir(&scratch.join(d)).is_err() {
                return End::Fail("the runner could not make a scratch directory".to_owned());
            }
        }
        if make_stubs(scratch).is_err() || private_dir(&self.cfg.homes).is_err() {
            return End::Fail("the runner could not make a scratch directory".to_owned());
        }
        // A key that already has a home is never reused: its credential is another sign-in's.
        if let Err(why) = self.claim_home(harness, home) {
            return End::Fail(why);
        }
        if let Err(why) = self.bound_version(cli, scratch).await {
            return End::Unsupported(why);
        }
        let mut env = child_env(&runner_env(), scratch);
        env.extend(home_env(harness, home));
        let mut program = cli.program.clone();
        let mut args: Vec<String> = cli
            .args
            .iter()
            .cloned()
            .chain(login_args(harness).iter().map(|a| (*a).to_owned()))
            .collect();
        // The Antigravity sign-in is an agent fed by typed lines: it runs in the session sandbox,
        // writing only its own home (and its scratch). The sandbox failing to build fails the start.
        if harness == "agy" && self.cfg.sandbox {
            (program, args) = agy::sandboxed(&program, &args, scratch, home, &self.cfg.homes);
        }
        let spec = Spec {
            program: Some(program.display().to_string()),
            args,
            cwd: Some(scratch.join("home").display().to_string()),
            env,
            size: SIZE,
            scrollback_bytes: None,
            fd3: None,
        };
        let Ok(spawned) = Pty::spawn(&spec) else {
            return End::Fail(format!("{harness} could not be started"));
        };
        let (mut pty, mut reader, mut writer, mut exit) =
            (spawned.pty, spawned.reader, spawned.writer, spawned.exit);
        let (out_tx, mut out) = mpsc::channel::<Zeroizing<Vec<u8>>>(64);
        std::thread::spawn(move || {
            let mut buf = Zeroizing::new([0u8; 4096]);
            while let Ok(n) = reader.read(&mut buf[..]) {
                if n == 0
                    || out_tx
                        .blocking_send(Zeroizing::new(buf[..n].to_vec()))
                        .is_err()
                {
                    break;
                }
            }
        });
        let end = self
            .watch_bound(
                harness,
                id,
                rx,
                &mut out,
                &mut writer,
                &mut pty,
                &mut exit,
                url_tx,
                waiters,
                acks,
            )
            .await;
        pty::hang_up(pty.pid, self.cfg.grace, exit.clone()).await;
        if let Some(kill) = ainkrad_sys::signal_number("KILL") {
            let _ = ainkrad_sys::killpg(pty.pid, kill);
        }
        pty.reap();
        end
    }

    /// Makes the account's home (it must not exist). For Antigravity also checks, atomically with
    /// the creation, that this runner has no other agy home, and marks this one.
    fn claim_home(&self, harness: &str, home: &Path) -> Result<(), String> {
        let _held = agy::START.lock().unwrap_or_else(|e| e.into_inner());
        let key = home
            .file_name()
            .and_then(|k| k.to_str())
            .unwrap_or_default();
        if harness == "agy" && agy::exists(&self.cfg.homes) {
            return Err(
                "this runner already has an Antigravity account; remove it before signing in another"
                    .to_owned(),
            );
        }
        let made = !home.exists()
            && seed(harness, home).is_ok()
            && (harness != "agy" || agy::mark(&self.cfg.homes, key).is_ok());
        made.then_some(())
            .ok_or_else(|| "the runner could not make the account's home".to_owned())
    }

    #[allow(clippy::too_many_arguments)]
    async fn watch_bound(
        &self,
        harness: &str,
        id: &str,
        rx: &mut mpsc::UnboundedReceiver<Msg>,
        out: &mut mpsc::Receiver<Zeroizing<Vec<u8>>>,
        writer: &mut Box<dyn Write + Send>,
        pty: &mut Pty,
        exit: &mut tokio::sync::watch::Receiver<Option<pty::Exit>>,
        url_tx: &mut Option<oneshot::Sender<Result<LoginUrl, StreamError>>>,
        waiters: &mut Vec<oneshot::Sender<LoginResult>>,
        acks: &mut Vec<oneshot::Sender<()>>,
    ) -> End {
        let guided = guided(harness);
        let mut screen = Screen::new(usize::from(SIZE.cols));
        let (start, mut bytes) = (Instant::now(), 0usize);
        let deadline = start + self.cfg.timeout;
        let url_deadline = start + self.cfg.url_timeout;
        let mut last_out = start;
        let mut found_at = None::<Instant>;
        let (mut exited, mut drain) = (false, None::<Instant>);
        let mut tick = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                chunk = out.recv() => {
                    let Some(chunk) = chunk else { return self.ended_bound(harness, &mut screen, exit).await; };
                    bytes += chunk.len();
                    if bytes > MAX_OUTPUT {
                        return End::Fail(format!("{harness} printed far more than a sign-in does"));
                    }
                    last_out = Instant::now();
                    screen.feed(&chunk);
                }
                _ = tick.tick() => {
                    if last_out.elapsed() >= QUIET && !screen.idle() {
                        screen.flush();
                    }
                    if Instant::now() >= deadline {
                        return End::Fail("the sign-in timed out".to_owned());
                    }
                    // A harness that stays up once signed in (agy) ends its sign-in on its own words.
                    if harness == "agy"
                        && last_out.elapsed() >= Duration::from_millis(1500)
                        && signed_in(screen.done())
                    {
                        return End::Done;
                    }
                    if url_tx.is_some() && !guided && Instant::now() >= url_deadline {
                        return End::Fail(format!("{harness} showed no sign-in page in time"));
                    }
                }
                Some(msg) = rx.recv() => match msg {
                    Msg::Cancel(ack) => {
                        acks.push(ack);
                        return End::Cancelled;
                    }
                    Msg::Wait(tx) => waiters.push(tx),
                    Msg::Code(_, tx) => {
                        let _ = tx.send(result(id, Some("this sign-in takes no code")));
                    }
                    Msg::Input(text, tx) => {
                        // An Antigravity sign-in takes a menu choice or a code, never free text.
                        if harness == "agy" && !agy::input_ok(&text) {
                            let _ = tx.send(result(id, Some("an Antigravity sign-in takes a menu number or a code, not text")));
                            continue;
                        }
                        // Typed as the claude sign-in types its code: the text, then Enter as a
                        // write of its own. It is never kept, logged or echoed back.
                        let sent = type_code(writer, &text, self.cfg.enter_delay).await;
                        let _ = tx.send(match sent {
                            Ok(()) => result(id, None),
                            Err(_) => result(id, Some("the line could not be typed")),
                        });
                        screen.flush();
                    }
                    Msg::Screen(tx) => {
                        screen.flush();
                        let _ = tx.send(snapshot(id, &screen));
                    }
                },
                _ = exit.changed(), if !exited => {
                    exited = true;
                    pty.release_slave();
                    drain = Some(Instant::now() + Duration::from_secs(1));
                }
                _ = async { tokio::time::sleep_until(drain.unwrap()).await }, if drain.is_some() => {
                    return self.ended_bound(harness, &mut screen, exit).await;
                }
            }
            // A guided sign-in is handed over once its output has been quiet for a moment, with the
            // page if it printed one: the user reads the screen and answers.
            if guided
                && url_tx.is_some()
                && last_out.elapsed() >= Duration::from_secs(2)
                && start != last_out
                && let Some(tx) = url_tx.take()
            {
                let done = screen.done();
                let _ = tx.send(Ok(LoginUrl {
                    login_id: id.to_owned(),
                    url: find_page(done).unwrap_or_default(),
                    code: find_device_code(done),
                }));
            }
            // The page and the code, sent once: the page is there, and so is the code, or the
            // output has been quiet for a moment (a harness with no device code).
            if url_tx.is_some()
                && let Some(page) = find_page(screen.done())
            {
                let code = find_device_code(screen.done());
                let at = *found_at.get_or_insert_with(Instant::now);
                if (code.is_some() || at.elapsed() >= Duration::from_millis(1500))
                    && let Some(tx) = url_tx.take()
                {
                    let _ = tx.send(Ok(LoginUrl {
                        login_id: id.to_owned(),
                        url: page,
                        code,
                    }));
                }
            }
        }
    }

    /// The CLI ended: success is exit 0 after the page was shown, nothing else.
    async fn ended_bound(
        &self,
        harness: &str,
        screen: &mut Screen,
        exit: &mut tokio::sync::watch::Receiver<Option<pty::Exit>>,
    ) -> End {
        screen.flush();
        let _ =
            tokio::time::timeout(Duration::from_millis(500), exit.wait_for(Option::is_some)).await;
        let how = match exit.borrow().as_ref() {
            Some(pty::Exit { code: Some(0), .. }) => return End::Done,
            Some(pty::Exit { code: Some(c), .. }) => format!("exited with code {c}"),
            Some(pty::Exit {
                signal: Some(s), ..
            }) => format!("was ended by {s}"),
            _ => "closed its output".to_owned(),
        };
        let last = parse::last_line(screen.done(), &screen.tail(), &[])
            .map(|l| format!(" (it last said: {l})"))
            .unwrap_or_default();
        End::Fail(format!("{harness} {how} before the sign-in finished{last}"))
    }
}

/// The screen as `login.screen` answers it: the last lines, each through the redactor and cut.
fn snapshot(id: &str, screen: &Screen) -> LoginScreen {
    let done = screen.done();
    let mut lines: Vec<String> = done
        .iter()
        .rev()
        .take(SCREEN_LINES)
        .map(|l| parse::redact(l, &[]).chars().take(300).collect::<String>())
        .collect();
    lines.reverse();
    let tail = screen.tail();
    if !tail.trim().is_empty() {
        lines.push(parse::redact(&tail, &[]).chars().take(300).collect());
    }
    LoginScreen {
        login_id: id.to_owned(),
        lines,
        url: find_page(done),
        code: find_device_code(done),
    }
}

/// Deletes `<homes>/<key>`. The key must be a plain one (`bound_key_ok`: no separator, no `..`), so
/// the path can only be a direct child of `homes`; a symlink there is refused (its target is never
/// followed or touched); `remove_dir_all` does not follow links inside the home either.
pub(super) fn wipe_home(homes: &Path, key: &str) -> Result<(), &'static str> {
    if !bound_key_ok(key) {
        return Err("a home key is 1 to 64 of [A-Za-z0-9_-]");
    }
    let dir = homes.join(key);
    match std::fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("the home could not be read"),
        Ok(m) if m.file_type().is_symlink() => Err("the home is a symlink: left alone"),
        Ok(m) if !m.is_dir() => Err("the home is not a directory"),
        Ok(_) => std::fs::remove_dir_all(&dir).map_err(|_| "the home could not be deleted"),
    }
}

/// Where a bound home lives for a runner whose logins are under `root` (`<state>/logins`).
pub(super) fn homes_of(root: &Path) -> PathBuf {
    root.with_file_name("agents-config").join(BOUND_HOME_DIR)
}
