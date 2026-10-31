//! The `pty` driver (E2-02, E2-03): terminals, each held by its own detached
//! `ainkrad-ptyhost` process, so they survive this runner (decision P2.3).
//!
//! - `pty.open` starts a host for a login shell or a command, then serves its stream as
//!   `pty.attach` does; `pty.attach` reaches a running one and resumes its output at a byte
//!   `seq`; `pty.close` hangs one up (HUP → TERM → KILL) and answers its exit.
//! - On an open or attach stream the bridge sends `opened`, then output under the Core's
//!   credit with the flow-control rules of `ainkrad_proto::v2::Outflow` (16 ms coalescing,
//!   drop-to-snapshot when the Core falls behind), then the exit as the `result`. The Core's
//!   `output` is typed input, `resize` and `signal` go to the host, a `close` detaches.
//! - Off by default, like `exec.run`: a terminal is a shell as this runner's user
//!   (`ainkrad-runner connect --enable-pty`).
//! - Every connection's hello lists the hosts found in the terminal directory (stale ones are
//!   cleaned), so a restarted runner re-announces the terminals it no longer has streams for.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ainkrad_proto::v2::{
    Body, Control, Credit, DRIVER_PTY, DriverInfo, Emit, ErrorCode, OP_PTY_ATTACH, OP_PTY_CLOSE,
    OP_PTY_OPEN, Outflow, Output, PtyOpen, Reply, SCROLLBACK_BUDGET, SCROLLBACK_BYTES,
    SIGNAL_HOST_LOST, SIGNALS, STREAM_WINDOW, Snapshot, StreamError, TerminalExit, TerminalInfo,
};
use ainkrad_ptyhost::client::{HostReader, HostWriter, connect, launch, new_id, scan};
use ainkrad_ptyhost::host::scrollback_dir;
use ainkrad_ptyhost::pty::{Exit, Spec, environment};
use ainkrad_ptyhost::store;
use ainkrad_ptyhost::wire::{FromHost, HostInfo, ToHost};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::{mpsc, oneshot};

/// Output a bridge buffers for a slow Core before it cuts to a snapshot.
const BACKLOG: usize = 1 << 20;

pub struct PtyConfig {
    /// Whether `pty` is offered at all (`--enable-pty`).
    pub enabled: bool,
    /// Terminals at once; one more is `busy`.
    pub capacity: u32,
    /// The `ainkrad-ptyhost` binary.
    pub host: PathBuf,
    /// Where hosts keep their sockets and records (`0700`).
    pub dir: PathBuf,
    /// Runner variables a terminal may ask for by name (`env_pass`), beyond the base set.
    pub env_allow: Vec<String>,
    /// The runner's environment, read once.
    pub env: Vec<(OsString, OsString)>,
    /// Between HUP, TERM and KILL on close.
    pub grace: Duration,
    /// The terminal sandbox (`termbox`): `Some(paths)` runs every shell with those paths
    /// hidden, `None` (`--terminal-sandbox=off`) runs shells unsandboxed.
    pub hide: Option<Vec<PathBuf>>,
    /// With the sandbox: paths the shell may read but not write (the runner binary, launchers).
    pub readonly: Vec<PathBuf>,
}

impl PtyConfig {
    /// Off, with the defaults for `dir` (`<state>/terminals`).
    pub fn new(dir: PathBuf) -> Self {
        Self {
            enabled: false,
            capacity: 32,
            host: ainkrad_ptyhost::client::find_host_binary()
                .unwrap_or_else(|| PathBuf::from("ainkrad-ptyhost")),
            dir,
            env_allow: ["LC_ALL", "LC_CTYPE", "TZ"].map(str::to_owned).to_vec(),
            env: std::env::vars_os().collect(),
            grace: Duration::from_secs(2),
            // On by default: a terminal is a shell as the runner's user.
            hide: Some(Vec::new()),
            readonly: Vec::new(),
        }
    }
}

pub struct PtyDriver {
    config: PtyConfig,
    /// The scrollback disk budget across this runner's terminals (E2-06.2), in bytes.
    budget: AtomicU64,
    /// Per terminal: the clients attached now and when one last attached, typed or left. A
    /// watch stream (the Core's exit monitor) is not a client and is not counted.
    clients: Mutex<HashMap<String, (u32, u64)>>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
}

/// One attached client of a terminal; leaving restarts its idle clock.
struct ClientGuard {
    driver: Arc<PtyDriver>,
    terminal: String,
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        let mut all = self.driver.clients.lock().unwrap();
        if let Some(c) = all.get_mut(&self.terminal) {
            c.0 = c.0.saturating_sub(1);
            c.1 = now_ms();
        }
    }
}

/// The scrollback files of a terminal being read must not be mistaken for the budget's:
/// `usage` counts every ring file in the directory.
fn clamp((min, max, _): (u64, u64, u64), v: u64) -> u64 {
    v.clamp(min, max)
}

fn err(code: ErrorCode, m: impl Into<String>) -> StreamError {
    StreamError::new(code, m)
}

fn exit_of(terminal: &str, e: &Exit) -> TerminalExit {
    TerminalExit {
        terminal: terminal.to_owned(),
        exit_code: e.code,
        signal: e.signal.clone(),
    }
}

/// The final answer of a stream whose host process is gone (killed, crashed) without telling
/// anyone how the child ended: the terminal is over, and the Core learns it.
fn lost_exit(terminal: &str) -> TerminalExit {
    TerminalExit {
        terminal: terminal.to_owned(),
        exit_code: None,
        signal: Some(SIGNAL_HOST_LOST.to_owned()),
    }
}

fn host_lost(op: Op, terminal: &str) -> Body {
    let exit = lost_exit(terminal);
    Body::Result(match op {
        Op::Open => Reply::PtyOpen(exit),
        Op::Attach => Reply::PtyAttach(exit),
    })
}

/// The decoded length of standard base64 (what credit counts).
pub fn b64_len(data: &str) -> u64 {
    let pad = data.bytes().rev().take_while(|b| *b == b'=').count();
    (data.len() / 4 * 3).saturating_sub(pad) as u64
}

/// What the Core is told about a host.
pub fn info_of(h: &HostInfo) -> TerminalInfo {
    TerminalInfo {
        terminal: h.id.clone(),
        state: h.state,
        size: h.size,
        seq: h.seq,
        pid: h.child,
        exit: h.exit.as_ref().map(|e| exit_of(&h.id, e)),
    }
}

/// Which op a stream was opened with: its `result` carries the same op.
#[derive(Clone, Copy)]
pub enum Op {
    Open,
    Attach,
}

impl PtyDriver {
    pub fn new(config: PtyConfig) -> Self {
        Self {
            config,
            budget: AtomicU64::new(SCROLLBACK_BUDGET.2),
            clients: Mutex::default(),
        }
    }

    /// Sets the scrollback disk budget (clamped to its bounds).
    pub fn set_budget(&self, bytes: u64) {
        self.budget
            .store(clamp(SCROLLBACK_BUDGET, bytes), Ordering::Relaxed);
    }

    /// Checks the budget once a second until the driver is dropped.
    // ponytail: a 1 s poll, so a flood overshoots the budget by about a second of output; a
    // host asking the runner when its ring rotates is the upgrade if that matters.
    pub fn spawn_budget_loop(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(d) = weak.upgrade() else { return };
                d.enforce_budget().await;
            }
        });
    }

    fn client(self: &Arc<Self>, terminal: &str) -> ClientGuard {
        let mut all = self.clients.lock().unwrap();
        let c = all.entry(terminal.to_owned()).or_default();
        c.0 += 1;
        c.1 = now_ms();
        ClientGuard {
            driver: Arc::clone(self),
            terminal: terminal.to_owned(),
        }
    }

    fn typed(&self, terminal: &str) {
        if let Some(c) = self.clients.lock().unwrap().get_mut(terminal) {
            c.1 = now_ms();
        }
    }

    /// Frees scrollback disk until the total is within the budget: the least recently used
    /// terminals first, never one with a client attached. A terminal's own cap still bounds
    /// the attached ones, so the total can exceed the budget by at most that many caps.
    pub async fn enforce_budget(&self) {
        if !self.config.enabled {
            return;
        }
        let dir = scrollback_dir(&self.config.dir);
        let budget = self.budget.load(Ordering::Relaxed);
        let total = |d: &std::path::Path| store::usage(d).iter().map(|u| u.1).sum::<u64>();
        let mut sum = total(&dir);
        if sum <= budget {
            return;
        }
        let mut cands: Vec<(u64, String)> = {
            let held = self.clients.lock().unwrap();
            store::usage(&dir)
                .into_iter()
                .filter(|u| held.get(&u.0).is_none_or(|c| c.0 == 0))
                .map(|u| (held.get(&u.0).map_or(u.2, |c| c.1.max(u.2)), u.0))
                .collect()
        };
        cands.sort();
        for (_, id) in cands {
            for _ in 0..2 {
                if sum <= budget {
                    return;
                }
                let Ok(Ok((_, _, mut wr))) =
                    tokio::time::timeout(Duration::from_secs(1), connect(&self.config.dir, &id))
                        .await
                else {
                    break;
                };
                if wr.send(&ToHost::Shed).await.is_err() {
                    break;
                }
                // The host frees it a moment later: wait for the effect, briefly.
                for _ in 0..50 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    let now = total(&dir);
                    if now < sum {
                        sum = now;
                        break;
                    }
                }
            }
        }
    }

    /// The driver as advertised in `hello`; `None` when it is off.
    pub fn info(&self) -> Option<DriverInfo> {
        self.config.enabled.then(|| DriverInfo {
            name: DRIVER_PTY.to_owned(),
            commands: [OP_PTY_OPEN, OP_PTY_ATTACH, OP_PTY_CLOSE]
                .map(str::to_owned)
                .to_vec(),
            capacity: self.config.capacity,
            ..DriverInfo::default()
        })
    }

    /// Every live host (re-adopted; stale records cleaned). Empty when the driver is off.
    pub async fn terminals(&self) -> Vec<TerminalInfo> {
        if !self.config.enabled {
            return Vec::new();
        }
        scan(&self.config.dir).await.iter().map(info_of).collect()
    }

    fn enabled(&self) -> Result<(), StreamError> {
        if self.config.enabled {
            Ok(())
        } else {
            Err(err(
                ErrorCode::UnsupportedCommand,
                "pty is off on this runner (ainkrad-runner connect --enable-pty)",
            ))
        }
    }

    /// Starts a host for `req`; its terminal id.
    pub async fn open(&self, req: &PtyOpen) -> Result<String, StreamError> {
        self.enabled()?;
        let invalid = |m: &str| err(ErrorCode::InvalidArgs, m);
        if !req.size.valid() {
            return Err(invalid("size must be 1 to 1000 rows and columns"));
        }
        if req.cwd.as_deref().is_some_and(|c| !c.starts_with('/')) {
            return Err(invalid("cwd must be absolute"));
        }
        if req.program.as_deref() == Some("") {
            return Err(invalid("program is empty"));
        }
        let live = scan(&self.config.dir).await.len();
        if live >= self.config.capacity as usize {
            let cap = self.config.capacity;
            return Err(err(ErrorCode::Busy, format!("pty is at capacity ({cap})")));
        }
        let mut spec = Spec {
            program: req.program.clone(),
            args: req.args.clone(),
            cwd: req.cwd.clone(),
            env: environment(
                &self.config.env,
                &self.config.env_allow,
                &req.env_pass,
                &req.env,
            ),
            size: req.size,
            scrollback_bytes: req.scrollback_bytes.map(|b| clamp(SCROLLBACK_BYTES, b)),
        };
        if let Some(b) = req.scrollback_budget {
            self.set_budget(b);
        }
        self.enforce_budget().await;
        if let Some(hide) = &self.config.hide {
            // The shell the host would start by default is named here, so the wrapper can run it.
            let program = spec
                .program
                .take()
                .or_else(|| spec.env.get("SHELL").cloned())
                .unwrap_or_else(|| "/bin/sh".to_owned());
            // `term new <runner> sh` names a program the way the unsandboxed host takes it.
            let program =
                super::termbox::resolve(&program, spec.env.get("PATH").map(String::as_str));
            let cwd = spec
                .cwd
                .clone()
                .or_else(|| spec.env.get("HOME").cloned())
                .filter(|c| c.starts_with('/'))
                .unwrap_or_else(|| "/".to_owned());
            let (launcher, args) =
                super::termbox::wrap(hide, &self.config.readonly, &program, &spec.args, &cwd)
                    .map_err(|e| invalid(&e))?;
            spec.program = Some(launcher);
            spec.args = args;
            spec.cwd.get_or_insert(cwd);
        }
        let id = new_id().map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
        launch(&self.config.host, &self.config.dir, &id, &spec)
            .await
            .map_err(|e| err(ErrorCode::SpawnFailed, e.to_string()))?;
        Ok(id)
    }

    /// Whether the host of `terminal` is gone for good: it does not answer and `scan` found
    /// its record stale (and cleaned it) now or before. A host that merely fails to answer
    /// still has its record, so it is not gone.
    async fn host_gone(&self, terminal: &str) -> bool {
        let live = scan(&self.config.dir).await;
        !live.iter().any(|h| h.id == terminal)
            && !ainkrad_ptyhost::host::record_path(&self.config.dir, terminal).exists()
    }

    async fn connect(
        &self,
        terminal: &str,
    ) -> Result<(HostInfo, HostReader, HostWriter), StreamError> {
        connect(&self.config.dir, terminal)
            .await
            .map_err(|_| err(ErrorCode::InvalidArgs, "no such terminal on this runner"))
    }

    /// Hangs `terminal` up and answers its exit once the host reports it.
    pub async fn close(&self, terminal: &str) -> Result<TerminalExit, StreamError> {
        self.enabled()?;
        let (info, mut rd, mut wr) = match self.connect(terminal).await {
            Ok(c) => c,
            // Nothing left to hang up: the terminal is over.
            Err(_) if self.host_gone(terminal).await => return Ok(lost_exit(terminal)),
            Err(e) => return Err(e),
        };
        let lost = |e: std::io::Error| err(ErrorCode::Internal, e.to_string());
        // Attached, so an exit announced before this connection is sent to it too.
        wr.send(&ToHost::Attach { seq: info.seq })
            .await
            .map_err(lost)?;
        let grace_ms = u64::try_from(self.config.grace.as_millis()).unwrap_or(u64::MAX);
        wr.send(&ToHost::Close { grace_ms }).await.map_err(lost)?;
        loop {
            match rd.recv().await.map_err(lost)? {
                Some(FromHost::Exit { exit }) => {
                    let _ = wr.send(&ToHost::Ack).await;
                    // Answered once the host is gone (it closes us after cleaning up), so the
                    // terminal is reaped when the Core hears of it, not a moment later.
                    let _ = tokio::time::timeout(Duration::from_secs(5), async {
                        while let Ok(Some(_)) = rd.recv().await {}
                    })
                    .await;
                    return Ok(exit_of(terminal, &exit));
                }
                Some(_) => {}
                None => return Err(err(ErrorCode::Internal, "the terminal host went away")),
            }
        }
    }

    /// Serves one open or attach stream until the terminal exits (`result`), the Core detaches
    /// (`cancel` fired or the session forgot the stream: `cancelled`), or the host is gone.
    /// Non-final frames go to `out` as they come; the final one is returned.
    #[allow(clippy::too_many_arguments)]
    pub async fn bridge(
        self: Arc<Self>,
        op: Op,
        watch: bool,
        terminal: String,
        seq: u64,
        stream: u64,
        mut inbox: mpsc::UnboundedReceiver<Body>,
        mut cancel: oneshot::Receiver<()>,
        out: mpsc::UnboundedSender<(u64, Body)>,
    ) -> Body {
        let (info, mut rd, mut wr) = match self.connect(&terminal).await {
            Ok(c) => c,
            // `scan` cleans a dead host's record: a terminal it no longer lists is gone.
            Err(_) if self.host_gone(&terminal).await => return host_lost(op, &terminal),
            Err(e) => return Body::Error(e),
        };
        let _client = (!watch).then(|| self.client(&terminal));
        let send = |b: Body| drop(out.send((stream, b)));
        send(Body::Control(Control::Opened(info_of(&info))));
        if wr.send(&ToHost::Attach { seq }).await.is_err() {
            return Body::Error(err(ErrorCode::Internal, "the terminal host went away"));
        }
        let mut flow = Outflow::new(STREAM_WINDOW, BACKLOG);
        let mut next = seq;
        let mut asked = false;
        let mut exited: Option<Exit> = None;
        loop {
            if let Some(e) = &exited
                && flow.pending() == 0
            {
                let _ = wr.send(&ToHost::Ack).await;
                let exit = exit_of(&terminal, e);
                return Body::Result(match op {
                    Op::Open => Reply::PtyOpen(exit),
                    Op::Attach => Reply::PtyAttach(exit),
                });
            }
            let wake = flow.deadline().map_or_else(
                || tokio::time::Instant::now() + Duration::from_secs(3600),
                tokio::time::Instant::from_std,
            );
            tokio::select! {
                _ = &mut cancel => {
                    // A signal sent just before the detach (a one-shot `signal` call) must
                    // still reach the host: the select picked the cancel first by chance.
                    while let Ok(b) = inbox.try_recv() {
                        if let Body::Control(Control::Signal(s)) = b
                            && SIGNALS.contains(&s.signal.as_str())
                        {
                            let _ = wr.send(&ToHost::Signal { signal: s.signal }).await;
                        }
                    }
                    return Body::Error(err(ErrorCode::Cancelled, "detached; the terminal keeps running"));
                }
                m = rd.recv() => match m {
                    Ok(Some(FromHost::Out { seq: s, data })) => {
                        let Ok(bytes) = STANDARD.decode(data) else { continue };
                        // A same-uid host is still input: a wrapping offset is dropped (L9).
                        let Some(end) = s.checked_add(bytes.len() as u64) else { continue };
                        if end > next {
                            let from = usize::try_from(next.saturating_sub(s)).unwrap_or(0);
                            flow.push(&bytes[from.min(bytes.len())..], std::time::Instant::now());
                            next = end;
                        }
                    }
                    Ok(Some(FromHost::Snapshot { seq: s, data })) => {
                        next = s;
                        asked = false;
                        // A snapshot costs credit (review M2): with none left, it waits for a
                        // fresh one once credit returns.
                        if flow.credit() == 0 {
                            flow.cut();
                        } else {
                            flow.spend(b64_len(&data));
                            send(Body::Control(Control::Snapshot(Snapshot { seq: s, data })));
                            flow.resynced();
                        }
                    }
                    Ok(Some(FromHost::Exit { exit })) => exited = Some(exit),
                    Ok(Some(_)) => {}
                    // Dropped by the host as too slow, or the host is gone: reattach where we were.
                    Ok(None) | Err(_) => {
                        let gone = || Body::Error(err(ErrorCode::Internal, "the terminal host went away"));
                        let Ok((_, r, mut w)) = self.connect(&terminal).await else {
                            return if self.host_gone(&terminal).await { host_lost(op, &terminal) } else { gone() };
                        };
                        if w.send(&ToHost::Attach { seq: next }).await.is_err() {
                            return gone();
                        }
                        (rd, wr) = (r, w);
                    }
                },
                b = inbox.recv() => match b {
                    None => return Body::Error(err(ErrorCode::Cancelled, "the stream was dropped")),
                    Some(Body::Output(Output { data })) => {
                        self.typed(&terminal);
                        let _ = wr.send(&ToHost::Input { data }).await;
                    }
                    Some(Body::Control(Control::Resize(size))) if size.valid() => {
                        let _ = wr.send(&ToHost::Resize { size }).await;
                    }
                    Some(Body::Control(Control::Signal(s))) if SIGNALS.contains(&s.signal.as_str()) => {
                        let _ = wr.send(&ToHost::Signal { signal: s.signal }).await;
                    }
                    Some(Body::Credit(Credit { bytes })) => flow.grant(bytes),
                    Some(_) => {}
                },
                () = tokio::time::sleep_until(wake) => {}
            }
            while let Some(e) = flow.poll(std::time::Instant::now()) {
                match e {
                    Emit::Out(b) => send(Body::Output(Output {
                        data: STANDARD.encode(b),
                    })),
                    Emit::Resync => {
                        if !asked && flow.credit() > 0 {
                            asked = wr.send(&ToHost::Snapshot).await.is_ok();
                        }
                        break;
                    }
                }
            }
        }
    }
}
