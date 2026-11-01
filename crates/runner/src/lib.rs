//! The runner daemon (E3.1, brainstorm §3): dials out to the server's
//! `/runner/v1/connect` over WebSocket (`wss://`; `ws://` only to loopback), authenticated by
//! `Authorization: Bearer <runner key>`, and speaks `ainkrad_proto::runner`.
//!
//! It works one run at a time. The run lives in a task that outlasts the connection: when
//! the socket drops, the daemon reconnects with backoff and announces the run in `Hello`,
//! so the server re-claims it (renews its lease) if it is back within the lease grace. It then
//! resends what the server may have missed: the `RunStarted` it never got a token for, or the
//! `RunEnded` it never acknowledged; an unacknowledged `RunEnded` is also resent on every
//! heartbeat tick.
//! Transcript chunks wait in a channel while it is offline.
//!
//! Transcripts (E3.9): every chunk and every failure or cancel reason is redacted before it
//! leaves the run's task, with the runner key, the run's token, the executor's `secrets`
//! (git askpass answers, secret env values) and the key shapes of `ainkrad_proto::redact`.
//! The last chunks sent are kept and resent after a reconnect; the server stores each `seq`
//! once, so a resend is harmless.
//!
//! Fallbacks (E15.3): a run moving along its fallback chain sends `RunFallback`, kept with
//! the transcript chunks and resent with them after a reconnect (the server applies it once).
//!
//! Permissions (E3.10): a run's tool call outside its policy goes to the server as
//! `ApprovalRequest`, kept and resent after a reconnect until the server's `Approval` comes
//! back and is handed to the waiting run.
//!
//! Sleep (E3.11): a machine that slept froze the daemon's timers, so it misses heartbeats and
//! its socket may be dead without knowing it. Every second it compares the wall clock with the
//! monotonic one (which stops during sleep on macOS); a jump past one heartbeat period means
//! it woke up, and it reconnects at once and re-announces its run. A run whose lease lapsed
//! past the server's lease grace meanwhile is `runner_lost` and requeued there, and the server
//! answers `Cancel`: the runner drops it and asks for work. Inside the grace the same `Hello`
//! re-claims it.
//!
//! Controls (1.19, decision #34): the server's `Pause` and `Message` for the current run go to
//! the executor (`Executor::control`): a pause ends the run once its tool call in flight ends,
//! a message is the harness's next turn. A stop is `Cancel`.
//!
//! State (1.20): `Hello` and a `Status` after each clean-up pass carry its `RunnerInfo` (one
//! slot, uptime, harness logins, last sleep, Power Nap preference); `ReadLog` reads the tail of
//! its log file, redacted (`state`).
//!
//! Disk (E15.9): the server's `Welcome` limits go to the executor; a clean-up pass
//! (`Executor::housekeep`: idle warm processes, idle worktrees, the disk cap) runs after each
//! `Welcome`, after each run, and every `HOUSEKEEP_EVERY`, one at a time, in its own task. Its
//! report goes to the server in `Disk`, and again in the next `Hello`.
//!
//! Stopping (`run_until`, SIGTERM): it asks for no more work. Idle, it closes its socket and
//! returns `Error::Stopped` at once; with a run in flight it keeps going until that run has
//! ended and the server acknowledged it, then returns. The caller bounds that wait: a run it
//! abandons is `runner_lost` once its lease expires and retried, as after a crash.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use ainkrad_proto::redact::Redactor;
use ainkrad_proto::runner::{
    DiskReport, HostLoad, Outcome, PROTOCOL_VERSION, RunToken, RunnerMessage, ServerMessage, Tokens,
};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, Stream, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

mod connect;
pub mod egress;
mod executor;
mod harness;
pub mod load;
pub mod mac;
pub mod mcp_bridge;
mod messages;
mod state;
pub mod v2;
mod work;
mod workspace;
use connect::request;
pub use connect::{Config, Error};
pub use executor::*;
pub use harness::{HarnessExecutor, core_mcp_url, mcp_url};
use load::host_load;
pub use workspace::{SessionWorkspace, Workspaces};

const MIN_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Transcript chunks kept for a resend after a reconnect.
// ponytail: a bounded window, not an acked log; chunks older than the last 256 that a dropped
// connection lost stay lost. Server acks per chunk are the upgrade if gaps ever matter.
const RESEND_WINDOW: usize = 256;
/// How often the clean-up pass runs besides after each run.
const HOUSEKEEP_EVERY: Duration = Duration::from_secs(300);
/// How long the connection may stay silent (no frame, no pong, no send through) before the
/// runner drops it and reconnects: a hung socket never errors on its own. The writer pings each
/// beat and axum answers with a pong, so a live connection is never this quiet.
const SILENCE: Duration = Duration::from_secs(90);

/// Runs the daemon: connects, reconnects with backoff, works runs with `executor`. Returns
/// only when it cannot go on.
pub async fn run<E: Executor>(config: Config, executor: E) -> Error {
    run_with_clock(config, executor, Arc::new(SystemTime::now)).await
}

/// `run`, until `stop` turns true: then it takes no new work and returns `Error::Stopped` once
/// no run is in flight (the module's "Stopping").
pub async fn run_until<E: Executor>(
    config: Config,
    executor: E,
    stop: watch::Receiver<bool>,
) -> Error {
    daemon(config, executor, Arc::new(SystemTime::now), stop, SILENCE).await
}

/// Resolves once `stop` is true; never if its sender is gone.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    if stop.wait_for(|s| *s).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// The wall clock the daemon reads to notice it slept.
pub type WallClock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// How often the daemon looks for a wall-clock jump.
const WAKE_CHECK: Duration = Duration::from_secs(1);

/// `run`, reading the wall clock from `clock` (tests jump it to fake a sleep).
pub async fn run_with_clock<E: Executor>(config: Config, executor: E, clock: WallClock) -> Error {
    daemon(config, executor, clock, watch::channel(false).1, SILENCE).await
}

/// Waits until the script just written at `path` can be executed. Linux refuses to exec a file
/// while any process holds it open for writing (ETXTBSY), and a fork on another test thread can
/// hold the writer's descriptor for a moment after it is closed. The script must exit at once
/// when `AINKRAD_EXEC_PROBE` is set; this runs it that way until the kernel stops refusing.
#[cfg(test)]
pub(crate) fn exec_ready(path: &std::path::Path) {
    use std::io::ErrorKind::ExecutableFileBusy;
    use std::process::Stdio;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let probe = std::process::Command::new(path)
            .env("AINKRAD_EXEC_PROBE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match probe {
            Err(e) if e.kind() == ExecutableFileBusy && std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => return,
        }
    }
}

/// `run`, with the silence limit set to `silence` (tests use a short one in real time).
#[cfg(test)]
pub(crate) async fn run_silenced<E: Executor>(
    config: Config,
    executor: E,
    silence: Duration,
) -> Error {
    daemon(
        config,
        executor,
        Arc::new(SystemTime::now),
        watch::channel(false).1,
        silence,
    )
    .await
}

async fn daemon<E: Executor>(
    config: Config,
    executor: E,
    clock: WallClock,
    stop: watch::Receiver<bool>,
    silence: Duration,
) -> Error {
    if let Err(e) = request(&config) {
        return e;
    }
    let (out_tx, out_rx) = mpsc::channel(256);
    let mut redactor = Redactor::new();
    redactor.known("runner_key", &config.key);
    for (name, value) in executor.secrets().await {
        redactor.known(&name, &value);
    }
    let mut daemon = Daemon {
        config,
        clock,
        redactor,
        executor: Arc::new(executor),
        current: None,
        out_tx,
        out_rx,
        disk: None,
        housekeeping: false,
        started: std::time::Instant::now(),
        slept: None,
        power_nap: None,
        stop,
        stopping: false,
        silence,
    };
    let mut backoff = MIN_BACKOFF;
    loop {
        if daemon.stopping && daemon.current.is_none() {
            return Error::Stopped;
        }
        let req = match request(&daemon.config) {
            Ok(req) => req,
            Err(e) => return e,
        };
        match tokio::time::timeout(SILENCE, tokio_tungstenite::connect_async(req)).await {
            Ok(Ok((ws, _))) => {
                if daemon.session(ws).await {
                    backoff = MIN_BACKOFF;
                }
                tracing::warn!("disconnected from the server");
            }
            Ok(Err(tungstenite::Error::Http(response))) if response.status().is_client_error() => {
                return Error::Refused(response.status().as_u16());
            }
            Ok(Err(e)) => tracing::warn!(error = %e, "connecting to the server failed"),
            Err(_) => tracing::warn!("connecting to the server timed out"),
        }
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            () = stopped(&mut daemon.stop), if !daemon.stopping => daemon.stopping = true,
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// What a run's task reports.
enum Out {
    Started {
        run: i64,
        session: Option<String>,
    },
    Event {
        run: i64,
        seq: u64,
        payload: serde_json::Value,
    },
    Ended {
        run: i64,
        outcome: Outcome,
    },
    Usage {
        run: i64,
        seq: u64,
        usage: Tokens,
    },
    Dropped {
        run: i64,
        reason: String,
    },
    Progress {
        run: i64,
        diff_files: Option<u32>,
        repos: Vec<ainkrad_proto::runner::RepoDiff>,
    },
    Fallback {
        run: i64,
        harness: String,
        model: String,
        account: Option<i64>,
        class: String,
        reason: String,
    },
    Approval {
        run: i64,
        id: String,
        tool: String,
        input: serde_json::Value,
        timeout_secs: u64,
        reply: Reply,
    },
    /// A clean-up pass ended, with its disk report if the executor keeps a disk.
    Disk(Option<DiskReport>),
    /// A `ReadFile` was answered (E15.12): the file's bytes, or why not.
    FileRead {
        request: i64,
        result: Result<Vec<u8>, String>,
    },
    /// A `ReadLog` was answered (1.20): the log's last lines, redacted, or why not.
    LogTail {
        request: i64,
        result: Result<Vec<String>, String>,
    },
    /// A `Probe` was done (1.25): the harness versions found now, or `None` when the executor
    /// has none to look for.
    Probed {
        request: i64,
        harnesses: Option<std::collections::BTreeMap<String, String>>,
    },
}

/// The run being worked on.
struct Current {
    job: Job,
    task: JoinHandle<()>,
    /// Hands the token to the task; taken once it is delivered.
    token: Option<oneshot::Sender<RunToken>>,
    /// The daemon's secrets and, once delivered, the run token: redacted from a text file
    /// read for a publish (E15.18), with the run's own (`run_secrets`) added per read.
    redactor: Redactor,
    /// The session sent in `RunStarted`, resent until a token arrives.
    started: Option<Option<String>>,
    /// Sent in `RunEnded`, resent until acknowledged.
    ended: Option<Outcome>,
    /// The last chunks sent, resent after a reconnect.
    sent: VecDeque<RunnerMessage>,
    /// Escalated tool calls by request id: the request, resent after a reconnect, and where
    /// the answer goes.
    asking: HashMap<String, (RunnerMessage, Reply)>,
}

struct Daemon<E> {
    config: Config,
    clock: WallClock,
    /// Every run's redaction, before its token is known.
    redactor: Redactor,
    executor: Arc<E>,
    current: Option<Current>,
    out_tx: mpsc::Sender<Out>,
    out_rx: mpsc::Receiver<Out>,
    /// The last disk report, for the next `Hello`.
    disk: Option<DiskReport>,
    /// A clean-up pass is running.
    housekeeping: bool,
    /// When the daemon started, for its uptime.
    started: std::time::Instant,
    /// How long the machine last slept, once it noticed (1.20).
    slept: Option<u64>,
    /// The admin's Power Nap preference, as the server last sent it (1.20).
    power_nap: Option<bool>,
    /// Turns true when the daemon is told to stop (`run_until`).
    stop: watch::Receiver<bool>,
    /// Told to stop: no more `Ready`.
    stopping: bool,
    /// How long the connection may stay silent before the session drops it (`SILENCE`).
    silence: Duration,
}

enum Wake {
    Server(Option<ServerMessage>),
    Out(Out),
    Check,
    House,
    Stop,
}

/// Whether the frame went out; a send that stalls on a dead socket counts as not sent.
async fn send(ws: &mut Ws, msg: &RunnerMessage) -> bool {
    tracing::debug!(?msg, "to server");
    let text = serde_json::to_string(msg).expect("messages serialise");
    let sent = tokio::time::timeout(SILENCE, ws.send(Message::Text(text.into()))).await;
    matches!(sent, Ok(Ok(())))
}

/// What the session's writer is asked to do (AIN-55).
enum Frame {
    Send(RunnerMessage),
    Close,
}

/// The session's queue to its writer. Dropping it, however the session ends, closes the
/// connection.
struct Queue(std_mpsc::Sender<Frame>);

impl Queue {
    /// Queues `msg`; `false` once the writer is gone (the connection is too).
    fn send(&self, msg: RunnerMessage) -> bool {
        self.0.send(Frame::Send(msg)).is_ok()
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        let _ = self.0.send(Frame::Close);
    }
}

/// The session's writer, on its own OS thread (AIN-55): it writes what the session queues,
/// and it sends the heartbeat on its own clock. A heartbeat therefore goes out while the
/// daemon's loop is stalled by a loaded host, which is when the lease matters most. Returns
/// when the session closes its queue or a write fails.
fn write(
    sink: SplitSink<Ws, Message>,
    frames: std_mpsc::Receiver<Frame>,
    beat: &Beat,
    every: Duration,
    silence: Duration,
) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    else {
        return;
    };
    let sink = RefCell::new(sink);
    // A write that stalls on a dead socket counts as failed, which ends the writer.
    // The two closures below never run at once, so the borrow held across the await is safe.
    #[allow(clippy::await_holding_refcell_ref)]
    let write = |frame: Message| {
        let sent = rt
            .block_on(async { tokio::time::timeout(silence, sink.borrow_mut().send(frame)).await });
        matches!(sent, Ok(Ok(())))
    };
    let mut send = |msg: &RunnerMessage| {
        tracing::debug!(?msg, "to server");
        let text = serde_json::to_string(msg).expect("messages serialise");
        write(Message::Text(text.into()))
    };
    // The server's pong is what shows an idle connection alive.
    let ping = || write(Message::Ping(Default::default()));
    pump(frames, beat, every, host_load, &mut send, ping);
    let _ = rt.block_on(sink.borrow_mut().close());
}

/// The message the heartbeat resends on each tick, set by the session (`Daemon::beat`).
type Beat = Mutex<Option<RunnerMessage>>;

/// The loop behind `write`, apart from the socket so a test can drive it: a message from
/// `frames` is sent as it comes; each `every` the `beat`, if any, is sent with the host's load
/// (`load`, sampled only for a heartbeat). Returns on `Close`, when the queue is gone, or
/// when `send` or the tick's `ping` fails.
fn pump(
    frames: std_mpsc::Receiver<Frame>,
    beat: &Beat,
    every: Duration,
    load: impl Fn() -> Option<HostLoad>,
    mut send: impl FnMut(&RunnerMessage) -> bool,
    ping: impl Fn() -> bool,
) {
    let mut due = Instant::now() + every;
    loop {
        match frames.recv_timeout(due.saturating_duration_since(Instant::now())) {
            Ok(Frame::Send(msg)) => {
                if !send(&msg) {
                    return;
                }
            }
            Ok(Frame::Close) | Err(std_mpsc::RecvTimeoutError::Disconnected) => return,
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                due = Instant::now() + every;
                if !ping() {
                    return;
                }
                let current = beat.lock().expect("beat lock").clone();
                let msg = match current {
                    Some(RunnerMessage::Heartbeat { run, .. }) => {
                        RunnerMessage::Heartbeat { run, load: load() }
                    }
                    Some(other) => other,
                    None => continue,
                };
                if !send(&msg) {
                    return;
                }
            }
        }
    }
}

/// The next server message; `None` once the connection is gone. Any frame, a pong included,
/// sets `heard`: the last time the server was known to be there.
async fn recv<S>(ws: &mut S, heard: &mut tokio::time::Instant) -> Option<ServerMessage>
where
    S: Stream<Item = Result<Message, tungstenite::Error>> + Unpin,
{
    loop {
        match ws.next().await? {
            Ok(Message::Text(text)) => {
                *heard = tokio::time::Instant::now();
                match serde_json::from_str(&text) {
                    Ok(msg) => {
                        tracing::debug!(?msg, "from server");
                        return Some(msg);
                    }
                    Err(e) => tracing::warn!(error = %e, "unreadable server message"),
                }
            }
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => *heard = tokio::time::Instant::now(),
        }
    }
}

impl<E: Executor> Daemon<E> {
    fn run_id(&self) -> Option<i64> {
        self.current.as_ref().map(|c| c.job.run)
    }

    /// One connection, until it drops; `true` if the server welcomed the runner.
    async fn session(&mut self, mut ws: Ws) -> bool {
        let hello = RunnerMessage::Hello {
            protocol: PROTOCOL_VERSION.to_owned(),
            runner_version: env!("CARGO_PKG_VERSION").to_owned(),
            tags: self.config.tags.clone(),
            harnesses: self.config.harnesses.clone(),
            runs: self.run_id().into_iter().collect(),
            disk: self.disk.clone().map(Box::new),
            info: Some(Box::new(self.info())),
            os: Some(std::env::consts::OS.to_owned()),
            arch: Some(std::env::consts::ARCH.to_owned()),
        };
        let mut heard = tokio::time::Instant::now();
        if !send(&mut ws, &hello).await {
            return false;
        }
        let welcome = match tokio::time::timeout(SILENCE, recv(&mut ws, &mut heard)).await {
            Ok(msg) => msg,
            Err(_) => {
                tracing::warn!("the server did not welcome the runner; reconnecting");
                return false;
            }
        };
        let ttl = match welcome {
            Some(ServerMessage::Welcome {
                lease_ttl_secs,
                limits,
                power_nap,
                ..
            }) => {
                self.executor.set_limits(limits.unwrap_or_default());
                self.power_nap = power_nap.or(self.power_nap);
                self.housekeep();
                lease_ttl_secs
            }
            Some(ServerMessage::Error { message }) => {
                tracing::error!(%message, "the server refused the hello");
                return false;
            }
            _ => return false,
        };
        let every = Duration::from_secs((ttl / 3).max(1) as u64);
        // Three beats of pongs missing is silence, however long the beat is.
        let silence = self.silence.max(every * 3);
        let (sink, mut stream) = ws.split();
        let (frames, rx) = std_mpsc::channel();
        let queue = Queue(frames);
        let beat: Arc<Beat> = Arc::new(Mutex::new(None));
        let writer_beat = beat.clone();
        let spawned = std::thread::Builder::new()
            .name("runner-writer".to_owned())
            .spawn(move || write(sink, rx, &writer_beat, every, silence));
        if spawned.is_err() {
            tracing::error!("starting the connection's writer failed");
            return false;
        }
        for msg in self.resume() {
            if !queue.send(msg) {
                return true;
            }
        }
        let mut check = tokio::time::interval(WAKE_CHECK);
        let start = tokio::time::Instant::now() + HOUSEKEEP_EVERY;
        let mut house = tokio::time::interval_at(start, HOUSEKEEP_EVERY);
        let mut last = (std::time::Instant::now(), (self.clock)());
        loop {
            *beat.lock().expect("beat lock") = self.beat();
            let wake = tokio::select! {
                biased;
                msg = recv(&mut stream, &mut heard) => Wake::Server(msg),
                Some(out) = self.out_rx.recv() => Wake::Out(out),
                _ = check.tick() => Wake::Check,
                _ = house.tick() => Wake::House,
                () = stopped(&mut self.stop), if !self.stopping => Wake::Stop,
            };
            let replies = match wake {
                Wake::Server(None) => return true,
                Wake::Check => {
                    let now = (std::time::Instant::now(), (self.clock)());
                    let wall = now.1.duration_since(last.1).unwrap_or_default();
                    let slept = wall.saturating_sub(now.0 - last.0);
                    last = now;
                    if slept > every {
                        tracing::warn!(?slept, "woke from sleep; reconnecting");
                        self.slept = Some(slept.as_secs());
                        return true;
                    }
                    if heard.elapsed() > silence {
                        tracing::warn!(?silence, "the server has gone silent; reconnecting");
                        return true;
                    }
                    vec![]
                }
                Wake::House => {
                    self.housekeep();
                    vec![]
                }
                Wake::Stop => {
                    tracing::info!(run = ?self.run_id(), "stopping: no new work");
                    self.stopping = true;
                    vec![]
                }
                Wake::Server(Some(msg)) => self.on_server(msg),
                Wake::Out(out) => self.on_out(out),
            };
            for msg in replies {
                if !queue.send(msg) {
                    return true;
                }
            }
            if self.stopping && self.current.is_none() {
                return true;
            }
        }
    }

    /// What the heartbeat resends on each tick (AIN-55): the current run's heartbeat, or its
    /// unacknowledged `RunEnded`; `None` when it has no run.
    fn beat(&self) -> Option<RunnerMessage> {
        let c = self.current.as_ref()?;
        Some(match &c.ended {
            None => RunnerMessage::Heartbeat {
                run: c.job.run,
                load: None,
            },
            Some(outcome) => RunnerMessage::RunEnded {
                run: c.job.run,
                outcome: outcome.clone(),
            },
        })
    }

    /// What to send after a `Welcome`: the recent chunks, then a resent `RunEnded` or
    /// `RunStarted`; or `Ready`.
    fn resume(&self) -> Vec<RunnerMessage> {
        let Some(c) = &self.current else {
            return vec![self.ready()];
        };
        let run = c.job.run;
        let mut msgs: Vec<RunnerMessage> = c.sent.iter().cloned().collect();
        msgs.extend(c.asking.values().map(|(request, _)| request.clone()));
        match (&c.ended, &c.started) {
            (Some(outcome), _) => msgs.push(RunnerMessage::RunEnded {
                run,
                outcome: outcome.clone(),
            }),
            (None, Some(session)) if c.token.is_some() => msgs.push(RunnerMessage::RunStarted {
                run,
                session: session.clone(),
            }),
            _ => {}
        }
        msgs
    }

    /// Drops the current run if it is `run`; then asks for the next one.
    fn finish(&mut self, run: i64) -> Vec<RunnerMessage> {
        if self.run_id() != Some(run) {
            return vec![];
        }
        if let Some(c) = self.current.take() {
            c.task.abort();
        }
        if self.stopping {
            return vec![];
        }
        self.housekeep();
        vec![self.ready()]
    }

    /// Starts a clean-up pass unless one is running; it reports back as `Out::Disk`.
    fn housekeep(&mut self) {
        if std::mem::replace(&mut self.housekeeping, true) {
            return;
        }
        let (executor, out) = (self.executor.clone(), self.out_tx.clone());
        tokio::spawn(async move {
            let report = executor.housekeep().await;
            let _ = out.send(Out::Disk(report)).await;
        });
    }

    fn ready(&self) -> RunnerMessage {
        RunnerMessage::Ready {
            workspaces: self.executor.workspaces(),
        }
    }
}

#[cfg(test)]
mod tests;
