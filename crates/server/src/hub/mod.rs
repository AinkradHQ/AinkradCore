//! The runner hub (E1-11.2, E1-11.4, E1-11.6): where paired runners connect (`connect`,
//! protocol v2 over a WebSocket at `/runner/v2/connect`) and how the Core's modules send them
//! commands.
//!
//! - **Connections.** One live connection per runner device: a newer one replaces the older,
//!   which is closed with `close_code::REPLACED` (4009). Revocation closes with 4001, a
//!   stopping Core with 1012, a runner silent past three heartbeats with 1001.
//! - **Capabilities.** A runner's `hello` lists its drivers and the ops each takes. The hub
//!   sends only an advertised op; any other is refused here with `unsupported_command` and
//!   never reaches the runner.
//! - **Routing.** [`Hub::dispatch`] opens a command stream (odd ids, never reused while the
//!   Core runs) and hands back its frames as a [`Dispatched`] stream: `output` frames, then one
//!   `result` or `error`. [`Hub::noop`] is the no-op command end to end.
//! - **Backpressure.** At most `min(sum of the runner's driver capacities, max_inflight)`
//!   commands in flight per runner (`busy` past it), a bounded send queue per connection
//!   (`busy` when full; a send stuck past `send_timeout` closes with 1013), and per-stream
//!   credit for `output`: a runner may send `STREAM_WINDOW` bytes, and more only as the
//!   dispatcher reads them (`credit`). Output past its credit fails the stream.
//! - **Resume by `seq`.** A command stream outlives its connection. The hub keeps every frame
//!   it sent on a stream in flight and counts the runner's. When the same runner process
//!   (`hello.boot`) reconnects within `resume`, the hub resends what the runner says it did not
//!   receive and lists what it received itself (`welcome.streams`); the runner resends the
//!   rest. A runner frame seen before (its `seq` is below the count) is dropped, so an answer
//!   arrives once. After the last frame the hub sends `close`: the runner may forget the stream.
//! - **Loss.** A command is reported `lost` to its dispatcher, exactly once, when its runner
//!   does not come back within `resume`, or comes back as another process (another `boot`).
//!   Nothing follows a `lost`.
//! - **Health** ([`Hub::runners`]): online, degraded (silent past two heartbeats), last seen,
//!   drivers, capacity and load, for the API (`api::v1::runners`) and the `runner.*` events.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::{
    Body, Close, Command, Control, Credit, DriverInfo, ErrorCode, Frame, OP_PTY_ATTACH,
    OP_PTY_OPEN, RunnerHello, STREAM_WINDOW, StreamError, StreamState,
};
use tokio::sync::{Notify, mpsc};

mod conn;
pub mod connect;

/// How the hub paces and bounds connections.
#[derive(Debug, Clone)]
pub struct HubConfig {
    /// Between heartbeats each way; silent for three is dead. Under the gateway's idle cut.
    pub heartbeat: Duration,
    /// From the upgrade to the runner's proof.
    pub handshake: Duration,
    /// A send to the runner blocked this long closes the connection (1013).
    pub send_timeout: Duration,
    /// Commands in flight per runner, whatever its drivers claim.
    pub max_inflight: usize,
    /// How long a disconnected runner's commands wait for it to come back.
    pub resume: Duration,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            heartbeat: Duration::from_secs(15),
            handshake: Duration::from_secs(10),
            send_timeout: Duration::from_secs(10),
            max_inflight: 64,
            resume: Duration::from_secs(60),
        }
    }
}

/// Frames queued per connection before `dispatch` answers `busy`.
const OUT_QUEUE: usize = 256;

/// The live connection of a runner.
struct Conn {
    generation: u64,
    out: mpsc::Sender<Frame>,
    /// Told when a newer connection replaces this one.
    replaced: Arc<Notify>,
}

/// A command in flight: where its frames go, every frame the Core sent on it (for resume),
/// how many runner frames arrived, and the runner's output credit left.
struct Pending {
    to: mpsc::UnboundedSender<Body>,
    // ponytail: every Core frame is kept until the answer; credits pile up on a stream with
    // much output. Drop the ones below the runner's count once output streams exist (E2).
    sent: Vec<Frame>,
    next_sent: u64,
    received: u64,
    credit: u64,
    /// A `pty.open`/`pty.attach` stream: it may carry one `opened` and credited `snapshot`s.
    terminal: bool,
    opened: bool,
}

impl Pending {
    /// The next Core frame on this stream, kept for a resend.
    fn frame(&mut self, stream: u64, body: Body) -> Frame {
        let f = Frame::new(stream, self.next_sent, body);
        self.next_sent = self.next_sent.saturating_add(1);
        self.sent.push(f.clone());
        f
    }

    fn ephemeral(&mut self, stream: u64, body: Body) -> Frame {
        let f = Frame::new(stream, self.next_sent, body);
        self.next_sent = self.next_sent.saturating_add(1);
        f
    }
}

struct Runner {
    name: String,
    hello: RunnerHello,
    conn: Option<Conn>,
    /// Bumped by every connection: a resume timer of an older one does nothing.
    epoch: u64,
    inflight: HashMap<u64, Pending>,
    /// Unix seconds of the last frame.
    last_seen: i64,
    degraded: bool,
}

impl Runner {
    fn advertises(&self, op: &str) -> bool {
        self.hello
            .drivers
            .iter()
            .any(|d| d.commands.iter().any(|c| c == op))
    }

    fn capacity(&self, max: usize) -> usize {
        let sum: u64 = self
            .hello
            .drivers
            .iter()
            .map(|d| u64::from(d.capacity))
            .sum();
        usize::try_from(sum).unwrap_or(usize::MAX).min(max)
    }

    /// Every command in flight is reported `lost`, once.
    fn lose_all(&mut self) {
        for (_, p) in self.inflight.drain() {
            let _ = p.to.send(Body::Error(StreamError::new(
                ErrorCode::Lost,
                "the runner went while the command was in flight; it may or may not have run",
            )));
        }
    }
}

/// A runner as the hub sees it (`Hub::runners`).
#[derive(Debug, Clone, PartialEq)]
pub struct RunnerState {
    pub online: bool,
    pub degraded: bool,
    /// Unix seconds.
    pub last_seen: i64,
    pub version: String,
    pub drivers: Vec<DriverInfo>,
    pub capacity: usize,
    /// Commands in flight.
    pub load: usize,
}

pub struct Hub {
    pub config: HubConfig,
    /// This Core process's random id (`welcome.boot`).
    pub boot: String,
    runners: Mutex<HashMap<String, Runner>>,
    generations: AtomicU64,
    /// The next command stream id: odd, and never reused while the Core runs.
    streams: AtomicU64,
}

/// A dispatched command's frames: `output` (and a terminal's `control`), then one `result` or
/// `error` (`lost` included).
pub struct Dispatched {
    pub stream: u64,
    runner: String,
    hub: Arc<Hub>,
    rx: mpsc::UnboundedReceiver<Body>,
}

impl Dispatched {
    /// The next frame; `None` after the last. Reading `output` grants the runner as much credit.
    pub async fn next(&mut self) -> Option<Body> {
        let body = self.rx.recv().await?;
        let read = match &body {
            Body::Output(o) => Some(&o.data),
            Body::Control(Control::Snapshot(s)) => Some(&s.data),
            _ => None,
        };
        if let Some(data) = read {
            self.hub
                .grant(&self.runner, self.stream, b64_len(data).unwrap_or(0));
        }
        Some(body)
    }

    /// The command's last frame, skipping its output.
    pub async fn outcome(mut self) -> Result<Body, StreamError> {
        while let Some(body) = self.next().await {
            match body {
                Body::Output(_) | Body::Control(_) => continue,
                Body::Error(e) => return Err(e),
                last => return Ok(last),
            }
        }
        Err(StreamError::new(
            ErrorCode::Lost,
            "the hub dropped the stream",
        ))
    }
}

/// The decoded length of standard base64 text; `None` when it is not whole quanta.
fn b64_len(text: &str) -> Option<u64> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let pad = text.bytes().rev().take_while(|b| *b == b'=').count();
    (text.len() as u64 / 4 * 3).checked_sub(pad as u64)
}

fn err(code: ErrorCode, why: &str) -> StreamError {
    StreamError::new(code, why)
}

impl Hub {
    pub fn new(config: HubConfig) -> Self {
        Self {
            config,
            boot: crate::auth::crypto::random_id("b_"),
            runners: Mutex::default(),
            generations: AtomicU64::new(1),
            streams: AtomicU64::new(1),
        }
    }

    /// Sends `command` to `runner`: `offline`, `unsupported_command` (not advertised) and
    /// `busy` (in-flight cap or a full send queue) are answered here, before anything is sent.
    pub fn dispatch(
        self: &Arc<Self>,
        runner: &str,
        command: Command,
    ) -> Result<Dispatched, StreamError> {
        let mut all = self.runners.lock().unwrap();
        let r = all
            .get_mut(runner)
            .filter(|r| r.conn.is_some())
            .ok_or_else(|| err(ErrorCode::Offline, "the runner is not connected"))?;
        if !r.advertises(command.op()) {
            return Err(err(
                ErrorCode::UnsupportedCommand,
                "the runner did not advertise that command",
            ));
        }
        if r.inflight.len() >= r.capacity(self.config.max_inflight) {
            return Err(err(ErrorCode::Busy, "the runner is at its capacity"));
        }
        let stream = self.streams.fetch_add(2, Ordering::Relaxed);
        let (to, rx) = mpsc::unbounded_channel();
        let terminal = matches!(command.op(), OP_PTY_OPEN | OP_PTY_ATTACH);
        let mut p = Pending {
            to,
            sent: Vec::new(),
            next_sent: 0,
            received: 0,
            credit: STREAM_WINDOW,
            terminal,
            opened: false,
        };
        let frame = p.frame(stream, Body::Command(command));
        let conn = r.conn.as_ref().expect("filtered above");
        if conn.out.try_send(frame).is_err() {
            return Err(err(ErrorCode::Busy, "the runner's connection is backed up"));
        }
        r.inflight.insert(stream, p);
        Ok(Dispatched {
            stream,
            runner: runner.to_owned(),
            hub: Arc::clone(self),
            rx,
        })
    }

    /// The no-op command on `runner`, to its answer.
    pub async fn noop(self: &Arc<Self>, runner: &str) -> Result<(), StreamError> {
        match self.dispatch(runner, Command::Noop)?.outcome().await? {
            Body::Result(_) => Ok(()),
            other => Err(err(
                ErrorCode::BadFrame,
                &format!("unexpected answer {other:?}"),
            )),
        }
    }

    /// Whether `runner` has a live connection.
    pub fn online(&self, runner: &str) -> bool {
        let all = self.runners.lock().unwrap();
        all.get(runner).is_some_and(|r| r.conn.is_some())
    }

    /// Sends a bounded, non-retained terminal input/control frame. Terminal input is deliberately
    /// not part of the resume buffer: typed passwords must live only long enough to reach the
    /// runner. The initial command and protocol control frames remain resumable.
    pub fn send_terminal(&self, runner: &str, stream: u64, body: Body) -> Result<(), StreamError> {
        let mut all = self.runners.lock().unwrap();
        let r = all
            .get_mut(runner)
            .filter(|r| r.conn.is_some())
            .ok_or_else(|| err(ErrorCode::Offline, "the runner is not connected"))?;
        let p = r
            .inflight
            .get_mut(&stream)
            .ok_or_else(|| err(ErrorCode::Lost, "the terminal stream is gone"))?;
        let frame = p.ephemeral(stream, body);
        r.conn
            .as_ref()
            .expect("filtered above")
            .out
            .try_send(frame)
            .map_err(|_| err(ErrorCode::Busy, "the runner's connection is backed up"))
    }

    /// Every runner that connected since the Core started, by device id.
    pub fn runners(&self) -> HashMap<String, RunnerState> {
        let all = self.runners.lock().unwrap();
        all.iter()
            .map(|(id, r)| {
                let state = RunnerState {
                    online: r.conn.is_some(),
                    degraded: r.conn.is_some() && r.degraded,
                    last_seen: r.last_seen,
                    version: r.hello.runner_version.clone(),
                    drivers: r.hello.drivers.clone(),
                    capacity: r.capacity(self.config.max_inflight),
                    load: r.inflight.len(),
                };
                (id.clone(), state)
            })
            .collect()
    }

    /// Makes `out` the live connection of `device` (named `name`); an older one is told to
    /// close (4009). The same runner process resumes its streams: the Core frames it did not
    /// receive are queued on `out`. Another process's streams are lost. Returns this
    /// connection's generation and the streams to list in the welcome.
    fn register(
        &self,
        device: &str,
        name: &str,
        hello: RunnerHello,
        out: mpsc::Sender<Frame>,
        replaced: Arc<Notify>,
        now: i64,
    ) -> (u64, Vec<StreamState>) {
        let generation = self.generations.fetch_add(1, Ordering::Relaxed);
        let mut all = self.runners.lock().unwrap();
        let r = all.entry(device.to_owned()).or_insert_with(|| Runner {
            name: name.to_owned(),
            hello: RunnerHello::default(),
            conn: None,
            epoch: 0,
            inflight: HashMap::new(),
            last_seen: now,
            degraded: false,
        });
        if let Some(old) = r.conn.take() {
            old.replaced.notify_one();
        }
        if hello.boot.is_none() || hello.boot != r.hello.boot {
            r.lose_all();
        }
        let mut streams = Vec::with_capacity(r.inflight.len());
        for (id, p) in &mut r.inflight {
            let got = hello
                .streams
                .iter()
                .find(|s| s.stream_id == *id)
                .map_or(0, |s| s.received);
            // The runner's hello is an acknowledgement of the Core frames it received.
            // Drop that prefix before resending: terminal input can include passwords and must
            // not remain in Core memory for the lifetime of a stream.
            let acknowledged = usize::try_from(got).unwrap_or(usize::MAX).min(p.sent.len());
            if acknowledged > 0 {
                p.sent.drain(..acknowledged);
            }
            for f in &p.sent {
                // ponytail: a resend past the queue is dropped; the runner would then wait
                // for the command until the Core loses it. Fine below OUT_QUEUE in flight.
                let _ = out.try_send(f.clone());
            }
            streams.push(StreamState {
                stream_id: *id,
                received: p.received,
            });
        }
        streams.sort_by_key(|s| s.stream_id);
        r.name = name.to_owned();
        r.hello = hello;
        r.epoch += 1;
        r.last_seen = now;
        r.degraded = false;
        r.conn = Some(Conn {
            generation,
            out,
            replaced,
        });
        (generation, streams)
    }

    /// The connection `generation` of `device` ended (a newer one is left alone). Its
    /// commands wait `resume` for the runner, then are lost.
    fn unregister(self: &Arc<Self>, device: &str, generation: u64, now: i64) {
        let mut all = self.runners.lock().unwrap();
        let Some(r) = all.get_mut(device) else { return };
        if !r.conn.as_ref().is_some_and(|c| c.generation == generation) {
            return;
        }
        r.conn = None;
        r.last_seen = now;
        if r.inflight.is_empty() {
            return;
        }
        let (hub, device, epoch) = (Arc::clone(self), device.to_owned(), r.epoch);
        tokio::spawn(async move {
            tokio::time::sleep(hub.config.resume).await;
            let mut all = hub.runners.lock().unwrap();
            if let Some(r) = all.get_mut(&device)
                && r.epoch == epoch
                && r.conn.is_none()
            {
                r.lose_all();
            }
        });
    }

    /// Marks `device` seen at `now`, and whether it is silent enough to be degraded; `true`
    /// when that just turned on.
    fn seen(&self, device: &str, now: i64, degraded: bool) -> bool {
        let mut all = self.runners.lock().unwrap();
        let Some(r) = all.get_mut(device) else {
            return false;
        };
        r.last_seen = r.last_seen.max(now);
        let turned = degraded && !r.degraded;
        r.degraded = degraded;
        turned
    }

    /// A frame from the runner on a command stream. A frame seen before is dropped.
    fn received(&self, device: &str, frame: Frame) {
        let stream = frame.stream_id;
        let mut all = self.runners.lock().unwrap();
        let Some(r) = all.get_mut(device) else { return };
        let Some(p) = r.inflight.get_mut(&stream) else {
            tracing::debug!(device, stream, kind = ?frame.kind, "frame for no stream in flight");
            return;
        };
        if frame.seq < p.received {
            tracing::debug!(
                device,
                stream,
                seq = frame.seq,
                "a resent frame seen before"
            );
            return;
        }
        // A `seq` at its maximum has no successor: the stream fails as `bad_frame`, and the
        // hub carries on for every other stream and runner (security review RH1).
        let body = match frame.seq.checked_add(1) {
            Some(next) => {
                p.received = next;
                match frame.body() {
                    Ok(Some(b)) => b,
                    Ok(None) => return,
                    Err(e) => Body::Error(e),
                }
            }
            None => {
                tracing::warn!(device, stream, "a seq with no successor: the stream fails");
                Body::Error(err(ErrorCode::BadFrame, "the runner's seq overflowed"))
            }
        };
        let last = match body {
            Body::Output(o) => match b64_len(&o.data) {
                Some(n) if n <= p.credit => {
                    p.credit -= n;
                    let _ = p.to.send(Body::Output(o));
                    return;
                }
                _ => {
                    tracing::warn!(device, stream, "output past its credit");
                    Body::Error(err(
                        ErrorCode::BadFrame,
                        "the runner sent output past its credit",
                    ))
                }
            },
            // A terminal stream's one `opened`, and its `snapshot`s under credit (E2-01, review
            // M2: a snapshot costs credit like output, and may overdraw it once to zero). Any
            // other control on a command stream fails it, so nothing reaches the dispatcher
            // unmetered.
            Body::Control(Control::Opened(o)) if p.terminal && !p.opened => {
                p.opened = true;
                let _ = p.to.send(Body::Control(Control::Opened(o)));
                return;
            }
            Body::Control(Control::Snapshot(s)) if p.terminal && p.credit > 0 => {
                match b64_len(&s.data) {
                    Some(n) => {
                        p.credit = p.credit.saturating_sub(n);
                        let _ = p.to.send(Body::Control(Control::Snapshot(s)));
                        return;
                    }
                    None => Body::Error(err(ErrorCode::BadFrame, "a snapshot that is not base64")),
                }
            }
            Body::Control(_) => {
                tracing::warn!(device, stream, "a control frame this stream does not take");
                Body::Error(err(
                    ErrorCode::BadFrame,
                    "the runner sent a control frame this stream does not take",
                ))
            }
            last @ (Body::Result(_) | Body::Error(_)) => last,
            // Credit and heartbeats on a stream: nothing to do for a command.
            _ => return,
        };
        let mut p = r.inflight.remove(&stream).expect("present");
        let _ = p.to.send(last);
        // The stream is over for the Core: the runner may forget it.
        if let Some(c) = &r.conn {
            let _ = c
                .out
                .try_send(p.frame(stream, Body::Close(Close::default())));
        }
    }

    /// The dispatcher read `bytes` of output on `stream`: the runner may send as many more.
    fn grant(&self, device: &str, stream: u64, bytes: u64) {
        let mut all = self.runners.lock().unwrap();
        let Some(r) = all.get_mut(device) else { return };
        let Some(p) = r.inflight.get_mut(&stream) else {
            return;
        };
        p.credit += bytes;
        let frame = p.frame(stream, Body::Credit(Credit { bytes }));
        if let Some(c) = &r.conn {
            // Kept in `sent` either way: a resume delivers it.
            let _ = c.out.try_send(frame);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::b64_len;

    #[test]
    fn base64_lengths() {
        assert_eq!(b64_len(""), Some(0));
        assert_eq!(b64_len("aGkK"), Some(3));
        assert_eq!(b64_len("aGk="), Some(2));
        assert_eq!(b64_len("aA=="), Some(1));
        assert_eq!(b64_len("aGk"), None);
    }
}
