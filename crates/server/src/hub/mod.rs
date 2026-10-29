//! The runner hub (E1-11.2): where paired runners connect (`connect`, protocol v2 over a
//! WebSocket at `/runner/v2/connect`) and how the Core's modules send them commands.
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
//! - **Loss.** A command whose connection goes before its answer is reported `lost` to its
//!   dispatcher, exactly once.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::{
    Body, Command, Credit, ErrorCode, Frame, RunnerHello, STREAM_WINDOW, StreamError,
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
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            heartbeat: Duration::from_secs(15),
            handshake: Duration::from_secs(10),
            send_timeout: Duration::from_secs(10),
            max_inflight: 64,
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

/// A command in flight: where its frames go, the runner's output credit left, and the
/// Core's next `seq` on the stream.
struct Pending {
    to: mpsc::UnboundedSender<Body>,
    credit: u64,
    seq: u64,
}

struct Runner {
    hello: RunnerHello,
    conn: Option<Conn>,
    inflight: HashMap<u64, Pending>,
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
                "the runner's connection went while the command was in flight",
            )));
        }
    }
}

pub struct Hub {
    pub config: HubConfig,
    runners: Mutex<HashMap<String, Runner>>,
    generations: AtomicU64,
    /// The next command stream id: odd, and never reused while the Core runs.
    streams: AtomicU64,
}

/// A dispatched command's frames: `output`, then one `result` or `error` (`lost` included).
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
        if let Body::Output(o) = &body {
            self.hub
                .grant(&self.runner, self.stream, b64_len(&o.data).unwrap_or(0));
        }
        Some(body)
    }

    /// The command's last frame, skipping its output.
    pub async fn outcome(mut self) -> Result<Body, StreamError> {
        while let Some(body) = self.next().await {
            match body {
                Body::Output(_) => continue,
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
        let conn = r.conn.as_ref().expect("filtered above");
        if conn
            .out
            .try_send(Frame::new(stream, 0, Body::Command(command)))
            .is_err()
        {
            return Err(err(ErrorCode::Busy, "the runner's connection is backed up"));
        }
        let (to, rx) = mpsc::unbounded_channel();
        let pending = Pending {
            to,
            credit: STREAM_WINDOW,
            seq: 1,
        };
        r.inflight.insert(stream, pending);
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

    /// Makes `out` the live connection of `device`; an older one is told to close (4009) and
    /// whatever it had in flight is lost. Returns this connection's generation.
    fn register(
        &self,
        device: &str,
        hello: RunnerHello,
        out: mpsc::Sender<Frame>,
        replaced: Arc<Notify>,
    ) -> u64 {
        let generation = self.generations.fetch_add(1, Ordering::Relaxed);
        let mut all = self.runners.lock().unwrap();
        let r = all.entry(device.to_owned()).or_insert_with(|| Runner {
            hello: hello.clone(),
            conn: None,
            inflight: HashMap::new(),
        });
        if let Some(old) = r.conn.take() {
            old.replaced.notify_one();
        }
        r.lose_all();
        r.hello = hello;
        r.conn = Some(Conn {
            generation,
            out,
            replaced,
        });
        generation
    }

    /// The connection `generation` of `device` ended; a newer one is left alone.
    fn unregister(&self, device: &str, generation: u64) {
        let mut all = self.runners.lock().unwrap();
        if let Some(r) = all.get_mut(device)
            && r.conn.as_ref().is_some_and(|c| c.generation == generation)
        {
            r.conn = None;
            r.lose_all();
        }
    }

    /// A frame from the runner on a command stream.
    fn received(&self, device: &str, frame: Frame) {
        let stream = frame.stream_id;
        let mut all = self.runners.lock().unwrap();
        let Some(r) = all.get_mut(device) else { return };
        let Some(p) = r.inflight.get_mut(&stream) else {
            tracing::debug!(device, stream, kind = ?frame.kind, "frame for no stream in flight");
            return;
        };
        let body = match frame.body() {
            Ok(Some(b)) => b,
            Ok(None) => return,
            Err(e) => Body::Error(e),
        };
        match body {
            Body::Output(o) => match b64_len(&o.data) {
                Some(n) if n <= p.credit => {
                    p.credit -= n;
                    let _ = p.to.send(Body::Output(o));
                }
                _ => {
                    tracing::warn!(device, stream, "output past its credit");
                    let p = r.inflight.remove(&stream).expect("present");
                    let _ = p.to.send(Body::Error(err(
                        ErrorCode::BadFrame,
                        "the runner sent output past its credit",
                    )));
                    if let Some(c) = &r.conn {
                        let close = ainkrad_proto::v2::Close {
                            reason: Some("output past its credit".to_owned()),
                        };
                        let _ = c
                            .out
                            .try_send(Frame::new(stream, p.seq, Body::Close(close)));
                    }
                }
            },
            last @ (Body::Result(_) | Body::Error(_)) => {
                let p = r.inflight.remove(&stream).expect("present");
                let _ = p.to.send(last);
            }
            // Credit, heartbeats on a stream, control: nothing to do for a command.
            _ => {}
        }
    }

    /// The dispatcher read `bytes` of output on `stream`: the runner may send as many more.
    fn grant(&self, device: &str, stream: u64, bytes: u64) {
        let mut all = self.runners.lock().unwrap();
        let Some(r) = all.get_mut(device) else { return };
        let (Some(p), Some(c)) = (r.inflight.get_mut(&stream), &r.conn) else {
            return;
        };
        let frame = Frame::new(stream, p.seq, Body::Credit(Credit { bytes }));
        if c.out.try_send(frame).is_ok() {
            p.credit += bytes;
            p.seq += 1;
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
