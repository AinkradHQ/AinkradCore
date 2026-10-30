//! What a runner keeps across connections (E1-11.4): its process `boot` id, the Core's, and
//! every command stream it holds. A stream holds how many Core frames arrived on it, every
//! frame the runner sent on it, and, while the command runs, its cancel.
//!
//! - A Core frame whose `seq` is below the stream's count was seen before and is skipped, so a
//!   command resent after a reconnect runs once.
//! - A command finishing while disconnected is kept, and sent when the next connection is up.
//! - `welcome.streams` says what the Core received on each stream it still has in flight; the
//!   runner resends the rest. A held stream the Core does not list is over for it (answered,
//!   or reported lost): a running one is cancelled, and both are forgotten. Another Core `boot`
//!   (a restarted Core) forgets every stream the same way.
//! - The Core's `close` after a stream's last frame means it has it: the stream is forgotten.
//!   A `close` while the command runs cancels it.
//! - A terminal stream (`pty.open`, `pty.attach`) is long: the Core's `output`, `control` and
//!   `credit` on it go to its bridge (`pty`), and its frames come back as they are made. Its
//!   sent frames are kept only until the Core's credit shows it read them, so a terminal's
//!   history is never held here (the host holds it, by byte `seq`).
//! - An `agent.*` command is a request about a session the agent driver owns (`agent`), not
//!   the session itself: forgetting its stream (a Core restart) leaves the harness running.
//! - Heartbeats go out at the Core's pace (`welcome.heartbeat_ms`); a Core silent for three is
//!   a dead connection, ended so the daemon redials.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ainkrad_proto::v2::{
    Body, CONTROL_STREAM, Command, Control, ErrorCode, Frame, FrameKind, Heartbeat, HostLoad,
    Reply, RunnerHello, StreamError, StreamState,
};
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use super::agent::AgentDriver;
use super::pty::{Op, PtyDriver};
use super::{ExecDriver, Link, handshake, key, lost, rotate, send};
use crate::load::host_load;

/// The wall clock; a test swaps it to fake a sleep (E2-15.3).
pub(super) type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// The pace when the Core names none.
const HEARTBEAT: Duration = Duration::from_secs(15);

/// Command streams held at once: the Core's own in-flight cap (`HubConfig::max_inflight`). A
/// Core that opens more without closing them gets `busy`, so a hostile one cannot grow the
/// runner's memory without bound (security review RH9). Each holds at most one `exec` result
/// (2 MiB of output) plus its frames.
pub(super) const MAX_HELD: usize = 64;

#[derive(Default)]
struct Held {
    /// Core frames received: the next `seq` expected.
    received: u64,
    /// Runner frames sent and not known to be received, from `seq` `base` on.
    sent: VecDeque<Frame>,
    base: u64,
    /// Output bytes the Core's credit acknowledged and not yet matched to a dropped frame.
    acked: u64,
    /// While the command runs.
    cancel: Option<oneshot::Sender<()>>,
    /// A terminal stream's bridge: where the Core's frames on it go.
    inbox: Option<mpsc::UnboundedSender<Body>>,
}

/// The credit a frame used: an `output`'s bytes, or a `snapshot`'s (review M2); `None` for a
/// frame credit does not count.
fn credited(f: &Frame) -> Option<u64> {
    let counted = match f.kind {
        FrameKind::Output => true,
        FrameKind::Control => f.payload.get("type").and_then(|t| t.as_str()) == Some("snapshot"),
        _ => false,
    };
    let data = f.payload.get("data")?.as_str().filter(|_| counted)?;
    Some(super::pty::b64_len(data))
}

impl Held {
    fn frame(&mut self, stream: u64, body: Body) -> Frame {
        let f = Frame::new(stream, self.base + self.sent.len() as u64, body);
        self.sent.push_back(f.clone());
        f
    }

    /// The Core granted `bytes` of credit: it read that much output (snapshots included), so
    /// every frame up to the last credited frame those bytes cover was received and need not
    /// be kept for a resend.
    fn ack(&mut self, bytes: u64) {
        self.acked = self.acked.saturating_add(bytes);
        let (mut budget, mut cut, mut spent) = (self.acked, 0, 0);
        for (i, f) in self.sent.iter().enumerate() {
            let Some(n) = credited(f) else {
                continue;
            };
            if n > budget {
                break;
            }
            budget -= n;
            spent += n;
            cut = i + 1;
        }
        self.sent.drain(..cut);
        self.base += cut as u64;
        self.acked -= spent;
    }
}

pub struct Session {
    exec: Arc<ExecDriver>,
    pty: Option<Arc<PtyDriver>>,
    /// Agent sessions (`--enable-agents`), if offered.
    agent: Option<Arc<AgentDriver>>,
    /// Where wall time comes from: a monotonic clock stands still while the machine sleeps.
    clock: Clock,
    boot: String,
    core_boot: Option<String>,
    streams: HashMap<u64, Held>,
    done_tx: mpsc::UnboundedSender<(u64, Body)>,
    done_rx: mpsc::UnboundedReceiver<(u64, Body)>,
}

impl Session {
    pub fn new(exec: Arc<ExecDriver>) -> Self {
        let (done_tx, done_rx) = mpsc::unbounded_channel();
        Self {
            exec,
            pty: None,
            agent: None,
            clock: Arc::new(SystemTime::now),
            boot: format!("b_{}", key::b64(&key::random::<16>())),
            core_boot: None,
            streams: HashMap::new(),
            done_tx,
            done_rx,
        }
    }

    /// Reads wall time from `clock` (tests fake a sleep with it).
    #[cfg(test)]
    pub(super) fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Offers the `pty` driver too (when its config enables it).
    pub fn with_pty(mut self, pty: Arc<PtyDriver>) -> Self {
        self.pty = Some(pty);
        self
    }

    /// Offers the `agent` driver too.
    pub fn with_agents(mut self, agent: Arc<AgentDriver>) -> Self {
        self.agent = Some(agent);
        self
    }

    /// Forgets `stream`, cancelling its command if it still runs (dropping the sender does).
    fn forget(&mut self, stream: u64) {
        self.streams.remove(&stream);
    }

    /// Serves one connection: the proof, the resume, then commands until it ends. `Ok` with
    /// the Core's close code; `Err` when it failed or the Core refused.
    pub async fn serve<S>(
        &mut self,
        ws: WebSocketStream<S>,
        link: &Link,
    ) -> Result<Option<u16>, StreamError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut sink, mut source) = ws.split();
        let mut held: Vec<StreamState> = self
            .streams
            .iter()
            .map(|(id, h)| StreamState {
                stream_id: *id,
                received: h.received,
            })
            .collect();
        held.sort_by_key(|s| s.stream_id);
        let (pty_info, terminals) = match &self.pty {
            Some(p) => (p.info(), p.terminals().await),
            None => (None, Vec::new()),
        };
        let hello = RunnerHello {
            drivers: std::iter::once(self.exec.info())
                .chain(pty_info)
                .chain(self.agent.as_ref().map(|a| a.info()))
                .collect(),
            boot: Some(self.boot.clone()),
            streams: held,
            terminals,
            load: host_load().map(|l| HostLoad {
                avg1: l.avg1,
                cores: l.cores,
            }),
            ..RunnerHello::default()
        };
        let (welcome, core_spki) = handshake(&mut sink, &mut source, link, hello).await?;
        if welcome.boot.is_none() || welcome.boot != self.core_boot {
            if self.core_boot.is_some() {
                tracing::info!("the Core restarted: every held stream is gone");
            }
            self.streams.clear();
            self.core_boot = welcome.boot.clone();
        }
        let listed: HashMap<u64, u64> = welcome
            .streams
            .iter()
            .map(|s| (s.stream_id, s.received))
            .collect();
        let gone: Vec<u64> = self
            .streams
            .keys()
            .filter(|id| !listed.contains_key(id))
            .copied()
            .collect();
        for id in gone {
            self.forget(id);
        }
        for (id, h) in &self.streams {
            let skip = listed[id].saturating_sub(h.base);
            for f in h
                .sent
                .iter()
                .skip(usize::try_from(skip).unwrap_or(usize::MAX))
            {
                send(&mut sink, f.clone()).await?;
            }
        }
        let heartbeat = welcome
            .heartbeat_ms
            .map_or(HEARTBEAT, Duration::from_millis);
        let mut beat = tokio::time::interval(heartbeat);
        beat.reset();
        let mut heard = Instant::now();
        let mut control = 2;
        let mut ticked = (self.clock)();
        loop {
            let frame = tokio::select! {
                Some((stream, body)) = self.done_rx.recv() => {
                    // A stream forgotten meanwhile (the Core lost or cancelled it) is dropped.
                    if let Some(h) = self.streams.get_mut(&stream) {
                        if matches!(body, Body::Result(_) | Body::Error(_)) {
                            h.cancel = None;
                            h.inbox = None;
                        }
                        let f = h.frame(stream, body);
                        send(&mut sink, f).await?;
                    }
                    continue;
                }
                _ = beat.tick() => {
                    // A wall-clock gap of over two beats means the machine slept (E2-15.3): the
                    // link is dead or the Core has dropped it, so end it now; the daemon redials
                    // at once and the streams resume by `seq`, rather than waiting out the
                    // silence check below.
                    let now = (self.clock)();
                    let gap = now.duration_since(ticked).unwrap_or_default();
                    ticked = now;
                    if gap > heartbeat * 2 {
                        tracing::info!(?gap, "woke from sleep; reconnecting");
                        return Ok(None);
                    }
                    if heard.elapsed() > heartbeat * 3 {
                        return Err(lost("the Core went silent"));
                    }
                    send(
                        &mut sink,
                        Frame::new(
                            CONTROL_STREAM,
                            control,
                            Body::Heartbeat(Heartbeat {
                                load: host_load().map(|l| HostLoad {
                                    avg1: l.avg1,
                                    cores: l.cores,
                                }),
                            }),
                        ),
                    )
                    .await?;
                    control += 1;
                    continue;
                }
                msg = source.next() => match msg {
                    Some(Ok(Message::Text(text))) => {
                        heard = Instant::now();
                        match serde_json::from_str::<Frame>(&text) {
                            Ok(frame) => frame,
                            Err(e) => {
                                let e = StreamError::new(ErrorCode::BadFrame, format!("not a frame: {e}"));
                                send(&mut sink, Frame::new(CONTROL_STREAM, control, Body::Error(e))).await?;
                                control += 1;
                                continue;
                            }
                        }
                    }
                    Some(Ok(Message::Close(c))) => return Ok(c.map(|c| c.code.into())),
                    None => return Ok(None),
                    Some(Ok(_)) => {
                        heard = Instant::now();
                        continue;
                    }
                    Some(Err(e)) => return Err(lost(e)),
                },
            };
            if let Some(f) = self.handle(frame, link, &core_spki) {
                send(&mut sink, f).await?;
            }
        }
    }

    /// One Core frame; the frame to answer with, if any.
    fn handle(&mut self, frame: Frame, link: &Link, core_spki: &[u8]) -> Option<Frame> {
        let stream = frame.stream_id;
        if stream == CONTROL_STREAM {
            if let Ok(Some(Body::Control(Control::Rotation(r)))) = frame.body() {
                rotate(link, &r, core_spki);
            }
            return None;
        }
        let refuse = |code, why: String| Body::Error(StreamError::new(code, why));
        // A `seq` at its maximum has no successor: the stream is refused as `bad_frame` and
        // forgotten (its command cancelled), and the session carries on (security review RH1).
        let Some(next) = frame.seq.checked_add(1) else {
            self.forget(stream);
            let why = format!("stream {stream}: the seq overflowed");
            return Some(Frame::new(stream, 0, refuse(ErrorCode::BadFrame, why)));
        };
        if let Some(h) = self.streams.get_mut(&stream) {
            if frame.seq < h.received {
                return None;
            }
            h.received = next;
        }
        match frame.body() {
            Ok(Some(Body::Command(command))) if stream % 2 == 1 => {
                if self.streams.contains_key(&stream) {
                    let why = format!("stream {stream} has a command already");
                    return Some(Frame::new(stream, 0, refuse(ErrorCode::BadFrame, why)));
                }
                if self.streams.len() >= MAX_HELD {
                    let why = format!("{MAX_HELD} streams held; close some first");
                    return Some(Frame::new(stream, 0, refuse(ErrorCode::Busy, why)));
                }
                let mut h = Held {
                    received: next,
                    ..Held::default()
                };
                let answer = self.start(stream, command, &mut h);
                let reply = answer.map(|b| h.frame(stream, b));
                self.streams.insert(stream, h);
                reply
            }
            Ok(Some(Body::Command(_))) => {
                let why = format!("stream {stream} cannot open a command");
                Some(Frame::new(stream, 0, refuse(ErrorCode::BadFrame, why)))
            }
            Ok(Some(Body::Close(_))) => {
                match self.streams.get_mut(&stream) {
                    Some(h) if h.cancel.is_some() => drop(h.cancel.take().map(|c| c.send(()))),
                    Some(_) => self.forget(stream),
                    None => {}
                }
                None
            }
            // A terminal's input, resize, signal and credit go to its bridge.
            Ok(Some(b @ (Body::Output(_) | Body::Control(_) | Body::Credit(_)))) => {
                if let Some(h) = self.streams.get_mut(&stream) {
                    if let Body::Credit(c) = &b {
                        h.ack(c.bytes);
                    }
                    if let Some(inbox) = &h.inbox {
                        let _ = inbox.send(b);
                    }
                }
                None
            }
            // Heartbeats and unknown kinds.
            Ok(_) => None,
            // On a stream it holds, numbered in it; on any other, answered once and not held,
            // so malformed frames on fresh ids grow nothing (RH9).
            Err(e) => match self.streams.get_mut(&stream) {
                Some(h) => Some(h.frame(stream, Body::Error(e))),
                None => Some(Frame::new(stream, 0, Body::Error(e))),
            },
        }
    }

    /// Starts `command`: an immediate answer, or `None` when a task answers later.
    fn start(&self, stream: u64, command: Command, h: &mut Held) -> Option<Body> {
        match command {
            Command::Noop => Some(Body::Result(Reply::Noop)),
            Command::ExecRun(req) => {
                let slot = match self.exec.slot() {
                    Ok(slot) => slot,
                    Err(e) => return Some(Body::Error(e)),
                };
                let (cancel_tx, cancel_rx) = oneshot::channel();
                h.cancel = Some(cancel_tx);
                let (exec, done) = (Arc::clone(&self.exec), self.done_tx.clone());
                tokio::spawn(async move {
                    let body = match exec.run(&req, cancel_rx).await {
                        Ok(result) => Body::Result(Reply::ExecRun(result)),
                        Err(e) => Body::Error(e),
                    };
                    drop(slot);
                    let _ = done.send((stream, body));
                });
                None
            }
            Command::PtyOpen(_) | Command::PtyAttach(_) | Command::PtyClose(_) => {
                self.start_pty(stream, command, h)
            }
            Command::AgentStart(_)
            | Command::AgentRead(_)
            | Command::AgentSend(_)
            | Command::AgentDecide(_)
            | Command::AgentStop(_) => self.start_agent(stream, command),
            Command::Unknown => Some(Body::Error(StreamError::new(
                ErrorCode::UnsupportedCommand,
                "no driver of this runner takes that command",
            ))),
        }
    }
}

impl Session {
    /// Starts a `pty.*` command; `None` when a task answers later.
    fn start_pty(&self, stream: u64, command: Command, h: &mut Held) -> Option<Body> {
        let Some(pty) = self.pty.as_ref().filter(|p| p.info().is_some()) else {
            return Some(Body::Error(StreamError::new(
                ErrorCode::UnsupportedCommand,
                "pty is off on this runner (ainkrad-runner connect --enable-pty)",
            )));
        };
        let (pty, done) = (Arc::clone(pty), self.done_tx.clone());
        let (cancel_tx, cancel_rx) = oneshot::channel();
        h.cancel = Some(cancel_tx);
        if let Command::PtyClose(req) = command {
            tokio::spawn(async move {
                let body = match pty.close(&req.terminal).await {
                    Ok(exit) => Body::Result(Reply::PtyClose(exit)),
                    Err(e) => Body::Error(e),
                };
                drop(cancel_rx);
                let _ = done.send((stream, body));
            });
            return None;
        }
        let (inbox_tx, inbox) = mpsc::unbounded_channel();
        h.inbox = Some(inbox_tx);
        tokio::spawn(async move {
            let (op, terminal, seq) = match command {
                Command::PtyOpen(req) => match pty.open(&req).await {
                    Ok(id) => (Op::Open, id, 0),
                    Err(e) => {
                        let _ = done.send((stream, Body::Error(e)));
                        return;
                    }
                },
                Command::PtyAttach(req) => (Op::Attach, req.terminal, req.seq),
                _ => return,
            };
            let last = pty
                .bridge(op, terminal, seq, stream, inbox, cancel_rx, done.clone())
                .await;
            let _ = done.send((stream, last));
        });
        None
    }
}

impl Session {
    /// An `agent.*` command, answered by a task: the session it names lives in the driver.
    fn start_agent(&self, stream: u64, command: Command) -> Option<Body> {
        let Some(agent) = self.agent.as_ref() else {
            return Some(Body::Error(StreamError::new(
                ErrorCode::UnsupportedCommand,
                "agents are off on this runner (ainkrad-runner connect --enable-agents)",
            )));
        };
        let (agent, done) = (Arc::clone(agent), self.done_tx.clone());
        tokio::spawn(async move {
            let answer = match command {
                Command::AgentStart(req) => agent.start(req).map(Reply::AgentStart),
                Command::AgentRead(req) => agent.read(&req).await.map(Reply::AgentRead),
                Command::AgentSend(req) => agent.send(&req.session, req.text).map(Reply::AgentSend),
                Command::AgentDecide(req) => agent.decide(req).map(Reply::AgentDecide),
                Command::AgentStop(req) => agent.stop(req).map(Reply::AgentStop),
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
}

#[cfg(test)]
mod tests {
    use ainkrad_proto::v2::{Control, Output, Size, TerminalInfo, TerminalState};

    use super::*;

    /// A terminal stream keeps only what the Core's credit does not yet cover, and numbering
    /// continues across what was dropped.
    #[test]
    fn credit_drops_the_frames_the_core_read() {
        let mut h = Held::default();
        let out = |n: usize| {
            Body::Output(Output {
                data: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    vec![0; n],
                ),
            })
        };
        let opened = Body::Control(Control::Opened(TerminalInfo {
            terminal: "t_a".to_owned(),
            state: TerminalState::Running,
            size: Size { rows: 1, cols: 1 },
            seq: 0,
            pid: None,
            exit: None,
        }));
        h.frame(7, opened);
        for n in [10, 20, 30] {
            h.frame(7, out(n));
        }
        h.ack(15);
        assert_eq!(
            (h.base, h.sent.len()),
            (2, 2),
            "opened and the first output went"
        );
        h.ack(15);
        assert_eq!((h.base, h.sent.len()), (3, 1));
        assert_eq!(h.frame(7, out(1)).seq, 4);
        h.ack(31);
        assert!(h.sent.is_empty());
        assert_eq!(h.acked, 0);
        // A snapshot is credited like output (review M2): acked, it goes.
        h.frame(
            7,
            Body::Control(Control::Snapshot(ainkrad_proto::v2::Snapshot {
                seq: 9,
                data: "AAAAAAAAAAAA".to_owned(),
            })),
        );
        h.ack(8);
        assert_eq!(h.sent.len(), 1);
        h.ack(1);
        assert!(h.sent.is_empty());
    }
}
