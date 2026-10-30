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
//! - An `agent.*` command is a request about a session the agent driver owns (`agent`), not
//!   the session itself: forgetting its stream (a Core restart) leaves the harness running.
//! - Heartbeats go out at the Core's pace (`welcome.heartbeat_ms`); a Core silent for three is
//!   a dead connection, ended so the daemon redials.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{
    Body, CONTROL_STREAM, Command, Control, ErrorCode, Frame, Reply, RunnerHello, StreamError,
    StreamState,
};
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use super::agent::AgentDriver;
use super::{ExecDriver, Link, handshake, key, lost, rotate, send};

/// The pace when the Core names none.
const HEARTBEAT: Duration = Duration::from_secs(15);

#[derive(Default)]
struct Held {
    /// Core frames received: the next `seq` expected.
    received: u64,
    /// Runner frames sent, numbered by position.
    sent: Vec<Frame>,
    /// While the command runs.
    cancel: Option<oneshot::Sender<()>>,
}

impl Held {
    fn frame(&mut self, stream: u64, body: Body) -> Frame {
        let f = Frame::new(stream, self.sent.len() as u64, body);
        self.sent.push(f.clone());
        f
    }
}

pub struct Session {
    exec: Arc<ExecDriver>,
    /// Agent sessions (`--enable-agents`), if offered.
    agent: Option<Arc<AgentDriver>>,
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
            agent: None,
            boot: format!("b_{}", key::b64(&key::random::<16>())),
            core_boot: None,
            streams: HashMap::new(),
            done_tx,
            done_rx,
        }
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
        let hello = RunnerHello {
            drivers: std::iter::once(self.exec.info())
                .chain(self.agent.as_ref().map(|a| a.info()))
                .collect(),
            boot: Some(self.boot.clone()),
            streams: held,
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
            for f in h.sent.iter().skip(listed[id] as usize) {
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
        loop {
            let frame = tokio::select! {
                Some((stream, body)) = self.done_rx.recv() => {
                    // A stream forgotten meanwhile (the Core lost or cancelled it) is dropped.
                    if let Some(h) = self.streams.get_mut(&stream) {
                        h.cancel = None;
                        let f = h.frame(stream, body);
                        send(&mut sink, f).await?;
                    }
                    continue;
                }
                _ = beat.tick() => {
                    if heard.elapsed() > heartbeat * 3 {
                        return Err(lost("the Core went silent"));
                    }
                    send(&mut sink, Frame::new(CONTROL_STREAM, control, Body::Heartbeat)).await?;
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
            // Heartbeats, credit, output (no driver takes input yet), unknown kinds.
            Ok(_) => None,
            Err(e) => {
                let h = self.streams.entry(stream).or_default();
                Some(h.frame(stream, Body::Error(e)))
            }
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
