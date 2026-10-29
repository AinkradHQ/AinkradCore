//! The runner's side of protocol v2 (E1-11.1, E1-11.5) on one connected WebSocket.
//!
//! `serve` sends `hello` with the drivers (only `exec` for now) and waits for `welcome`, then
//! answers each `command` on its own stream with one `result` or `error`; a `close` from the
//! Core cancels that command. Commands run concurrently, up to each driver's capacity.
//!
//! Not wired into `main` or the v1 daemon yet: dialing, Core identity (E1-11.3) and
//! reconnect/resume (E1-11.4) come with the hub (E1-11.2).

use std::collections::HashMap;
use std::sync::Arc;

use ainkrad_proto::runner::protocol_major;
use ainkrad_proto::v2::{
    Body, CONTROL_STREAM, Command, Control, ErrorCode, Frame, PROTOCOL_VERSION, Reply, RunnerHello,
    StreamError,
};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

mod exec;
pub use exec::{ExecConfig, ExecDriver};

/// Serves the Core on `ws` until it closes the connection (`Ok`) or refuses the runner, or
/// the connection fails (`Err`). Commands still running when it ends are killed.
pub async fn serve<S>(ws: WebSocketStream<S>, exec: Arc<ExecDriver>) -> Result<(), StreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut sink, mut source) = ws.split();
    let mut out = Seqs::default();
    let hello = Control::Hello(RunnerHello {
        protocol: PROTOCOL_VERSION.to_owned(),
        runner_version: env!("CARGO_PKG_VERSION").to_owned(),
        drivers: vec![exec.info()],
        os: Some(std::env::consts::OS.to_owned()),
        arch: Some(std::env::consts::ARCH.to_owned()),
    });
    send(
        &mut sink,
        out.frame(CONTROL_STREAM, Body::Control(hello), false),
    )
    .await?;
    welcome(&mut source).await?;

    let (done_tx, mut done_rx) = mpsc::channel::<(u64, Body)>(64);
    // Each running command's cancel; dropping one (or the map) cancels it too.
    let mut running: HashMap<u64, oneshot::Sender<()>> = HashMap::new();
    loop {
        let frame = tokio::select! {
            Some((stream, body)) = done_rx.recv() => {
                running.remove(&stream);
                send(&mut sink, out.frame(stream, body, true)).await?;
                continue;
            }
            msg = source.next() => match msg {
                Some(Ok(Message::Text(text))) => match serde_json::from_str::<Frame>(&text) {
                    Ok(frame) => frame,
                    Err(e) => {
                        let e = StreamError::new(ErrorCode::BadFrame, format!("not a frame: {e}"));
                        send(&mut sink, out.frame(CONTROL_STREAM, Body::Error(e), false)).await?;
                        continue;
                    }
                },
                Some(Ok(Message::Close(_))) | None => return Ok(()),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(lost(e)),
            },
        };
        let stream = frame.stream_id;
        let reply = match frame.body() {
            Ok(Some(Body::Command(command)))
                if stream % 2 == 1 && !running.contains_key(&stream) =>
            {
                start(&exec, stream, command, &done_tx, &mut running)
            }
            Ok(Some(Body::Command(_))) => Some(Body::Error(StreamError::new(
                ErrorCode::BadFrame,
                format!("stream {stream} cannot open a command"),
            ))),
            Ok(Some(Body::Close(_))) => {
                if let Some(cancel) = running.remove(&stream) {
                    let _ = cancel.send(());
                }
                None
            }
            // Heartbeats, credit, output (no driver takes input yet), unknown kinds.
            Ok(_) => None,
            Err(e) => Some(Body::Error(e)),
        };
        if let Some(body) = reply {
            // A refusal ends its stream, unless that stream is a command still running.
            let last = stream != CONTROL_STREAM && !running.contains_key(&stream);
            send(&mut sink, out.frame(stream, body, last)).await?;
        }
    }
}

/// Starts `command` on `stream`: an immediate answer, or `None` when a task answers later.
fn start(
    exec: &Arc<ExecDriver>,
    stream: u64,
    command: Command,
    done: &mpsc::Sender<(u64, Body)>,
    running: &mut HashMap<u64, oneshot::Sender<()>>,
) -> Option<Body> {
    match command {
        Command::Noop => Some(Body::Result(Reply::Noop)),
        Command::ExecRun(req) => {
            let slot = match exec.slot() {
                Ok(slot) => slot,
                Err(e) => return Some(Body::Error(e)),
            };
            let (cancel_tx, cancel_rx) = oneshot::channel();
            running.insert(stream, cancel_tx);
            let (exec, done) = (exec.clone(), done.clone());
            tokio::spawn(async move {
                let body = match exec.run(&req, cancel_rx).await {
                    Ok(result) => Body::Result(Reply::ExecRun(result)),
                    Err(e) => Body::Error(e),
                };
                drop(slot);
                let _ = done.send((stream, body)).await;
            });
            None
        }
        Command::Unknown => Some(Body::Error(StreamError::new(
            ErrorCode::UnsupportedCommand,
            "no driver of this runner takes that command",
        ))),
    }
}

/// Waits for the Core's `welcome`; its `error` (or a major it does not share) is a refusal.
async fn welcome<S>(
    source: &mut futures_util::stream::SplitStream<WebSocketStream<S>>,
) -> Result<(), StreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bad = |m: String| StreamError::new(ErrorCode::BadFrame, m);
    loop {
        let text = match source.next().await {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(Message::Close(_))) | None => return Err(bad("closed before welcome".into())),
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(lost(e)),
        };
        let frame: Frame = serde_json::from_str(&text).map_err(|e| bad(e.to_string()))?;
        match frame.body()? {
            Some(Body::Control(Control::Welcome(w))) => {
                return if protocol_major(&w.protocol) == protocol_major(PROTOCOL_VERSION) {
                    Ok(())
                } else {
                    let m = format!("the Core speaks {}", w.protocol);
                    Err(StreamError::new(ErrorCode::UnsupportedVersion, m))
                };
            }
            Some(Body::Error(e)) => return Err(e),
            _ => continue,
        }
    }
}

fn lost(e: impl std::fmt::Display) -> StreamError {
    StreamError::new(ErrorCode::Internal, format!("connection lost: {e}"))
}

async fn send<S>(
    sink: &mut futures_util::stream::SplitSink<WebSocketStream<S>, Message>,
    frame: Frame,
) -> Result<(), StreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let text = serde_json::to_string(&frame).expect("a frame serializes");
    sink.send(Message::Text(text.into())).await.map_err(lost)
}

/// The runner's next `seq` per stream; a stream's counter goes with its last frame.
#[derive(Default)]
struct Seqs(HashMap<u64, u64>);

impl Seqs {
    fn frame(&mut self, stream: u64, body: Body, last: bool) -> Frame {
        let seq = if last {
            self.0.remove(&stream).unwrap_or(0)
        } else {
            let next = self.0.entry(stream).or_insert(0);
            *next += 1;
            *next - 1
        };
        Frame::new(stream, seq, body)
    }
}

#[cfg(test)]
mod tests;
