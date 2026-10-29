//! The runner's side of protocol v2 (E1-11.1, E1-11.5) on one connected WebSocket.
//!
//! `serve` sends `hello` with the drivers (only `exec` for now) and waits for `welcome`, then
//! answers each `command` on its own stream with one `result` or `error`; a `close` from the
//! Core cancels that command. Commands run concurrently, up to each driver's capacity.
//!
//! Before any command, the connection proof (`ainkrad_proto::v2::auth`, handshake spec §13):
//! the hello carries the device id and a nonce; the Core's `auth` must come from the pinned
//! identity and sign this connection's exporter, or the runner closes and sends nothing more;
//! then the runner's own `proof`. A `rotation` from the Core moves the pin (`Enrolment::rotate`).
//! `client` and `pair` are the HTTP side; reconnect/resume (E1-11.4) comes with the daemon.

use std::collections::HashMap;
use std::sync::Arc;

use ainkrad_proto::runner::protocol_major;
use ainkrad_proto::v2::{
    Body, CONTROL_STREAM, Command, Control, CoreAuth, ErrorCode, Frame, PROTOCOL_VERSION, Reply,
    RunnerHello, RunnerProof, StreamError, core_auth_message, runner_auth_message,
};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

pub mod cli;
pub mod client;
pub mod dial;
mod exec;
pub mod key;
pub mod pair;
pub use exec::{ExecConfig, ExecDriver};

/// What the runner proves itself with on one connection.
pub struct Link {
    pub key: Arc<key::Key>,
    /// The enrolment (device id, pinned fingerprint); a rotation updates it here and, when
    /// `save` names a file, there too.
    pub enrolment: Arc<std::sync::Mutex<key::Enrolment>>,
    pub save: Option<std::path::PathBuf>,
    /// This connection's TLS exporter, or `NO_CHANNEL_BINDING` on plain loopback.
    pub exporter: [u8; 32],
}

/// Serves the Core on `ws` until it closes the connection (`Ok`) or refuses the runner, or
/// the connection fails (`Err`); `core_identity_mismatch` when the Core is not the pinned one.
/// Commands still running when it ends are killed.
pub async fn serve<S>(
    ws: WebSocketStream<S>,
    exec: Arc<ExecDriver>,
    link: &Link,
) -> Result<(), StreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut sink, mut source) = ws.split();
    let mut out = Seqs::default();
    let (device, pin) = {
        let e = link.enrolment.lock().unwrap();
        (e.device_id.clone(), e.core_fp.clone())
    };
    let nonce_r = key::random::<32>();
    let hello = Control::Hello(RunnerHello {
        protocol: PROTOCOL_VERSION.to_owned(),
        runner_version: env!("CARGO_PKG_VERSION").to_owned(),
        drivers: vec![exec.info()],
        os: Some(std::env::consts::OS.to_owned()),
        arch: Some(std::env::consts::ARCH.to_owned()),
        device_id: Some(device.clone()),
        nonce: Some(key::b64(&nonce_r)),
    });
    send(
        &mut sink,
        out.frame(CONTROL_STREAM, Body::Control(hello), false),
    )
    .await?;
    let auth = match next_control(&mut source).await? {
        Control::Auth(auth) => auth,
        _ => return Err(StreamError::new(ErrorCode::BadFrame, "expected auth")),
    };
    // Nothing more goes to a Core that is not the pinned one: returning drops the socket.
    let core_spki = check_core(&auth, &pin, &link.exporter, &nonce_r, &device)?;
    let nonce_c = key::unb64(&auth.nonce, 43)
        .ok_or_else(|| StreamError::new(ErrorCode::BadFrame, "auth has no 32-byte nonce"))?;
    let sig = link
        .key
        .sign(&runner_auth_message(&link.exporter, &nonce_c, &pin));
    let proof = Control::Proof(RunnerProof {
        sig: key::b64(&sig),
    });
    send(
        &mut sink,
        out.frame(CONTROL_STREAM, Body::Control(proof), false),
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
            Ok(Some(Body::Control(Control::Rotation(r)))) if stream == CONTROL_STREAM => {
                rotate(link, &r, &core_spki);
                None
            }
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

/// The Core's `auth` checked against the pin and this connection: its SPKI when it holds.
fn check_core(
    auth: &CoreAuth,
    pin: &str,
    exporter: &[u8],
    nonce_r: &[u8],
    device: &str,
) -> Result<Vec<u8>, StreamError> {
    let mismatch = |why: String| {
        tracing::error!(%why, "core_identity_mismatch: refusing this Core");
        StreamError::new(ErrorCode::CoreIdentityMismatch, why)
    };
    let spki = key::unb64(&auth.core_spki, 122).unwrap_or_default();
    let presented = key::fingerprint(&spki);
    if presented != pin {
        return Err(mismatch(format!(
            "pinned Core {pin}, this server presents {presented}"
        )));
    }
    let message = core_auth_message(exporter, nonce_r, device);
    let signed = key::unb64(&auth.sig, 86).is_some_and(|s| key::verify(&spki, &message, &s));
    if !signed {
        return Err(mismatch(format!(
            "the Core {pin} did not sign this connection"
        )));
    }
    Ok(spki)
}

/// Applies a rotation statement and saves the moved pin; anything else is ignored.
fn rotate(link: &Link, r: &ainkrad_proto::v2::Rotation, core_spki: &[u8]) {
    let mut e = link.enrolment.lock().unwrap();
    if !e.rotate(r, core_spki) {
        tracing::warn!("a rotation statement that does not hold was ignored");
        return;
    }
    tracing::info!(
        new_fp = e.core_fp,
        seq = e.rotation_seq,
        "Core identity rotated; pin moved"
    );
    if let Some(path) = &link.save
        && let Err(err) = e.save(path)
    {
        tracing::error!(error = %err, "saving the rotated pin failed");
    }
}

/// The next `control` body on stream 0; the Core's `error` there is a refusal.
async fn next_control<S>(
    source: &mut futures_util::stream::SplitStream<WebSocketStream<S>>,
) -> Result<Control, StreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let text = match source.next().await {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(Message::Close(_))) | None => {
                return Err(StreamError::new(
                    ErrorCode::BadFrame,
                    "closed during the proof",
                ));
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(lost(e)),
        };
        let frame: Frame = serde_json::from_str(&text)
            .map_err(|e| StreamError::new(ErrorCode::BadFrame, e.to_string()))?;
        match frame.body()? {
            Some(Body::Control(c)) if frame.stream_id == CONTROL_STREAM => return Ok(c),
            Some(Body::Error(e)) => return Err(e),
            _ => continue,
        }
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
