//! The runner's side of protocol v2 (E1-11.1, E1-11.5) on one connected WebSocket.
//!
//! `serve` sends `hello` with the drivers (only `exec` for now) and waits for `welcome`, then
//! answers each `command` on its own stream with one `result` or `error`; a `close` from the
//! Core cancels that command. Commands run concurrently, up to each driver's capacity.
//!
//! Before any command, the connection proof (`ainkrad_proto::v2::auth`, handshake spec §13):
//! the hello carries the device id and a nonce; the Core's `auth` must come from the pinned
//! identity and sign this connection's exporter, or the runner closes and sends nothing more;
//! then the runner's own `proof`. A `rotation` from the Core announces its next key, accepted
//! beside the pin until the Core proves it, which moves the pin (`Enrolment::rotate`).
//! `client` and `pair` are the HTTP side. A [`Session`] outlives connections: the daemon
//! (`daemon`) reconnects with backoff and resumes its streams by `seq` (E1-11.4).

use std::sync::Arc;

use ainkrad_proto::runner::protocol_major;
use ainkrad_proto::v2::{
    Body, CONTROL_STREAM, Control, CoreAuth, CoreWelcome, ErrorCode, Frame, PROTOCOL_VERSION,
    RunnerHello, RunnerProof, StreamError, core_auth_message, runner_auth_message,
};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

pub mod cli;
pub mod client;
pub mod daemon;
pub mod dial;
mod exec;
pub mod key;
pub mod pair;
pub mod pty;
mod session;
pub use exec::{ExecConfig, ExecDriver};
pub use pty::{PtyConfig, PtyDriver};
pub use session::Session;

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

/// Serves the Core on `ws` with a fresh [`Session`] until the connection ends: the Core's
/// close code (`Ok`), or why it failed or refused (`Err`; `core_identity_mismatch` when the
/// Core is not the pinned one). Commands still running when it ends are killed.
pub async fn serve<S>(
    ws: WebSocketStream<S>,
    exec: Arc<ExecDriver>,
    link: &Link,
) -> Result<Option<u16>, StreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    Session::new(exec).serve(ws, link).await
}

/// The connection proof, runner side: `hello` (with what `session` holds), the Core's `auth`
/// checked against the pin, our `proof`, then the Core's `welcome`. Returns the welcome and
/// the Core's SPKI.
async fn handshake<S>(
    sink: &mut futures_util::stream::SplitSink<WebSocketStream<S>, Message>,
    source: &mut futures_util::stream::SplitStream<WebSocketStream<S>>,
    link: &Link,
    hello: RunnerHello,
) -> Result<(CoreWelcome, Vec<u8>), StreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (device, pins) = {
        let e = link.enrolment.lock().unwrap();
        (e.device_id.clone(), e.clone())
    };
    let nonce_r = key::random::<32>();
    let hello = Control::Hello(RunnerHello {
        protocol: PROTOCOL_VERSION.to_owned(),
        runner_version: env!("CARGO_PKG_VERSION").to_owned(),
        os: Some(std::env::consts::OS.to_owned()),
        arch: Some(std::env::consts::ARCH.to_owned()),
        device_id: Some(device.clone()),
        nonce: Some(key::b64(&nonce_r)),
        ..hello
    });
    send(sink, Frame::new(CONTROL_STREAM, 0, Body::Control(hello))).await?;
    let auth = match next_control(source).await? {
        Control::Auth(auth) => auth,
        _ => return Err(StreamError::new(ErrorCode::BadFrame, "expected auth")),
    };
    // Nothing more goes to a Core that is not the pinned one: returning drops the socket.
    let core_spki = check_core(&auth, &pins, &link.exporter, &nonce_r, &device)?;
    // The fingerprint the Core proved: the pin, or the announced next key, which now becomes
    // the pin.
    let pin = key::fingerprint(&core_spki);
    {
        let mut e = link.enrolment.lock().unwrap();
        if e.proven(&pin) {
            tracing::info!(core_fp = pin, "the Core proved its rotated key; pin moved");
            save(link, &e);
        }
    }
    let nonce_c = key::unb64(&auth.nonce, 43)
        .ok_or_else(|| StreamError::new(ErrorCode::BadFrame, "auth has no 32-byte nonce"))?;
    let sig = link
        .key
        .sign(&runner_auth_message(&link.exporter, &nonce_c, &pin));
    let proof = Control::Proof(RunnerProof {
        sig: key::b64(&sig),
    });
    send(sink, Frame::new(CONTROL_STREAM, 1, Body::Control(proof))).await?;
    Ok((welcome(source).await?, core_spki))
}

/// The Core's `auth` checked against the pins (`Enrolment::accepts`) and this connection: its
/// SPKI when it holds.
fn check_core(
    auth: &CoreAuth,
    pins: &key::Enrolment,
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
    let pin = &pins.core_fp;
    if !pins.accepts(&presented) {
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

/// Applies a rotation statement and saves the announced key; the Core re-sends the statement
/// on every connection of its window, so one already recorded is skipped quietly. Anything
/// else is ignored.
fn rotate(link: &Link, r: &ainkrad_proto::v2::Rotation, core_spki: &[u8]) {
    let mut e = link.enrolment.lock().unwrap();
    if e.next_fp.as_deref() == Some(r.new_fp.as_str()) && e.rotation_seq == r.seq {
        return;
    }
    if !e.rotate(r, core_spki) {
        tracing::warn!("a rotation statement that does not hold was ignored");
        return;
    }
    tracing::info!(
        next_fp = r.new_fp,
        not_before = r.not_before,
        seq = e.rotation_seq,
        "Core identity rotation announced; the new key is accepted beside the pin"
    );
    save(link, &e);
}

/// Saves the enrolment where `link` says, if anywhere.
fn save(link: &Link, e: &key::Enrolment) {
    if let Some(path) = &link.save
        && let Err(err) = e.save(path)
    {
        tracing::error!(error = %err, "saving the enrolment failed");
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
) -> Result<CoreWelcome, StreamError>
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
                    Ok(w)
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

#[cfg(test)]
mod tests;
