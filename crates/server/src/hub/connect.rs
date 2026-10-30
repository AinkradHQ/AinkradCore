//! `GET /runner/v2/connect` (E1-11.2, E1-11.3, handshake spec §13): a pre-auth route that
//! authenticates inside the upgrade, in this order:
//!
//! 1. The shared checks (`gateway::preauth`), then the signed request with a session
//!    (`gate::verify`, §5.3): the same uniform `auth_failed`, limits and lockouts as every
//!    other signed call. Nothing below runs for a stranger.
//! 2. A `runner` device holding the `runner` scope, else 403 `forbidden_scope` (audited).
//! 3. The channel binding: the TLS exporter, or `NO_CHANNEL_BINDING` for a Unix-socket peer
//!    of the Core's own user, or a loopback TCP peer when `serve --allow-plain-runner` is set
//!    (`HubConfig::allow_plain_loopback`, security review RH2); any other plain HTTP is refused
//!    (400). A runner reaching the Core through a TLS-terminating proxy has an exporter the
//!    Core does not share: runners need TLS end to end to the Core.
//! 4. A WebSocket upgrade, else 400.
//! 5. In the socket, within `HubConfig::handshake`: `hello` naming the signed device with a
//!    32-byte nonce, the Core's `auth`, the runner's `proof`. Any failure is the one `error`
//!    `auth_failed`, a 1008 close, a log line with the real reason, and an audit row
//!    (`runner.refused`) for the first of each device and reason per window, the rest only
//!    counted; an unsupported protocol major is `unsupported_version`.
//!
//! Neither nonce, signature nor exporter is ever logged.

use std::net::SocketAddr;

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_proto::runner::protocol_major;
use ainkrad_proto::v2::{
    Body, CONTROL_STREAM, Control, CoreAuth, ErrorCode, Frame, NO_CHANNEL_BINDING,
    PROTOCOL_VERSION, RunnerHello, StreamError, close_code, core_auth_message, runner_auth_message,
};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::api::App;
use crate::api::v1::ApiError;
use crate::api::v1::gate::{self, Mode};
use crate::auth::crypto::{b64, random, unb64, verify};
use crate::gateway::preauth::PREAUTH_BODY;
use crate::gateway::{Exporter, Local};
use crate::store::gov::Device;

/// The route.
pub const PATH: &str = "/runner/v2/connect";

/// The largest WebSocket message a runner may send: an `exec` result holds up to 1 MiB of
/// stdout and of stderr each, base64 inside JSON.
pub const MAX_MESSAGE: usize = 8 << 20;

/// The audit action of a refused, authenticated runner connection.
pub const REFUSED: &str = "runner.refused";

pub async fn connect(State(app): State<App>, req: Request) -> Response {
    let (mut parts, raw) = req.into_parts();
    let addr = gate::address(&app, &parts);
    let v = match gate::verify(&app, &parts, raw, PREAUTH_BODY, &addr, Mode::Session).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let device = v.device;
    if device.kind != "runner" || !device.scopes.iter().any(|s| s == "runner") {
        tracing::warn!(device = device.id, "runner hub refused: not a runner");
        audit_refusal(&app, &device, "not a runner device").await;
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "this device's scopes do not allow that",
        )
        .into_response();
    }
    let binding = match parts.extensions.get::<Exporter>() {
        Some(x) => x.0,
        None if plain_ok(&parts, app.hub.config.allow_plain_loopback) => NO_CHANNEL_BINDING,
        None => {
            tracing::warn!(device = device.id, addr, "runner hub refused: no TLS");
            return ApiError::bad_request("runners connect over TLS").into_response();
        }
    };
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &app).await {
        Ok(ws) => ws,
        Err(_) => return ApiError::bad_request("not a WebSocket upgrade").into_response(),
    };
    // Subscribed before the upgrade, so a revocation in between is not missed.
    let revoked = crate::auth::until_revoked(
        app.live.devices(&app.pool, crate::auth::BACKSTOP),
        app.auth.subscribe(),
        device.id.clone(),
    );
    ws.max_message_size(MAX_MESSAGE)
        .on_upgrade(move |socket| serve(app, socket, device, binding, revoked))
}

/// Plain HTTP only from this host: the Unix socket from the Core's own user, or a loopback
/// TCP peer when `loopback` allows it (RH2).
fn plain_ok(parts: &axum::http::request::Parts, loopback: bool) -> bool {
    match parts.extensions.get::<Local>() {
        Some(local) => local.same_user,
        None => {
            loopback
                && parts
                    .extensions
                    .get::<ConnectInfo<SocketAddr>>()
                    .is_some_and(|ConnectInfo(a)| a.ip().is_loopback())
        }
    }
}

async fn serve(
    app: App,
    mut socket: WebSocket,
    device: Device,
    binding: [u8; 32],
    revoked: impl Future<Output = ()> + Send + 'static,
) {
    let shake = handshake(&app, &mut socket, &device, &binding);
    let hello = match tokio::time::timeout(app.hub.config.handshake, shake).await {
        Ok(Ok(hello)) => hello,
        Ok(Err((code, why))) => return refuse(&app, socket, &device, code, why).await,
        Err(_) => {
            let why = "no proof in time";
            return refuse(&app, socket, &device, ErrorCode::AuthFailed, why).await;
        }
    };
    tracing::info!(
        device = device.id,
        version = hello.runner_version,
        "runner connected"
    );
    super::conn::run(app, socket, device, hello, revoked).await;
}

type Refused = (ErrorCode, &'static str);

/// The exchange of `ainkrad_proto::v2::auth`, Core side.
async fn handshake(
    app: &App,
    socket: &mut WebSocket,
    device: &Device,
    x: &[u8; 32],
) -> Result<RunnerHello, Refused> {
    let fail = |why| (ErrorCode::AuthFailed, why);
    let Control::Hello(hello) = control(socket).await? else {
        return Err(fail("the first frame is not hello"));
    };
    if protocol_major(&hello.protocol) != protocol_major(PROTOCOL_VERSION) {
        return Err((ErrorCode::UnsupportedVersion, "unsupported protocol major"));
    }
    if hello.device_id.as_deref() != Some(device.id.as_str()) {
        return Err(fail("hello names another device"));
    }
    let nonce_r = hello
        .nonce
        .as_deref()
        .and_then(|n| unb64(n, 43))
        .ok_or(fail("hello has no 32-byte nonce"))?;
    let nonce_c = random::<32>();
    let identity = &app.auth.identity;
    let sig = identity.sign(&core_auth_message(x, &nonce_r, &device.id));
    let auth = Control::Auth(CoreAuth {
        core_spki: b64(&identity.spki),
        nonce: b64(&nonce_c),
        sig: b64(&sig),
    });
    send(socket, Frame::new(CONTROL_STREAM, 0, Body::Control(auth)))
        .await
        .map_err(|()| fail("the runner went"))?;
    let Control::Proof(proof) = control(socket).await? else {
        return Err(fail("the second frame is not proof"));
    };
    let message = runner_auth_message(x, &nonce_c, &identity.fp);
    let ok = unb64(&proof.sig, 86).is_some_and(|s| verify(&device.routine_spki, &message, &s));
    if !ok {
        return Err(fail("bad runner proof"));
    }
    Ok(hello)
}

/// The next text frame as a `control` body on stream 0.
async fn control(socket: &mut WebSocket) -> Result<Control, Refused> {
    let fail = |why| (ErrorCode::AuthFailed, why);
    loop {
        let text = match socket.recv().await {
            Some(Ok(Message::Text(t))) => t,
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            _ => return Err(fail("closed or not text during the handshake")),
        };
        let frame: Frame = serde_json::from_str(&text).map_err(|_| fail("not a frame"))?;
        return match frame.body() {
            Ok(Some(Body::Control(c))) if frame.stream_id == CONTROL_STREAM => Ok(c),
            _ => Err(fail("not a control frame on stream 0")),
        };
    }
}

pub(super) async fn send(socket: &mut WebSocket, frame: Frame) -> Result<(), ()> {
    let text = serde_json::to_string(&frame).expect("a frame serializes");
    socket.send(Message::Text(text.into())).await.map_err(drop)
}

/// The one refusal: `error` with a constant message per code, then a 1008 close.
async fn refuse(app: &App, mut socket: WebSocket, device: &Device, code: ErrorCode, why: &str) {
    tracing::warn!(device = device.id, why, "runner connection refused");
    audit_refusal(app, device, why).await;
    let message = match code {
        ErrorCode::UnsupportedVersion => "unsupported protocol version",
        _ => "authentication failed",
    };
    let frame = Frame::new(
        CONTROL_STREAM,
        1,
        Body::Error(StreamError::new(code, message)),
    );
    let _ = send(&mut socket, frame).await;
    let close = Message::Close(Some(CloseFrame {
        code: close_code::POLICY,
        reason: message.into(),
    }));
    let _ = socket.send(close).await;
}

/// One audit row per authenticated device and reason per window (`auth::refusals`): the first
/// refusal is audited, the repeats only counted, so a runner that retries cannot grow the
/// audit log (review M4). Strangers are never audited; the gate's limits count them.
async fn audit_refusal(app: &App, device: &Device, why: &str) {
    let key = format!("{REFUSED}:{}:{why}", device.id);
    if !app.auth.refusals.note(&key, app.clock.unix()) {
        return;
    }
    let event = NewAuditEvent {
        actor: AuditActor::System,
        action: REFUSED.to_owned(),
        entity: Some(AuditEntity {
            kind: "device".to_owned(),
            id: device.seq,
        }),
        details: json!({"device_id": device.id, "reason": why}).to_string(),
    };
    if let Err(e) = crate::store::audit::append_one(&app.pool, &event).await {
        tracing::error!(error = %e, "auditing a runner refusal failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(ext: impl FnOnce(&mut axum::http::Extensions)) -> axum::http::request::Parts {
        let (mut parts, ()) = axum::http::Request::new(()).into_parts();
        ext(&mut parts.extensions);
        parts
    }

    /// Security review RH2: plain text from loopback TCP only behind the flag; from the Unix
    /// socket only for the Core's own user; never from anywhere else.
    #[test]
    fn plain_http_only_from_this_host_and_loopback_only_by_flag() {
        let at = |ip: &'static str| {
            move |e: &mut axum::http::Extensions| {
                e.insert(ConnectInfo(SocketAddr::new(ip.parse().unwrap(), 1)));
            }
        };
        for ip in ["127.0.0.1", "::1"] {
            assert!(plain_ok(&parts(at(ip)), true));
            assert!(!plain_ok(&parts(at(ip)), false), "{ip} without the flag");
        }
        let local = |same_user| {
            move |e: &mut axum::http::Extensions| {
                e.insert(Local { same_user });
            }
        };
        for flag in [false, true] {
            assert!(plain_ok(&parts(local(true)), flag));
            assert!(!plain_ok(&parts(local(false)), flag), "another user");
            assert!(!plain_ok(&parts(at("10.0.0.1")), flag));
            assert!(!plain_ok(&parts(at("2001:db8::1")), flag));
            assert!(!plain_ok(&parts(|_| {}), flag));
        }
    }
}
