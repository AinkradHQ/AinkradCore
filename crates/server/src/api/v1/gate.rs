//! The signed-request gate (handshake spec §5.3), in the spec's order:
//!
//! 1. Host, Origin, Authorization, a canonical path, the query names (`api::refusal`), and the
//!    body size (413).
//! 2. The six `Ainkrad-*` headers in their exact formats (400 `bad_request`); with no
//!    `Ainkrad-Device` at all, the plain 401 `auth_failed` of an unsigned request.
//! 3. The address's lockout, and the (address, claimed device)'s (429).
//! 4. The clock: `|now − timestamp| ≤ 60 s`, else 401 `clock_skew` with `server_time`. No
//!    device is looked up yet, so this leaks nothing.
//! 5. The device. Unknown, revoked, pending or locked: a dummy verify against a key nobody
//!    holds, so every refusal costs the same, then fail.
//! 6. ES256 over the canonical bytes with the device's routine key.
//! 7. `(device, nonce)` into the replay cache, only after the signature verified, so a stranger
//!    cannot burn another device's nonces.
//! 8. The session: live and the device's, else 401 `session_expired` (only reached with a valid
//!    signature, so it leaks nothing).
//! 9. The route's declared scope (`scopes`, deny by default) → 403 `forbidden_scope`; step-up
//!    comes with E1-09.3.
//! 10. The device's request bucket (429).
//!
//! Steps 5 to 7 fail with the identical 401 `auth_failed`, take at least `FAIL_FLOOR`, and
//! count against the address and the (address, claimed device) in the store (§11); nothing
//! says whether the device exists.
//! The log carries the real reason, never a signature, nonce or key.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::{ApiError, Caller, Client, query_ok, too_many};
use crate::api::{App, limit, refusal};
use crate::auth::signed::{self, Canonical};
use crate::auth::{Replay, SKEW, Session, crypto};
use crate::store::gov::{self, ADDRESS, ADDRESS_DEVICE, Device};

/// The largest body a signed request may carry (the gateway's own cap is the same).
pub const SIGNED_BODY: usize = 1024 * 1024;

/// The least time a refusal at steps 5 to 7 takes (§14: timing equalised). Far above the
/// lookup and verify differences it hides, and it slows a guesser too.
// ponytail: a fixed floor; a store slower than this leaks its own jitter, never the reason.
pub const FAIL_FLOOR: std::time::Duration = std::time::Duration::from_millis(50);

/// A refusal, ready to send (boxed: a `Response` is large).
pub type Refusal = Box<Response>;

/// What the call carries: a session (every `/api/v1` route) or none (`/handshake/session`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Session,
    NoSession,
}

/// The one answer for steps 5 to 7, whatever the reason.
pub fn auth_failed() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "auth_failed",
        "authentication failed",
    )
}

/// The limiter key of the request's address: `ip:<v4>`, `ip:<v6 /64>`, or `ip:local` on the
/// Unix socket. `X-Forwarded-For` counts only from a configured trusted proxy (none by default).
pub fn address(app: &App, req: &Parts) -> String {
    let Some(ConnectInfo(peer)) = req.extensions.get::<ConnectInfo<SocketAddr>>() else {
        return "ip:local".to_owned();
    };
    let xff = req.headers.get_all("x-forwarded-for").iter();
    let xff = xff.filter_map(|v| v.to_str().ok());
    match limit::client_ip(peer.ip(), xff, &app.trusted_proxies) {
        IpAddr::V4(ip) => format!("ip:{ip}"),
        IpAddr::V6(ip) => {
            let s = ip.segments();
            format!("ip:{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

fn locked(until: i64, now: i64) -> Response {
    too_many(std::time::Duration::from_secs((until - now).max(1) as u64))
}

/// Steps 2 to 10 for a request whose shared checks passed and whose body was read: the device
/// and, in `Mode::Session`, its session.
/// The verified device and session, and the body, which is read only once steps 2 to 4
/// passed (at most `limit` bytes, else 413), so an unsigned, locked or skewed request never
/// makes the server buffer it.
pub struct Verified {
    pub device: Device,
    pub session: Option<Session>,
    pub body: Bytes,
}

pub async fn verify(
    app: &App,
    parts: &Parts,
    raw: Body,
    limit: usize,
    addr: &str,
    mode: Mode,
) -> Result<Verified, Refusal> {
    // Unsigned altogether: the plain 401 every unknown path also gets (spec §4), so routes
    // cannot be told apart. Not counted: it names no device and proves nothing.
    if !parts.headers.contains_key(signed::DEVICE) {
        tracing::debug!(addr, "unsigned request refused");
        return Err(auth_failed().into_response().into());
    }
    let h = signed::parse(&parts.headers, mode == Mode::Session)
        .map_err(|why| ApiError::bad_request(why).into_response())?;
    let now = app.clock.unix();
    let ipdev = format!("ipdev:{addr}:{}", h.device);
    if let Some(until) = gov::locked_until(&app.pool, &[addr, &ipdev], now)
        .await
        .map_err(|e| ApiError::from(e).into_response())?
    {
        tracing::warn!(
            addr,
            device = h.device,
            "signed request refused: locked out"
        );
        return Err(locked(until, now).into());
    }
    if (now - h.timestamp).abs() > SKEW {
        let mut e = ApiError::new(
            StatusCode::UNAUTHORIZED,
            "clock_skew",
            "the request's timestamp is too far from the server's clock",
        );
        e.server_time = Some(now);
        return Err(e.into_response().into());
    }
    let started = tokio::time::Instant::now();
    let device = gov::get_device(&app.pool, &h.device)
        .await
        .map_err(|e| ApiError::from(e).into_response())?;
    // Only a usable device's request may carry the full body; anything else is held to the
    // pre-auth 16 KiB before it is hashed (review L1).
    let usable = device.as_ref().is_some_and(Device::usable);
    // Every device's body is held to the same `limit`, and one past it is the same refusal
    // whoever claims to send it (review N5). Only a usable device's body is kept; any other is
    // read and dropped as it arrives, so it costs no memory and answers no sooner (review L1).
    let (bytes, oversize) = if usable {
        match body(raw, limit).await {
            Ok(b) => (b, false),
            Err(_) => (Bytes::new(), true),
        }
    } else {
        drain(raw, limit).await;
        (Bytes::new(), false)
    };
    let body: &[u8] = &bytes;
    let message = Canonical {
        core_fp: &app.auth.identity.fp,
        device: &h.device,
        session: h.session.as_deref(),
        method: parts.method.as_str(),
        path: parts.uri.path(),
        query: parts.uri.query().unwrap_or(""),
        timestamp: h.timestamp,
        nonce: &h.nonce,
        body,
    }
    .bytes();
    let refused = match &device {
        Some(_) if oversize => {
            crypto::dummy_verify(&message, &h.signature);
            Some("body too large")
        }
        Some(d) if usable => {
            if !crypto::verify(&d.routine_spki, &message, &h.signature) {
                Some("bad signature")
            } else {
                match app.auth.take_nonce(&d.id, &h.nonce, now) {
                    Ok(()) => None,
                    Err(Replay::Seen) => Some("replayed nonce"),
                    Err(Replay::Full) => {
                        tracing::warn!(device = d.id, "replay cache full");
                        return Err(too_many(std::time::Duration::from_secs(5)).into());
                    }
                }
            }
        }
        other => {
            crypto::dummy_verify(&message, &h.signature);
            Some(match other {
                None => "unknown device",
                Some(_) => "device not usable",
            })
        }
    };
    if let Some(why) = refused {
        let refusal = fail(app, addr, &ipdev, &h.device, why, now).await;
        // Every refusal at steps 5 to 7 takes at least `FAIL_FLOOR` from the lookup on, so its
        // time says nothing about whether the device exists or why it failed.
        tokio::time::sleep_until(started + FAIL_FLOOR).await;
        return Err(refusal.into());
    }
    let device = device.expect("verified above");
    let session = match (&h.session, mode) {
        (Some(id), Mode::Session) => match app.auth.session(id, &device.id, now) {
            Some(s) => Some(s),
            None => {
                return Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "session_expired",
                    "the session is gone or expired; run the challenge again",
                )
                .into_response()
                .into());
            }
        },
        _ => None,
    };
    if let Err(wait) = app.limits.requests.take(&device.id, Instant::now()) {
        return Err(too_many(wait).into());
    }
    gov::mark_used(
        &app.pool,
        &device.id,
        device.last_used_at.as_deref(),
        &app.clock.now(),
    )
    .await
    .map_err(|e| ApiError::from(e).into_response())?;
    Ok(Verified {
        device,
        session,
        body: bytes,
    })
}

/// An authentication failure: counted against the address and the (address, claimed device),
/// logged with its real reason, answered as the one `auth_failed`.
pub async fn fail(
    app: &App,
    addr: &str,
    ipdev: &str,
    device: &str,
    why: &'static str,
    now: i64,
) -> Response {
    tracing::warn!(addr, device, why, "signed request refused");
    // Counted in memory first, in one critical section: past the address's budget a refusal
    // is a cheap 429 that writes nothing, however many arrive at once (review M2).
    if !app.auth.failures.count(addr, now) {
        return too_many(std::time::Duration::from_secs(ADDRESS.lock as u64));
    }
    for (key, rule) in [(addr, ADDRESS), (ipdev, ADDRESS_DEVICE)] {
        if let Err(e) = gov::record_failure(&app.pool, key, rule, now).await {
            return ApiError::from(e).into_response();
        }
    }
    auth_failed().into_response()
}

/// Reads and drops a body up to `limit` bytes without keeping it.
async fn drain(mut raw: Body, limit: usize) {
    use axum::body::HttpBody;
    let mut seen = 0;
    while seen <= limit {
        let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut raw).poll_frame(cx)).await;
        match frame {
            Some(Ok(f)) => seen += f.data_ref().map_or(0, |d| d.len()),
            _ => break,
        }
    }
}

/// Reads the whole body, up to `limit`; a larger one is a 413.
pub async fn body(body: Body, limit: usize) -> Result<Bytes, Refusal> {
    to_bytes(body, limit)
        .await
        .map_err(|_| Box::new(crate::gateway::preauth::too_large()))
}

/// The gate every route but the pre-auth ones passes. It runs before routing, as the outer
/// layer `gateway::preauth::gate`, so an unknown path without a valid signature is the same 401
/// as a known one.
pub(crate) async fn client_gate(State(app): State<App>, req: Request, next: Next) -> Response {
    if let Some((status, code, why)) = refusal(&app, req.uri(), req.headers(), query_ok) {
        tracing::warn!(%status, why, "client request refused");
        return ApiError::new(status, code, why).into_response();
    }
    let (mut parts, raw) = req.into_parts();
    let addr = address(&app, &parts);
    let v = match verify(&app, &parts, raw, SIGNED_BODY, &addr, Mode::Session).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    // Deny by default: the route's declared scope, or nothing (`scopes`).
    let need = super::scopes::required(&parts.method, parts.uri.path(), &app.modules);
    if !need.is_some_and(|s| v.device.scopes.iter().any(|d| d == s)) {
        tracing::warn!(device = v.device.id, need, "scope refused");
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "this device's scopes do not allow that",
        )
        .into_response();
    }
    let session = v.session.expect("Mode::Session has one").id;
    parts.extensions.insert(Caller {
        device: v.device,
        session,
    });
    parts.extensions.insert(Client(addr));
    next.run(Request::from_parts(parts, Body::from(v.body)))
        .await
}
