//! The event socket for browsers (handshake spec §10, E1-08.5; the store is `auth::ticket`):
//! `POST /api/v1/ws-ticket`, a signed request, gives the session a one-time ticket, and
//! `GET /api/v1/events/ws` takes it in `Sec-WebSocket-Protocol: ainkrad.v1,
//! ainkrad-ticket.<ticket>` in place of a signature. The server answers `ainkrad.v1`.
//!
//! Redemption runs in the gate, before routing: the ticket is spent on lookup, then its session
//! must still be live and its device re-read from the store and still usable (a revocation since
//! issue fails it), and the route's scope is checked as for any request. An unknown, used,
//! expired or dead-session ticket is the one `auth_failed`, counted against the address, no
//! sooner than `gate::FAIL_FLOOR`. A ticket is good for the event socket only.

use axum::Json;
use axum::extract::{Extension, State};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

use super::gate::{self, Refusal, Verified};
use super::{ApiError, Caller, too_many};
use crate::api::App;
use crate::auth::ticket::TICKET_SECS;
use crate::store::gov;

/// The path a ticket opens, and the only one.
pub const WS_PATH: &str = "/api/v1/events/ws";
/// The subprotocol a ticket travels in, before the ticket itself.
pub const PREFIX: &str = "ainkrad-ticket.";
/// The subprotocol the server answers.
pub const PROTOCOL: &str = "ainkrad.v1";

#[derive(Debug, Serialize, ToSchema)]
pub struct WsTicket {
    /// 16 random bytes, base64url: offer `ainkrad.v1, ainkrad-ticket.<ticket>` as the
    /// WebSocket subprotocols of `GET /api/v1/events/ws`. Good once.
    pub ticket: Option<String>,
    pub expires_in: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/ws-ticket", operation_id = "createWsTicket", tag = "events",
    responses((status = 200, description = "A one-time ticket for this session's event socket, \
        live 30 s, for browsers, which cannot sign an upgrade. At most four live per session (a \
        new one replaces the oldest); 429 past ten at once, then one every 6 s", body = WsTicket)))]
pub async fn issue(State(app): State<App>, Extension(me): Extension<Caller>) -> Response {
    if let Err(wait) = app
        .auth
        .ticket_limit
        .take(&me.session, std::time::Instant::now())
    {
        return too_many(wait);
    }
    match app
        .auth
        .issue_ticket(&me.device.id, &me.session, app.clock.unix())
    {
        Some(t) => Json(WsTicket {
            ticket: Some(t),
            expires_in: Some(TICKET_SECS),
        })
        .into_response(),
        None => {
            ApiError::new(StatusCode::UNAUTHORIZED, "session_expired", "no session").into_response()
        }
    }
}

/// The ticket an unsigned event-socket upgrade offers, if that is what this request is.
pub fn offered(parts: &Parts) -> Option<String> {
    if parts.method != Method::GET
        || parts.uri.path() != WS_PATH
        || parts.headers.contains_key(crate::auth::signed::DEVICE)
    {
        return None;
    }
    parts
        .headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .find_map(|p| p.trim().strip_prefix(PREFIX).map(str::to_owned))
}

/// Spends `ticket` for the device and session it was issued to.
pub async fn redeem(app: &App, ticket: &str, addr: &str) -> Result<Verified, Refusal> {
    let now = app.clock.unix();
    if let Some(until) = gov::locked_until(&app.pool, &[addr], now)
        .await
        .map_err(|e| ApiError::from(e).into_response())?
    {
        return Err(too_many(std::time::Duration::from_secs((until - now).max(1) as u64)).into());
    }
    let started = tokio::time::Instant::now();
    let refused = |why: &'static str| async move {
        let ipdev = format!("ipdev:{addr}:ticket");
        let r = gate::fail(app, addr, &ipdev, "-", why, now).await;
        tokio::time::sleep_until(started + gate::FAIL_FLOOR).await;
        Err(r.into())
    };
    let Some((device, session)) = app.auth.take_ticket(ticket, now) else {
        return refused("unknown, used or expired ticket").await;
    };
    match gov::get_device(&app.pool, &device).await {
        Ok(Some(d)) if d.usable() => Ok(Verified {
            device: d,
            session: Some(session),
            body: Default::default(),
        }),
        Ok(_) => refused("ticket of a device no longer usable").await,
        Err(e) => Err(ApiError::from(e).into_response().into()),
    }
}
