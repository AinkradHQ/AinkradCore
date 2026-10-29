//! The live event stream with replay (E10.2, decision #14). One sequence (`store::events`)
//! covers every audited change (`audit`) and whatever kinds the modules write. Two ways to
//! read it, same `Event` schema:
//!
//! - `GET /api/v1/events?after=<seq>&limit=<n>`: a page, oldest first (HTTP replay).
//! - `GET /api/v1/events/ws`: a WebSocket. The resume point is the `Last-Event-ID` header on
//!   the upgrade request (never the URL): events after it are replayed, then new ones stream
//!   live. Without it the socket starts at the newest event (live only); `0` replays all.
//!   Each text frame is one `Event`. The server pings every `heartbeat` and closes a socket
//!   it has not heard from in three (1001). A client that does not keep up — a send blocked
//!   for `send_timeout` — is closed with code 1013 and `…, at most <seq>`: the last frame
//!   the server tried to send (it may or may not have arrived). The hint is best effort (a
//!   stuck socket may never deliver it); a client always resumes from the last seq it read.
//!   The server holds at most one page per socket, never a growing buffer.
//!
//! Retention (E1-04.4): events older than `events.retention_secs` are trimmed, and the newest
//! trimmed seq is the floor. A resume point below it gets a defined answer instead of a silent
//! gap: the HTTP replay a 410 `PastRetention` (code `past_retention`, the `floor`); the socket
//! closes with 4410 and `past retention, floor <seq>`. The client then re-syncs: it reads
//! `GET /api/v1/events/latest`, reloads the state it shows from the resource routes, and
//! resumes from that `seq`.
//!
//! Paperclip's UI polled and its socket only invalidated caches, with no replay; here the
//! app polls nothing and misses nothing across a disconnect.

use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

use super::types::{Page, Timestamp, ts};
use super::{ApiError, ApiResult, Paging, trace};
use crate::api::App;
use crate::store::events::{self, MAX_EVENTS, StoredEvent};

/// One entry of the event stream. `seq` only grows: it is the replay cursor. New kinds may be
/// added: a client skips an event whose kind it does not know.
#[derive(Debug, Serialize, ToSchema, schemars::JsonSchema)]
pub struct Event {
    pub seq: i64,
    pub at: Timestamp,
    /// What happened: `audit` (an audited change; the payload is the audit row: `audit_seq`,
    /// `action`, `actor_kind`, `actor_id`, `entity_kind`, `entity_id`, `details`), or a kind a
    /// module writes. The registered kinds are listed in `x-event-kinds`.
    pub kind: String,
    #[schema(value_type = Object)]
    pub payload: Value,
}

impl From<StoredEvent> for Event {
    fn from(e: StoredEvent) -> Self {
        Self {
            seq: e.seq,
            at: ts(&e.at),
            kind: e.kind,
            payload: e.payload.0,
        }
    }
}

#[utoipa::path(get, path = "/api/v1/events", operation_id = "listEvents", tag = "events",
    params(Paging),
    responses((status = 200, description = "Events after `after` (default 0), oldest first, \
        at most `limit` (default and most 1000); the same events the WebSocket carries", body = Page<Event>),
        (status = 410, description = "`after` is below the retention floor: some events after it \
        were trimmed. Re-sync from `GET /api/v1/events/latest`", body = PastRetention)))]
pub async fn replay(State(app): State<App>, Query(page): Query<Paging>) -> Response {
    let limit = page.limit.unwrap_or(MAX_EVENTS).clamp(1, MAX_EVENTS - 1);
    match events::replay(&app.pool, page.after.unwrap_or(0), limit + 1).await {
        Ok(Ok(got)) => {
            let got = got.into_iter().map(Event::from).collect();
            Json(Page::of(got, limit, |e| e.seq)).into_response()
        }
        Ok(Err(past)) => PastRetention::new(past.floor).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

/// The 410 of a replay from below the retention floor (E1-04.4).
#[derive(Debug, Serialize, ToSchema)]
pub struct PastRetention {
    /// `past_retention`.
    pub code: String,
    pub message: String,
    pub error_id: String,
    /// The newest trimmed seq: every event above it is still there.
    pub floor: i64,
}

impl PastRetention {
    fn new(floor: i64) -> Self {
        Self {
            code: "past_retention".to_owned(),
            message: format!(
                "events up to {floor} were trimmed; re-sync from /api/v1/events/latest"
            ),
            error_id: trace::error_id(),
            floor,
        }
    }
}

impl IntoResponse for PastRetention {
    fn into_response(self) -> Response {
        tracing::info!(
            floor = self.floor,
            error_id = self.error_id,
            "replay past retention"
        );
        (StatusCode::GONE, Json(self)).into_response()
    }
}

/// The newest event's seq a client would be shown: the catch-up target.
#[derive(Debug, Serialize, ToSchema, schemars::JsonSchema)]
pub struct LatestEvent {
    /// 0 when there is none yet.
    pub seq: i64,
    /// The retention floor: events up to it were trimmed, so a client whose last read seq is
    /// below it re-syncs (E1-04.4). Absent from servers before API minor 2.
    pub floor: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/events/latest", operation_id = "latestEvent",
    tag = "events",
    responses((status = 200, description = "The newest event's seq: how far a catching-up \
        client has to go, and where a client past retention resumes after re-syncing", body = LatestEvent)))]
pub async fn latest(State(app): State<App>) -> ApiResult<LatestEvent> {
    Ok(Json(LatestEvent {
        seq: events::last_event_seq(&app.pool).await?,
        floor: Some(events::floor(&app.pool).await?),
    }))
}

/// How the socket paces itself.
#[derive(Debug, Clone, Copy)]
pub struct StreamConfig {
    /// How often a caught-up socket looks for new events.
    pub poll: Duration,
    /// Ping interval; a socket silent for three is closed.
    pub heartbeat: Duration,
    /// How long one frame may wait on a slow client before it is closed.
    pub send_timeout: Duration,
    /// Events read (and held) at a time.
    pub page: u32,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            // ponytail: each socket polls the table; a broadcast from the writers if many
            // clients ever make that cost show.
            poll: Duration::from_millis(250),
            heartbeat: Duration::from_secs(20),
            send_timeout: Duration::from_secs(10),
            page: 200,
        }
    }
}

/// The resume point of the upgrade request: `Last-Event-ID`, when present.
fn last_event_id(headers: &HeaderMap) -> Result<Option<i64>, ApiError> {
    let Some(v) = headers.get("last-event-id") else {
        return Ok(None);
    };
    v.to_str()
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .map(Some)
        .ok_or_else(|| ApiError::bad_request("Last-Event-ID is an event seq"))
}

#[utoipa::path(get, path = "/api/v1/events/ws", operation_id = "streamEvents", tag = "events",
    params(("Last-Event-ID" = Option<i64>, Header,
        description = "Replay events after this seq first; absent: only new events")),
    responses((status = 101, description = "Switching to a WebSocket. Each text frame is one \
        `Event` (schema `Event`). Closed with 1013 when the client falls behind (a send blocked too long), \
        with the reason `too slow; resume from the last seq read, at most <seq>`: `<seq>` is \
        the last event the server tried to send. The hint is best effort; the client \
        reconnects with `Last-Event-ID` set to the last seq it actually read. Also closed \
        with 1001 (no pong), 1011 (server error), 4001 (the device was revoked) and 4003 (its \
        scopes changed: reconnect), with the same hint; with 4410 and \
        `past retention, floor <seq>` when the resume point is below the retention floor \
        (re-sync from `/api/v1/events/latest`)")))]
pub async fn ws(
    State(app): State<App>,
    Extension(me): Extension<super::Caller>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let after = match last_event_id(&headers) {
        Ok(Some(after)) => after,
        Ok(None) => match events::last_event_seq(&app.pool).await {
            Ok(head) => head,
            Err(e) => return ApiError::from(e).into_response(),
        },
        Err(e) => return e.into_response(),
    };
    // Subscribed before the upgrade, so a revocation or scope change in between is not missed.
    let revoked = crate::auth::until_revoked(
        app.pool.clone(),
        app.auth.subscribe(),
        me.device.id.clone(),
        crate::auth::BACKSTOP,
    );
    let rescoped = crate::auth::until_rescoped(
        app.pool.clone(),
        app.auth.subscribe_rescoped(),
        me.device.id,
        me.device.scopes,
        crate::auth::BACKSTOP,
    );
    let changed = async move {
        tokio::select! {
            () = revoked => End::Revoked,
            () = rescoped => End::Rescoped,
        }
    };
    ws.on_upgrade(move |socket| stream(app, socket, after, changed))
}

/// Why a socket ended, for the log.
enum End {
    Gone,
    Slow,
    Silent,
    Failed,
    /// The server is stopping.
    Restart,
    /// The resume point is below the retention floor.
    Past(i64),
    /// The device was revoked (handshake spec §10).
    Revoked,
    /// The device's scopes changed: it reconnects for a re-filtered stream (§10).
    Rescoped,
}

/// Sends every event after `after`, then new ones as they land, until the client goes, falls
/// behind or goes silent.
async fn stream(
    app: App,
    mut socket: WebSocket,
    mut after: i64,
    changed: impl std::future::Future<Output = End>,
) {
    tokio::pin!(changed);
    let cfg = app.stream;
    let mut poll = tokio::time::interval(cfg.poll);
    let mut ping = tokio::time::interval(cfg.heartbeat);
    ping.reset();
    let mut heard = Instant::now();
    let mut closing = app.closing.subscribe();
    let end = 'live: loop {
        // Catch up page by page; only one page is ever held.
        loop {
            let page = match events::replay(&app.pool, after, cfg.page).await {
                Ok(Ok(page)) => page,
                Ok(Err(past)) => break 'live End::Past(past.floor),
                Err(e) => {
                    tracing::error!(error = %e, "event stream read failed");
                    break 'live End::Failed;
                }
            };
            let full = page.len() == cfg.page as usize;
            for e in page {
                let seq = e.seq;
                let text = serde_json::to_string(&Event::from(e)).unwrap_or_default();
                match tokio::time::timeout(
                    cfg.send_timeout,
                    socket.send(Message::Text(text.into())),
                )
                .await
                {
                    Ok(Ok(())) => (after, heard) = (seq, Instant::now()),
                    Ok(Err(_)) => break 'live End::Gone,
                    // The frame may still go out: the hint counts it as sent.
                    Err(_) => {
                        after = seq;
                        break 'live End::Slow;
                    }
                }
            }
            if !full {
                break;
            }
        }
        tokio::select! {
            () = crate::api::stopping(&mut closing) => break End::Restart,
            end = &mut changed => break end,
            _ = poll.tick() => {}
            _ = ping.tick() => {
                if heard.elapsed() > cfg.heartbeat * 3 {
                    break End::Silent;
                }
                let sent = tokio::time::timeout(cfg.send_timeout, socket.send(Message::Ping(Default::default())));
                match sent.await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => break End::Gone,
                    Err(_) => break End::Slow,
                }
            }
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break End::Gone,
                Some(Ok(_)) => heard = Instant::now(),
            },
        }
    };
    let hint = format!("resume from the last seq read, at most {after}");
    let (code, why) = match end {
        End::Gone => return,
        End::Slow => (1013, format!("too slow; {hint}")),
        End::Silent => (1001, format!("no pong; {hint}")),
        End::Failed => (1011, format!("server error; {hint}")),
        End::Restart => (1012, format!("server restarting; {hint}")),
        End::Past(floor) => (
            4410,
            format!("past retention, floor {floor}; re-sync from /api/v1/events/latest"),
        ),
        End::Revoked => (4001, format!("revoked; {hint}")),
        End::Rescoped => (4003, format!("scope changed; {hint}")),
    };
    tracing::info!(code, why, "event stream closed");
    let close = Message::Close(Some(CloseFrame {
        code,
        reason: why.into(),
    }));
    // The client may be why the socket is stuck: try briefly, then wait briefly for its
    // close reply (so a reader gets the frame before the connection drops), then drop it.
    let closing = async {
        if socket.send(close).await.is_ok() {
            while let Some(Ok(msg)) = socket.recv().await {
                if matches!(msg, Message::Close(_)) {
                    break;
                }
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(2), closing).await;
}
