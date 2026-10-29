//! The live event stream with replay (E10.2, decision #14). One sequence (`store::events`)
//! covers every audited change (issue and run states, approvals, …), transcript chunks and
//! wakes. Two ways to read it, same `Event` schema:
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
//! Paperclip's UI polled and its socket only invalidated caches, with no replay; here the
//! app polls nothing and misses nothing across a disconnect.

use std::time::{Duration, Instant};

use ainkrad_core::audit::AuditActor;
use axum::Extension;
use axum::Json;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

use super::model::TranscriptChunk;
use super::scope::Acting;
use super::types::{Page, Timestamp, WakeSource, ts};
use super::{ApiError, ApiResult, Paging};
use crate::api::App;
use crate::store::events::{self, MAX_EVENTS, StoredEvent, What};

/// Who acted, on an audited change.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventActor {
    User { user_id: i64 },
    Agent { agent_id: i64 },
    Runner { runner_id: i64 },
    System {},
}

impl From<AuditActor> for EventActor {
    fn from(actor: AuditActor) -> Self {
        match actor {
            AuditActor::User(u) => Self::User { user_id: u.0 },
            AuditActor::Agent(a) => Self::Agent { agent_id: a.0 },
            AuditActor::Runner(r) => Self::Runner { runner_id: r.0 },
            AuditActor::System => Self::System {},
        }
    }
}

/// What happened. New types may be added: a client skips an event it cannot decode.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventPayload {
    /// An audited change: `action` is dotted (`issue.in_review`, `run.failed`,
    /// `approval.approved`, …) and names the `entity` it happened to.
    Audit {
        audit_seq: i64,
        action: String,
        actor: EventActor,
        entity_kind: Option<String>,
        entity_id: Option<i64>,
        company_id: Option<i64>,
        run_id: Option<i64>,
        #[schema(value_type = Object)]
        details: Value,
    },
    /// A chunk of a run's transcript.
    Transcript { run_id: i64, chunk: TranscriptChunk },
    /// A wake queued for an agent.
    Wake {
        wake_id: i64,
        agent_id: i64,
        issue_id: Option<i64>,
        source: WakeSource,
        reason: String,
    },
}

/// One entry of the event stream. `seq` only grows: it is the replay cursor.
#[derive(Debug, Serialize, ToSchema)]
pub struct Event {
    pub seq: i64,
    pub at: Timestamp,
    pub payload: EventPayload,
}

impl From<StoredEvent> for Event {
    fn from(e: StoredEvent) -> Self {
        let payload = match e.what {
            What::Audit {
                audit_seq,
                action,
                actor,
                entity,
                company_id,
                run_id,
                details,
            } => EventPayload::Audit {
                audit_seq,
                action,
                actor: actor.into(),
                entity_kind: entity.as_ref().map(|(k, _)| k.clone()),
                entity_id: entity.map(|(_, id)| id),
                company_id,
                run_id,
                details,
            },
            What::Transcript {
                run_id,
                seq,
                at,
                kind,
                payload,
            } => EventPayload::Transcript {
                run_id,
                chunk: TranscriptChunk {
                    seq,
                    at: ts(&at),
                    kind,
                    payload,
                },
            },
            What::Wake {
                wake_id,
                agent_id,
                issue_id,
                source,
                reason,
            } => EventPayload::Wake {
                wake_id,
                agent_id,
                issue_id,
                source: source.into(),
                reason,
            },
        };
        Self {
            seq: e.seq,
            at: ts(&e.at),
            payload,
        }
    }
}

#[utoipa::path(get, path = "/api/v1/events", operation_id = "listEvents", tag = "events",
    params(Paging),
    responses((status = 200, description = "Events after `after` (default 0), oldest first, \
        at most `limit` (default and most 1000); the same events the WebSocket carries", body = Page<Event>)))]
pub async fn replay(
    State(app): State<App>,
    Extension(acting): Extension<Acting>,
    Query(page): Query<Paging>,
) -> ApiResult<Page<Event>> {
    let limit = page.limit.unwrap_or(MAX_EVENTS).clamp(1, MAX_EVENTS - 1);
    let mut got = events::list_events(&app.pool, page.after.unwrap_or(0), limit + 1).await?;
    let more = got.len() > limit as usize;
    got.truncate(limit as usize);
    // The cursor moves past what a company does not see, so paging never stalls on it.
    let next_after = more.then(|| got.last().map(|e| e.seq)).flatten();
    let mut items = vec![];
    for e in got {
        if visible(&app, acting, &e).await? {
            items.push(e.into());
        }
    }
    Ok(Json(Page { items, next_after }))
}

/// The newest event's seq a client would be shown: the catch-up target.
#[derive(Debug, Serialize, ToSchema)]
pub struct LatestEvent {
    /// 0 when there is none yet.
    pub seq: i64,
}

#[utoipa::path(get, path = "/api/v1/events/latest", operation_id = "latestEvent",
    tag = "events",
    responses((status = 200, description = "The newest event's seq, of the acting company's \
        events when `X-Citadel-Company` is sent: how far a catching-up client has to go", body = LatestEvent)))]
pub async fn latest(
    State(app): State<App>,
    Extension(acting): Extension<Acting>,
) -> ApiResult<LatestEvent> {
    Ok(Json(LatestEvent {
        seq: latest_seq(&app, acting).await?,
    }))
}

/// The newest seq of an event `acting` sees.
pub async fn latest_seq(app: &App, acting: Acting) -> Result<i64, sqlx::Error> {
    match acting.0 {
        Some(c) => events::last_company_event_seq(&app.pool, c.0).await,
        None => events::last_event_seq(&app.pool).await,
    }
}

/// Whether `e` belongs to the company a request works in (E15.14): an audited change of it, a
/// transcript chunk of its run, a wake of its agent; anything when it names none.
async fn visible(app: &App, acting: Acting, e: &StoredEvent) -> Result<bool, sqlx::Error> {
    if acting.0.is_none() {
        return Ok(true);
    }
    let company: Option<i64> = match &e.what {
        What::Audit { company_id, .. } => *company_id,
        What::Transcript { run_id, .. } => {
            let sql = "SELECT a.company_id FROM runs r JOIN agents a ON a.id = r.agent_id \
                       WHERE r.id = ?";
            sqlx::query_scalar(sql)
                .bind(run_id)
                .fetch_optional(&app.pool)
                .await?
        }
        What::Wake { agent_id, .. } => {
            let sql = "SELECT company_id FROM agents WHERE id = ?";
            sqlx::query_scalar(sql)
                .bind(agent_id)
                .fetch_optional(&app.pool)
                .await?
        }
    };
    Ok(acting.sees(company))
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
        with 1001 (no pong) and 1011 (server error), with the same hint")))]
pub async fn ws(
    State(app): State<App>,
    Extension(acting): Extension<Acting>,
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
    ws.on_upgrade(move |socket| stream(app, acting, socket, after))
}

/// Why a socket ended, for the log.
enum End {
    Gone,
    Slow,
    Silent,
    Failed,
    /// The server is stopping.
    Restart,
}

/// Sends every event after `after`, then new ones as they land, until the client goes, falls
/// behind or goes silent.
async fn stream(app: App, acting: Acting, mut socket: WebSocket, mut after: i64) {
    let cfg = app.stream;
    let mut poll = tokio::time::interval(cfg.poll);
    let mut ping = tokio::time::interval(cfg.heartbeat);
    ping.reset();
    let mut heard = Instant::now();
    let mut closing = app.closing.subscribe();
    let end = 'live: loop {
        // Catch up page by page; only one page is ever held.
        loop {
            let page = match events::list_events(&app.pool, after, cfg.page).await {
                Ok(page) => page,
                Err(e) => {
                    tracing::error!(error = %e, "event stream read failed");
                    break 'live End::Failed;
                }
            };
            let full = page.len() == cfg.page as usize;
            for e in page {
                let seq = e.seq;
                match visible(&app, acting, &e).await {
                    Ok(true) => {}
                    Ok(false) => {
                        after = seq;
                        continue;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "event stream read failed");
                        break 'live End::Failed;
                    }
                }
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
    let (code, why) = match end {
        End::Gone => return,
        End::Slow => (1013, "too slow"),
        End::Silent => (1001, "no pong"),
        End::Failed => (1011, "server error"),
        End::Restart => (1012, "server restarting"),
    };
    let why = format!("{why}; resume from the last seq read, at most {after}");
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
