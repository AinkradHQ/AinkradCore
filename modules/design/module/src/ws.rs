//! The sync socket: `GET /modules/design/v1/docs/{doc}/sync`. Security model: see `sync.rs`; this file is the wire.
//!
//! Frames. Binary, one tag byte first:
//!   client -> server  `01` + update bytes (yrs v1)
//!   server -> client  `01` + seq (u64 BE) + update   an update, live or replayed from the cursor
//!                     `02` + seq (u64 BE) + state    the whole document (no cursor, or it is no longer in the log)
//!                     `03` + seq (u64 BE)            the client's update is stored (acknowledged after the commit).
//!                                                    A durability receipt, NOT a resume cursor: other peers' updates
//!                                                    with a lower seq may still be queued for this socket. The cursor is
//!                                                    the highest seq of an `01`/`02` frame the client has applied.
//! Text frames are presence, JSON both ways: the client sends `{"cursor":[x,y]?,"selection":[ids]?,"view":[x,y,w,h]?}` (view = the visible world rect, for follow mode), everyone else
//! receives it stamped `{"peer":"person:d_...","conn":n,...}` (or `{"conn":n,"gone":true}`).
//! Resume: the `Last-Update-Seq` header on the upgrade, the last seq the client applied. Without it, or when it is
//! older than the compacted log or newer than the head, the client is sent a snapshot first. The client sends its
//! own unsent updates as `01` frames after connecting; applying a repeat is harmless.
//! Close codes: 1008 protocol violation, 1009 too large / document full, 1011 server error, 1013 too slow (resume
//! from the last seq), 4001 revoked, 4003 scopes changed, 4409 archived, 4412 resync needed (the update depends on state the Core lacks: reconnect without a cursor), 4429 too many updates, 1001 server stopping.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, Caller};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use design_doc::MAX_PEER_UPDATE_BYTES;
use design_model::ids::is_node_id;
use design_model::limits::MAX_COORD;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;

use crate::sync::{BYTE_RATE, Backlog, Lease, OpenError, Out, PRESENCE_RATE, Refusal, Registry};

const HEARTBEAT: Duration = Duration::from_secs(20);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PRESENCE_BYTES: usize = 4096;
const MAX_SELECTION: usize = 256;

pub(crate) fn doc_id_ok(s: &str) -> bool {
    s.len() == 19 && s.starts_with("dd_") && s[3..].bytes().all(|c| c.is_ascii_hexdigit())
}

/// A token bucket: `rate` per second, a burst of `rate * 2`.
struct Bucket {
    tokens: f64,
    rate: f64,
    at: Instant,
}

impl Bucket {
    fn new(rate: f64) -> Self {
        Self {
            tokens: rate * 2.0,
            rate,
            at: Instant::now(),
        }
    }
    fn take(&mut self, cost: f64) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * self.rate)
            .min(self.rate * 2.0);
        self.at = now;
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresenceIn {
    cursor: Option<[f64; 2]>,
    selection: Option<Vec<String>>,
    view: Option<[f64; 4]>,
}

/// A presence message re-made from validated fields only, stamped with who sent it.
fn presence(text: &str, origin: &str, conn: u64) -> Option<String> {
    if text.len() > MAX_PRESENCE_BYTES {
        return None;
    }
    let p: PresenceIn = serde_json::from_str(text).ok()?;
    if p.cursor
        .is_some_and(|c| c.iter().any(|v| !v.is_finite() || v.abs() > MAX_COORD))
    {
        return None;
    }
    if p.view.is_some_and(|v| {
        v.iter().any(|n| !n.is_finite() || n.abs() > MAX_COORD) || v[2] <= 0.0 || v[3] <= 0.0
    }) {
        return None;
    }
    let sel = p.selection.unwrap_or_default();
    if sel.len() > MAX_SELECTION || sel.iter().any(|s| !is_node_id(s)) {
        return None;
    }
    Some(
        json!({"peer": origin, "conn": conn, "cursor": p.cursor, "selection": sel, "view": p.view})
            .to_string(),
    )
}

fn frame(tag: u8, seq: i64, body: &[u8]) -> Message {
    let mut v = Vec::with_capacity(9 + body.len());
    v.push(tag);
    v.extend_from_slice(&(seq as u64).to_be_bytes());
    v.extend_from_slice(body);
    Message::Binary(v.into())
}

fn close(code: u16, reason: &str) -> Message {
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.to_owned().into(),
    }))
}

fn cursor(h: &HeaderMap) -> Result<Option<i64>, ApiError> {
    let Some(v) = h.get("last-update-seq") else {
        return Ok(None);
    };
    v.to_str()
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .map(Some)
        .ok_or_else(|| ApiError::bad_request("Last-Update-Seq is an update seq"))
}

/// Which close a refusal is.
fn refusal_close(r: &Refusal) -> Message {
    match r {
        Refusal::Violation(design_doc::Refused::TooLarge) => close(1009, "update too large"),
        Refusal::Violation(e) => close(1008, &e.to_string().chars().take(100).collect::<String>()),
        Refusal::DocFull => close(1009, "document full"),
        Refusal::Resync => close(4412, "resync needed"),
        Refusal::Archived => close(4409, "design archived"),
        Refusal::Store => close(1011, "server error"),
    }
}

#[utoipa::path(get, path = "/docs/{doc}/sync", operation_id = "designSyncDoc", tag = "design",
    params(("doc" = String, Path, description = "Design id"),
        ("Last-Update-Seq" = Option<i64>, Header, description = "The last update seq this client applied; absent or out of the log: a snapshot first")),
    responses((status = 101, description = "A WebSocket: the live document of a `design` or `system` doc (binary frames `01` update, `02` snapshot, `03` ack, a durability receipt that is not a resume cursor: resume from the highest `01`/`02` seq applied; text frames are presence JSON). Every update is validated before it is stored or relayed; a refused one closes the socket (1008, 1009 too large, 4429 rate). Also 1013 (too slow: resume from the last seq), 4001 (revoked), 4003 (scopes changed), 4409 (archived), 4412 (the update depends on state the Core lacks: reconnect without a cursor and resend)"),
        (status = 404, description = "No such design, or a mockup (no live document)"),
        (status = 429, description = "This device already holds the most sockets it may"),
        (status = 503, description = "Too many designs are open and none is idle"),
        (status = 409, description = "The design is archived")))]
pub(crate) async fn sync(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Extension(reg): Extension<Arc<Registry>>,
    Path(doc): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let none = || ApiError::not_found("no such design").into_response();
    if !doc_id_ok(&doc) {
        return none();
    }
    let after = match cursor(&headers) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    match sqlx::query_as::<_, (String, String)>("SELECT kind, state FROM design_docs WHERE id = ?")
        .bind(&doc)
        .fetch_optional(&app.pool)
        .await
    {
        Ok(None) => return none(),
        Ok(Some((k, _))) if k == "mockup" => return none(),
        Ok(Some((_, s))) if s != "active" => {
            return ApiError::conflict("the design is archived").into_response();
        }
        Ok(Some(_)) => {}
        Err(e) => return ApiError::from(e).into_response(),
    }
    // Subscribed before the upgrade, so a revocation in between is not missed (as the event socket does).
    let revoked = ainkrad_core_server::auth::until_revoked(
        app.live.devices(&app.pool, app.stream.backstop),
        app.auth.subscribe(),
        me.device.id.clone(),
    );
    let rescoped = ainkrad_core_server::auth::until_rescoped(
        app.live.devices(&app.pool, app.stream.backstop),
        app.auth.subscribe_rescoped(),
        me.device.id.clone(),
        me.device.scopes.clone(),
    );
    use ainkrad_core_server::auth::{DeviceNow, device_now};
    match device_now(&app.pool, &me.device.id, Some(&me.device.scopes)).await {
        DeviceNow::Usable => {}
        DeviceNow::Gone => {
            return ApiError::new(
                StatusCode::UNAUTHORIZED,
                "auth_failed",
                "authentication failed",
            )
            .into_response();
        }
        DeviceNow::Unknown => {
            return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "try again")
                .into_response();
        }
    }
    let lease = match reg.open(&app.pool, &doc, &me.device.id).await {
        Ok(l) => l,
        Err(OpenError::Device) => {
            return ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_sockets",
                "this device has too many open designs",
            )
            .into_response();
        }
        Err(OpenError::Busy) => {
            return ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "too many designs are open, try again",
            )
            .into_response();
        }
        Err(OpenError::Store(e)) => return ApiError::from(e).into_response(),
    };
    let origin = format!("person:{}", me.device.id);
    let ended = async move {
        tokio::select! {
            () = revoked => 4001,
            () = rescoped => 4003,
        }
    };
    ws.max_message_size(MAX_PEER_UPDATE_BYTES + 16)
        .max_frame_size(MAX_PEER_UPDATE_BYTES + 16)
        .on_upgrade(move |socket| session(app, socket, lease, origin, after, ended))
}

async fn send(socket: &mut WebSocket, m: Message) -> bool {
    matches!(
        tokio::time::timeout(SEND_TIMEOUT, socket.send(m)).await,
        Ok(Ok(()))
    )
}

async fn session(
    app: App,
    mut socket: WebSocket,
    lease: Lease,
    origin: String,
    after: Option<i64>,
    ended: impl std::future::Future<Output = u16>,
) {
    tokio::pin!(ended);
    let end = run(&app, &mut socket, &lease, &origin, after, &mut ended).await;
    if let Some(m) = end {
        let _ = send(&mut socket, m).await;
    }
    // `lease` drops here: presence removed, peer counted out.
}

/// Runs the socket; the close to send, if any.
async fn run(
    app: &App,
    socket: &mut WebSocket,
    lease: &Lease,
    origin: &str,
    after: Option<i64>,
    ended: &mut (impl std::future::Future<Output = u16> + Unpin),
) -> Option<Message> {
    let actor = &lease.actor;
    let conn = lease.conn;
    let joined = match actor.join(after).await {
        Ok(j) => j,
        Err(_) => return Some(close(1011, "server error")),
    };
    let mut rx = joined.rx;
    match joined.backlog {
        Backlog::Snapshot(s) => {
            if !send(socket, frame(2, joined.head, &s)).await {
                return None;
            }
        }
        Backlog::Updates(list) => {
            for (seq, data) in list {
                if !send(socket, frame(1, seq, &data)).await {
                    return None;
                }
            }
        }
    }
    for p in joined.presence {
        if !send(socket, Message::Text(p.as_str().into())).await {
            return None;
        }
    }
    let (mut updates, mut bytes, mut pres) = (
        Bucket::new(lease.rate()),
        Bucket::new(BYTE_RATE),
        Bucket::new(PRESENCE_RATE),
    );
    let mut closing = app.closing.subscribe();
    let mut ping = tokio::time::interval(HEARTBEAT);
    ping.reset();
    let mut heard = Instant::now();
    loop {
        tokio::select! {
            _ = closing.changed() => return Some(close(1001, "server stopping")),
            code = &mut *ended => return Some(close(code, if code == 4001 { "device revoked" } else { "scopes changed" })),
            _ = ping.tick() => {
                if heard.elapsed() > HEARTBEAT * 3 {
                    return Some(close(1001, "silent"));
                }
                if !send(socket, Message::Ping(Default::default())).await {
                    return None;
                }
            }
            got = rx.recv() => match got {
                Ok(Out::Update { seq, from, bytes }) if from != conn => {
                    if !send(socket, frame(1, seq, &bytes)).await { return None; }
                }
                Ok(Out::Presence { from, json }) if from != conn => {
                    if !send(socket, Message::Text(json.as_str().into())).await { return None; }
                }
                Ok(Out::Left { conn: c }) if c != conn => {
                    let m = json!({"conn": c, "gone": true}).to_string();
                    if !send(socket, Message::Text(m.into())).await { return None; }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(_)) => return Some(close(1013, "too slow; resume from the last seq read")),
                Err(RecvError::Closed) => return Some(close(1011, "server error")),
            },
            msg = socket.recv() => {
                heard = Instant::now();
                match msg {
                    None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return None,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(Message::Binary(b))) => {
                        let Some((&1, update)) = b.split_first() else {
                            return Some(close(1008, "unknown frame"));
                        };
                        if !updates.take(1.0) || !bytes.take(update.len() as f64) {
                            return Some(close(4429, "too many updates"));
                        }
                        match actor.submit(conn, origin, update).await {
                            Ok(seq) => if !send(socket, frame(3, seq, &[])).await { return None; },
                            Err(r) => return Some(refusal_close(&r)),
                        }
                    }
                    Some(Ok(Message::Text(t))) => {
                        // Over the rate: dropped, not a violation (a cursor moves faster than the cap).
                        if pres.take(1.0) {
                            match presence(t.as_str(), origin, conn) {
                                Some(p) => actor.set_presence(conn, Arc::new(p)),
                                None => return Some(close(1008, "bad presence")),
                            }
                        }
                    }
                }
            }
        }
    }
}
