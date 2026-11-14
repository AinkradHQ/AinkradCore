//! The Brain as AI sessions see it through Code Mode (plan E4): read operations over the rooms a
//! session may see (`access::visible_rooms`, plan D3) and `brain.propose`, which drops a candidate
//! into a room's Inbox and nothing else. These routes answer only the Code Mode dispatcher's
//! synthetic caller (its session is `code_mode:<id>`); a person has the room routes.
//!
//! Every text a third party wrote (source titles and snippets, record bodies, tags) leaves inside
//! the fixed `ainkrad_core::untrusted` envelope, one per item, so a script sees data and the model
//! sees the notice. A room the session cannot see is the same 404 as an unknown id. Only
//! `accepted` records are returned: candidates and rejected ones never leave the Inbox.

use ainkrad_core::untrusted::wrap;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::begin_write;
use ainkrad_proto::redact::Redactor;
use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use utoipa::{IntoParams, ToSchema};

use crate::access::{Visible, visible_room, visible_rooms};
use crate::answer::KINDS;
use crate::distil::log_op;
use crate::inbox::open_room;
use crate::index::{fts, words};
use crate::rooms::RoomAccess;
use crate::{Brain, code, rand_id, record};

/// The marker in `records.distil` of a candidate an AI session proposed: `ai:<session id>`.
pub(crate) const PROPOSED: &str = "ai:";
const SESSION: &str = "code_mode:";
const DEFAULT_LIMIT: u32 = 10;
const MAX_LIMIT: u32 = 25;
const MAX_BODY: usize = 2000;
/// A list shows this much of a record; `brain.record` has all of it.
pub(crate) const LIST_BODY: usize = 400;
/// Candidates one session may propose into one room.
/// ponytail: per room file, not a session-wide counter; a control-plane table if that is needed.
const PROPOSE_CAP: i64 = 20;
/// Rooms one search reads.
const MAX_ROOMS: usize = 20;

/// The session behind a Code Mode call.
fn session_of(me: &Caller) -> Result<String, ApiError> {
    me.session
        .strip_prefix(SESSION)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            code(
                403,
                "session_only",
                "this route answers AI sessions; use the room routes",
            )
        })
}

/// `room` when the session may see it; else the 404 of an unknown id (audited once per window).
async fn room_of(app: &App, session: &str, room: &str) -> Result<Visible, ApiError> {
    if let Some(v) = visible_room(app, session, room).await? {
        return Ok(v);
    }
    if app
        .auth
        .refusals
        .note(&format!("brain_ai {session}"), app.clock.unix())
    {
        let mut tx = begin_write(&app.pool).await?;
        record(
            &mut tx,
            "brain.ai.refused",
            json!({"session": session, "room": room.chars().take(64).collect::<String>(),
                "project": ainkrad_core_server::ops_catalog::session_project(&app.pool, session).await}),
            None,
        )
        .await?;
        tx.commit().await?;
    }
    Err(ApiError::not_found("no such room"))
}

/// The rooms a call reads: the named one (visible or 404), else every visible room.
async fn scope(app: &App, session: &str, room: Option<&str>) -> Result<Vec<Visible>, ApiError> {
    match room {
        Some(r) => Ok(vec![room_of(app, session, r).await?]),
        None => Ok(visible_rooms(app, session)
            .await?
            .into_iter()
            .take(MAX_ROOMS)
            .collect()),
    }
}

/// The open file of each room that is open; how many were not (a closed lease, or unreadable).
async fn open_all(
    app: &App,
    b: &Brain,
    rooms: Vec<Visible>,
    named: bool,
) -> Result<(Vec<(Visible, RoomAccess)>, usize), ApiError> {
    if named {
        let v = rooms.into_iter().next().expect("one named room");
        let a = open_room(app, b, &v.id).await?;
        return Ok((vec![(v, a)], 0));
    }
    let key = b.key(app).await?;
    let (mut open, mut closed) = (vec![], 0);
    for v in rooms {
        match b.rooms().access(app, &key, &v.id).await {
            Ok(a) => open.push((v, a)),
            Err(_) => closed += 1,
        }
    }
    Ok((open, closed))
}

#[derive(Serialize, ToSchema)]
pub struct AiRoom {
    pub id: String,
    pub name: String,
    pub kind: String,
    /// Whether the room's lease is live: only an open room can be searched or read.
    pub open: bool,
}

#[utoipa::path(get, path = "/ai/rooms", operation_id = "brainAiRooms", tag = "brain",
    responses((status = 200, description = "The rooms this AI session may see (its project's, or ones the room's access list names), within each room's model policy", body = Vec<AiRoom>)))]
pub(crate) async fn rooms(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
) -> ApiResult<Vec<AiRoom>> {
    let session = session_of(&me)?;
    let now = app.clock.unix();
    Ok(Json(
        visible_rooms(&app, &session)
            .await?
            .into_iter()
            .map(|v| AiRoom {
                open: b.rooms().is_open(&v.id, now),
                id: v.id,
                name: v.name,
                kind: v.kind,
            })
            .collect(),
    ))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AiSearchQuery {
    /// Words to find; all must appear.
    pub q: String,
    /// One room to search; none searches every visible, open room.
    pub room: Option<String>,
    /// At most this many hits (default 10, most 25).
    pub limit: Option<u32>,
    /// `auto` (default: keywords and meaning when the local model is on), `keyword` or `meaning`
    /// (meaning only; keywords when the model is off or slow).
    pub mode: Option<String>,
}

#[derive(Clone, Serialize, ToSchema)]
pub struct AiHit {
    pub room: String,
    /// `record` (an accepted record, listed first) or `source`.
    pub kind: String,
    /// The record id, or the source's item id.
    pub id: String,
    pub started_at: String,
    /// The match, inside the outside-text envelope.
    pub text: String,
}

#[derive(Serialize, ToSchema)]
pub struct AiHits {
    pub hits: Vec<AiHit>,
    pub rooms_searched: usize,
    /// Visible rooms that were closed and so not searched.
    pub rooms_closed: usize,
    /// `keyword`, `meaning` or `both`: how these hits were ranked.
    pub ranked_by: String,
}

pub(crate) fn cut(s: &str, n: usize) -> (String, bool) {
    let t = s.trim();
    if t.chars().count() <= n {
        return (t.to_owned(), false);
    }
    (format!("{}…", t.chars().take(n).collect::<String>()), true)
}

#[utoipa::path(get, path = "/ai/search", operation_id = "brainAiSearch", tag = "brain",
    params(AiSearchQuery),
    responses((status = 200, description = "Hits across the rooms this AI session may see: accepted records first, then sources best first. Every text is wrapped as outside data.", body = AiHits)))]
pub(crate) async fn search(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Query(q): Query<AiSearchQuery>,
) -> ApiResult<AiHits> {
    let session = session_of(&me)?;
    let mode = q.mode.as_deref().unwrap_or("auto");
    if !["auto", "keyword", "meaning"].contains(&mode) {
        return Err(ApiError::bad_request("mode is auto, keyword or meaning"));
    }
    let ws = words(&q.q);
    if ws.is_empty() {
        return Err(ApiError::bad_request("q needs at least one word"));
    }
    let expr = ws
        .iter()
        .map(|w| format!("\"{w}\""))
        .collect::<Vec<_>>()
        .join(" ");
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let named = q.room.is_some();
    let rooms = scope(&app, &session, q.room.as_deref()).await?;
    let (open, closed) = open_all(&app, &b, rooms, named).await?;
    let key = b.key(&app).await?;
    let (mut recs, mut srcs) = (vec![], vec![]);
    for (v, a) in &open {
        let cond = vec!["body LIKE ?"; ws.len()].join(" AND ");
        let sql = format!(
            "SELECT id, type, body, tags, source_ids, created_at FROM records WHERE status = 'accepted' AND {cond} \
             ORDER BY created_at DESC, id LIMIT {limit}"
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
        for w in &ws {
            query = query.bind(format!("%{w}%"));
        }
        for r in query.fetch_all(a.pool()).await? {
            recs.push((
                r.try_get::<String, _>("created_at")?,
                record_of(&v.id, &r, LIST_BODY)?,
            ));
        }
        for (rank, h) in fts(&app, &key, a, limit, &expr).await? {
            srcs.push((
                rank,
                AiHit {
                    room: v.id.clone(),
                    kind: "source".to_owned(),
                    text: wrap(&format!("source {} | {}", h.item_id, h.title), &h.snippet),
                    id: h.item_id,
                    started_at: h.started_at,
                },
            ));
        }
    }
    let meaning = if mode == "keyword" {
        None
    } else {
        crate::ai_semantic::rank(&app, &b, &q.q, &open, limit as usize).await
    };
    for (_, a) in &open {
        a.pool().close().await;
    }
    if let (Some(m), "meaning") = (&meaning, mode) {
        return Ok(Json(AiHits {
            hits: m.clone(),
            rooms_searched: open.len(),
            rooms_closed: closed,
            ranked_by: "meaning".to_owned(),
        }));
    }
    recs.sort_by(|x, y| y.0.cmp(&x.0));
    srcs.sort_by(|x, y| x.0.total_cmp(&y.0));
    let mut hits: Vec<AiHit> = recs
        .into_iter()
        .take(limit.div_ceil(2) as usize)
        .map(|(at, r)| AiHit {
            room: r.room,
            kind: "record".to_owned(),
            id: r.id,
            started_at: at,
            text: r.text,
        })
        .collect();
    hits.extend(srcs.into_iter().map(|(_, h)| h));
    hits.truncate(limit as usize);
    let ranked_by = if meaning.is_some() { "both" } else { "keyword" };
    if let Some(m) = meaning {
        hits = crate::ai_semantic::fuse(hits, m, limit as usize);
    }
    Ok(Json(AiHits {
        hits,
        rooms_searched: open.len(),
        rooms_closed: closed,
        ranked_by: ranked_by.to_owned(),
    }))
}

#[derive(Serialize, ToSchema)]
pub struct AiRecord {
    pub id: String,
    pub room: String,
    #[serde(rename = "type")]
    #[schema(rename = "type")]
    pub kind: String,
    pub created_at: String,
    /// Item ids of the sources it came from.
    pub sources: Vec<String>,
    /// Its tags and body, inside the outside-text envelope; a list cuts a long body.
    pub text: String,
    pub truncated: bool,
}

pub(crate) fn record_of(
    room: &str,
    r: &sqlx::sqlite::SqliteRow,
    max_body: usize,
) -> Result<AiRecord, sqlx::Error> {
    let id: String = r.try_get("id")?;
    let kind: String = r.try_get("type")?;
    let tags: Vec<String> =
        serde_json::from_str(&r.try_get::<String, _>("tags")?).unwrap_or_default();
    let (body, truncated) = cut(&r.try_get::<String, _>("body")?, max_body);
    let text = if tags.is_empty() {
        body
    } else {
        format!("tags: {}\n{body}", tags.join(", "))
    };
    Ok(AiRecord {
        text: wrap(&format!("record {id} ({kind})"), &text),
        sources: r
            .try_get::<Option<String>, _>("source_ids")
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        room: room.to_owned(),
        created_at: r.try_get("created_at")?,
        kind,
        id,
        truncated,
    })
}

#[utoipa::path(get, path = "/ai/rooms/{room}/records/{id}", operation_id = "brainAiRecord", tag = "brain",
    params(("room" = String, Path, description = "Room id"), ("id" = String, Path, description = "Record id")),
    responses((status = 200, description = "One accepted record of a room this AI session may see, whole, as outside data; a candidate or rejected one is a 404", body = AiRecord)))]
pub(crate) async fn one(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path((room, id)): Path<(String, String)>,
) -> ApiResult<AiRecord> {
    let session = session_of(&me)?;
    let v = room_of(&app, &session, &room).await?;
    let a = open_room(&app, &b, &v.id).await?;
    let row = sqlx::query("SELECT * FROM records WHERE id = ? AND status = 'accepted'")
        .bind(&id)
        .fetch_optional(a.pool())
        .await?;
    a.pool().close().await;
    let row = row.ok_or_else(|| ApiError::not_found("no such record"))?;
    Ok(Json(record_of(&v.id, &row, MAX_BODY)?))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// One room; none reads every visible, open room.
    pub room: Option<String>,
    /// At most this many (default 10, most 25).
    pub limit: Option<u32>,
}

#[derive(Serialize, ToSchema)]
pub struct AiRecords {
    pub records: Vec<AiRecord>,
    /// Visible rooms that were closed and so not read.
    pub rooms_closed: usize,
}

/// Accepted records of `kinds`, newest first, across the rooms the call reads.
async fn list(
    app: &App,
    b: &Brain,
    me: &Caller,
    q: ListQuery,
    kinds: &[&str],
) -> ApiResult<AiRecords> {
    let session = session_of(me)?;
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let named = q.room.is_some();
    let rooms = scope(app, &session, q.room.as_deref()).await?;
    let (open, closed) = open_all(app, b, rooms, named).await?;
    let marks = vec!["?"; kinds.len()].join(",");
    let sql = format!(
        "SELECT * FROM records WHERE status = 'accepted' AND type IN ({marks}) \
         ORDER BY created_at DESC, id LIMIT {limit}"
    );
    let mut all = vec![];
    for (v, a) in &open {
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.clone()));
        for k in kinds {
            query = query.bind(*k);
        }
        for r in query.fetch_all(a.pool()).await? {
            all.push(record_of(&v.id, &r, LIST_BODY)?);
        }
        a.pool().close().await;
    }
    all.sort_by(|x, y| y.created_at.cmp(&x.created_at).then(x.id.cmp(&y.id)));
    all.truncate(limit as usize);
    Ok(Json(AiRecords {
        records: all,
        rooms_closed: closed,
    }))
}

#[utoipa::path(get, path = "/ai/decisions", operation_id = "brainAiDecisions", tag = "brain",
    params(ListQuery),
    responses((status = 200, description = "Accepted decisions of the rooms this AI session may see, newest first, as outside data", body = AiRecords)))]
pub(crate) async fn decisions(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Query(q): Query<ListQuery>,
) -> ApiResult<AiRecords> {
    list(&app, &b, &me, q, &["decision"]).await
}

#[utoipa::path(get, path = "/ai/project-state", operation_id = "brainAiProjectState", tag = "brain",
    params(ListQuery),
    responses((status = 200, description = "Accepted project-state records, tasks (open threads) and rules (landmines) of the rooms this AI session may see, newest first, as outside data", body = AiRecords)))]
pub(crate) async fn project_state(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Query(q): Query<ListQuery>,
) -> ApiResult<AiRecords> {
    list(&app, &b, &me, q, &["project-state", "task", "rule"]).await
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Propose {
    /// `decision`, `fact`, `preference`, `rule`, `project-state`, `task` or `summary`.
    #[serde(rename = "type")]
    #[schema(rename = "type")]
    pub kind: String,
    /// One self-contained statement, 1 to 2000 characters.
    pub body: String,
    /// At most 8 tags of 1 to 40 characters.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Item ids of sources in the same room (at most 20).
    #[serde(default)]
    pub sources: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Proposed {
    pub room: String,
    pub id: String,
    /// Always `candidate`: a person decides in the Inbox.
    pub status: String,
    /// The same statement was already in the room: nothing was added.
    pub duplicate: bool,
}

#[utoipa::path(post, path = "/ai/rooms/{room}/propose", operation_id = "brainAiPropose", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    request_body = Propose,
    responses((status = 200, description = "The proposal waits in the room's Inbox as a candidate (never accepted automatically; a repeat of the same statement is `duplicate`; 20 per session per room)", body = Proposed)))]
pub(crate) async fn propose(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path(room): Path<String>,
    Json(req): Json<Propose>,
) -> ApiResult<Proposed> {
    let session = session_of(&me)?;
    let body = Redactor::new().text(req.body.trim());
    let ok = KINDS.contains(&req.kind.as_str())
        && (1..=MAX_BODY).contains(&body.chars().count())
        && req.tags.len() <= 8
        && req
            .tags
            .iter()
            .all(|t| (1..=40).contains(&t.chars().count()))
        && req.sources.len() <= 20;
    if !ok {
        return Err(ApiError::bad_request(
            "a known type, a body of 1 to 2000 characters, at most 8 tags of 1 to 40 and 20 sources",
        ));
    }
    let v = room_of(&app, &session, &room).await?;
    let a = open_room(&app, &b, &v.id).await?;
    // The room's file closes on every path: a pool left open holds a rolled-back read.
    let done = land(&app, &a, &session, &req, &body).await;
    a.pool().close().await;
    let (id, waiting) = done?;
    let Some(waiting) = waiting else {
        return Ok(Json(Proposed {
            room: v.id,
            id,
            status: "candidate".to_owned(),
            duplicate: true,
        }));
    };
    // Ids and counts only (Q-15); the origin is the session's, set by the dispatcher.
    let mut ctl = begin_write(&app.pool).await?;
    record(
        &mut ctl,
        "brain.ai.proposed",
        json!({"room": v.id, "record": id, "session": session, "type": req.kind,
            "project": ainkrad_core_server::ops_catalog::session_project(&app.pool, &session).await}),
        Some((
            "brain.inbox",
            json!({"room": v.id, "op": "proposed", "waiting": waiting}),
        )),
    )
    .await?;
    ctl.commit().await?;
    Ok(Json(Proposed {
        room: v.id,
        id,
        status: "candidate".to_owned(),
        duplicate: false,
    }))
}

/// Adds the candidate to the open room: its id and how many wait, or `None` waiting for a repeat.
async fn land(
    app: &App,
    a: &RoomAccess,
    session: &str,
    req: &Propose,
    body: &str,
) -> Result<(String, Option<i64>), ApiError> {
    let now = app.clock.now();
    let mut tx = a.pool().begin().await?;
    for s in &req.sources {
        let known: i64 = sqlx::query_scalar("SELECT count(*) FROM sources WHERE item_id = ?")
            .bind(s)
            .fetch_one(&mut *tx)
            .await?;
        if known == 0 {
            return Err(ApiError::bad_request("a source is not in this room"));
        }
    }
    let same: Option<String> =
        sqlx::query_scalar("SELECT id FROM records WHERE type = ? AND body = ? LIMIT 1")
            .bind(&req.kind)
            .bind(body)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(id) = same {
        return Ok((id, None));
    }
    let marker = format!("{PROPOSED}{session}");
    let mine: i64 = sqlx::query_scalar("SELECT count(*) FROM records WHERE distil = ?")
        .bind(&marker)
        .fetch_one(&mut *tx)
        .await?;
    if mine >= PROPOSE_CAP {
        return Err(code(
            429,
            "too_many_proposals",
            "this session proposed enough to this room; a person must review them first",
        ));
    }
    let id = rand_id("rec-");
    // Always a candidate: the room's auto-accept list is for distillation, never for this.
    sqlx::query(
        "INSERT INTO records (id, type, status, body, tags, source_ids, created_at, distil) \
         VALUES (?, ?, 'candidate', ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.kind)
    .bind(body)
    .bind(json!(req.tags).to_string())
    .bind(json!(req.sources).to_string())
    .bind(&now)
    .bind(&marker)
    .execute(&mut *tx)
    .await?;
    log_op(&mut tx, "record.candidate", &id, &now).await?;
    sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES ('inbox.proposed', ?, ?)")
        .bind(json!({"record": id, "session": session}).to_string())
        .bind(&now)
        .execute(&mut *tx)
        .await?;
    let waiting: i64 =
        sqlx::query_scalar("SELECT count(*) FROM records WHERE status = 'candidate'")
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok((id, Some(waiting)))
}
