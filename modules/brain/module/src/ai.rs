//! The Brain as AI sessions see it through Code Mode (plan E4): read operations over the rooms a
//! session may see (`access::visible_rooms`, plan D3) and `brain.propose`, which drops a candidate
//! into a room's Inbox and nothing else. These routes answer only the Code Mode dispatcher's
//! synthetic caller (its session is `code_mode:<id>`); a person has the room routes.
//!
//! SECURITY MODEL (Brain v2, B2-03; read before changing anything here)
//!
//! 1. Two layers. Sources (`sources.text`, what was imported) are raw, third-party text. Memory
//!    (the `memory` view: accepted, current, not archived) is the distilled layer. Every
//!    `brainAi*` read serves MEMORY ONLY: search, record, decisions, project state. None of them
//!    selects `sources.text`, searches `fts`, or embeds a source.
//! 2. Raw source text leaves through exactly one door, `brainAiEvidence`, and only for a pair the
//!    room itself vouches for: the named record is in memory AND cites the named source
//!    (`record_sources`, or the old `source_ids` list). Anything else (an uncited source, an
//!    archived or superseded record, an unknown id, a hidden room) is the same 404. The caller
//!    must name the citing record; there is no "give me this source" route. The snippet is cut
//!    to `EVIDENCE_CHARS`. `tests/gate/ai.rs` fails if any other op returns source text.
//! 3. Every text a third party wrote (record bodies, tags, evidence snippets) leaves inside the
//!    fixed `ainkrad_core::untrusted` envelope, one per item, so a script sees data and the model
//!    sees the notice. Titles and ids are wrapped in the label (`wrap` flattens it).
//! 4. Room isolation: every route resolves its room through `access::visible_room(s)` (the
//!    project/access-list match AND the whole fallback chain inside the room's model policy,
//!    checked on every call). A room the session cannot see is the same 404 as an unknown id.
//!    Nothing here reads a room it did not get from that gate.
//! 5. The index (`rec_fts`) only nominates ids. The text always comes from `memory` at read time,
//!    so a stale index can mis-rank but never return a record that left memory.

use ainkrad_core::untrusted::wrap;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::scheduler::iso_of_unix;
use ainkrad_core_server::store::begin_write;
use ainkrad_proto::redact::Redactor;
use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use brain_model::merge::DEMOTE_SQL;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use utoipa::{IntoParams, ToSchema};

use crate::access::{Visible, visible_room, visible_rooms};
use crate::answer::KINDS;
use crate::distil::log_op;
use crate::inbox::open_room;
use crate::index::{rec_fts, words};
use crate::policy;
use crate::rooms::RoomAccess;
use crate::{Brain, code, rand_id, record};

/// The marker in `records.distil` of a candidate an AI session proposed: `ai:<session id>`.
pub(crate) const PROPOSED: &str = "ai:";
pub(crate) const SESSION: &str = "code_mode:";
const DEFAULT_LIMIT: u32 = 10;
const MAX_LIMIT: u32 = 25;
const MAX_BODY: usize = 2000;
/// How much of a cited source `brainAiEvidence` returns.
const EVIDENCE_CHARS: usize = 2000;
/// A list shows this much of a record; `brain.record` has all of it.
pub(crate) const LIST_BODY: usize = 400;
/// Candidates one session may propose into one room.
/// ponytail: per room file, not a session-wide counter; a control-plane table if that is needed.
const PROPOSE_CAP: i64 = 20;
const PROPOSE_INVALID: &str = "a known type, a body of 1 to 2000 characters, at most 8 tags of 1 to 40 and 20 sources that are in this room";
/// Rooms one search reads.
const MAX_ROOMS: usize = 20;

/// The session behind a Code Mode call.
pub(crate) fn session_of(me: &Caller) -> Result<String, ApiError> {
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

/// The rooms a call reads: the named one (visible or 404), else every visible room; true when
/// `MAX_ROOMS` cut the list.
pub(crate) async fn scope(
    app: &App,
    session: &str,
    room: Option<&str>,
) -> Result<(Vec<Visible>, bool), ApiError> {
    match room {
        Some(r) => Ok((vec![room_of(app, session, r).await?], false)),
        None => {
            let all = visible_rooms(app, session).await?;
            let cut = all.len() > MAX_ROOMS;
            Ok((all.into_iter().take(MAX_ROOMS).collect(), cut))
        }
    }
}

/// The open file of each room that is open; how many were not (a closed lease, or unreadable).
pub(crate) async fn open_all(
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
    /// Always `record`: a fact in force. Sources are read through `brainAiEvidence` only.
    pub kind: String,
    /// The record id.
    pub id: String,
    pub started_at: String,
    /// The match, inside the outside-text envelope.
    pub text: String,
    /// The sort key (`DEMOTE_SQL`): fresh, stale, then contested last. Not in the contract.
    #[serde(skip)]
    pub(crate) demote: i64,
}

/// The kind of the record a `memory` row contests (B4-02 round 3), for its label (`record_of`);
/// NULL when that record is archived or purged, which the label shows as "(gone)".
pub(crate) const CONTESTS_KIND: &str =
    "(SELECT t.type FROM records t WHERE t.id = memory.contests AND t.archived_at IS NULL) AS contests_kind";

#[derive(Serialize, ToSchema)]
pub struct AiHits {
    pub hits: Vec<AiHit>,
    pub rooms_searched: usize,
    /// Visible rooms that were closed and so not searched.
    pub rooms_closed: usize,
    /// `keyword`, `meaning` or `both`: how these hits were ranked. Always set; optional in the schema
    /// only because it joined the contract after 1.0 (a new field may not be required).
    pub ranked_by: Option<String>,
    /// False when a cap (rooms per search, records per room for meaning) cut what was read, so a
    /// missing hit may exist. Always set; optional in the schema for the same reason as `ranked_by`.
    pub complete: Option<bool>,
}

/// The time before which a `project-state` or `task` last in use is stale in `room` (B4-02): the
/// room's `review_days` ago. Stale ones rank after fresh ones in every retrieval op, and contested
/// ones after both (`DEMOTE_SQL`).
pub(crate) async fn stale_cutoff(app: &App, room: &str) -> String {
    let days = policy::load(app, room).await.map_or(90, |p| p.review_days);
    iso_of_unix(app.clock.unix() - days * 86_400)
}

/// Longest chain of replaced records `brainAiRecord` follows.
const MAX_HISTORY: usize = 10;

pub(crate) fn cut(s: &str, n: usize) -> (String, bool) {
    let t = s.trim();
    if t.chars().count() <= n {
        return (t.to_owned(), false);
    }
    (format!("{}…", t.chars().take(n).collect::<String>()), true)
}

#[utoipa::path(get, path = "/ai/search", operation_id = "brainAiSearch", tag = "brain",
    params(AiSearchQuery),
    responses((status = 200, description = "Memory records (current, not archived) across the rooms this AI session may see, best first. Never raw sources: those come through brainAiEvidence for a record that cites them. Every text is wrapped as outside data.", body = AiHits)))]
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
    let (rooms, rooms_cut) = scope(&app, &session, q.room.as_deref()).await?;
    let (open, closed) = open_all(&app, &b, rooms, named).await?;
    let key = b.key(&app).await?;
    let mut recs: Vec<(bool, f64, AiHit)> = vec![];
    for (v, a) in &open {
        let cutoff = stale_cutoff(&app, &v.id).await;
        for (rank, id) in rec_fts(&app, &key, a, limit, &expr).await? {
            // The index only nominates: the text is read from `memory` now.
            let sql = format!(
                "SELECT id, type, body, tags, source_ids, created_at, contests, {CONTESTS_KIND}, {DEMOTE_SQL} AS demote FROM memory WHERE id = ?"
            );
            let row = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(&cutoff)
                .bind(&id)
                .fetch_optional(a.pool())
                .await?;
            if let Some(r) = row {
                let rec = record_of(&v.id, &r, LIST_BODY)?;
                let demote = r.try_get::<i64, _>("demote")?;
                recs.push((
                    demote,
                    rank,
                    AiHit {
                        room: v.id.clone(),
                        kind: "record".to_owned(),
                        started_at: rec.created_at,
                        text: rec.text,
                        id: rec.id,
                        demote,
                    },
                ));
            }
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
    let capped = rooms_cut || meaning.as_ref().is_some_and(|m| m.1);
    let meaning = meaning.map(|m| m.0);
    if let (Some(m), "meaning") = (&meaning, mode) {
        return Ok(Json(AiHits {
            hits: m.clone(),
            rooms_searched: open.len(),
            rooms_closed: closed,
            ranked_by: Some("meaning".to_owned()),
            complete: Some(!capped),
        }));
    }
    // Fresh, then stale, then contested (B4-02), then by rank.
    recs.sort_by(|x, y| {
        x.0.cmp(&y.0)
            .then(x.1.total_cmp(&y.1))
            .then_with(|| x.2.id.cmp(&y.2.id))
    });
    let mut hits: Vec<AiHit> = recs.into_iter().map(|(_, _, h)| h).collect();
    hits.truncate(limit as usize);
    let ranked_by = if meaning.is_some() { "both" } else { "keyword" };
    if let Some(m) = meaning {
        hits = crate::ai_semantic::fuse(hits, m, limit as usize);
    }
    Ok(Json(AiHits {
        hits,
        rooms_searched: open.len(),
        rooms_closed: closed,
        ranked_by: Some(ranked_by.to_owned()),
        complete: Some(!capped),
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
    /// Only `brainAiRecord`: what this record replaced, newest first (B4-02), so "what was true in
    /// March" stays answerable. A replaced record is reachable only through its successor in memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<AiPast>>,
}

/// A record a current one replaced. `text` is outside data, like every record text.
#[derive(Serialize, ToSchema)]
pub struct AiPast {
    pub id: String,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub text: String,
}

/// The records `id` replaced, newest first, following `supersedes` links (at most `MAX_HISTORY`).
async fn history_of(
    conn: &mut sqlx::SqliteConnection,
    id: &str,
) -> Result<Vec<AiPast>, sqlx::Error> {
    let mut out = vec![];
    let mut next: Option<String> =
        sqlx::query_scalar("SELECT supersedes FROM records WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?
            .flatten();
    while let Some(old) = next.take().filter(|_| out.len() < MAX_HISTORY) {
        let Some(r) = sqlx::query(
            "SELECT * FROM records WHERE id = ? AND status = 'accepted' AND archived_at IS NULL",
        )
        .bind(&old)
        .fetch_optional(&mut *conn)
        .await?
        else {
            break;
        };
        out.push(AiPast {
            valid_from: r.try_get::<Option<String>, _>("valid_from").ok().flatten(),
            valid_to: r.try_get::<Option<String>, _>("valid_to").ok().flatten(),
            text: record_of("", &r, LIST_BODY)?.text,
            id: old,
        });
        next = r.try_get::<Option<String>, _>("supersedes").ok().flatten();
    }
    Ok(out)
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
    let mut text = if tags.is_empty() {
        body
    } else {
        format!("tags: {}\n{body}", tags.join(", "))
    };
    // A contested record says so, so the session sees the conflict (B4-02 round 3).
    let contests = r.try_get::<Option<String>, _>("contests").ok().flatten();
    let contests_kind = r
        .try_get::<Option<String>, _>("contests_kind")
        .ok()
        .flatten();
    if let Some(c) = contests {
        let k = contests_kind.as_deref().unwrap_or("gone");
        text = format!("contests record {c} ({k}), unresolved\n{text}");
    }
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
        history: None,
    })
}

#[utoipa::path(get, path = "/ai/rooms/{room}/records/{id}", operation_id = "brainAiRecord", tag = "brain",
    params(("room" = String, Path, description = "Room id"), ("id" = String, Path, description = "Record id")),
    responses((status = 200, description = "One memory record (current, not archived) of a room this AI session may see, whole, as outside data; a candidate, rejected, superseded or archived one is a 404", body = AiRecord)))]
pub(crate) async fn one(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path((room, id)): Path<(String, String)>,
) -> ApiResult<AiRecord> {
    let session = session_of(&me)?;
    let v = room_of(&app, &session, &room).await?;
    let a = open_room(&app, &b, &v.id).await?;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT *, {CONTESTS_KIND} FROM memory WHERE id = ?"
    )))
    .bind(&id)
    .fetch_optional(a.pool())
    .await?;
    let past = match &row {
        Some(_) => Some(history_of(&mut *a.pool().acquire().await?, &id).await?),
        None => None,
    };
    a.pool().close().await;
    let row = row.ok_or_else(|| ApiError::not_found("no such record"))?;
    let mut rec = record_of(&v.id, &row, MAX_BODY)?;
    rec.history = past.filter(|p| !p.is_empty());
    Ok(Json(rec))
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

/// Memory records of `kinds`, newest first, across the rooms the call reads.
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
    let (rooms, _) = scope(app, &session, q.room.as_deref()).await?;
    let (open, closed) = open_all(app, b, rooms, named).await?;
    let marks = vec!["?"; kinds.len()].join(",");
    let sql = format!(
        "SELECT *, {CONTESTS_KIND}, {DEMOTE_SQL} AS demote FROM memory WHERE type IN ({marks}) \
         ORDER BY demote, created_at DESC, id LIMIT {limit}"
    );
    let mut all = vec![];
    for (v, a) in &open {
        let mut query =
            sqlx::query(sqlx::AssertSqlSafe(sql.clone())).bind(stale_cutoff(app, &v.id).await);
        for k in kinds {
            query = query.bind(*k);
        }
        for r in query.fetch_all(a.pool()).await? {
            all.push((
                r.try_get::<i64, _>("demote")?,
                record_of(&v.id, &r, LIST_BODY)?,
            ));
        }
        a.pool().close().await;
    }
    // Fresh, then stale, then contested (B4-02), then newest first.
    all.sort_by(|x, y| {
        (x.0.cmp(&y.0))
            .then(y.1.created_at.cmp(&x.1.created_at))
            .then(x.1.id.cmp(&y.1.id))
    });
    all.truncate(limit as usize);
    Ok(Json(AiRecords {
        records: all.into_iter().map(|(_, r)| r).collect(),
        rooms_closed: closed,
    }))
}

#[utoipa::path(get, path = "/ai/decisions", operation_id = "brainAiDecisions", tag = "brain",
    params(ListQuery),
    responses((status = 200, description = "Current (memory) decisions of the rooms this AI session may see, newest first, as outside data", body = AiRecords)))]
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
    responses((status = 200, description = "Current (memory) project-state records, tasks (open threads) and rules (landmines) of the rooms this AI session may see, newest first, as outside data", body = AiRecords)))]
pub(crate) async fn project_state(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Query(q): Query<ListQuery>,
) -> ApiResult<AiRecords> {
    list(&app, &b, &me, q, &["project-state", "task", "rule"]).await
}

#[derive(Serialize, ToSchema)]
pub struct AiEvidence {
    pub room: String,
    /// The citing record.
    pub record: String,
    /// The cited source's item id.
    pub source: String,
    /// The source's start of text, inside the outside-text envelope; empty when `compacted`.
    pub text: String,
    /// The snippet was cut at 2000 characters.
    pub truncated: bool,
    /// The source's text was removed by retention; only the citation remains.
    pub compacted: bool,
}

#[utoipa::path(get, path = "/ai/rooms/{room}/records/{id}/sources/{source}", operation_id = "brainAiEvidence", tag = "brain",
    params(("room" = String, Path, description = "Room id"), ("id" = String, Path, description = "The memory record that cites the source"), ("source" = String, Path, description = "Item id of the cited source")),
    responses((status = 200, description = "The start (2000 characters) of a source that a current memory record cites, as outside data. The only op that returns raw source text. A source the record does not cite is a 404.", body = AiEvidence)))]
pub(crate) async fn evidence(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path((room, record_id, source)): Path<(String, String, String)>,
) -> ApiResult<AiEvidence> {
    let session = session_of(&me)?;
    let v = room_of(&app, &session, &room).await?;
    let a = open_room(&app, &b, &v.id).await?;
    // One query, so "the record is in memory", "it cites this source" and "the source exists" are
    // decided together. ponytail: the `source_ids` arm exists because writers still fill only that
    // list; drop it once they write `record_sources` (B4).
    let row = sqlx::query(
        "SELECT s.title AS title, s.text AS text, s.compacted_at AS compacted_at \
         FROM memory m JOIN sources s ON s.item_id = ?2 \
         WHERE m.id = ?1 AND (\
             EXISTS (SELECT 1 FROM record_sources rs WHERE rs.record = m.id AND rs.source = s.item_id) \
             OR EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(m.source_ids) THEN m.source_ids ELSE '[]' END) j \
                        WHERE j.value = s.item_id))",
    )
    .bind(&record_id)
    .bind(&source)
    .fetch_optional(a.pool())
    .await;
    a.pool().close().await;
    let r = row?.ok_or_else(|| ApiError::not_found("no such evidence"))?;
    let compacted = r.try_get::<Option<String>, _>("compacted_at")?.is_some();
    let (text, truncated) = if compacted {
        (String::new(), false)
    } else {
        let (snip, cut_) = cut(&r.try_get::<String, _>("text")?, EVIDENCE_CHARS);
        (
            wrap(
                &format!("source {source} | {}", r.try_get::<String, _>("title")?),
                &snip,
            ),
            cut_,
        )
    };
    // Ids only: who read which source, through which record.
    let mut ctl = begin_write(&app.pool).await?;
    record(
        &mut ctl,
        "brain.ai.evidence",
        json!({"room": v.id, "record": record_id, "source": source, "session": session}),
        None,
    )
    .await?;
    ctl.commit().await?;
    Ok(Json(AiEvidence {
        room: v.id,
        record: record_id,
        source,
        text,
        truncated,
        compacted,
    }))
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
        return Err(ApiError::bad_request(PROPOSE_INVALID));
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
            // The same 400 as any other invalid proposal: no oracle for which ids exist.
            // ponytail: a session may cite any source id of a room it sees; restricting it to ids
            // it read through record.sources / evidence needs per-session tracking. The Inbox
            // shows the cited sources to the reviewer (plan note).
            return Err(ApiError::bad_request(PROPOSE_INVALID));
        }
    }
    let same: Option<String> =
        sqlx::query_scalar("SELECT id FROM records WHERE type = ? AND body = ? LIMIT 1")
            .bind(&req.kind)
            .bind(body)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(id) = same {
        // The id only when the match is memory: a candidate, rejected or archived record is not
        // something an AI session may learn exists.
        let in_memory: i64 = sqlx::query_scalar("SELECT count(*) FROM memory WHERE id = ?")
            .bind(&id)
            .fetch_one(&mut *tx)
            .await?;
        return Ok((if in_memory > 0 { id } else { String::new() }, None));
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
