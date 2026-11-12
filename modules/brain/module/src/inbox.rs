//! The Inbox (E6-4, Core half): candidate records a distillation proposed, waiting for the user.
//! Accept, edit (then accept) or reject; a decision never deletes (Q-8): a rejected record stays,
//! marked. Reading needs the room open (Touch ID, lease). Which kinds skip the review is the
//! room's `auto_accept` list in its policy, empty by default (`distil::store_candidates`).

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::store::begin_write;
use ainkrad_proto::redact::Redactor;
use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use utoipa::{IntoParams, ToSchema};

use crate::answer::KINDS;
use crate::distil::log_op;
use crate::rooms::{AccessError, RoomAccess};
use crate::{Brain, code, record};

const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 200;
const MAX_BODY: usize = 2000;

#[derive(Serialize, ToSchema)]
pub struct InboxRecord {
    pub id: String,
    /// `decision`, `fact`, `preference`, `rule`, `project-state`, `task` or `summary`.
    #[serde(rename = "type")]
    #[schema(rename = "type")]
    pub kind: String,
    /// `candidate`, `accepted` or `rejected`.
    pub status: String,
    pub body: String,
    pub tags: Vec<String>,
    /// The sources it came from, each a source stored in the same room.
    pub sources: Vec<SourceRef>,
    /// When it was distilled (RFC 3339).
    #[schema(required = false)]
    pub distilled_at: String,
    /// The provider and account name the distilling AI session ran on; none for a record made by hand.
    pub distilled_by: Option<DistilledBy>,
    /// The tool (harness) the AI session ran, such as `claude`.
    pub tool: Option<String>,
    /// `auto`, or the device that decided; none while it waits.
    pub decided_by: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct SourceRef {
    pub item_id: String,
    /// `claude_code`, `codex`, `doc`, `jira`, `github`, ...
    pub source_kind: String,
    pub title: String,
    /// The start of the source's text, at most 240 characters.
    pub quote: String,
    pub started_at: String,
    /// The room that holds the source.
    pub room: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct DistilledBy {
    pub provider: String,
    /// The account's name.
    pub account: String,
}

#[derive(Serialize, ToSchema)]
pub struct InboxPage {
    pub items: Vec<InboxRecord>,
    /// Candidates still waiting for a decision in the whole room.
    pub waiting: i64,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct InboxQuery {
    /// `candidate` (default), `accepted`, `rejected`.
    pub status: Option<String>,
    /// Candidate id to continue after.
    pub after: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Deserialize, ToSchema)]
pub struct Decision {
    /// `accept`, `edit` (change, then accept) or `reject`.
    pub action: String,
    /// `edit`: the new text, 1 to 2000 characters.
    pub body: Option<String>,
    /// `edit`: the new kind.
    #[serde(rename = "type")]
    #[schema(rename = "type")]
    pub kind: Option<String>,
    /// `edit`: the new tags.
    pub tags: Option<Vec<String>>,
}

async fn open_room(app: &App, b: &Brain, room: &str) -> Result<RoomAccess, ApiError> {
    let key = b.key(app).await?;
    b.rooms()
        .access(app, &key, room)
        .await
        .map_err(|e| match e {
            AccessError::Unknown => ApiError::not_found("no such room"),
            AccessError::Closed => code(409, "room_closed", "open the room first"),
            AccessError::Newer => code(
                409,
                "room_file_newer",
                "the room file was written by a newer version",
            ),
            AccessError::Unavailable => {
                code(500, "room_unavailable", "the room could not be opened")
            }
        })
}

/// The record without its source details, and the item ids to fill them from.
fn candidate(r: &sqlx::sqlite::SqliteRow) -> Result<(InboxRecord, Vec<String>), sqlx::Error> {
    let list = |c: &str| -> Result<Vec<String>, sqlx::Error> {
        Ok(serde_json::from_str(&r.try_get::<String, _>(c)?).unwrap_or_default())
    };
    let by = match (
        r.try_get::<Option<String>, _>("provider")?,
        r.try_get::<Option<String>, _>("account")?,
    ) {
        (Some(provider), Some(account)) => Some(DistilledBy { provider, account }),
        _ => None,
    };
    let rec = InboxRecord {
        id: r.try_get("id")?,
        kind: r.try_get("type")?,
        status: r.try_get("status")?,
        body: r.try_get("body")?,
        tags: list("tags")?,
        sources: vec![],
        distilled_at: r.try_get("created_at")?,
        distilled_by: by,
        tool: r.try_get("tool")?,
        decided_by: r.try_get("decided_by")?,
    };
    Ok((rec, list("source_ids")?))
}

/// Fills each record's sources from the room's own `sources` table.
async fn fill(
    pool: &sqlx::SqlitePool,
    room: &str,
    recs: Vec<(InboxRecord, Vec<String>)>,
) -> Result<Vec<InboxRecord>, sqlx::Error> {
    let mut out = Vec::with_capacity(recs.len());
    for (mut rec, ids) in recs {
        for id in ids {
            let row = sqlx::query(
                "SELECT item_id, source_kind, title, text, started_at FROM sources WHERE item_id = ?",
            )
            .bind(&id)
            .fetch_optional(pool)
            .await?;
            if let Some(r) = row {
                rec.sources.push(SourceRef {
                    item_id: r.try_get("item_id")?,
                    source_kind: r.try_get("source_kind")?,
                    title: r.try_get("title")?,
                    quote: r
                        .try_get::<String, _>("text")?
                        .trim()
                        .chars()
                        .take(240)
                        .collect(),
                    started_at: r.try_get("started_at")?,
                    room: Some(room.to_owned()),
                });
            }
        }
        out.push(rec);
    }
    Ok(out)
}

#[utoipa::path(get, path = "/rooms/{room}/inbox", operation_id = "brainInbox", tag = "brain",
    params(("room" = String, Path, description = "Room id"), InboxQuery),
    responses((status = 200, description = "Candidate records of an open room, oldest first, with how many wait", body = InboxPage)))]
pub(crate) async fn list(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(room): Path<String>,
    Query(q): Query<InboxQuery>,
) -> ApiResult<InboxPage> {
    let status = q.status.as_deref().unwrap_or("candidate");
    if !["candidate", "accepted", "rejected"].contains(&status) {
        return Err(ApiError::bad_request(
            "status is `candidate`, `accepted` or `rejected`",
        ));
    }
    let access = open_room(&app, &b, &room).await?;
    let rows = sqlx::query("SELECT * FROM records WHERE status = ? AND id > ? ORDER BY id LIMIT ?")
        .bind(status)
        .bind(q.after.as_deref().unwrap_or(""))
        .bind(q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT))
        .fetch_all(access.pool())
        .await?;
    let waiting: i64 =
        sqlx::query_scalar("SELECT count(*) FROM records WHERE status = 'candidate'")
            .fetch_one(access.pool())
            .await?;
    let raw = rows.iter().map(candidate).collect::<Result<Vec<_>, _>>()?;
    let items = fill(access.pool(), &room, raw).await?;
    access.pool().close().await;
    Ok(Json(InboxPage { items, waiting }))
}

#[utoipa::path(post, path = "/rooms/{room}/inbox/{id}", operation_id = "brainDecide", tag = "brain",
    params(("room" = String, Path, description = "Room id"), ("id" = String, Path, description = "Candidate id")),
    request_body = Decision,
    responses((status = 200, description = "The candidate after the decision; one already decided is a 409", body = InboxRecord)))]
pub(crate) async fn decide(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<ainkrad_core_server::api::v1::Caller>,
    Path((room, id)): Path<(String, String)>,
    Json(req): Json<Decision>,
) -> ApiResult<InboxRecord> {
    let edit = match req.action.as_str() {
        "accept" | "reject" => false,
        "edit" => true,
        _ => {
            return Err(ApiError::bad_request(
                "action is `accept`, `edit` or `reject`",
            ));
        }
    };
    if edit {
        let ok_body = req
            .body
            .as_deref()
            .is_none_or(|t| (1..=MAX_BODY).contains(&t.trim().chars().count()));
        let ok_kind = req.kind.as_deref().is_none_or(|k| KINDS.contains(&k));
        let ok_tags = req.tags.as_ref().is_none_or(|t| {
            t.len() <= 8 && t.iter().all(|x| (1..=40).contains(&x.chars().count()))
        });
        if !(ok_body && ok_kind && ok_tags)
            || (req.body.is_none() && req.kind.is_none() && req.tags.is_none())
        {
            return Err(ApiError::bad_request(
                "edit needs a body of 1 to 2000 characters, a known type or up to 8 tags",
            ));
        }
    }
    let access = open_room(&app, &b, &room).await?;
    let now = app.clock.now();
    let mut tx = access.pool().begin().await?;
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM records WHERE id = ?")
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await?;
    match status.as_deref() {
        None => return Err(ApiError::not_found("no such candidate")),
        Some("candidate") => {}
        Some(_) => {
            return Err(code(
                409,
                "already_decided",
                "the candidate was decided already",
            ));
        }
    }
    let to = if req.action == "reject" {
        "rejected"
    } else {
        "accepted"
    };
    sqlx::query(
        "UPDATE records SET status = ?, reviewed_at = ?, decided_by = ?, \
         body = coalesce(?, body), type = coalesce(?, type), tags = coalesce(?, tags) WHERE id = ?",
    )
    .bind(to)
    .bind(&now)
    .bind(&me.device.id)
    .bind(req.body.as_deref().map(|t| Redactor::new().text(t.trim())))
    .bind(&req.kind)
    .bind(req.tags.as_ref().map(|t| json!(t).to_string()))
    .bind(&id)
    .execute(&mut *tx)
    .await?;
    let op = if edit {
        "record.edited".to_owned()
    } else {
        format!("record.{to}")
    };
    log_op(&mut tx, &op, &id, &now).await?;
    sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES (?, ?, ?)")
        .bind(format!("inbox.{}", req.action))
        .bind(json!({"record": id, "by": me.device.id}).to_string())
        .bind(&now)
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query("SELECT * FROM records WHERE id = ?")
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
    let raw = candidate(&row)?;
    let waiting: i64 =
        sqlx::query_scalar("SELECT count(*) FROM records WHERE status = 'candidate'")
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    let out = fill(access.pool(), &room, vec![raw])
        .await?
        .pop()
        .expect("one record");
    access.pool().close().await;
    // Ids and counts only (Q-15).
    let mut ctl = begin_write(&app.pool).await?;
    record(
        &mut ctl,
        "brain.inbox.decided",
        json!({"room": room, "action": req.action, "waiting": waiting}),
        Some((
            "brain.inbox",
            json!({"room": room, "op": "decided", "waiting": waiting}),
        )),
    )
    .await?;
    ctl.commit().await?;
    Ok(Json(out))
}
