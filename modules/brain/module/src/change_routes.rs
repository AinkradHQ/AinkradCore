//! The change-set routes (B2-02): list, see changes, Undo. Person only: every handler refuses an AI
//! session. They need the room open (lease), like the Inbox. The mechanism is in `changes`.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::begin_write;
use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use utoipa::{IntoParams, ToSchema};

use crate::changes::{Refused, undo};
use crate::inbox::open_room;
use crate::{Brain, code, record};

const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 200;
const MAX_ROWS: u32 = 500;

pub(crate) fn person_only(me: &Caller) -> Result<(), ApiError> {
    if me.session.starts_with(crate::ai::SESSION) {
        return Err(code(
            403,
            "person_only",
            "an AI session cannot list or undo changes; a person does",
        ));
    }
    Ok(())
}

#[derive(Serialize, ToSchema)]
pub struct Change {
    pub id: String,
    /// `distil`, `checkpoint`, `ai`, `tidy`, `purge` or `archive`.
    pub kind: String,
    /// The line the App shows, such as "Saved 5 · reinforced 3 · replaced 1".
    pub summary: String,
    /// Counts by outcome, for example `{"saved": 5, "reinforced": 3}`.
    #[schema(value_type = Object)]
    pub counts: Value,
    /// RFC 3339.
    pub at: String,
    /// When Undo ran; none while it can still be undone.
    pub undone_at: Option<String>,
    /// Records the set changed (a purge keeps none).
    pub rows: i64,
}

#[derive(Serialize, ToSchema)]
pub struct ChangeRow {
    pub seq: i64,
    pub record: String,
    /// The record as it was (the `records` columns and `_sources`); none: it did not exist.
    #[schema(value_type = Option<Object>)]
    pub before: Option<Value>,
    /// The record as the change left it; none: the change removed it.
    #[schema(value_type = Option<Object>)]
    pub after: Option<Value>,
}

#[derive(Serialize, ToSchema)]
pub struct ChangeDetail {
    pub change: Change,
    pub rows: Vec<ChangeRow>,
    /// More rows follow: ask again with `after` set to the last `seq`.
    pub more: bool,
}

#[derive(Serialize, ToSchema)]
pub struct UndoResult {
    pub change: String,
    /// Records put back as they were.
    pub restored: Vec<String>,
    /// Records changed since this change set, left as they are.
    pub skipped: Vec<String>,
    /// True when it had been undone before; nothing changed now.
    pub already_undone: bool,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ChangesQuery {
    /// Change id to continue after (the list is newest first).
    pub after: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RowsQuery {
    /// Row `seq` to continue after.
    pub after: Option<i64>,
    pub limit: Option<u32>,
}

fn change_of(r: &sqlx::sqlite::SqliteRow) -> Result<Change, sqlx::Error> {
    Ok(Change {
        id: r.try_get("id")?,
        kind: r.try_get("kind")?,
        summary: r.try_get("summary")?,
        counts: serde_json::from_str(&r.try_get::<String, _>("counts")?).unwrap_or(Value::Null),
        at: r.try_get("at")?,
        undone_at: r.try_get("undone_at")?,
        rows: r.try_get("n_rows")?,
    })
}

const CHANGE_SQL: &str = "SELECT c.*, (SELECT count(*) FROM change_rows w WHERE w.change = c.id) AS n_rows FROM changes c";

#[utoipa::path(get, path = "/rooms/{room}/changes", operation_id = "brainChangeSets", tag = "brain",
    params(("room" = String, Path, description = "Room id"), ChangesQuery),
    responses((status = 200, description = "The room's change sets, newest first (person only)", body = Vec<Change>)))]
pub(crate) async fn list(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path(room): Path<String>,
    Query(q): Query<ChangesQuery>,
) -> ApiResult<Vec<Change>> {
    person_only(&me)?;
    let access = open_room(&app, &b, &room).await?;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "{CHANGE_SQL} WHERE c.id < ? ORDER BY c.id DESC LIMIT ?"
    )))
    .bind(q.after.as_deref().unwrap_or("\u{10ffff}"))
    .bind(q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT))
    .fetch_all(access.pool())
    .await?;
    access.pool().close().await;
    Ok(Json(rows.iter().map(change_of).collect::<Result<_, _>>()?))
}

#[utoipa::path(get, path = "/rooms/{room}/changes/{id}", operation_id = "brainChangeSet", tag = "brain",
    params(("room" = String, Path, description = "Room id"), ("id" = String, Path, description = "Change id"), RowsQuery),
    responses((status = 200, description = "One change set with its before and after rows (person only)", body = ChangeDetail)))]
pub(crate) async fn one(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path((room, id)): Path<(String, String)>,
    Query(q): Query<RowsQuery>,
) -> ApiResult<ChangeDetail> {
    person_only(&me)?;
    let access = open_room(&app, &b, &room).await?;
    let head = sqlx::query(sqlx::AssertSqlSafe(format!("{CHANGE_SQL} WHERE c.id = ?")))
        .bind(&id)
        .fetch_optional(access.pool())
        .await?
        .ok_or_else(|| ApiError::not_found("no such change"))?;
    let limit = q.limit.unwrap_or(100).clamp(1, MAX_ROWS);
    let rows = sqlx::query(
        "SELECT seq, record, before, after FROM change_rows WHERE change = ? AND seq > ? ORDER BY seq LIMIT ?",
    )
    .bind(&id)
    .bind(q.after.unwrap_or(-1))
    .bind(limit + 1)
    .fetch_all(access.pool())
    .await?;
    access.pool().close().await;
    let parse = |r: &sqlx::sqlite::SqliteRow, c: &str| -> Result<Option<Value>, sqlx::Error> {
        Ok(r.try_get::<Option<String>, _>(c)?
            .and_then(|t| serde_json::from_str(&t).ok()))
    };
    let more = rows.len() > limit as usize;
    let rows = rows
        .iter()
        .take(limit as usize)
        .map(|r| {
            Ok(ChangeRow {
                seq: r.try_get("seq")?,
                record: r.try_get("record")?,
                before: parse(r, "before")?,
                after: parse(r, "after")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
    Ok(Json(ChangeDetail {
        change: change_of(&head)?,
        rows,
        more,
    }))
}

#[utoipa::path(post, path = "/rooms/{room}/changes/{id}/undo", operation_id = "brainUndoChange", tag = "brain",
    params(("room" = String, Path, description = "Room id"), ("id" = String, Path, description = "Change id")),
    responses((status = 200, description = "Rows put back; rows changed since are kept and listed. A second call changes nothing. A purge, or a change older than 30 days, is a 409 (person only)", body = UndoResult)))]
pub(crate) async fn undo_route(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path((room, id)): Path<(String, String)>,
) -> ApiResult<UndoResult> {
    person_only(&me)?;
    let access = open_room(&app, &b, &room).await?;
    let now = app.clock.now();
    let mut tx = access.pool().begin().await?;
    let done = undo(&mut tx, &id, &now).await?;
    let done = match done {
        None => return Err(ApiError::not_found("no such change")),
        Some(Err(Refused::Purge)) => {
            return Err(code(
                409,
                "not_undoable",
                "a purge removed its rows for good",
            ));
        }
        Some(Err(Refused::Expired)) => {
            return Err(code(
                409,
                "undo_expired",
                "this change is older than its Undo window (30 days, 90 for a tidy) and can no longer be undone",
            ));
        }
        Some(Ok(d)) => d,
    };
    if !done.already_undone {
        sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES ('change.undone', ?, ?)")
            .bind(json!({"change": id, "by": me.device.id, "restored": done.restored.len(), "skipped": done.skipped.len()}).to_string())
            .bind(&now)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    access.pool().close().await;
    if !done.already_undone {
        // Ids and counts only (Q-15).
        let mut ctl = begin_write(&app.pool).await?;
        record(
            &mut ctl,
            "brain.change.undone",
            json!({"room": room, "change": id, "restored": done.restored.len(), "skipped": done.skipped.len()}),
            None,
        )
        .await?;
        ctl.commit().await?;
    }
    Ok(Json(UndoResult {
        change: id,
        restored: done.restored,
        skipped: done.skipped,
        already_undone: done.already_undone,
    }))
}
