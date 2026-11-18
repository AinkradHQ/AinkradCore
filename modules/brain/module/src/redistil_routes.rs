//! The re-distil routes (B6-01). Person only: every handler refuses an AI session, and no AI op
//! exists for a run. A real run needs a step-up (`DESTRUCTIVE`); the dry run changes no memory and
//! does not. Both answer with counts and states, never text. The engine is in `redistil`.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Serialize;
use sqlx::Row;
use utoipa::ToSchema;

use crate::change_routes::person_only;
use crate::redistil::{cancel as cancel_run, start, summary_line};
use crate::{Brain, policy};

#[derive(Serialize, ToSchema)]
pub struct RedistilView {
    pub id: String,
    pub room: String,
    /// A dry run reads and counts, and writes no memory.
    pub dry_run: bool,
    /// `running`, `committing`, `done`, `failed` (start it again within 24 hours to resume) or
    /// `cancelled`.
    pub state: String,
    /// Sources the run reads, and how many it has read.
    pub total: i64,
    pub read: i64,
    /// Facts that stay (re-derived, or protected), facts written, and old facts archived. Set when `done`.
    pub kept: Option<i64>,
    pub new_facts: Option<i64>,
    pub archived: Option<i64>,
    /// "Kept 84 facts, archived 1,203 items" (a dry run: "Would keep ..."). Set when `done`.
    pub summary: Option<String>,
    /// The change set to Undo (`POST /rooms/{room}/changes/{id}/undo`); none for a dry run.
    pub change: Option<String>,
    /// Why it waits or failed.
    pub detail: String,
    pub started_at: String,
    pub updated_at: String,
}

fn view(r: &sqlx::sqlite::SqliteRow) -> Result<RedistilView, sqlx::Error> {
    let dry = r.try_get::<i64, _>("dry_run")? == 1;
    let (kept, new_facts, archived): (Option<i64>, Option<i64>, Option<i64>) = (
        r.try_get("kept")?,
        r.try_get("new_facts")?,
        r.try_get("archived")?,
    );
    let summary = match (kept, new_facts, archived) {
        (Some(k), Some(n), Some(a)) => Some(summary_line(k + n, a, dry)),
        _ => None,
    };
    Ok(RedistilView {
        id: r.try_get("id")?,
        room: r.try_get("room")?,
        dry_run: dry,
        state: r.try_get("state")?,
        total: r.try_get("total")?,
        read: r.try_get("read")?,
        kept,
        new_facts,
        archived,
        summary,
        change: r.try_get("change")?,
        detail: r.try_get("detail")?,
        started_at: r.try_get("started_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

async fn show(app: &App, id: &str) -> ApiResult<RedistilView> {
    let r = sqlx::query("SELECT * FROM brain_redistils WHERE id = ?")
        .bind(id)
        .fetch_one(&app.pool)
        .await?;
    Ok(Json(view(&r)?))
}

#[utoipa::path(post, path = "/rooms/{room}/redistil", operation_id = "brainRedistil", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    responses((status = 200, description = "Starts, or resumes, the real re-distil of the room: every source is read again in the background, then new facts are written and every old fact nothing re-derived is archived, as one change set with Undo (step-up; person only; one room at a time). 409 `nothing_to_redistil`, `redistil_busy`, `redistil_open`", body = RedistilView)))]
pub(crate) async fn apply(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path(room): Path<String>,
) -> ApiResult<RedistilView> {
    person_only(&me)?;
    let run = start(&app, &b, &me, &room, false).await?;
    show(&app, &run.id).await
}

#[utoipa::path(post, path = "/rooms/{room}/redistil/dry-run", operation_id = "brainRedistilDryRun", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    responses((status = 200, description = "Starts, or resumes, the dry run: the same pass, counted and rolled back. It writes no memory and reports counts only (person only)", body = RedistilView)))]
pub(crate) async fn dry_run(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path(room): Path<String>,
) -> ApiResult<RedistilView> {
    person_only(&me)?;
    let run = start(&app, &b, &me, &room, true).await?;
    show(&app, &run.id).await
}

#[utoipa::path(post, path = "/rooms/{room}/redistil/cancel", operation_id = "brainRedistilCancel", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    responses((status = 200, description = "Cancels the room's open run, real or dry: its waiting batch is dropped and what it staged and marked is cleared; nothing is archived (person only). 404 when no run is open; 409 `redistil_committing` while the run writes its result", body = RedistilView)))]
pub(crate) async fn cancel(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path(room): Path<String>,
) -> ApiResult<RedistilView> {
    person_only(&me)?;
    policy::load(&app, &room).await?;
    match cancel_run(&app, &b, &room).await? {
        Some(id) => show(&app, &id).await,
        None => Err(ApiError::not_found("no open re-distil run in this room")),
    }
}

#[utoipa::path(get, path = "/rooms/{room}/redistil", operation_id = "brainRedistils", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    responses((status = 200, description = "The room's last ten runs, newest first (counts only; person only)", body = Vec<RedistilView>)))]
pub(crate) async fn list(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(room): Path<String>,
) -> ApiResult<Vec<RedistilView>> {
    person_only(&me)?;
    policy::load(&app, &room).await?;
    let rows = sqlx::query(
        "SELECT * FROM brain_redistils WHERE room = ? ORDER BY started_at DESC, id DESC LIMIT 10",
    )
    .bind(&room)
    .fetch_all(&app.pool)
    .await?;
    Ok(Json(rows.iter().map(view).collect::<Result<_, _>>()?))
}
