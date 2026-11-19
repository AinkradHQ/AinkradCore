//! Autonomy for the import (E9-5, D-26): the rooms an import sorted are accepted and imported by
//! the Core itself, once the semantic step is done (or off). Nothing is asked; the person can undo.
//!
//! Policy, all of it here:
//! - Only a `full` run is auto-accepted. An incremental run already routes into known rooms
//!   (`sync::route_known`) and leaves anything new in review.
//! - Unsorted, a room that mixes two employers and a merged room are never accepted by this step:
//!   they stay `proposed`, exactly as when a person leaves them out.
//! - The step waits while the local model's suggestions are `pending`.
//! - Undo archives the rooms the run made (the files and sources stay, nothing is deleted), so the
//!   dreaming sweep stops reading them. Only an auto-accepted run can be undone this way.

use std::sync::Arc;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::store::begin_write;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use brain_model::group::UNSORTED;
use serde::Serialize;
use sqlx::Row;
use utoipa::ToSchema;

use crate::review::mixed;
use crate::{Brain, code, record};

const EVERY_SECS: u64 = 30;

/// Accepts and imports every sortable room of each full run in review. Returns the rooms made.
pub(crate) async fn step(app: &App, b: &Brain) -> Result<usize, ApiError> {
    if b.key(app).await.is_err() {
        return Ok(0);
    }
    let runs: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM brain_import_runs WHERE state = 'review' AND kind = 'full' ORDER BY id",
    )
    .fetch_all(&app.pool)
    .await?;
    let mut made = 0;
    for run in runs {
        let st = crate::imports::staging(app, b, &run, false).await?;
        let semantic: Option<String> =
            sqlx::query_scalar("SELECT state FROM semantic WHERE id = 1")
                .fetch_optional(&st)
                .await
                .unwrap_or(None);
        if semantic.as_deref() == Some("pending") {
            st.close().await;
            continue;
        }
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM proposals WHERE state = 'proposed' ORDER BY id")
            .fetch_all(&st)
            .await?;
        for id in ids.iter().filter(|i| i.as_str() != UNSORTED) {
            if !mixed(&st, id).await? {
                sqlx::query("UPDATE proposals SET state = 'accepted' WHERE id = ?")
                    .bind(id)
                    .execute(&st)
                    .await?;
            }
        }
        let out = crate::commit::commit_accepted(app, b, &run, st).await?;
        if !out.rooms.is_empty() {
            let rooms: Vec<&str> = out.rooms.iter().map(|r| r.room.as_str()).collect();
            let mut tx = begin_write(&app.pool).await?;
            record(
                &mut tx,
                "brain.import.auto_accepted",
                serde_json::json!({"run": run, "rooms": rooms}),
                None,
            )
            .await?;
            tx.commit().await?;
            made += out.rooms.len();
        }
    }
    Ok(made)
}

#[derive(Serialize, ToSchema)]
pub struct AutoImport {
    pub run: String,
    /// When the Core accepted the rooms.
    pub at: String,
    /// The rooms it made that are still active.
    pub rooms: i64,
}

#[utoipa::path(get, path = "/auto-imports", operation_id = "brainAutoImports", tag = "brain",
    responses((status = 200, description = "Imports the Core accepted by itself in the last 7 days that still have an active room, newest first, each with its Undo (`POST /auto-imports/{run}/undo`)", body = Vec<AutoImport>)))]
pub(crate) async fn list(State(app): State<App>) -> ApiResult<Vec<AutoImport>> {
    let rows = sqlx::query(
        "SELECT json_extract(a.details, '$.run') AS run, a.at AS at, \
                (SELECT count(*) FROM json_each(a.details, '$.rooms') j \
                 JOIN brain_rooms r ON r.id = j.value WHERE r.state = 'active') AS rooms \
         FROM audit_events a WHERE a.action = 'brain.import.auto_accepted' \
         AND a.at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-7 days') ORDER BY a.seq DESC",
    )
    .fetch_all(&app.pool)
    .await?;
    let mut out = vec![];
    for r in rows {
        let rooms: i64 = r.try_get("rooms")?;
        if rooms > 0 {
            out.push(AutoImport {
                run: r.try_get("run")?,
                at: r.try_get("at")?,
                rooms,
            });
        }
    }
    Ok(Json(out))
}

#[derive(Serialize, ToSchema)]
pub struct Undone {
    /// Rooms archived.
    pub rooms: i64,
}

#[utoipa::path(post, path = "/auto-imports/{run}/undo", operation_id = "brainAutoImportUndo", tag = "brain",
    params(("run" = String, Path, description = "Run id")),
    responses((status = 200, description = "Archives the rooms the Core accepted for this run by itself; nothing is deleted. `not_auto` (409) for a run the Core did not accept", body = Undone)))]
pub(crate) async fn undo(
    State(app): State<App>,
    Extension(_b): Extension<Brain>,
    Path(run): Path<String>,
) -> ApiResult<Undone> {
    let rooms: Vec<String> = sqlx::query_scalar(
        "SELECT j.value FROM audit_events a, json_each(a.details, '$.rooms') j \
         WHERE a.action = 'brain.import.auto_accepted' AND json_extract(a.details, '$.run') = ?",
    )
    .bind(&run)
    .fetch_all(&app.pool)
    .await?;
    if rooms.is_empty() {
        return Err(code(409, "not_auto", "the Core did not accept this run by itself"));
    }
    let mut tx = begin_write(&app.pool).await?;
    let mut n = 0;
    for room in &rooms {
        n += sqlx::query("UPDATE brain_rooms SET state = 'archived' WHERE id = ? AND state = 'active'")
            .bind(room)
            .execute(&mut *tx)
            .await?
            .rows_affected() as i64;
    }
    record(
        &mut tx,
        "brain.import.auto_undone",
        serde_json::json!({"run": run, "rooms": rooms}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(Undone { rooms: n }))
}

struct AutoImportJob(Brain);

impl JobHandler for AutoImportJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let Some(app) = self.0.inner.app.get() else {
                return Err("the Core is still starting".to_owned());
            };
            match step(app, &self.0).await {
                Ok(0) => run.idle(),
                Ok(_) => {}
                Err(e) => return Err(format!("{}: {}", e.code, e.message)),
            }
            Ok(())
        })
    }
}

pub(crate) fn job(b: &Brain) -> Job {
    Job::new(
        "brain_auto_import",
        Schedule::Every(EVERY_SECS),
        Arc::new(AutoImportJob(b.clone())),
    )
}

impl Brain {
    /// Accepts and imports the full runs in review now (the `brain_auto_import` job does this every
    /// 30 s). Returns how many rooms were made.
    pub async fn auto_import_step(&self) -> Result<usize, ApiError> {
        match self.inner.app.get() {
            Some(app) => step(app, self).await,
            None => Ok(0),
        }
    }
}
