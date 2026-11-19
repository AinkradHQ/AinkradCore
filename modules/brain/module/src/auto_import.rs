//! Autonomy for the import (E9-5, D-26): the rooms an import sorted are accepted and imported by
//! the Core itself, once the semantic step is done (or off). Nothing is asked; the person can undo.
//!
//! Policy, all of it here:
//! - Every run in review is looked at: a new room of a later (incremental) run is accepted too. A run stays
//!   in review while Unsorted holds items, which are re-filed into the closest room as the model finds it.
//! - Unsorted, a room that mixes two employers and a merged room are never accepted by this step:
//!   they stay `proposed`, exactly as when a person leaves them out.
//! - The step waits while the local model's suggestions are `pending`.
//! - Undo puts the sort back to one pile: the rooms the run made are archived (their files and sources
//!   stay, nothing is deleted) and the run's staged items return to Unsorted in a run open for review
//!   again, which this step then leaves to the person. Only an auto-accepted run can be undone.

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

/// Files what waits in Unsorted into the rooms the local model found closest (E9-5: Unsorted is a quiet
/// bucket that keeps re-sorting). A hint already passed the model's strength and margin. A room of this
/// run takes the item as it is; a committed room gets a proposal of its name, which `route_known` then
/// commits into it. Returns the items moved.
async fn resort_unsorted(
    app: &App,
    b: &Brain,
    run: &str,
    st: &sqlx::SqlitePool,
) -> Result<usize, ApiError> {
    let hints = crate::suggest::ready_closest(app, b, st, run).await?;
    let mut moved = 0;
    let mut to_known: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for h in hints {
        if h.in_review {
            moved += sqlx::query("UPDATE items SET proposal = ? WHERE item_id = ? AND proposal = ?")
                .bind(&h.room_id)
                .bind(&h.item_id)
                .bind(UNSORTED)
                .execute(st)
                .await?
                .rows_affected() as usize;
        } else {
            to_known.entry(h.room_name).or_default().push(h.item_id);
        }
    }
    for (name, ids) in to_known {
        crate::review::split_into(st, UNSORTED, &ids, Some(&name)).await?;
        moved += ids.len();
    }
    Ok(moved)
}

/// Accepts and imports every sortable room of each run in review, and re-sorts Unsorted. Returns the rooms made.
pub(crate) async fn step(app: &App, b: &Brain) -> Result<usize, ApiError> {
    if b.key(app).await.is_err() {
        return Ok(0);
    }
    let runs: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM brain_import_runs WHERE state = 'review' \
         AND id NOT IN (SELECT json_extract(details, '$.run') FROM audit_events WHERE action = 'brain.import.auto_undone') \
         ORDER BY id",
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
        let moved = resort_unsorted(app, b, &run, &st).await?;
        let ids: Vec<String> =
            sqlx::query_scalar("SELECT id FROM proposals WHERE state = 'proposed' ORDER BY id")
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
        let out = crate::commit::commit_accepted(app, b, &run, st, true).await?;
        if out.rooms.is_empty() && moved == 0 {
            continue;
        }
        // Undo only covers rooms this step made, never a room that took re-sorted items.
        let rooms: Vec<&str> = out
            .rooms
            .iter()
            .filter(|r| r.created)
            .map(|r| r.room.as_str())
            .collect();
        made += rooms.len();
        if !rooms.is_empty() {
            let mut tx = begin_write(&app.pool).await?;
            record(
                &mut tx,
                "brain.import.auto_accepted",
                serde_json::json!({"run": run, "rooms": rooms}),
                None,
            )
            .await?;
            tx.commit().await?;
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
    /// Items back in Unsorted, waiting in the run's review.
    #[schema(required = false)]
    pub items: i64,
}

#[utoipa::path(post, path = "/auto-imports/{run}/undo", operation_id = "brainAutoImportUndo", tag = "brain",
    params(("run" = String, Path, description = "Run id")),
    responses((status = 200, description = "Puts the sort back to one pile: the rooms the Core made for this run are archived (nothing is deleted) and the run's staged items return to Unsorted in a run that is open for review again. The Core does not accept this run by itself again. `not_auto` (409) for a run the Core did not accept", body = Undone)))]
pub(crate) async fn undo(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
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
        return Err(code(
            409,
            "not_auto",
            "the Core did not accept this run by itself",
        ));
    }
    let again: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'brain.import.auto_undone' AND json_extract(details, '$.run') = ?",
    )
    .bind(&run)
    .fetch_one(&app.pool)
    .await?;
    if again > 0 {
        return Err(code(
            409,
            "already_undone",
            "this import was already put back",
        ));
    }
    // The staged items go first: if the staging file is gone nothing else changes.
    let st = crate::imports::staging(&app, &b, &run, false).await?;
    let mut stx = st.begin().await?;
    sqlx::query("DELETE FROM proposals WHERE id != ?")
        .bind(UNSORTED)
        .execute(&mut *stx)
        .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO proposals (id, name, kind_guess, kind) VALUES (?, 'Unsorted', 'general', 'general')",
    )
    .bind(UNSORTED)
    .execute(&mut *stx)
    .await?;
    sqlx::query("UPDATE proposals SET state = 'proposed' WHERE id = ?")
        .bind(UNSORTED)
        .execute(&mut *stx)
        .await?;
    let items = sqlx::query("UPDATE items SET proposal = ? WHERE mark IS NULL OR mark != 'refused'")
        .bind(UNSORTED)
        .execute(&mut *stx)
        .await?
        .rows_affected() as i64;
    stx.commit().await?;
    st.close().await;
    let mut tx = begin_write(&app.pool).await?;
    let mut n = 0;
    for room in &rooms {
        n += sqlx::query(
            "UPDATE brain_rooms SET state = 'archived' WHERE id = ? AND state = 'active'",
        )
        .bind(room)
        .execute(&mut *tx)
        .await?
        .rows_affected() as i64;
        // The sources stay in the archived room's file. Their hashes are released so the items,
        // back in review, can be sorted into rooms again (a refused hash is not "stored").
        sqlx::query("UPDATE brain_seen SET room = 'refused' WHERE run = ? AND room = ?")
            .bind(&run)
            .bind(room)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "UPDATE brain_import_runs SET state = 'review', stage = 'review', committed_at = NULL WHERE id = ?",
    )
    .bind(&run)
    .execute(&mut *tx)
    .await?;
    record(
        &mut tx,
        "brain.import.auto_undone",
        serde_json::json!({"run": run, "rooms": rooms, "items": items}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(Undone { rooms: n, items }))
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
