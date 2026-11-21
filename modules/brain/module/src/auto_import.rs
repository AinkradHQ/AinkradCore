//! The import's preparation (E9-5, D-26; "review before filing", 2026-11-21): the Core gets every
//! run in review ready for the person, and files nothing by itself. Nothing reaches the Brain until
//! the person imports through the review routes (accept, rename, merge, commit).
//!
//! Policy, all of it here:
//! - Every run in review is looked at. The step waits while the local model's suggestions are `pending`.
//! - With the model's step `off` (no model installed, or switched off) the Core tidies the proposal by
//!   names and sizes alone (`tidy::prepare`): one room per product, tiny rooms to Unsorted. With the
//!   model the semantic step has tidied it already. Either tidy is undone by `POST /imports/{run}/semantic/undo`.
//! - What waits in Unsorted is re-filed into the room the local model found closest (staging only).
//! - Runs the Core accepted by itself before 0.10.2 keep their Undo: it puts the sort back to one pile —
//!   the rooms the run made are archived (their files and sources stay, nothing is deleted) and the
//!   run's staged items return to Unsorted in a run open for review again, which this step then leaves
//!   to the person.

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

use crate::{Brain, code, record};

const EVERY_SECS: u64 = 30;

/// Files what waits in Unsorted into the rooms the local model found closest (E9-5: Unsorted is a quiet
/// bucket that keeps re-sorting). A hint already passed the model's strength and margin. A room of this
/// run takes the item as it is; a committed room gets a proposal of its name, which the person's
/// import then files into it. Staging only. Returns the items moved.
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

/// Prepares every run in review for the person: the tidy without a model, and Unsorted re-filed.
/// Accepts and commits nothing. Returns how many runs or items it changed.
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
    let mut changed = 0;
    for run in runs {
        let st = crate::imports::staging(app, b, &run, false).await?;
        let state = crate::suggest::status(app, &st, b, &run).await?;
        if state == "pending" {
            st.close().await;
            continue;
        }
        if state == "off" && crate::tidy::prepare(b, &st, &run).await? {
            changed += 1;
        }
        changed += resort_unsorted(app, b, &run, &st).await?;
        st.close().await;
    }
    Ok(changed)
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
    responses((status = 200, description = "Imports the Core accepted by itself (before 0.10.2; it no longer does) in the last 7 days that still have an active room, newest first, each with its Undo (`POST /auto-imports/{run}/undo`)", body = Vec<AutoImport>)))]
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
    /// Prepares the runs in review now (the `brain_auto_import` job does this every 30 s); files
    /// nothing. Returns how many runs or items it changed.
    pub async fn auto_import_step(&self) -> Result<usize, ApiError> {
        match self.inner.app.get() {
            Some(app) => step(app, self).await,
            None => Ok(0),
        }
    }
}
