//! The import's Learn step (E9-4, 17-brain-import): per place, how far its distillation is, what
//! it learned and which account did the work, and the running cost. Counts, ids and the Core's own
//! numbers only: no source or record text. Read from the control plane, plus one count per room
//! file: the sources still to read, so a place is `done` only when every one was read.
//!
//! A place's rooms are the rooms the run put sources in (`brain_seen.run`); its distillations are
//! those rooms' distils created since the run started. Cost is the sum of their sessions'
//! `cost_usd_micros`; a session with no price yet is counted in `unpriced`, never as zero.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiResult;
use ainkrad_core_server::scheduler::iso_of_unix;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Serialize;
use sqlx::Row;
use utoipa::ToSchema;

use crate::Brain;
use crate::imports::run_state;

#[derive(Serialize, ToSchema)]
pub struct LearningPlace {
    pub room: String,
    pub name: String,
    /// Sources the run stored in the room.
    pub sources: i64,
    /// Sources read by finished distils so far.
    pub read: i64,
    /// Records proposed by finished distils.
    pub learned: i64,
    /// `pending`, `learning`, `waiting` (needs an account or a runner), `failed` (the latest
    /// distil failed; tried again at `retry_at`) or `done` (every source read, nothing open).
    pub state: String,
    /// Sources of the room still to read; absent when the room file cannot be read now.
    #[schema(required = false)]
    pub left: Option<i64>,
    /// When `failed`: when the Core tries the place again (2, 5, 15, 60 minutes, then 6 hours
    /// after the latest failure, by how many failed in a row). In the past: on its next sweep.
    #[schema(required = false)]
    pub retry_at: Option<String>,
    /// When `failed`: why the latest distil failed.
    #[schema(required = false)]
    pub failure: Option<String>,
    /// The provider of the account that did the latest distil, once one ran.
    pub provider: Option<String>,
    pub cost_usd_micros: i64,
}

#[derive(Serialize, ToSchema)]
pub struct Learning {
    pub run: String,
    pub places: Vec<LearningPlace>,
    /// What the distils of this run cost so far, in millionths of a dollar.
    pub total_cost_usd_micros: i64,
    /// Sessions of the run with no price yet (their cost is not in the total).
    pub unpriced: i64,
    /// True once every place is `done`.
    pub done: bool,
}

#[utoipa::path(get, path = "/imports/{run}/learning", operation_id = "brainImportLearning", tag = "brain",
    params(("run" = String, Path, description = "Run id")),
    responses((status = 200, description = "Per place: progress, what it learned, the account used and the cost so far; plus the running total. Distillation is a mandatory step of the import (D-26)", body = Learning)))]
pub(crate) async fn get(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(run): Path<String>,
) -> ApiResult<Learning> {
    run_state(&app, &run).await?;
    let rows = sqlx::query(
        "SELECT r.id AS room, r.name AS name, \
                (SELECT count(*) FROM brain_seen s WHERE s.room = r.id AND s.run = ?1) AS sources, \
                coalesce(sum(CASE WHEN d.state = 'done' THEN d.sources END), 0) AS read, \
                coalesce(sum(CASE WHEN d.state = 'done' THEN d.candidates END), 0) AS learned, \
                coalesce(sum(d.state IN ('queued','running')), 0) AS active, \
                coalesce(sum(d.state IN ('waiting','needs_local_model')), 0) AS waiting, \
                coalesce(sum(d.state = 'done'), 0) AS finished, \
                coalesce(sum(a.cost_usd_micros), 0) AS cost, \
                coalesce(sum(a.id IS NOT NULL AND a.cost_usd_micros IS NULL), 0) AS unpriced, \
                (SELECT json_extract(a2.chain, '$[' || coalesce(a2.chain_pos, 0) || '].provider') \
                   FROM brain_distils d2 JOIN core_agent_sessions a2 ON a2.id = d2.session \
                  WHERE d2.room = r.id AND d2.created_at >= (SELECT started_at FROM brain_import_runs WHERE id = ?1) \
                  ORDER BY d2.created_at DESC LIMIT 1) AS provider \
         FROM brain_rooms r \
         LEFT JOIN brain_distils d ON d.room = r.id \
              AND d.created_at >= (SELECT started_at FROM brain_import_runs WHERE id = ?1) \
         LEFT JOIN core_agent_sessions a ON a.id = d.session \
         WHERE r.id IN (SELECT room FROM brain_seen WHERE run = ?1) \
         GROUP BY r.id ORDER BY lower(r.name)",
    )
    .bind(&run)
    .fetch_all(&app.pool)
    .await?;
    let (mut places, mut total, mut unpriced) = (vec![], 0, 0);
    for r in rows {
        let (active, waiting, finished): (i64, i64, i64) = (
            r.try_get("active")?,
            r.try_get("waiting")?,
            r.try_get("finished")?,
        );
        let cost: i64 = r.try_get("cost")?;
        total += cost;
        unpriced += r.try_get::<i64, _>("unpriced")?;
        let room: String = r.try_get("room")?;
        let left = left_in(&app, &b, &room).await;
        let retry = {
            let mut c = app.pool.acquire().await?;
            crate::retry::retry_at(&mut c, &room).await?
        };
        let state = state_of(active, waiting, finished, retry.is_some(), left);
        let failure: Option<String> = if state == "failed" {
            sqlx::query_scalar(
                "SELECT detail FROM brain_distils WHERE room = ? AND state = 'failed' \
                 ORDER BY updated_at DESC LIMIT 1",
            )
            .bind(&room)
            .fetch_optional(&app.pool)
            .await?
        } else {
            None
        };
        places.push(LearningPlace {
            room,
            name: r.try_get("name")?,
            sources: r.try_get("sources")?,
            read: r.try_get("read")?,
            learned: r.try_get("learned")?,
            state: state.to_owned(),
            left,
            retry_at: retry.filter(|_| state == "failed").map(iso_of_unix),
            failure,
            provider: r.try_get("provider")?,
            cost_usd_micros: cost,
        });
    }
    let done = !places.is_empty() && places.iter().all(|p| p.state == "done");
    Ok(Json(Learning {
        run,
        places,
        total_cost_usd_micros: total,
        unpriced,
        done,
    }))
}

/// The room's sources still to distil (as the sweep counts them); `None` when its file cannot be read.
async fn left_in(app: &App, b: &Brain, room: &str) -> Option<i64> {
    let pool = crate::distil::canon(app, b, room).await.ok()?;
    let n =
        sqlx::query_scalar("SELECT count(*) FROM sources WHERE distilled IS NULL AND pointer = 0")
            .fetch_one(&pool)
            .await
            .ok();
    pool.close().await;
    n
}

/// A place is `learning` while a distil runs or is queued, or between two distils while sources
/// are left; `waiting` when one waits on an account or a runner; `failed` when its latest distil
/// failed and sources are left; `done` once every source is read and nothing is open; else
/// `pending`. With `left` unknown, `done` once one finished.
pub(crate) fn state_of(
    active: i64,
    waiting: i64,
    finished: i64,
    failed: bool,
    left: Option<i64>,
) -> &'static str {
    let more = left.map_or(finished == 0, |n| n > 0);
    if active > 0 {
        "learning"
    } else if waiting > 0 {
        "waiting"
    } else if failed && more {
        "failed"
    } else if more && finished > 0 {
        "learning"
    } else if more {
        "pending"
    } else {
        "done"
    }
}

#[cfg(test)]
mod tests {
    use super::state_of;

    #[test]
    fn a_place_is_done_only_when_every_source_is_read_and_none_is_open() {
        assert_eq!(state_of(1, 0, 3, false, Some(9)), "learning");
        assert_eq!(state_of(0, 1, 0, false, Some(9)), "waiting");
        // 151 of 1,250 read, nothing open between two distils: still learning, never done.
        assert_eq!(state_of(0, 0, 41, false, Some(1_099)), "learning");
        assert_eq!(state_of(0, 0, 41, true, Some(1_099)), "failed");
        assert_eq!(state_of(0, 0, 0, true, Some(5)), "failed");
        assert_eq!(state_of(0, 0, 42, true, Some(0)), "done");
        assert_eq!(state_of(0, 0, 2, false, Some(0)), "done");
        assert_eq!(state_of(0, 0, 0, false, Some(3)), "pending");
        assert_eq!(state_of(0, 0, 2, false, None), "done");
        assert_eq!(state_of(0, 0, 0, false, None), "pending");
    }
}
