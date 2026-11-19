//! The import's Learn step (E9-4, 17-brain-import): per place, how far its distillation is, what
//! it learned and which account did the work, and the running cost. Counts, ids and the Core's own
//! numbers only: no source or record text. Read from the control plane; no room file is opened.
//!
//! A place's rooms are the rooms the run put sources in (`brain_seen.run`); its distillations are
//! those rooms' distils created since the run started. Cost is the sum of their sessions'
//! `cost_usd_micros`; a session with no price yet is counted in `unpriced`, never as zero.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiResult;
use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use sqlx::Row;
use utoipa::ToSchema;

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
    /// `pending`, `learning`, `waiting` (needs an account or a runner) or `done`.
    pub state: String,
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
pub(crate) async fn get(State(app): State<App>, Path(run): Path<String>) -> ApiResult<Learning> {
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
        places.push(LearningPlace {
            room: r.try_get("room")?,
            name: r.try_get("name")?,
            sources: r.try_get("sources")?,
            read: r.try_get("read")?,
            learned: r.try_get("learned")?,
            state: state_of(active, waiting, finished).to_owned(),
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

/// A place is `learning` while a distil runs or is queued, `waiting` when one waits on an account
/// or a runner, `done` once one finished and nothing is open, else `pending`.
pub(crate) fn state_of(active: i64, waiting: i64, finished: i64) -> &'static str {
    if active > 0 {
        "learning"
    } else if waiting > 0 {
        "waiting"
    } else if finished > 0 {
        "done"
    } else {
        "pending"
    }
}

#[cfg(test)]
mod tests {
    use super::state_of;

    #[test]
    fn a_place_is_done_only_when_one_finished_and_none_is_open() {
        assert_eq!(state_of(1, 0, 3), "learning");
        assert_eq!(state_of(0, 1, 0), "waiting");
        assert_eq!(state_of(0, 0, 2), "done");
        assert_eq!(state_of(0, 0, 0), "pending");
    }
}
