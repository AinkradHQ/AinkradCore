//! Runs and their transcripts (E11.4): an agent's runs, one run, and its transcript from a
//! chunk on. Live chunks arrive on the event stream; these reads fill in and catch up. A
//! project's stage timings (E15.6) summarise how fast its runs start.

use citadel_core::exec::RunId;
use citadel_core::org::AgentId;
use citadel_core::work::ProjectId;
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Serialize;
use utoipa::ToSchema;

use super::model::{Run, TranscriptChunk};
use super::routing::Since;
use super::types::Page;
use super::{ApiError, ApiResult, Paging};
use crate::api::App;
use crate::store::{exec, org, work};

/// Default and most runs on a page.
const RUNS_PAGE: u32 = 50;
/// Default and most transcript chunks on a page.
const CHUNKS_PAGE: u32 = 500;

#[utoipa::path(get, path = "/api/v1/agents/{id}/runs", operation_id = "listAgentRuns", tag = "runs",
    params(("id" = i64, Path, description = "Agent id"), Paging),
    responses((status = 200, description = "The agent's runs, newest first; `after` continues \
        with runs older than that id", body = Page<Run>)))]
pub async fn list_agent_runs(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(page): Query<Paging>,
) -> ApiResult<Page<Run>> {
    org::get_agent(&app.pool, AgentId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no agent {id}")))?;
    let limit = page.limit.unwrap_or(RUNS_PAGE).clamp(1, RUNS_PAGE);
    // ponytail: reads all the agent's runs, then pages; a keyset query when agents have
    // thousands of runs.
    let runs: Vec<Run> = exec::list_runs(&app.pool, AgentId(id))
        .await?
        .into_iter()
        .rev()
        .filter(|r| page.after.is_none_or(|after| r.id.0 < after))
        .take(limit as usize + 1)
        .map(Into::into)
        .collect();
    Ok(Json(Page::of(runs, limit, |r| r.id)))
}

#[utoipa::path(get, path = "/api/v1/runs/{id}", operation_id = "getRun", tag = "runs",
    params(("id" = i64, Path, description = "Run id")),
    responses((status = 200, description = "The run", body = Run)))]
pub async fn get_run(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Run> {
    let r = exec::get_run(&app.pool, RunId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no run {id}")))?;
    Ok(Json(r.into()))
}

#[utoipa::path(get, path = "/api/v1/runs/{id}/transcript", operation_id = "getTranscript",
    tag = "runs", params(("id" = i64, Path, description = "Run id"), Paging),
    responses((status = 200, description = "The run's transcript in order, from the chunk after \
        `after` (its `seq`)", body = Page<TranscriptChunk>)))]
pub async fn transcript(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(page): Query<Paging>,
) -> ApiResult<Page<TranscriptChunk>> {
    exec::get_run(&app.pool, RunId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no run {id}")))?;
    let limit = page.limit.unwrap_or(CHUNKS_PAGE).clamp(1, CHUNKS_PAGE);
    // ponytail: reads the whole transcript, then pages; a seq range query if transcripts
    // grow past a few thousand chunks.
    let chunks: Vec<TranscriptChunk> = exec::list_run_events(&app.pool, RunId(id))
        .await?
        .into_iter()
        .filter(|c| c.seq > page.after.unwrap_or(0))
        .take(limit as usize + 1)
        .map(Into::into)
        .collect();
    Ok(Json(Page::of(chunks, limit, |c| c.seq)))
}

/// One stage of a run's start over a project's runs (E15.6): how many runs reached it, and
/// its median and 95th-percentile seconds; absent with none.
#[derive(Debug, Serialize, ToSchema)]
pub struct StageStat {
    /// `wake_to_claim`, `claim_to_workspace`, `workspace_to_harness`,
    /// `harness_to_first_token`, `wake_to_first_token` or `first_token_to_end`.
    pub stage: String,
    pub runs: i64,
    pub p50_secs: Option<f64>,
    pub p95_secs: Option<f64>,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/timing", operation_id = "getRunTiming",
    tag = "runs", params(("id" = i64, Path, description = "Project id"), Since),
    responses((status = 200, description = "Each stage of its runs' start, in order", body = Vec<StageStat>)))]
pub async fn timing(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(q): Query<Since>,
) -> ApiResult<Vec<StageStat>> {
    work::get_project(&app.pool, ProjectId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no project {id}")))?;
    match exec::stage_timing(&app.pool, ProjectId(id), q.since.as_deref()).await {
        Ok(stats) => Ok(Json(
            stats
                .into_iter()
                .map(|s| StageStat {
                    stage: s.stage.to_owned(),
                    runs: s.runs as i64,
                    p50_secs: s.p50_secs,
                    p95_secs: s.p95_secs,
                })
                .collect(),
        )),
        Err(sqlx::Error::InvalidArgument(why)) => Err(ApiError::bad_request(why)),
        Err(e) => Err(e.into()),
    }
}
