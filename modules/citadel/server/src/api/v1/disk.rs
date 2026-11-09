//! A runner's disk (E15.9, 10-runners): its last report, split into build caches, mirrors,
//! active and idle worktrees, each idle worktree with how long until it is removed.

use citadel_core::exec::RunnerId;
use citadel_core::settings::{Key, Scope};
use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use utoipa::ToSchema;

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult};
use crate::api::App;
use crate::store::{exec, settings};

/// A runner's disk use as it last reported it, against its settings.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunnerDisk {
    pub runner_id: i64,
    pub measured_at: Timestamp,
    /// Everything under its work root.
    pub used_bytes: u64,
    /// `runner.disk_cap_bytes`, and the share of it past which idle worktrees are evicted.
    pub cap_bytes: u64,
    pub evict_percent: u32,
    /// Shared build caches (one per repo), and the bare repo mirrors (never evicted).
    pub caches_bytes: u64,
    pub mirrors_bytes: u64,
    pub active_bytes: u64,
    pub idle_bytes: u64,
    /// Over the cap with nothing left to evict: it needs a person.
    pub full: bool,
    /// `workspace.idle_secs`: how long a worktree may sit idle before it is removed.
    pub idle_limit_secs: u64,
    /// Oldest use first.
    pub worktrees: Vec<WorktreeDisk>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorktreeDisk {
    pub issue_id: i64,
    pub bytes: u64,
    /// A run is using it: never evicted.
    pub active: bool,
    pub idle_secs: u64,
    /// Seconds until it is removed for idleness, as of the report; absent while active.
    pub removed_in_secs: Option<u64>,
}

#[utoipa::path(get, path = "/api/v1/runners/{id}/disk", operation_id = "getRunnerDisk",
    tag = "org", params(("id" = i64, Path, description = "Runner id")),
    responses((status = 200, description = "The runner's disk use as it last reported it",
        body = RunnerDisk), (status = 404, description = "No such runner, or no report yet")))]
pub async fn get_disk(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<RunnerDisk> {
    let runner = RunnerId(id);
    let (report, at) = exec::runner_disk(&app.pool, runner)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no disk report from runner {id}")))?;
    let mine = Scope::Runner(runner);
    let idle_limit = settings::value(&app.pool, Key::WorkspaceIdleSecs, mine).await? as u64;
    let evict = settings::value(&app.pool, Key::DiskEvictPercent, mine).await? as u32;
    let sum = |active: bool| -> u64 {
        let all = report.worktrees.iter().filter(|w| w.active == active);
        all.map(|w| w.bytes).sum()
    };
    Ok(Json(RunnerDisk {
        runner_id: id,
        measured_at: ts(&at),
        used_bytes: report.used_bytes,
        cap_bytes: report.cap_bytes,
        evict_percent: evict,
        caches_bytes: report.caches_bytes,
        mirrors_bytes: report.mirrors_bytes,
        active_bytes: sum(true),
        idle_bytes: sum(false),
        full: report.full,
        idle_limit_secs: idle_limit,
        worktrees: report
            .worktrees
            .iter()
            .map(|w| WorktreeDisk {
                issue_id: w.issue,
                bytes: w.bytes,
                active: w.active,
                idle_secs: w.idle_secs,
                removed_in_secs: (!w.active).then(|| idle_limit.saturating_sub(w.idle_secs)),
            })
            .collect(),
    }))
}
