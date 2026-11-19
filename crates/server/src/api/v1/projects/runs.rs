//! Running a project over the API (Core 0.9, P5-03; orchestration in `crate::runs`). Reading a
//! run, and saying a viewer is looking at it, is `read`; start, stop and restart are `admin` and
//! destructive (a step-up): they start and stop containers on a runner. A start answers at once
//! with the run `starting`; the run reaches `running` or `failed` in the background, so clients
//! read it again. A second start while a run is live is a 409.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use utoipa::ToSchema;

use super::super::types::{Timestamp, opt_ts, ts};
use super::super::{ApiError, ApiResult, Caller};
use super::{num, who};
use crate::api::App;
use crate::runs::{self, HubLink, Link, StartOpts};
use crate::store::audit::origin;
use crate::store::projects as projects_store;
use crate::store::runs::{self as store, Run};
use crate::store::secrets::Error;

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectRun {
    pub id: String,
    pub spec_version: i64,
    /// The runner it is placed on.
    pub runner: String,
    /// `starting`, `running`, `stopping`, `stopped` or `failed`.
    pub state: String,
    /// Why it ended, or is ending: `user`, `idle`, `crash`, `runner_lost`, `replaced` or
    /// `start_failed`.
    pub stop_reason: Option<String>,
    /// What went wrong, for a failed run (redacted).
    pub error: Option<String>,
    pub started_by: String,
    pub started_at: Timestamp,
    pub stopped_at: Option<Timestamp>,
    pub last_activity_at: Option<Timestamp>,
    /// When the idle stop is due, for a running run.
    pub idle_stop_at: Option<Timestamp>,
    /// The run configuration it started from, when it did (Core 0.10).
    #[schema(required = false)]
    pub config_id: Option<i64>,
    /// The environment it ran in.
    #[schema(required = false)]
    pub environment: Option<String>,
}

/// `idle` is the project's idle stop in minutes, `None` when it never stops for idleness.
fn view(r: Run, idle: Option<i64>) -> ProjectRun {
    let due = idle.and_then(|m| runs::idle_due(&r, m));
    ProjectRun {
        id: r.id,
        spec_version: r.spec_version,
        runner: r.runner,
        state: r.state,
        stop_reason: r.stop_reason,
        error: r.error,
        started_by: r.started_by,
        started_at: ts(&r.started_at),
        stopped_at: opt_ts(r.stopped_at.as_deref()),
        last_activity_at: opt_ts(r.last_activity_at.as_deref()),
        idle_stop_at: opt_ts(due.as_deref()),
        config_id: r.config_id,
        environment: r.environment,
    }
}

async fn shown(app: &App, r: Run) -> Result<ProjectRun, ApiError> {
    let mut conn = app.pool.acquire().await?;
    let p = projects_store::get(&mut conn, r.project_id).await?;
    Ok(view(r, (!p.idle_never).then_some(p.idle_minutes)))
}

/// `runner_error` (the runner refused or did not answer) is a 502; the rest as the broker maps it.
fn err(e: Error) -> ApiError {
    match e {
        Error::Refused {
            code: "runner_error",
            message,
        } => ApiError::new(StatusCode::BAD_GATEWAY, "runner_error", message),
        e => e.into(),
    }
}

fn link(app: &App) -> Arc<dyn Link> {
    Arc::new(HubLink(Arc::clone(&app.hub)))
}

async fn start_now(app: &App, me: &Caller, id: i64) -> Result<ProjectRun, ApiError> {
    start_opts(app, me, id, &StartOpts::default()).await
}

/// A start from a run configuration (`replace` stops a live run first).
pub async fn start_with(
    app: &App,
    me: &Caller,
    id: i64,
    opts: &StartOpts,
    replace: bool,
) -> Result<ProjectRun, ApiError> {
    if replace {
        // Only that configuration's live run: the others keep running.
        let now = app.clock.now();
        runs::replace_config(app, &*link(app), id, opts.config, who(me, &now))
            .await
            .map_err(err)?;
    }
    start_opts(app, me, id, opts).await
}

async fn start_opts(
    app: &App,
    me: &Caller,
    id: i64,
    opts: &StartOpts,
) -> Result<ProjectRun, ApiError> {
    let now = app.clock.now();
    let link = link(app);
    let pending = runs::begin_start_with(app, &*link, id, opts, who(me, &now))
        .await
        .map_err(err)?;
    let idle = (!pending.project.idle_never).then_some(pending.project.idle_minutes);
    let out = view(pending.run.clone(), idle);
    let proof = app.hub.admin_elevation(me);
    // A task local does not cross a spawn: carry the request's origin to the run's last audit row.
    let (app, o) = (app.clone(), origin::current());
    tokio::spawn(origin::scope(o, async move {
        runs::drive_start(&app, &*link, pending, proof).await;
    }));
    Ok(out)
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/run", operation_id = "getProjectRun",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "The project's live run, else its newest. 404 for no \
        such project or when it never ran", body = ProjectRun)))]
pub async fn status(State(app): State<App>, Path(id): Path<String>) -> ApiResult<ProjectRun> {
    let id = num(&id, "project")?;
    let mut conn = app.pool.acquire().await?;
    projects_store::get(&mut conn, id).await.map_err(err)?;
    drop(conn);
    let run = store::latest(&app.pool, id)
        .await?
        .ok_or_else(|| ApiError::not_found("the project has never run"))?;
    Ok(Json(shown(&app, run).await?))
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/run/start", operation_id = "startProjectRun",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "The run, `starting` (audited and emitted as \
        `project.run_started`); it then becomes `running` or `failed`. 404 for no such project \
        or no run spec; 409 `conflict` when the project is archived or already has a live run, \
        409 `no_runner` when no online runner can run projects", body = ProjectRun)))]
pub async fn start(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<ProjectRun> {
    Ok(Json(start_now(&app, &me, num(&id, "project")?).await?))
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/run/stop", operation_id = "stopProjectRun",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "The run, `stopped` (audited and emitted as \
        `project.run_stopped`). 404 for no such project or no live run; 502 `runner_error` when \
        the runner refused: the run stays `stopping` and the Core retries", body = ProjectRun)))]
pub async fn stop(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<ProjectRun> {
    let now = app.clock.now();
    let r = runs::stop(
        &app,
        &*link(&app),
        num(&id, "project")?,
        "user",
        who(&me, &now),
    )
    .await
    .map_err(err)?;
    Ok(Json(shown(&app, r).await?))
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/runs/{run}/stop",
    operation_id = "stopProjectRunById", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("run" = String, Path, description = "The run's id")),
    responses((status = 200, description = "That run, `stopped` (as `stopProjectRun`, for one of \
        several live runs). 404 for no such project or when the run is not a live run of it; 502 \
        `runner_error` as `stopProjectRun`", body = ProjectRun)))]
pub async fn stop_run(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, run)): Path<(String, String)>,
) -> ApiResult<ProjectRun> {
    let now = app.clock.now();
    let r = runs::stop_run(
        &app,
        &*link(&app),
        num(&id, "project")?,
        &run,
        "user",
        who(&me, &now),
    )
    .await
    .map_err(err)?;
    Ok(Json(shown(&app, r).await?))
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/run/restart",
    operation_id = "restartProjectRun", tag = "projects",
    params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "The live run, if any, is stopped (reason `replaced`) \
        and a new one starts: the new run, `starting`. Errors as start and stop", body = ProjectRun)))]
pub async fn restart(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<ProjectRun> {
    let id = num(&id, "project")?;
    let now = app.clock.now();
    runs::replace(&app, &*link(&app), id, who(&me, &now))
        .await
        .map_err(err)?;
    Ok(Json(start_now(&app, &me, id).await?))
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/run/activity",
    operation_id = "touchProjectRun", tag = "projects",
    params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "A viewer is on the project's Run tab: the idle stop \
        is pushed back. The run as it now is; 404 for no such project or when it never ran",
        body = ProjectRun)))]
pub async fn activity(State(app): State<App>, Path(id): Path<String>) -> ApiResult<ProjectRun> {
    let pid = num(&id, "project")?;
    store::touch(&app.pool, pid, &app.clock.now()).await?;
    status(State(app), Path(id)).await
}

#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HistoryQuery {
    /// How many runs, newest first; default 20, at most 100.
    pub limit: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/runs", operation_id = "listProjectRuns",
    tag = "projects",
    params(("id" = String, Path, description = "The project's id"), HistoryQuery),
    responses((status = 200, description = "The project's runs, live or finished, newest first \
        (Core 0.10). 404 for no such project", body = Vec<ProjectRun>)))]
pub async fn history(
    State(app): State<App>,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<HistoryQuery>,
) -> ApiResult<Vec<ProjectRun>> {
    let id = num(&id, "project")?;
    let mut conn = app.pool.acquire().await?;
    let p = projects_store::get(&mut conn, id).await.map_err(err)?;
    drop(conn);
    let all = store::recent(&app.pool, id, q.limit.unwrap_or(20).clamp(1, 100)).await?;
    Ok(Json(
        all.into_iter().map(|r| view(r, p.idle_minutes)).collect(),
    ))
}
