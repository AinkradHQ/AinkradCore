//! Heavy jobs (E15 §5.3): a command the Core sends to other hardware, its output stream and its
//! controls. Reading is `read`; starting, signalling, cancelling and the stream are `terminal`
//! and need the app unlock, as a terminal does. Events: `job.queued|started|ended {id, project,
//! device}`.
//!
//! F0: the contract and stubs (an empty list, 404 for one job, 501 for the rest) so the App lane
//! has fixtures. The E15-3 lane fills them (`heavy/run.rs`).

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::types::{Timestamp, opt_ts, ts};
use super::{ApiError, ApiResult, Caller};
use crate::api::App;
use crate::heavy::decide::{Decision, Deps, decide as heavy_decide};
use crate::heavy::{history, rules};

/// Why the Core put a job where it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobPlaceReason {
    Core,
    Overflow,
    Runner,
    ThisMac,
    /// No other machine could take it (`Job.missing` says what was missing).
    CoreNoFit,
    Pinned,
}

/// Which step of the decision made the command heavy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobTier {
    Rule,
    History,
    Decision,
    /// A `task` run configuration.
    Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    /// Files going to the machine, or coming back.
    Syncing,
    Running,
    Ended,
    Failed,
    Cancelled,
    /// Its machine went away and it was not re-run.
    Lost,
}

/// One job.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Job {
    /// `j_…`.
    pub id: String,
    /// The project id; absent for a job of a session with no project.
    pub project: Option<i64>,
    /// The AI session (`as_…`) it came from.
    pub session: Option<String>,
    /// The terminal it came from.
    pub terminal: Option<String>,
    /// What it runs, `cargo build`.
    pub label: String,
    /// The device it runs on, `d_…`.
    pub device: String,
    pub device_name: String,
    pub place_reason: JobPlaceReason,
    /// With `core_no_fit`: what no other machine had (`xcode`, `os macos`).
    pub missing: Option<String>,
    pub tier: JobTier,
    pub state: JobState,
    pub exit_code: Option<i32>,
    /// Files the Core kept over the machine's version (`.ainkrad/conflicts/<job>/`).
    pub conflicts: u32,
    pub created_at: Timestamp,
    pub started_at: Option<Timestamp>,
    pub ended_at: Option<Timestamp>,
    pub duration_ms: Option<u64>,
}

/// `POST /jobs`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NewJob {
    pub project: Option<i64>,
    pub session: Option<String>,
    pub argv: Vec<String>,
    /// A wire path relative to the project or session folder; empty is its root.
    #[serde(default)]
    pub cwd_rel: String,
    /// Allow-listed variable names to values.
    pub env: Option<BTreeMap<String, String>>,
    /// The caller is a terminal: an interactive command answers 409 `interactive`.
    #[serde(default)]
    pub tty: bool,
}

/// The 200 answer of `POST /jobs`: run it where you are.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JobLocal {
    /// Always `local`.
    pub verdict: String,
    /// Why (`light`, `rule`, `no_hardware`, ...).
    pub reason: String,
    /// Report the local run's outcome and duration (`POST /runner/jobs/report`, the shim's `done`
    /// frame), for the command history.
    pub report: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JobSignal {
    /// `INT`, `TERM` or `KILL`.
    pub signal: String,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
// Read by the E15-3 handler; the F0 stub answers an empty list.
#[allow(dead_code)]
pub struct JobsQuery {
    pub project: Option<i64>,
    pub session: Option<String>,
    /// One `JobState`.
    pub state: Option<String>,
    /// At most this many, newest first (default 50, at most 200).
    pub limit: Option<u32>,
}

fn not_yet() -> ApiError {
    ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        "not_implemented",
        "heavy jobs arrive with E15-3",
    )
}

#[utoipa::path(post, path = "/api/v1/jobs", operation_id = "createJob", tag = "jobs",
    request_body = NewJob,
    responses(
        (status = 201, description = "The command was placed on other hardware", body = Job),
        (status = 200, description = "Run it locally, and why", body = JobLocal),
        (status = 409, description = "`interactive`: a tty and an interactive command run locally")))]
pub async fn create(State(app): State<App>, Json(req): Json<NewJob>) -> Response {
    let asked = Asked {
        project: req.project,
        session: req.session,
        argv: req.argv,
        cwd_rel: req.cwd_rel,
        tty: req.tty,
    };
    answer(&app, asked)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

#[utoipa::path(get, path = "/api/v1/jobs", operation_id = "listJobs", tag = "jobs",
    params(JobsQuery),
    responses((status = 200, description = "Jobs, newest first. Needs `read`", body = Vec<Job>)))]
pub async fn list(State(app): State<App>, Query(q): Query<JobsQuery>) -> ApiResult<Vec<Job>> {
    let limit = i64::from(q.limit.unwrap_or(50).clamp(1, 200));
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "{SELECT} WHERE (?1 IS NULL OR j.project_id = ?1) AND (?2 IS NULL OR j.session_id = ?2) \
         AND (?3 IS NULL OR j.state = ?3) ORDER BY j.created_at DESC, j.id DESC LIMIT ?4"
    ))
    .bind(q.project)
    .bind(q.session)
    .bind(q.state)
    .bind(limit)
    .fetch_all(&app.pool)
    .await?;
    Ok(Json(rows.into_iter().map(Job::from).collect()))
}

#[utoipa::path(get, path = "/api/v1/jobs/{id}", operation_id = "getJob", tag = "jobs",
    params(("id" = String, Path, description = "`j_…`")),
    responses((status = 200, description = "One job. Needs `read`", body = Job)))]
pub async fn get(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Job> {
    let row: Option<Row> = sqlx::query_as(&format!("{SELECT} WHERE j.id = ?"))
        .bind(&id)
        .fetch_optional(&app.pool)
        .await?;
    row.map(|r| Json(Job::from(r)))
        .ok_or_else(|| ApiError::not_found("no such job"))
}

#[utoipa::path(get, path = "/api/v1/jobs/{id}/stream", operation_id = "streamJob", tag = "jobs",
    params(("id" = String, Path, description = "`j_…`")),
    responses((status = 101, description = "Job WebSocket: `out`, `state` and `exit` frames, \
        replaying up to 4 MiB")))]
pub async fn stream(Path(_): Path<String>) -> Response {
    not_yet().into_response()
}

#[utoipa::path(post, path = "/api/v1/jobs/{id}/signal", operation_id = "signalJob", tag = "jobs",
    request_body = JobSignal, params(("id" = String, Path, description = "`j_…`")),
    responses((status = 204, description = "The signal was delivered to the job's process group")))]
pub async fn signal(Path(_): Path<String>, Json(_): Json<JobSignal>) -> Response {
    not_yet().into_response()
}

#[utoipa::path(delete, path = "/api/v1/jobs/{id}", operation_id = "cancelJob", tag = "jobs",
    params(("id" = String, Path, description = "`j_…`")),
    responses((status = 204, description = "Cancelled: TERM, then KILL after 10 s; nothing is \
        synced back")))]
pub async fn cancel(Path(_): Path<String>) -> Response {
    not_yet().into_response()
}

/// `POST /runner/jobs`: what the built-in runner forwards from a shim, with the origin it stamped
/// (the sandbox the socket belongs to, never the shim's word).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RunnerNewJob {
    /// The AI session (`as_…`) whose sandbox the shim ran in.
    pub session: Option<String>,
    /// The Core terminal it ran in.
    pub terminal: Option<String>,
    pub project: Option<i64>,
    pub argv: Vec<String>,
    /// A wire path relative to the session or project folder (the runner maps the shim's `cwd`).
    #[serde(default)]
    pub cwd_rel: String,
    pub env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub tty: bool,
}

/// `POST /runner/jobs/report`: a local run the Core said to report (`JobLocal.report`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RunnerJobReport {
    pub session: Option<String>,
    pub terminal: Option<String>,
    pub project: Option<i64>,
    pub argv: Vec<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub duration_ms: u64,
}

#[utoipa::path(post, path = "/api/v1/runner/jobs", operation_id = "runnerCreateJob", tag = "jobs",
    request_body = RunnerNewJob,
    responses(
        (status = 201, description = "Placed on other hardware. Only the built-in runner may call it \
            (`runner` scope)", body = Job),
        (status = 200, description = "Run it locally, and why", body = JobLocal),
        (status = 409, description = "`interactive`")))]
pub async fn runner_create(
    State(app): State<App>,
    Extension(caller): Extension<Caller>,
    Json(req): Json<RunnerNewJob>,
) -> Response {
    if let Err(e) = built_in(&app, &caller).await {
        return e.into_response();
    }
    let asked = Asked {
        project: req.project,
        session: req.session,
        argv: req.argv,
        cwd_rel: req.cwd_rel,
        tty: req.tty,
    };
    answer(&app, asked)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

#[utoipa::path(post, path = "/api/v1/runner/jobs/{job}/signal", operation_id = "runnerSignalJob",
    tag = "jobs", request_body = JobSignal, params(("job" = String, Path, description = "`j_…`")),
    responses((status = 204, description = "A signal the shim forwarded; a second `INT` cancels. \
        Built-in runner only")))]
pub async fn runner_signal(
    State(app): State<App>,
    Extension(caller): Extension<Caller>,
    Path(_job): Path<String>,
    Json(_): Json<JobSignal>,
) -> Response {
    if let Err(e) = built_in(&app, &caller).await {
        return e.into_response();
    }
    // E15-3 step 2: `heavy/run.rs` owns the live jobs; until it is wired no job can be running.
    ApiError::not_found("no such job").into_response()
}

#[utoipa::path(post, path = "/api/v1/runner/jobs/report", operation_id = "runnerReportJob",
    tag = "jobs", request_body = RunnerJobReport,
    responses((status = 204, description = "A local run's outcome, for the command history. \
        Built-in runner only")))]
pub async fn runner_report(
    State(app): State<App>,
    Extension(caller): Extension<Caller>,
    Json(r): Json<RunnerJobReport>,
) -> Response {
    if let Err(e) = built_in(&app, &caller).await {
        return e.into_response();
    }
    // Only a clean run says how long the command takes; a failed or killed one ends early.
    if let (Some(project), Some(0)) = (r.project, r.exit_code) {
        let key = history::cmd_key(&r.argv);
        let ms = i64::try_from(r.duration_ms).unwrap_or(i64::MAX);
        if let Err(e) = history::record(&app.pool, project, &key, ms, &app.clock.now()).await {
            return ApiError::from(e).into_response();
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// What a request to run a command asks.
struct Asked {
    project: Option<i64>,
    session: Option<String>,
    argv: Vec<String>,
    cwd_rel: String,
    tty: bool,
}

/// The user's settings are not wired yet: a model must be this sure before a job leaves the Core.
const MIN_CONFIDENCE: f32 = 0.7;

fn local(reason: &str, report: bool) -> Response {
    Json(JobLocal {
        verdict: "local".to_owned(),
        reason: reason.to_owned(),
        report,
    })
    .into_response()
}

/// Only the Core's own runner (the one the installer enrolled) may call the runner routes.
async fn built_in(app: &App, caller: &Caller) -> Result<(), ApiError> {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT device_id FROM core_pairings WHERE kind = 'runner' AND sas = ? AND device_id = ?",
    )
    .bind(crate::store::gov::LOCAL_ENROL_SAS)
    .bind(&caller.device.id)
    .fetch_optional(&app.pool)
    .await?;
    found.map(|_| ()).ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "not_built_in",
            "only the Core's own runner may call this",
        )
    })
}

/// Tiers 0 to 3 for one request. Placing and running a heavy job is `heavy/run.rs` (step 2).
async fn answer(app: &App, a: Asked) -> Result<Response, ApiError> {
    if a.argv.is_empty() || a.argv.len() > 256 || a.argv[0].is_empty() {
        return Err(ApiError::bad_request(
            "argv is one to 256 words, the first a program",
        ));
    }
    if !a.cwd_rel.is_empty() && ainkrad_proto::v2::wire_path_problem(&a.cwd_rel).is_some() {
        return Ok(local("bad_cwd", false));
    }
    // A session's commands belong to the project the session is in.
    let project = match (a.project, &a.session) {
        (None, Some(session)) => sqlx::query_scalar::<_, Option<i64>>(
            "SELECT project_id FROM core_agent_sessions WHERE id = ?",
        )
        .bind(session)
        .fetch_optional(&app.pool)
        .await?
        .flatten(),
        (p, _) => p,
    };
    let a = Asked { project, ..a };
    let ws = crate::heavy::workspace();
    let (rules, dir) = match a.project {
        Some(p) => {
            let toml = tokio::fs::read_to_string(ws.jobs_toml(p))
                .await
                .unwrap_or_default();
            let base = ws
                .project_meta(p)
                .parent()
                .map(std::path::Path::to_path_buf);
            (
                rules::parse_project(&toml),
                base.map(|b| b.join(&a.cwd_rel)),
            )
        }
        None => (Vec::new(), None),
    };
    let decider = crate::decisions::Stub;
    let deps = Deps {
        pool: &app.pool,
        decide: &decider,
        user: ainkrad_core::ids::UserId(1),
        min_confidence: MIN_CONFIDENCE,
    };
    let dir = dir.unwrap_or_default();
    Ok(
        match heavy_decide(&deps, a.project, &a.argv, a.tty, &rules, &dir).await {
            Decision::Interactive => {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "interactive",
                    "a terminal user is waiting on this command: run it where it was typed",
                ));
            }
            Decision::Local { reason, report } => local(reason, report),
            // E15-3 step 2 places the job and streams it. Until `heavy/run.rs` exists nothing can
            // take it, and the command runs where it was typed.
            Decision::Heavy { .. } => local("no_hardware", true),
        },
    )
}

/// `core_hw_jobs` joined with the device's name, as `Job` reads it.
const SELECT: &str = "SELECT j.id, j.project_id, j.session_id, j.terminal_id, j.argv, j.device_id, \
    d.name AS device_name, j.place_reason, j.tier, j.state, j.exit_code, j.conflicts, j.created_at, \
    j.started_at, j.ended_at, j.duration_ms \
    FROM core_hw_jobs j JOIN core_devices d ON d.id = j.device_id";

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    project_id: Option<i64>,
    session_id: Option<String>,
    terminal_id: Option<String>,
    argv: String,
    device_id: String,
    device_name: String,
    place_reason: String,
    tier: String,
    state: String,
    exit_code: Option<i64>,
    conflicts: i64,
    created_at: String,
    started_at: Option<String>,
    ended_at: Option<String>,
    duration_ms: Option<i64>,
}

/// A stored word as its enum (`serde` snake_case), else the enum's default reading.
fn word<T: serde::de::DeserializeOwned>(s: &str, fallback: T) -> T {
    serde_json::from_value(serde_json::Value::String(s.to_owned())).unwrap_or(fallback)
}

impl From<Row> for Job {
    fn from(r: Row) -> Self {
        let words: Vec<String> = serde_json::from_str(&r.argv).unwrap_or_default();
        // `core_no_fit:xcode` is the reason `core_no_fit` and what was missing.
        let (reason, missing) = match r.place_reason.split_once(':') {
            Some((a, m)) => (a.to_owned(), Some(m.to_owned())),
            None => (r.place_reason.clone(), None),
        };
        Job {
            id: r.id,
            project: r.project_id,
            session: r.session_id,
            terminal: r.terminal_id,
            label: words.iter().take(3).cloned().collect::<Vec<_>>().join(" "),
            device: r.device_id,
            device_name: r.device_name,
            place_reason: word(&reason, JobPlaceReason::Core),
            missing,
            tier: word(&r.tier, JobTier::Rule),
            state: word(&r.state, JobState::Lost),
            exit_code: r.exit_code.and_then(|c| i32::try_from(c).ok()),
            conflicts: u32::try_from(r.conflicts).unwrap_or(0),
            created_at: ts(&r.created_at),
            started_at: opt_ts(r.started_at.as_deref()),
            ended_at: opt_ts(r.ended_at.as_deref()),
            duration_ms: r.duration_ms.and_then(|d| u64::try_from(d).ok()),
        }
    }
}
