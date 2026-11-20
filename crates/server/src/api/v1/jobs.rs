//! Heavy jobs (E15 §5.3): a command the Core sends to other hardware, its output stream and its
//! controls. Reading is `read`; starting, signalling, cancelling and the stream are `terminal`
//! and need the app unlock, as a terminal does. Events: `job.queued|started|ended {id, project,
//! device}`.
//!
//! F0: the contract and stubs (an empty list, 404 for one job, 501 for the rest) so the App lane
//! has fixtures. The E15-3 lane fills them (`heavy/run.rs`).

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::types::Timestamp;
use super::{ApiError, ApiResult};

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
pub async fn create(Json(_): Json<NewJob>) -> Response {
    not_yet().into_response()
}

#[utoipa::path(get, path = "/api/v1/jobs", operation_id = "listJobs", tag = "jobs",
    params(JobsQuery),
    responses((status = 200, description = "Jobs, newest first. Needs `read`", body = Vec<Job>)))]
pub async fn list(Query(_): Query<JobsQuery>) -> ApiResult<Vec<Job>> {
    Ok(Json(Vec::new()))
}

#[utoipa::path(get, path = "/api/v1/jobs/{id}", operation_id = "getJob", tag = "jobs",
    params(("id" = String, Path, description = "`j_…`")),
    responses((status = 200, description = "One job. Needs `read`", body = Job)))]
pub async fn get(Path(_): Path<String>) -> ApiResult<Job> {
    Err(ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "no such job",
    ))
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
pub async fn runner_create(Json(_): Json<RunnerNewJob>) -> Response {
    not_yet().into_response()
}

#[utoipa::path(post, path = "/api/v1/runner/jobs/{job}/signal", operation_id = "runnerSignalJob",
    tag = "jobs", request_body = JobSignal, params(("job" = String, Path, description = "`j_…`")),
    responses((status = 204, description = "A signal the shim forwarded; a second `INT` cancels. \
        Built-in runner only")))]
pub async fn runner_signal(Path(_): Path<String>, Json(_): Json<JobSignal>) -> Response {
    not_yet().into_response()
}

#[utoipa::path(post, path = "/api/v1/runner/jobs/report", operation_id = "runnerReportJob",
    tag = "jobs", request_body = RunnerJobReport,
    responses((status = 204, description = "A local run's outcome, for the command history. \
        Built-in runner only")))]
pub async fn runner_report(Json(_): Json<RunnerJobReport>) -> Response {
    not_yet().into_response()
}
