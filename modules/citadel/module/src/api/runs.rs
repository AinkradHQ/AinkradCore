//! The run engine's routes (S7): list and read runs, their transcripts, the admin's controls
//! (cancel, kill, message), a manual wake, and the engine's switch.
//!
//! A run's harness is an agent session of the platform, which holds the transcript; the route
//! reads it through the Core's store. Every route that makes an agent act or stops one is a
//! step-up route (`DESTRUCTIVE`): cancel, kill, message, wake and the engine switch. The reads
//! below `admin` show ids, states and tokens only; the transcript and the engine's state stay
//! `admin`.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller, Paging};
use ainkrad_core_server::store::agents as sessions;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, OpenApi, ToSchema};

use super::error::found;
use super::scope::Acting;
use super::types::{Timestamp, opt_ts, ts};
use crate::domain::org::AgentId;
use crate::domain::work::{IssueId, RunId, WakeSource};
use crate::store::exec::{
    self as engine, ControlError, NewWakeRequest, Platform, Run, RunFilter, enqueue_wake,
};

pub fn routes() -> Router<App> {
    Router::new()
        .route("/runs", get(list_runs))
        .route("/runs/{id}", get(get_run))
        .route("/runs/{id}/transcript", get(transcript))
        .route("/runs/{id}/cancel", post(cancel))
        .route("/runs/{id}/kill", post(kill))
        .route("/runs/{id}/message", post(message))
        .route("/agents/{id}/wake", post(wake))
        .route("/engine", get(get_engine).post(set_engine))
}

pub const SCOPES: &[(&str, &str, &str)] =
    &[("GET", "/runs", "read"), ("GET", "/runs/{id}", "read")];

/// Not phone reads: a transcript holds what the agent saw and did.
pub const ADMIN_READS: &[&str] = &["/runs/{id}/transcript", "/engine"];

pub const DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/runs/{id}/cancel"),
    ("POST", "/runs/{id}/kill"),
    ("POST", "/runs/{id}/message"),
    ("POST", "/agents/{id}/wake"),
    ("POST", "/engine"),
];

/// `(path segment, SQL)` company owners of this slice's resources (`scope::OWNERS`).
pub const OWNERS: &[(&str, &str)] = &[(
    "runs",
    "SELECT a.company_id FROM citadel_runs r JOIN citadel_agents a ON a.id = r.agent_id \
     WHERE r.id = ?",
)];

#[derive(Debug, Serialize, ToSchema)]
pub struct RunOut {
    pub id: i64,
    pub agent_id: i64,
    pub issue_id: Option<i64>,
    /// The agent session (`as_...`) that is its harness.
    pub session_id: Option<String>,
    /// `queued`, `claimed`, `running`, `succeeded`, `failed`, `cancelled`, `timed_out` or `runner_lost`.
    pub state: String,
    /// Set exactly when the run is over.
    pub terminal_reason: Option<String>,
    pub harness: String,
    pub model: Option<String>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    /// Millionths of a dollar; absent while unpriced (never 0).
    pub cost_usd_micros: Option<i64>,
    pub queued_at: Timestamp,
    pub started_at: Option<Timestamp>,
    pub ended_at: Option<Timestamp>,
}

impl From<Run> for RunOut {
    fn from(r: Run) -> Self {
        Self {
            id: r.id.0,
            agent_id: r.agent_id.0,
            issue_id: r.issue_id.map(|i| i.0),
            session_id: r.session_id,
            state: r.state.as_str().to_owned(),
            terminal_reason: r.terminal_reason,
            harness: r.harness.as_str().to_owned(),
            model: r.model_used,
            input_tokens: r.usage.input_tokens,
            output_tokens: r.usage.output_tokens,
            cache_tokens: r.usage.cache_tokens,
            cost_usd_micros: r.usage.cost_usd_micros,
            queued_at: ts(&r.queued_at),
            started_at: opt_ts(r.started_at.as_deref()),
            ended_at: opt_ts(r.ended_at.as_deref()),
        }
    }
}

async fn one(app: &App, id: i64) -> Result<Run, ApiError> {
    found(engine::get_run(&app.pool, RunId(id)).await?, "run")
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RunsQuery {
    pub agent: Option<i64>,
    pub issue: Option<i64>,
    /// Only runs that are not over.
    pub live: Option<bool>,
    /// Runs with an id below this; absent, from the newest.
    pub before: Option<i64>,
    pub limit: Option<i64>,
}

#[utoipa::path(get, path = "/runs", operation_id = "listRuns", tag = "runs", params(RunsQuery),
    responses((status = 200, description = "Runs, newest first (at most `limit`, 50 by default, \
        200 at most), only those of the company in `X-Citadel-Company` when it is sent",
        body = Vec<RunOut>)))]
pub async fn list_runs(
    State(app): State<App>,
    acting: Acting,
    Query(q): Query<RunsQuery>,
) -> ApiResult<Vec<RunOut>> {
    let filter = RunFilter {
        agent: q.agent.map(AgentId),
        issue: q.issue.map(IssueId),
        live: q.live.unwrap_or(false),
    };
    let runs = engine::list_runs(&app.pool, filter, q.before, q.limit.unwrap_or(50)).await?;
    let mut out = Vec::new();
    for r in runs {
        if acting.sees(engine::run_company(&app.pool, r.id).await?) {
            out.push(r.into());
        }
    }
    Ok(Json(out))
}

#[utoipa::path(get, path = "/runs/{id}", operation_id = "getRun", tag = "runs",
    params(("id" = i64, Path, description = "Run id")),
    responses((status = 200, description = "The run", body = RunOut)))]
pub async fn get_run(State(app): State<App>, _: Acting, Path(id): Path<i64>) -> ApiResult<RunOut> {
    Ok(Json(one(&app, id).await?.into()))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TranscriptEntry {
    pub seq: u64,
    pub at_ms: i64,
    #[schema(value_type = Object)]
    pub body: Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RunTranscript {
    pub run: i64,
    /// The session's state.
    pub state: String,
    pub last_seq: i64,
    pub entries: Vec<TranscriptEntry>,
}

#[utoipa::path(get, path = "/runs/{id}/transcript", operation_id = "getRunTranscript",
    tag = "runs", params(("id" = i64, Path, description = "Run id"), Paging),
    responses((status = 200, description = "The session's entries with `seq` above `after`, \
        oldest first, at most `limit` (500 by default, 1000 at most), redacted by the platform; \
        an empty transcript for a run with no session yet", body = RunTranscript)))]
pub async fn transcript(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Query(p): Query<Paging>,
) -> ApiResult<RunTranscript> {
    let run = one(&app, id).await?;
    let Some(sid) = run.session_id else {
        return Ok(Json(RunTranscript {
            run: id,
            state: run.state.as_str().to_owned(),
            last_seq: 0,
            entries: vec![],
        }));
    };
    let s = found(sessions::get(&app.pool, &sid).await?, "session")?;
    let limit = p.limit.unwrap_or(500).clamp(1, 1000);
    let entries = sessions::transcript(&app.pool, &sid, p.after.unwrap_or(0), limit).await?;
    Ok(Json(RunTranscript {
        run: id,
        state: s.state,
        last_seq: s.last_seq,
        entries: entries
            .into_iter()
            .map(|e| TranscriptEntry {
                seq: e.seq,
                at_ms: e.at,
                body: e.body,
            })
            .collect(),
    }))
}

fn controlled(e: ControlError) -> ApiError {
    match e {
        ControlError::NotFound => ApiError::not_found("no such run"),
        ControlError::NotLive(state) => ApiError::new(
            StatusCode::CONFLICT,
            "run_not_live",
            format!("the run is not live ({})", state.as_str()),
        ),
        ControlError::Unreachable(_) => ApiError::new(
            StatusCode::BAD_GATEWAY,
            "runner_failed",
            "the runner did not take it; the request is kept and asked again",
        ),
        ControlError::Db(e) => e.into(),
    }
}

async fn stop(app: App, me: Caller, id: i64, kill: bool) -> ApiResult<RunOut> {
    let now = app.clock.now();
    let run = engine::stop_run(&app, &Platform, RunId(id), kill, &me.device.id, &now)
        .await
        .map_err(controlled)?;
    Ok(Json(run.into()))
}

#[utoipa::path(post, path = "/runs/{id}/cancel", operation_id = "cancelRun", tag = "runs",
    params(("id" = i64, Path, description = "Run id")),
    responses((status = 200, description = "Its harness finishes the tool call in flight and \
        stops; the run ends `cancelled` once the runner has acknowledged (audited as \
        `run.cancelled`). 409 `run_not_live` when it is over, 502 `runner_failed` when the \
        runner is away (the request is kept)", body = RunOut)))]
pub async fn cancel(
    State(app): State<App>,
    _: Acting,
    Extension(me): Extension<Caller>,
    Path(id): Path<i64>,
) -> ApiResult<RunOut> {
    stop(app, me, id, false).await
}

#[utoipa::path(post, path = "/runs/{id}/kill", operation_id = "killRun", tag = "runs",
    params(("id" = i64, Path, description = "Run id")),
    responses((status = 200, description = "Its harness is killed now (audited as `run.killed`)",
        body = RunOut)))]
pub async fn kill(
    State(app): State<App>,
    _: Acting,
    Extension(me): Extension<Caller>,
    Path(id): Path<i64>,
) -> ApiResult<RunOut> {
    stop(app, me, id, true).await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RunMessage {
    /// 1 byte to 16 KiB.
    pub text: String,
}

#[utoipa::path(post, path = "/runs/{id}/message", operation_id = "messageRun", tag = "runs",
    params(("id" = i64, Path, description = "Run id")), request_body = RunMessage,
    responses((status = 200, description = "Given to the harness as its next turn (audited as \
        `run.messaged`, its length only). 409 `run_not_live` unless the run is running", body = RunOut)))]
pub async fn message(
    State(app): State<App>,
    _: Acting,
    Extension(me): Extension<Caller>,
    Path(id): Path<i64>,
    Json(b): Json<RunMessage>,
) -> ApiResult<RunOut> {
    if b.text.is_empty() || b.text.len() > 16 * 1024 {
        return Err(ApiError::bad_request("a message is 1 byte to 16 KiB"));
    }
    engine::message_run(&app, &Platform, RunId(id), &b.text, &me.device.id)
        .await
        .map_err(controlled)?;
    Ok(Json(one(&app, id).await?.into()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct WakeBody {
    /// Why, for the agent: 1 to 500 characters.
    pub reason: String,
    pub issue_id: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WakeOut {
    pub id: i64,
    /// `pending`, `coalesced` (folded into a pending wake of the same agent and issue), or `dropped`.
    pub status: String,
}

#[utoipa::path(post, path = "/agents/{id}/wake", operation_id = "wakeAgent", tag = "runs",
    params(("id" = i64, Path, description = "Agent id")), request_body = WakeBody,
    responses((status = 200, description = "The wake is queued; the engine starts the run when \
        it is allowed to (the engine on, budgets, a free runner)", body = WakeOut)))]
pub async fn wake(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(b): Json<WakeBody>,
) -> ApiResult<WakeOut> {
    let reason = b.reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 {
        return Err(ApiError::bad_request("a reason is 1 to 500 characters"));
    }
    found(
        crate::store::org::get_agent(&app.pool, AgentId(id)).await?,
        "agent",
    )?;
    // A manual wake is idempotent per second, so a double tap is one wake.
    let key = format!("manual:agent:{id}:{}", app.clock.unix());
    let w = enqueue_wake(
        &app.pool,
        &NewWakeRequest {
            agent_id: AgentId(id),
            issue_id: b.issue_id.map(IssueId),
            source: WakeSource::Manual,
            reason: reason.to_owned(),
            idempotency_key: key,
            not_before: None,
        },
    )
    .await
    .map_err(super::error::refused)?;
    Ok(Json(WakeOut {
        id: w.id,
        status: w.status.as_str().to_owned(),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EngineState {
    pub enabled: bool,
}

#[utoipa::path(get, path = "/engine", operation_id = "getEngine", tag = "runs",
    responses((status = 200, description = "Whether the engine may start runs on its own",
        body = EngineState)))]
pub async fn get_engine(State(app): State<App>) -> ApiResult<EngineState> {
    Ok(Json(EngineState {
        enabled: engine::engine_device(&app.pool).await?.is_some(),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EngineBody {
    pub enabled: bool,
}

#[utoipa::path(post, path = "/engine", operation_id = "setEngine", tag = "runs",
    request_body = EngineBody,
    responses((status = 200, description = "On, the engine starts sessions without a client in \
        hand, as the device that stepped up to say so (audited as `engine.enabled`); off, no new \
        run starts and the live ones go on", body = EngineState)))]
pub async fn set_engine(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(b): Json<EngineBody>,
) -> ApiResult<EngineState> {
    engine::set_engine(&app.pool, b.enabled, &me.device.id, &app.clock.now()).await?;
    Ok(Json(EngineState { enabled: b.enabled }))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_runs, get_run, transcript, cancel, kill, message, wake, get_engine, set_engine
    ),
    components(schemas(
        RunOut,
        RunTranscript,
        TranscriptEntry,
        RunMessage,
        WakeBody,
        WakeOut,
        EngineState,
        EngineBody
    ))
)]
pub struct Doc;
