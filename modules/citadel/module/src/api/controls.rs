//! The admin's controls over what the engine found (S7): the stuck list, releasing a checkout a
//! dead run holds, retrying an ended run, and terminating an agent. Every route that changes
//! something is a step-up route (`DESTRUCTIVE`) and `admin` (deny by default); the stuck list
//! stays `admin` too (`ADMIN_READS`). Each goes through the engine as the admin and is audited.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use super::error::found;
use super::model::Agent;
use super::model::work::Issue;
use super::scope::Acting;
use crate::domain::org::AgentId;
use crate::domain::work::{IssueId, RunId};
use crate::store::exec::{self as engine, Platform, StuckActionError};
use crate::store::org::ESCALATION_USER;

pub fn routes() -> Router<App> {
    Router::new()
        .route("/stuck", get(list_stuck))
        .route("/issues/{id}/release-checkout", post(release_checkout))
        .route("/runs/{id}/retry", post(retry_run))
        .route("/agents/{id}/terminate", post(terminate))
        .route("/companies/{id}/requests", post(submit_request))
        .route("/agents/{id}/pause", post(pause))
        .route("/agents/{id}/resume", post(resume))
}

/// Not a phone read: it names why work is stuck and who it waits on.
pub const ADMIN_READS: &[&str] = &["/stuck"];

/// Each of these changes work or ends an agent: a step-up.
pub const DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/issues/{id}/release-checkout"),
    ("POST", "/runs/{id}/retry"),
    ("POST", "/agents/{id}/terminate"),
    ("POST", "/agents/{id}/pause"),
    // Starts spend (the CEO's wake) like `/agents/{id}/wake`, so the same step-up.
    ("POST", "/companies/{id}/requests"),
    ("POST", "/agents/{id}/resume"),
];

fn refused(e: StuckActionError) -> ApiError {
    match e {
        StuckActionError::NotFound(why) => ApiError::not_found(why),
        StuckActionError::Conflict(why) => ApiError::conflict(why),
        StuckActionError::Db(e) => e.into(),
    }
}

/// Why something is stuck and what would unstick it.
#[derive(Debug, Serialize, ToSchema)]
pub struct StuckItem {
    /// The rule that found it (`todo_idle`, `checkout_dead`, `wake_no_runner`, ...).
    pub kind: String,
    pub issue_id: Option<i64>,
    /// The agent it waits on, when there is one.
    pub agent_id: Option<i64>,
    pub reason: String,
    pub action: String,
    /// What the repair pass does about it by itself (while the engine is on).
    pub repair: String,
    /// The issue's last automatic repair (`repair.<rule>` in the audit), if any.
    pub last_repair: Option<String>,
    /// How long it has been stuck, in seconds as of the report.
    pub stuck_secs: Option<i64>,
    pub run_id: Option<i64>,
    pub wake_id: Option<i64>,
}

#[utoipa::path(get, path = "/stuck", operation_id = "listStuck", tag = "controls",
    responses((status = 200, description = "Every stuck issue, wake or queued run, as of now \
        (read-only: the repair pass acts on the same report while the engine is on)",
        body = Vec<StuckItem>)))]
pub async fn list_stuck(State(app): State<App>, acting: Acting) -> ApiResult<Vec<StuckItem>> {
    let report = engine::stuck_report(&app, &Platform, &app.clock.now()).await?;
    let mut out = vec![];
    for s in report {
        // Company scope: what the acting company does not own is not shown.
        let company: Option<i64> = match (s.issue_id, s.agent_id) {
            (Some(i), _) => {
                sqlx::query_scalar(
                    "SELECT p.company_id FROM citadel_issues i \
                 JOIN citadel_projects p ON p.id = i.project_id WHERE i.id = ?",
                )
                .bind(i.0)
                .fetch_optional(&app.pool)
                .await?
            }
            (None, Some(a)) => {
                sqlx::query_scalar("SELECT company_id FROM citadel_agents WHERE id = ?")
                    .bind(a.0)
                    .fetch_optional(&app.pool)
                    .await?
            }
            (None, None) => None,
        };
        if !acting.sees(company) {
            continue;
        }
        out.push(StuckItem {
            kind: s.kind.as_str().to_owned(),
            issue_id: s.issue_id.map(|i| i.0),
            agent_id: s.agent_id.map(|a| a.0),
            reason: s.reason,
            action: s.action,
            repair: s.repair.as_str().to_owned(),
            last_repair: s.last_repair.map(|l| format!("{} at {}", l.action, l.at)),
            stuck_secs: s.stuck_secs,
            run_id: s.run_id.map(|r| r.0),
            wake_id: s.wake_id,
        });
    }
    Ok(Json(out))
}

#[utoipa::path(post, path = "/issues/{id}/release-checkout",
    operation_id = "releaseCheckout", tag = "controls",
    params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issue, released by the run that held it and has \
        ended (the stuck rule `checkout_dead`; audited as `issue.released`). 409 when it is not \
        checked out, or its run is still live: stop the run instead", body = Issue)))]
pub async fn release_checkout(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Issue> {
    let i = engine::release_dead_checkout(&app.pool, IssueId(id), BY)
        .await
        .map_err(refused)?;
    super::work::issue_out(&app, i).await.map(Json)
}

/// The wake that will start a retry.
#[derive(Debug, Serialize, ToSchema)]
pub struct Retried {
    pub agent_id: i64,
    pub issue_id: Option<i64>,
    pub wake_id: i64,
}

#[utoipa::path(post, path = "/runs/{id}/retry", operation_id = "retryRun", tag = "controls",
    params(("id" = i64, Path, description = "Run id")),
    responses((status = 200, description = "The ended run's agent woken again on its issue \
        (audited as `run.retried`); the engine starts it when it is allowed to (budgets, a free \
        runner). A wake already pending for the agent and issue takes it in. 409 while the run \
        is live or for a closed issue", body = Retried)))]
pub async fn retry_run(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Retried> {
    let w = engine::retry_run(&app.pool, RunId(id), BY, &app.clock.now())
        .await
        .map_err(refused)?;
    Ok(Json(Retried {
        agent_id: w.agent_id.0,
        issue_id: w.issue_id.map(|i| i.0),
        wake_id: w.id,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TerminateBody {
    /// Why, 1 to 500 characters.
    pub reason: String,
}

#[utoipa::path(post, path = "/agents/{id}/terminate", operation_id = "terminateAgent",
    tag = "controls", params(("id" = i64, Path, description = "Agent id")),
    request_body = TerminateBody,
    responses(
        (status = 200, description = "The agent, `terminated` for good (audited as \
            `agent.terminated`, listing what it undid): its pending wakes are dropped, its open \
            issues handed to the admin, and its live runs asked to stop", body = Agent),
        (status = 409, description = "Already terminated")))]
pub async fn terminate(
    State(app): State<App>,
    _: Acting,
    Extension(me): Extension<Caller>,
    Path(id): Path<i64>,
    Json(b): Json<TerminateBody>,
) -> ApiResult<Agent> {
    let reason = b.reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 {
        return Err(ApiError::bad_request("a reason is 1 to 500 characters"));
    }
    let a = found(
        crate::store::org::get_agent(&app.pool, AgentId(id)).await?,
        "agent",
    )?;
    let done = engine::terminate_agent(
        &app,
        &Platform,
        a.id,
        reason,
        ESCALATION_USER,
        (BY, &me.device.id),
        &app.clock.now(),
    )
    .await?;
    if !done {
        return Err(ApiError::conflict(format!(
            "agent {id} is terminated already"
        )));
    }
    let a = found(
        crate::store::org::get_agent(&app.pool, a.id).await?,
        "agent",
    )?;
    super::org_admin::agent_out(&app, a).await.map(Json)
}

#[utoipa::path(post, path = "/agents/{id}/pause", operation_id = "pauseAgent", tag = "controls",
    params(("id" = i64, Path, description = "Agent id")),
    responses(
        (status = 200, description = "The agent, paused (audited as `agent.paused`): never \
            dispatched while paused; its live runs are asked to stop", body = Agent),
        (status = 409, description = "The agent is not active")))]
pub async fn pause(
    State(app): State<App>,
    _: Acting,
    Extension(me): Extension<Caller>,
    Path(id): Path<i64>,
) -> ApiResult<Agent> {
    let a = found(
        crate::store::org::get_agent(&app.pool, AgentId(id)).await?,
        "agent",
    )?;
    if !engine::pause_agent(&app, &Platform, a.id, (BY, &me.device.id), &app.clock.now()).await? {
        return Err(ApiError::conflict(format!(
            "agent {id} is {}, not active",
            a.status.as_str()
        )));
    }
    let a = found(
        crate::store::org::get_agent(&app.pool, a.id).await?,
        "agent",
    )?;
    super::org_admin::agent_out(&app, a).await.map(Json)
}

#[utoipa::path(post, path = "/agents/{id}/resume", operation_id = "resumeAgent", tag = "controls",
    params(("id" = i64, Path, description = "Agent id")),
    responses(
        (status = 200, description = "The agent, active again (audited as `agent.resumed`) and \
            woken on each open issue waiting on it; the only way out of a pause, the loop \
            breaker's included", body = Agent),
        (status = 409, description = "The agent is not paused")))]
pub async fn resume(State(app): State<App>, _: Acting, Path(id): Path<i64>) -> ApiResult<Agent> {
    let a = found(
        crate::store::org::get_agent(&app.pool, AgentId(id)).await?,
        "agent",
    )?;
    if !engine::resume_agent(&app.pool, a.id, BY, &app.clock.now()).await? {
        return Err(ApiError::conflict(format!(
            "agent {id} is {}, not paused",
            a.status.as_str()
        )));
    }
    let a = found(
        crate::store::org::get_agent(&app.pool, a.id).await?,
        "agent",
    )?;
    super::org_admin::agent_out(&app, a).await.map(Json)
}

/// A request to the company, for its CEO to route.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewRequest {
    pub title: String,
    #[serde(default)]
    pub body: String,
    /// The company's project it is for: a hint, named in the CEO's wake.
    pub project_id: Option<i64>,
    /// `low`, `normal` or `urgent`; absent: no level.
    pub priority: Option<RequestPriority>,
    /// Acceptance criteria, in order.
    #[serde(default)]
    pub criteria: Vec<String>,
}

/// How urgent a request is; `normal` is the `medium` level.
#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestPriority {
    Low,
    Normal,
    Urgent,
}

#[utoipa::path(post, path = "/companies/{id}/requests", operation_id = "submitRequest",
    tag = "org", params(("id" = i64, Path, description = "Company id")), request_body = NewRequest,
    responses((status = 200, description = "The request, as an issue in the company's intake; \
        its CEO is woken (a wake like any other: the engine still checks the budgets)",
        body = Issue)))]
pub async fn submit_request(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(new): Json<NewRequest>,
) -> ApiResult<Issue> {
    use crate::domain::work::{Criterion, PriorityLevel, ProjectId};
    use crate::store::work::{IntakeError, IntakeExtra, submit_intake_with};
    let c = found(
        crate::store::org::get_company(&app.pool, crate::domain::org::CompanyId(id)).await?,
        "company",
    )?;
    if new.title.trim().is_empty() {
        return Err(ApiError::bad_request("a request needs a title"));
    }
    if new.title.chars().count() > 200
        || new.body.chars().count() > 20_000
        || new.criteria.len() > 20
        || new.criteria.iter().any(|c| c.chars().count() > 500)
    {
        return Err(ApiError::bad_request(
            "a title is at most 200 characters, a body 20000, and 20 criteria of 500",
        ));
    }
    let extra = IntakeExtra {
        project_id: new.project_id.map(ProjectId),
        priority_level: match new.priority {
            None => PriorityLevel::None,
            Some(RequestPriority::Low) => PriorityLevel::Low,
            Some(RequestPriority::Normal) => PriorityLevel::Medium,
            Some(RequestPriority::Urgent) => PriorityLevel::Urgent,
        },
        criteria: new
            .criteria
            .into_iter()
            .map(|text| Criterion { text, done: false })
            .collect(),
    };
    let i = submit_intake_with(&app.pool, c.id, new.title.trim(), &new.body, &extra, BY)
        .await
        .map_err(|e| match e {
            IntakeError::NotFound => ApiError::not_found(e.to_string()),
            IntakeError::Elsewhere => ApiError::not_found("no such project in the company"),
            IntakeError::Db(sqlx::Error::InvalidArgument(why) | sqlx::Error::Protocol(why)) => {
                ApiError::bad_request(why)
            }
            IntakeError::Db(e) => e.into(),
            e => ApiError::conflict(e.to_string()),
        })?;
    super::work::issue_out(&app, i).await.map(Json)
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_stuck,
        release_checkout,
        retry_run,
        terminate,
        pause,
        resume,
        submit_request
    ),
    components(schemas(StuckItem, Retried, TerminateBody, NewRequest, RequestPriority))
)]
pub struct Doc;
