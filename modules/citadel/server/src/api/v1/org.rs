//! The org (E11.3, E11.8, E11.9): companies, the org chart, agents, runners, "why stuck",
//! and a request to the company (its CEO's intake, E6.3).

use citadel_core::org::{AgentId, CompanyId};
use citadel_core::work::{self as core, ProjectId};
use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use utoipa::ToSchema;

use super::model::{Agent, Department, Issue, OrgChart, StuckIssue};
use super::scope::Acting;
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::{exec, org, work};

pub(super) async fn company(app: &App, id: i64) -> Result<citadel_core::org::Company, ApiError> {
    org::get_company(&app.pool, CompanyId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no company {id}")))
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/org", operation_id = "getOrgChart", tag = "org",
    params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company's org chart", body = OrgChart)))]
pub async fn org_chart(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<OrgChart> {
    let c = company(&app, id).await?;
    let chart = org::org_chart(&app.pool, c.id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no company {id}")))?;
    let departments: Vec<Department> = serde_json::from_value(chart["departments"].clone())
        .map_err(|e| {
            tracing::error!(error = %e, "org chart shape");
            ApiError::from(sqlx::Error::Decode(e.into()))
        })?;
    let agents = company_agents(&app, c.id).await?;
    Ok(Json(OrgChart {
        company: c.into(),
        agents,
        departments,
    }))
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/agents", operation_id = "listAgents", tag = "org",
    params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company's agents", body = Vec<Agent>)))]
pub async fn list_agents(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<Agent>> {
    let c = company(&app, id).await?;
    company_agents(&app, c.id).await.map(Json)
}

#[utoipa::path(get, path = "/api/v1/agents/{id}", operation_id = "getAgent", tag = "org",
    params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The agent", body = Agent)))]
pub async fn get_agent(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Agent> {
    let a = org::get_agent(&app.pool, AgentId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no agent {id}")))?;
    agent_out(&app, a).await.map(Json)
}

/// The company's agents as the client sees them, each with its figure's state.
async fn company_agents(app: &App, c: CompanyId) -> Result<Vec<Agent>, ApiError> {
    let agents = org::list_agents(&app.pool, c).await?;
    let now = app.clock.now();
    let doing = org::avatars::activity(&app.pool, Some(c), None, &now).await?;
    let caps = caps(app, c).await?;
    let presets: std::collections::HashMap<i64, i64> = sqlx::query_as(
        "SELECT id, chain_preset_id FROM agents WHERE company_id = ? AND chain_preset_id IS NOT NULL",
    )
    .bind(c.0)
    .fetch_all(&app.pool)
    .await?
    .into_iter()
    .collect();
    let queued = org::queued_wakes(&app.pool, c).await?;
    Ok(agents
        .into_iter()
        .map(|a| {
            let activity = doing.get(&a.id).cloned().unwrap_or_default();
            let preset = presets.get(&a.id.0).copied();
            Agent {
                chain_preset_id: preset,
                queued_wakes: queued.get(&a.id.0).copied().unwrap_or(0),
                ..Agent::of(a, &activity, caps)
            }
        })
        .collect())
}

/// `a` as the client sees it, with its figure's state.
pub(super) async fn agent_out(app: &App, a: citadel_core::org::Agent) -> Result<Agent, ApiError> {
    let now = app.clock.now();
    let doing = org::avatars::activity(&app.pool, None, Some(a.id), &now).await?;
    let activity = doing.get(&a.id).cloned().unwrap_or_default();
    let caps = caps(app, a.company_id).await?;
    let preset: Option<i64> = sqlx::query_scalar("SELECT chain_preset_id FROM agents WHERE id = ?")
        .bind(a.id.0)
        .fetch_one(&app.pool)
        .await?;
    let queued = org::queued_wakes(&app.pool, a.company_id).await?;
    Ok(Agent {
        chain_preset_id: preset,
        queued_wakes: queued.get(&a.id.0).copied().unwrap_or(0),
        ..Agent::of(a, &activity, caps)
    })
}

/// The company's effective `run.token_cap` and `issue.token_cap`.
async fn caps(app: &App, c: CompanyId) -> Result<(i64, i64), ApiError> {
    use citadel_core::settings::{Key, Scope};
    let at = Scope::Company(c);
    let run = crate::store::settings::value(&app.pool, Key::RunTokenCap, at).await?;
    let issue = crate::store::settings::value(&app.pool, Key::IssueTokenCap, at).await?;
    Ok((run, issue))
}

#[utoipa::path(get, path = "/api/v1/stuck", operation_id = "listStuck", tag = "org",
    responses((status = 200, description = "Every stuck issue or wake, why, and what would unstick it",
        body = Vec<StuckIssue>)))]
pub async fn list_stuck(
    State(app): State<App>,
    Extension(acting): Extension<Acting>,
) -> ApiResult<Vec<StuckIssue>> {
    let now = app.clock.now();
    let all = exec::stuck_report(&app.pool, &now).await?;
    let mut out = vec![];
    for core in all {
        let since: Option<String> = match core.stuck_secs {
            Some(secs) => {
                sqlx::query_scalar(
                    "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?, '-' || ? || ' seconds')",
                )
                .bind(&now)
                .bind(secs)
                .fetch_one(&app.pool)
                .await?
            }
            None => None,
        };
        let mut s = StuckIssue::from(core);
        s.stuck_since = since.as_deref().map(super::types::ts);
        super::stuck::enrich(&app, &mut s).await?;
        // In a company (E15.14): only its own issues and agents.
        let company = match (s.issue_id, s.agent_id) {
            _ if acting.0.is_none() => None,
            (Some(i), _) => issue_company(&app, i).await?,
            (None, Some(a)) => org::get_agent(&app.pool, AgentId(a))
                .await?
                .map(|a| a.company_id.0),
            (None, None) => None,
        };
        if acting.sees(company) {
            out.push(s);
        }
    }
    Ok(Json(out))
}

async fn issue_company(app: &App, issue: i64) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT p.company_id FROM issues i JOIN projects p ON p.id = i.project_id WHERE i.id = ?",
    )
    .bind(issue)
    .fetch_optional(&app.pool)
    .await
}

/// A request to the company, for its CEO to route.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewRequest {
    pub title: String,
    #[serde(default)]
    pub body: String,
    /// The company's project it is for (API minor 18): a hint, named in the CEO's wake.
    pub project_id: Option<i64>,
    /// `low`, `normal` or `urgent`; absent: `normal`.
    pub priority: Option<RequestPriority>,
    /// Acceptance criteria, in order.
    #[serde(default)]
    pub criteria: Vec<String>,
}

/// How urgent a request is; `normal` is the `medium` level, `urgent` bumps its wakes.
#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestPriority {
    Low,
    Normal,
    Urgent,
}

#[utoipa::path(post, path = "/api/v1/companies/{id}/requests", operation_id = "submitRequest",
    tag = "org", params(("id" = i64, Path, description = "Company id")), request_body = NewRequest,
    responses((status = 200, description = "The request, as an issue in the company's intake", body = Issue)))]
pub async fn submit_request(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(new): Json<NewRequest>,
) -> ApiResult<Issue> {
    let c = company(&app, id).await?;
    if new.title.trim().is_empty() {
        return Err(ApiError::bad_request("a request needs a title"));
    }
    let extra = work::IntakeExtra {
        project_id: new.project_id.map(ProjectId),
        priority_level: match new.priority {
            None => core::PriorityLevel::None,
            Some(RequestPriority::Low) => core::PriorityLevel::Low,
            Some(RequestPriority::Normal) => core::PriorityLevel::Medium,
            Some(RequestPriority::Urgent) => core::PriorityLevel::Urgent,
        },
        criteria: new
            .criteria
            .into_iter()
            .map(|text| core::Criterion { text, done: false })
            .collect(),
    };
    let i = work::submit_intake_with(&app.pool, c.id, new.title.trim(), &new.body, &extra, BY)
        .await
        .map_err(|e| match e {
            work::IntakeError::NotFound => ApiError::not_found(e.to_string()),
            work::IntakeError::Elsewhere => ApiError::not_found("no such project in the company"),
            work::IntakeError::Db(sqlx::Error::InvalidArgument(why)) => ApiError::bad_request(why),
            work::IntakeError::Db(e) => e.into(),
            e => ApiError::conflict(e.to_string()),
        })?;
    super::issues::issue_out(&app, i).await.map(Json)
}
