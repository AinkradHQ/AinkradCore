//! Staffing a company from the app (screen 11 A, "Your company has no agents yet"): apply the
//! Engineering template, or propose one agent. Either way every new agent is a hire (decision
//! #43): it waits, `pending_approval`, on a `hire_agent` approval the admin decides, through the
//! same store calls as `citadel-server template apply` and `agent add`, audited as the admin.

use citadel_core::org::{AgentId, AgentStatus, NewAgent};
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::model::Agent;
use super::org::{agent_out, company};
use super::types::{Effort, Harness, OrgRole, Sandbox, TeamRole};
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::org::{self, OrgError};

/// The routes that came with API minor 7 (staffing, profile decisions, requirement actions) on
/// paths of their own; those on existing paths are in `router`.
pub(super) fn routes() -> Router<App> {
    use super::{hub, profile, requirements};
    Router::new()
        .route(
            "/api/v1/companies/{id}/templates/{template}",
            post(apply_template),
        )
        .route(
            "/api/v1/projects/{id}/profile/history",
            get(profile::history),
        )
        .route(
            "/api/v1/projects/{id}/profile/proposals/{proposal_id}/decision",
            post(profile::decide),
        )
        .route(
            "/api/v1/requirements/{id}/cancel",
            post(requirements::cancel),
        )
        .route("/api/v1/requirements/{id}/pause", post(requirements::pause))
        .route(
            "/api/v1/requirements/{id}/resume",
            post(requirements::resume),
        )
        .route("/api/v1/requirements/{id}/done", post(requirements::finish))
        .route(
            "/api/v1/requirements/{id}/attachments/{name}",
            post(hub::attach),
        )
}

pub(super) fn refused(e: OrgError) -> ApiError {
    match e {
        OrgError::NotFound | OrgError::OtherCompany => ApiError::not_found(e.to_string()),
        OrgError::Db(sqlx::Error::InvalidArgument(why)) => ApiError::bad_request(why),
        OrgError::Db(e) => e.into(),
        e => ApiError::conflict(e.to_string()),
    }
}

/// What applying a template left in place.
#[derive(Debug, Serialize, ToSchema)]
pub struct TemplateApplied {
    pub department_id: i64,
    pub team_id: i64,
    /// Its agents, the CTO first, then the team in seat order; new ones `pending_approval`.
    pub agents: Vec<Agent>,
    /// The hire approvals this apply opened, for the admin to decide (none on a re-apply).
    pub hire_approval_ids: Vec<i64>,
    pub skills_published: usize,
}

#[utoipa::path(post, path = "/api/v1/companies/{id}/templates/{template}",
    operation_id = "applyTemplate", tag = "org",
    params(("id" = i64, Path, description = "Company id"),
        ("template" = String, Path, description = "The template: `engineering`")),
    responses((status = 200, description = "The Engineering department, a CTO and a scrum team \
        (product owner, lead, two developers, QA, DevOps) with their role skills; each new agent \
        waits on its hire approval. Applying it again adds only what is missing",
        body = TemplateApplied)))]
pub async fn apply_template(
    State(app): State<App>,
    Path((id, template)): Path<(i64, String)>,
) -> ApiResult<TemplateApplied> {
    let c = company(&app, id).await?;
    if template != "engineering" {
        return Err(ApiError::not_found(format!(
            "no template {template:?}; there is engineering"
        )));
    }
    let now = app.clock.now();
    let a = org::apply_engineering(&app.pool, c.id, BY, &now)
        .await
        .map_err(refused)?;
    let mut agents = vec![];
    for agent in a.agents {
        agents.push(agent_out(&app, agent).await?);
    }
    Ok(Json(TemplateApplied {
        department_id: a.department.id.0,
        team_id: a.team.id.0,
        agents,
        hire_approval_ids: a.hires.iter().map(|h| h.0).collect(),
        skills_published: a.skills_published,
    }))
}

/// An agent the admin proposes; it is hired only once its approval is approved.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AgentProposal {
    /// Unique within the company.
    pub name: String,
    /// Free-text job title ("QA", "Designer"…).
    pub role: String,
    /// Absent: none (`ceo` and `cto` at most once per company).
    pub org_role: Option<OrgRole>,
    pub harness: Harness,
    pub model: String,
    /// Capabilities a runner must offer, e.g. `macos`.
    #[serde(default)]
    pub runner_tags: Vec<String>,
    /// An agent of the company it reports to.
    pub reports_to: Option<i64>,
    /// Why the company needs it: shown on the hire approval.
    pub justification: String,
    /// What it is (API minor 17); like the fields below, applied when the hire is approved.
    #[serde(default)]
    pub description: String,
    pub effort: Option<Effort>,
    pub sandbox: Option<Sandbox>,
    #[serde(default)]
    pub instructions: String,
    #[serde(default)]
    pub guidelines: Vec<String>,
    /// A team of the company to seat it on (with `team_role`, default `member`); a product
    /// owner or lead seat the team has filled is a 409.
    pub team_id: Option<i64>,
    pub team_role: Option<TeamRole>,
    /// One of `listPalettes`; absent: the company's least used.
    pub palette_id: Option<String>,
}

/// A proposed agent and the approval that hires it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProposedAgent {
    /// `pending_approval` until the approval is decided.
    pub agent: Agent,
    pub hire_approval_id: i64,
}

#[utoipa::path(post, path = "/api/v1/companies/{id}/agents", operation_id = "proposeAgent",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    request_body = AgentProposal,
    responses((status = 200, description = "The agent, pending its `hire_agent` approval (audited \
        as `agent.hire_requested`); approving it hires it, rejecting terminates it",
        body = ProposedAgent)))]
pub async fn propose_agent(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(p): Json<AgentProposal>,
) -> ApiResult<ProposedAgent> {
    let c = company(&app, id).await?;
    if let Some(boss) = p.reports_to {
        let theirs = org::get_agent(&app.pool, AgentId(boss)).await?;
        if theirs.is_none_or(|b| b.company_id != c.id) {
            return Err(ApiError::not_found(format!(
                "no agent {boss} in company {id}"
            )));
        }
    }
    if p.team_id.is_none() && p.team_role.is_some() {
        return Err(ApiError::bad_request("a team_role needs a team_id"));
    }
    let extras = org::HireExtras {
        profile: citadel_core::org::AgentProfile {
            description: p.description.clone(),
            effort: p.effort.map(Into::into),
            sandbox: p.sandbox.map(Into::into),
            instructions: p.instructions.clone(),
            guidelines: p.guidelines.clone(),
        },
        team: p.team_id.map(|t| {
            let role = p
                .team_role
                .map_or(citadel_core::org::TeamRole::Member, Into::into);
            (citadel_core::org::TeamId(t), role)
        }),
        palette_id: p.palette_id.clone(),
    };
    let new = NewAgent {
        company_id: c.id,
        name: p.name.trim().to_owned(),
        role: p.role.trim().to_owned(),
        org_role: p
            .org_role
            .map_or(citadel_core::org::OrgRole::None, Into::into),
        reports_to: p.reports_to.map(AgentId),
        harness: p.harness.into(),
        model: p.model.trim().to_owned(),
        runner_tags: p.runner_tags,
        status: AgentStatus::PendingApproval,
    };
    let now = app.clock.now();
    let (agent, approval) =
        org::hire_agent_with(&app.pool, &new, None, &p.justification, &extras, BY, &now)
            .await
            .map_err(|e| match e {
                OrgError::Db(sqlx::Error::Database(d)) if d.message().contains("UNIQUE") => {
                    ApiError::conflict("the company has an agent of that name or org role already")
                }
                e => refused(e),
            })?;
    Ok(Json(ProposedAgent {
        agent: agent_out(&app, agent).await?,
        hire_approval_id: approval.id.0,
    }))
}
