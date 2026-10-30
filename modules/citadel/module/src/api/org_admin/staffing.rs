//! Staffing a company from the app (screen 11 A, "Your company has no agents yet"): apply the
//! Engineering template, or propose one agent. Either way every new agent is a hire (decision
//! #43): it waits, `pending_approval`, on a `hire_agent` approval the admin decides, through the
//! same store calls as the CLI, audited as the admin.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, State};

use super::{agent_out, company, org_refused, parse};
use crate::api::model::org_admin::{AgentProposal, ProposedAgent, TemplateApplied};
use crate::api::scope::Acting;
use crate::domain::org::{AgentId, AgentProfile, AgentStatus, NewAgent, OrgRole, TeamId, TeamRole};
use crate::store::org;

#[utoipa::path(post, path = "/companies/{id}/templates/{template}",
    operation_id = "applyTemplate", tag = "org",
    params(("id" = i64, Path, description = "Company id"),
        ("template" = String, Path, description = "The template: `engineering`")),
    responses((status = 200, description = "The Engineering department, a CTO and a scrum team \
        (product owner, lead, two developers, QA, DevOps) with their role skills; each new agent \
        waits on its hire approval. Applying it again adds only what is missing",
        body = TemplateApplied)))]
pub async fn apply_template(
    State(app): State<App>,
    _: Acting,
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
        .map_err(org_refused)?;
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

#[utoipa::path(post, path = "/companies/{id}/agents", operation_id = "proposeAgent",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    request_body = AgentProposal,
    responses((status = 200, description = "The agent, pending its `hire_agent` approval (audited \
        as `agent.hire_requested`); approving it hires it, rejecting terminates it",
        body = ProposedAgent)))]
pub async fn propose_agent(
    State(app): State<App>,
    _: Acting,
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
    let team_role = match &p.team_role {
        Some(r) => parse::<TeamRole>("team_role", r)?,
        None => TeamRole::Member,
    };
    let extras = org::HireExtras {
        profile: AgentProfile {
            description: p.description.clone(),
            effort: p
                .effort
                .as_deref()
                .map(|v| parse("effort", v))
                .transpose()?,
            sandbox: p
                .sandbox
                .as_deref()
                .map(|v| parse("sandbox", v))
                .transpose()?,
            instructions: p.instructions.clone(),
            guidelines: p.guidelines.clone(),
        },
        team: p.team_id.map(|t| (TeamId(t), team_role)),
        palette_id: p.palette_id.clone(),
    };
    let new = NewAgent {
        company_id: c.id,
        name: p.name.trim().to_owned(),
        role: p.role.trim().to_owned(),
        org_role: match &p.org_role {
            Some(r) => parse::<OrgRole>("org_role", r)?,
            None => OrgRole::None,
        },
        reports_to: p.reports_to.map(AgentId),
        harness: parse("harness", &p.harness)?,
        model: p.model.trim().to_owned(),
        runner_tags: p.runner_tags,
        status: AgentStatus::PendingApproval,
    };
    let now = app.clock.now();
    let (agent, approval) =
        org::hire_agent_with(&app.pool, &new, None, &p.justification, &extras, BY, &now)
            .await
            .map_err(|e| match e {
                org::OrgError::Db(sqlx::Error::Database(d)) if d.message().contains("UNIQUE") => {
                    ApiError::conflict("the company has an agent of that name or org role already")
                }
                e => org_refused(e),
            })?;
    Ok(Json(ProposedAgent {
        agent: agent_out(&app, agent).await?,
        hire_approval_id: approval.id.0,
    }))
}
