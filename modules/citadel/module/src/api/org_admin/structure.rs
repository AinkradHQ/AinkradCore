//! Shaping the org over HTTP (API minor 17): the org chart, departments (name, about, head),
//! teams and seats, through `store::org` as the admin, each audited (`department.updated`,
//! `team.updated`, `team.member_seated`, `team.member_unseated`), and the company logo reset.
//!
//! Adding and renaming a department or team, and deleting one, are `api::org`'s routes (the
//! first slice); the monolith's `PATCH` forms with `about` and `head_agent_id` are here, under
//! `patchDepartment` and `patchTeam`.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, State};

use super::{agent_out_all, company, company_out, failed, org_refused, parse};
use crate::api::error::found;
use crate::api::model::org_admin::{
    DepartmentUpdate, OrgChart, OrgDepartment, OrgTeam, SeatRequest, TeamUpdate,
};
use crate::api::scope::Acting;
use crate::domain::org::{AgentId, CompanyId, DepartmentId, TeamId, TeamRole};
use crate::store::org::{self, DepartmentChange, OrgError};

/// `org_refused`, a name or seat that is taken being a conflict.
fn conflicted(e: OrgError) -> ApiError {
    org_refused(e)
}

async fn chart(app: &App, id: CompanyId, with_agents: bool) -> Result<OrgChart, ApiError> {
    let c = company(app, id.0).await?;
    let chart = found(org::org_chart(&app.pool, c.id).await?, "company")?;
    let departments = serde_json::from_value(chart["departments"].clone())
        .map_err(|e| ApiError::from(sqlx::Error::Decode(e.into())))?;
    let agents = match with_agents {
        true => agent_out_all(app, c.id).await?,
        false => vec![],
    };
    Ok(OrgChart {
        company: c.into(),
        agents,
        departments,
    })
}

#[utoipa::path(get, path = "/companies/{id}/org", operation_id = "getOrgChart", tag = "org",
    params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company's org chart", body = OrgChart)))]
pub async fn org_chart(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<OrgChart> {
    Ok(Json(chart(&app, CompanyId(id), true).await?))
}

async fn department_out(app: &App, d: crate::domain::org::Department) -> ApiResult<OrgDepartment> {
    let found = chart(app, d.company_id, false)
        .await?
        .departments
        .into_iter()
        .find(|x| x.id == d.id.0);
    found
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no department {}", d.id.0)))
}

async fn team_out(app: &App, t: crate::domain::org::Team) -> ApiResult<OrgTeam> {
    let d = found(
        org::get_department(&app.pool, t.department_id).await?,
        "department",
    )?;
    let found = chart(app, d.company_id, false)
        .await?
        .departments
        .into_iter()
        .flat_map(|d| d.teams)
        .find(|x| x.id == t.id.0);
    found
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no team {}", t.id.0)))
}

#[utoipa::path(patch, path = "/departments/{id}", operation_id = "patchDepartment",
    tag = "org", params(("id" = i64, Path, description = "Department id")),
    request_body = DepartmentUpdate,
    responses((status = 200, description = "The department as changed (audited as \
        `department.updated`); 409 for a name the company has", body = OrgDepartment)))]
pub async fn patch_department(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(u): Json<DepartmentUpdate>,
) -> ApiResult<OrgDepartment> {
    let change = DepartmentChange {
        name: u.name,
        about: u.about,
        head: u.head_agent_id.map(|h| h.map(AgentId)),
    };
    let d = org::edit_department(&app.pool, DepartmentId(id), &change, BY)
        .await
        .map_err(conflicted)?;
    department_out(&app, d).await
}

#[utoipa::path(patch, path = "/teams/{id}", operation_id = "patchTeam", tag = "org",
    params(("id" = i64, Path, description = "Team id")), request_body = TeamUpdate,
    responses((status = 200, description = "The team as changed (audited as `team.updated`)",
        body = OrgTeam)))]
pub async fn patch_team(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(u): Json<TeamUpdate>,
) -> ApiResult<OrgTeam> {
    let t = org::edit_team(
        &app.pool,
        TeamId(id),
        u.name.as_deref(),
        u.department_id.map(DepartmentId),
        BY,
    )
    .await
    .map_err(conflicted)?;
    team_out(&app, t).await
}

#[utoipa::path(put, path = "/teams/{id}/members/{agent_id}", operation_id = "seatAgent",
    tag = "org", params(("id" = i64, Path, description = "Team id"),
        ("agent_id" = i64, Path, description = "Agent id")),
    request_body = SeatRequest,
    responses((status = 200, description = "The team with the agent seated (or its seat \
        changed; audited as `team.member_seated`); 409 when another agent is the team's product \
        owner or lead; 404 for an agent of another company", body = OrgTeam)))]
pub async fn seat(
    State(app): State<App>,
    _: Acting,
    Path((id, agent)): Path<(i64, i64)>,
    Json(s): Json<SeatRequest>,
) -> ApiResult<OrgTeam> {
    let t = TeamId(id);
    let role: TeamRole = parse("team_role", &s.team_role)?;
    org::seat_checked(&app.pool, t, AgentId(agent), role, s.capacity, BY)
        .await
        .map_err(conflicted)?;
    let team = found(org::get_team(&app.pool, t).await?, "team")?;
    team_out(&app, team).await
}

#[utoipa::path(delete, path = "/teams/{id}/members/{agent_id}", operation_id = "unseatAgent",
    tag = "org", params(("id" = i64, Path, description = "Team id"),
        ("agent_id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The team without the agent (audited as \
        `team.member_unseated`); 404 when it had no seat there", body = OrgTeam)))]
pub async fn unseat(
    State(app): State<App>,
    _: Acting,
    Path((id, agent)): Path<(i64, i64)>,
) -> ApiResult<OrgTeam> {
    let t = TeamId(id);
    if !org::unseat_member(&app.pool, t, AgentId(agent), BY)
        .await
        .map_err(conflicted)?
    {
        return Err(ApiError::not_found(format!(
            "agent {agent} has no seat on team {id}"
        )));
    }
    let team = found(org::get_team(&app.pool, t).await?, "team")?;
    team_out(&app, team).await
}

#[utoipa::path(delete, path = "/companies/{id}/logo", operation_id = "resetCompanyLogo",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company without a logo (audited as \
        `company.logo_reset`)", body = crate::api::model::Company)))]
pub async fn reset_logo(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<crate::api::model::Company> {
    org::logo::reset_logo(&app.pool, CompanyId(id), BY)
        .await
        .map_err(|e| match e {
            org::avatars::AvatarError::NoCompany(c) => {
                ApiError::not_found(format!("no company {}", c.0))
            }
            org::avatars::AvatarError::Db(e) => failed(e),
            e => ApiError::bad_request(e.to_string()),
        })?;
    company_out(&app, id).await
}
