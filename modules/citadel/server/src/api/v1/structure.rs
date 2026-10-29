//! Shaping the org over HTTP (API minor 17): departments (name, about, head), teams and seats,
//! through `store::org::structure` as the admin, each audited (`department.added`,
//! `department.updated`, `department.deleted`, `team.added`, `team.updated`, `team.deleted`,
//! `team.member_seated`, `team.member_unseated`; every audited change is also an event on the
//! stream).

use citadel_core::org::{AgentId, CompanyId, DepartmentId, TeamId};
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::hire::refused;
use super::model::{Department, OrgChart, Team};
use super::org::company;
use super::quest::serde_with_none;
use super::types::TeamRole;
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::org::{self, DepartmentChange, OrgError};

/// `refused`, a name or seat that is taken being a conflict.
fn failed(e: OrgError) -> ApiError {
    match e {
        OrgError::Db(sqlx::Error::Database(d)) if d.message().contains("UNIQUE") => {
            ApiError::conflict("that name or seat is taken already")
        }
        e => refused(e),
    }
}

async fn chart(app: &App, id: CompanyId) -> Result<OrgChart, ApiError> {
    let c = company(app, id.0).await?;
    let chart = org::org_chart(&app.pool, c.id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no company {}", id.0)))?;
    let departments = serde_json::from_value(chart["departments"].clone())
        .map_err(|e| ApiError::from(sqlx::Error::Decode(e.into())))?;
    Ok(OrgChart {
        company: c.into(),
        agents: vec![],
        departments,
    })
}

async fn department_out(app: &App, d: citadel_core::org::Department) -> ApiResult<Department> {
    let found = chart(app, d.company_id)
        .await?
        .departments
        .into_iter()
        .find(|x| x.id == d.id.0);
    found
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no department {}", d.id.0)))
}

async fn team_out(app: &App, t: citadel_core::org::Team) -> ApiResult<Team> {
    let d = org::get_department(&app.pool, t.department_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no department {}", t.department_id.0)))?;
    let found = chart(app, d.company_id)
        .await?
        .departments
        .into_iter()
        .flat_map(|d| d.teams)
        .find(|x| x.id == t.id.0);
    found
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no team {}", t.id.0)))
}

/// A department to add.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewDepartment {
    /// 1-100 characters, unique within the company.
    pub name: String,
    /// At most 2000 characters.
    #[serde(default)]
    pub about: String,
    /// An agent of the company.
    pub head_agent_id: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/companies/{id}/departments", operation_id = "createDepartment",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    request_body = NewDepartment,
    responses((status = 200, description = "The department, with no teams (audited as \
        `department.added`); 409 for a name the company has", body = Department)))]
pub async fn create_department(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(n): Json<NewDepartment>,
) -> ApiResult<Department> {
    let c = company(&app, id).await?;
    let head = n.head_agent_id.map(AgentId);
    let d = org::create_department_with(&app.pool, c.id, &n.name, &n.about, head, BY)
        .await
        .map_err(failed)?;
    department_out(&app, d).await
}

/// What to change about a department; absent fields stay, `null` clears the head.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DepartmentUpdate {
    pub name: Option<String>,
    pub about: Option<String>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<i64>)]
    pub head_agent_id: Option<Option<i64>>,
}

#[utoipa::path(patch, path = "/api/v1/departments/{id}", operation_id = "updateDepartment",
    tag = "org", params(("id" = i64, Path, description = "Department id")),
    request_body = DepartmentUpdate,
    responses((status = 200, description = "The department as changed (audited as \
        `department.updated`); 409 for a name the company has", body = Department)))]
pub async fn update_department(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(u): Json<DepartmentUpdate>,
) -> ApiResult<Department> {
    let change = DepartmentChange {
        name: u.name,
        about: u.about,
        head: u.head_agent_id.map(|h| h.map(AgentId)),
    };
    let d = org::edit_department(&app.pool, DepartmentId(id), &change, BY)
        .await
        .map_err(failed)?;
    department_out(&app, d).await
}

/// What a delete removed.
#[derive(Debug, Serialize, ToSchema)]
pub struct Removed {
    pub id: i64,
}

#[utoipa::path(delete, path = "/api/v1/departments/{id}", operation_id = "deleteDepartment",
    tag = "org", params(("id" = i64, Path, description = "Department id")),
    responses((status = 200, description = "Deleted (audited as `department.deleted`); 409 while \
        it has teams", body = Removed)))]
pub async fn delete_department(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Removed> {
    org::remove_department(&app.pool, DepartmentId(id), BY)
        .await
        .map_err(failed)?;
    Ok(Json(Removed { id }))
}

/// A team to add.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewTeam {
    /// 1-100 characters.
    pub name: String,
}

#[utoipa::path(post, path = "/api/v1/departments/{id}/teams", operation_id = "createTeam",
    tag = "org", params(("id" = i64, Path, description = "Department id")),
    request_body = NewTeam,
    responses((status = 200, description = "The team, with no members (audited as `team.added`)",
        body = Team)))]
pub async fn create_team(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(n): Json<NewTeam>,
) -> ApiResult<Team> {
    let t = org::add_team(&app.pool, DepartmentId(id), &n.name, BY)
        .await
        .map_err(failed)?;
    team_out(&app, t).await
}

/// What to change about a team; absent fields stay.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TeamUpdate {
    pub name: Option<String>,
    /// Move it to another department of the same company.
    pub department_id: Option<i64>,
}

#[utoipa::path(patch, path = "/api/v1/teams/{id}", operation_id = "updateTeam", tag = "org",
    params(("id" = i64, Path, description = "Team id")), request_body = TeamUpdate,
    responses((status = 200, description = "The team as changed (audited as `team.updated`)",
        body = Team)))]
pub async fn update_team(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(u): Json<TeamUpdate>,
) -> ApiResult<Team> {
    let t = org::edit_team(
        &app.pool,
        TeamId(id),
        u.name.as_deref(),
        u.department_id.map(DepartmentId),
        BY,
    )
    .await
    .map_err(failed)?;
    team_out(&app, t).await
}

#[utoipa::path(delete, path = "/api/v1/teams/{id}", operation_id = "deleteTeam", tag = "org",
    params(("id" = i64, Path, description = "Team id")),
    responses((status = 200, description = "Deleted with its seats (audited as `team.deleted`, \
        naming the agents unseated); the projects it owned have no team", body = Removed)))]
pub async fn delete_team(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Removed> {
    org::remove_team(&app.pool, TeamId(id), BY)
        .await
        .map_err(failed)?;
    Ok(Json(Removed { id }))
}

/// A seat on a team.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SeatRequest {
    pub team_role: TeamRole,
    /// Points per sprint.
    pub capacity: Option<u32>,
}

#[utoipa::path(put, path = "/api/v1/teams/{id}/members/{agent_id}", operation_id = "seatAgent",
    tag = "org", params(("id" = i64, Path, description = "Team id"),
        ("agent_id" = i64, Path, description = "Agent id")),
    request_body = SeatRequest,
    responses((status = 200, description = "The team with the agent seated (or its seat changed; \
        audited as `team.member_seated`); 409 when another agent is the team's product owner or \
        lead; 404 for an agent of another company", body = Team)))]
pub async fn seat(
    State(app): State<App>,
    Path((id, agent)): Path<(i64, i64)>,
    Json(s): Json<SeatRequest>,
) -> ApiResult<Team> {
    let t = TeamId(id);
    org::seat_checked(
        &app.pool,
        t,
        AgentId(agent),
        s.team_role.into(),
        s.capacity,
        BY,
    )
    .await
    .map_err(failed)?;
    let team = org::get_team(&app.pool, t)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no team {id}")))?;
    team_out(&app, team).await
}

#[utoipa::path(delete, path = "/api/v1/teams/{id}/members/{agent_id}", operation_id = "unseatAgent",
    tag = "org", params(("id" = i64, Path, description = "Team id"),
        ("agent_id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The team without the agent (audited as \
        `team.member_unseated`); 404 when it had no seat there", body = Team)))]
pub async fn unseat(
    State(app): State<App>,
    Path((id, agent)): Path<(i64, i64)>,
) -> ApiResult<Team> {
    let t = TeamId(id);
    if !org::unseat_member(&app.pool, t, AgentId(agent), BY)
        .await
        .map_err(failed)?
    {
        return Err(ApiError::not_found(format!(
            "agent {agent} has no seat on team {id}"
        )));
    }
    let team = org::get_team(&app.pool, t)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no team {id}")))?;
    team_out(&app, team).await
}
