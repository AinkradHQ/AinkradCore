//! Companies, departments, teams and agents (read), typed: the responses are the contract's
//! `model` types, each route is documented for the Core contract (`spec`), and each takes
//! [`Acting`] so a client working in one company never reaches another's data (`scope`).
//! A refused write maps through `error::refused`.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use utoipa::ToSchema;

use super::error::{found, refused};
use super::model::{Agent, Company, Deleted, Department, Team};
use super::scope::Acting;
use super::types::CompanyKind;
use crate::domain::org::{AgentId, CompanyId, CompanyKind as Kind, DepartmentId, TeamId};
use crate::store::org::{self, service};

fn kind(text: Option<&str>) -> Result<Option<Kind>, ApiError> {
    text.map(|t| {
        t.parse()
            .map_err(|_| ApiError::bad_request("kind is `own` or `client`"))
    })
    .transpose()
}

#[utoipa::path(get, path = "/companies", operation_id = "listCompanies", tag = "org",
    responses((status = 200, description = "Every company, own or client (only the one named \
        in `X-Citadel-Company`, when it is sent): the company switcher", body = Vec<Company>)))]
pub async fn list_companies(State(app): State<App>, acting: Acting) -> ApiResult<Vec<Company>> {
    let all = org::list_companies(&app.pool).await?;
    let own = all.into_iter().filter(|c| acting.sees(Some(c.id.0)));
    Ok(Json(own.map(Into::into).collect()))
}

#[utoipa::path(get, path = "/companies/{id}", operation_id = "getCompany", tag = "org",
    params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company", body = Company)))]
pub async fn get_company(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Company> {
    let c = found(org::get_company(&app.pool, CompanyId(id)).await?, "company")?;
    Ok(Json(c.into()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewCompany {
    pub name: String,
    /// `own` (the default) or `client`; anything else is a 400.
    #[schema(value_type = Option<CompanyKind>)]
    pub kind: Option<String>,
}

#[utoipa::path(post, path = "/companies", operation_id = "createCompany", tag = "org",
    request_body = NewCompany,
    responses((status = 200, description = "The new company (audited as `citadel.company.created`)",
        body = Company)))]
pub async fn create_company(
    State(app): State<App>,
    Json(n): Json<NewCompany>,
) -> ApiResult<Company> {
    let kind = kind(n.kind.as_deref())?.unwrap_or(Kind::Own);
    let c = service::add_company(&app.pool, &n.name, kind, BY)
        .await
        .map_err(refused)?;
    Ok(Json(c.into()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CompanyChange {
    pub name: Option<String>,
    #[schema(value_type = Option<CompanyKind>)]
    pub kind: Option<String>,
}

#[utoipa::path(put, path = "/companies/{id}", operation_id = "updateCompany", tag = "org",
    params(("id" = i64, Path, description = "Company id")), request_body = CompanyChange,
    responses((status = 200, description = "The company as changed (audited as \
        `citadel.company.updated`)", body = Company)))]
pub async fn update_company(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(c): Json<CompanyChange>,
) -> ApiResult<Company> {
    let kind = kind(c.kind.as_deref())?;
    let c = service::change_company(&app.pool, CompanyId(id), c.name.as_deref(), kind, BY)
        .await
        .map_err(refused)?;
    Ok(Json(found(c, "company")?.into()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NameBody {
    pub name: String,
}

#[utoipa::path(get, path = "/companies/{id}/departments", operation_id = "listDepartments",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "Its departments", body = Vec<Department>)))]
pub async fn list_departments(
    State(app): State<App>,
    _: Acting,
    Path(company): Path<i64>,
) -> ApiResult<Vec<Department>> {
    let all = org::list_departments(&app.pool, CompanyId(company)).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(post, path = "/companies/{id}/departments", operation_id = "createDepartment",
    tag = "org", params(("id" = i64, Path, description = "Company id")), request_body = NameBody,
    responses((status = 200, description = "The new department (audited as \
        `citadel.department.added`)", body = Department)))]
pub async fn add_department(
    State(app): State<App>,
    _: Acting,
    Path(company): Path<i64>,
    Json(n): Json<NameBody>,
) -> ApiResult<Department> {
    let d = service::add_department(&app.pool, CompanyId(company), &n.name, BY)
        .await
        .map_err(refused)?;
    Ok(Json(d.into()))
}

#[utoipa::path(put, path = "/departments/{id}", operation_id = "updateDepartment", tag = "org",
    params(("id" = i64, Path, description = "Department id")), request_body = NameBody,
    responses((status = 200, description = "The department as renamed", body = Department)))]
pub async fn rename_department(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(n): Json<NameBody>,
) -> ApiResult<Department> {
    let d = service::rename_department(&app.pool, DepartmentId(id), &n.name, BY)
        .await
        .map_err(refused)?;
    Ok(Json(found(d, "department")?.into()))
}

#[utoipa::path(delete, path = "/departments/{id}", operation_id = "deleteDepartment",
    tag = "org", params(("id" = i64, Path, description = "Department id")),
    responses((status = 200, description = "Deleted, with its teams; needs a step-up",
        body = Deleted)))]
pub async fn remove_department(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Deleted> {
    let gone = service::remove_department(&app.pool, DepartmentId(id), BY)
        .await
        .map_err(refused)?;
    found(gone.then_some(()), "department")?;
    Ok(Json(Deleted { deleted: id }))
}

#[utoipa::path(get, path = "/departments/{id}/teams", operation_id = "listTeams", tag = "org",
    params(("id" = i64, Path, description = "Department id")),
    responses((status = 200, description = "Its teams", body = Vec<Team>)))]
pub async fn list_teams(
    State(app): State<App>,
    _: Acting,
    Path(department): Path<i64>,
) -> ApiResult<Vec<Team>> {
    let all = org::list_teams(&app.pool, DepartmentId(department)).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(post, path = "/departments/{id}/teams", operation_id = "createTeam", tag = "org",
    params(("id" = i64, Path, description = "Department id")), request_body = NameBody,
    responses((status = 200, description = "The new team (audited as `citadel.team.added`)",
        body = Team)))]
pub async fn add_team(
    State(app): State<App>,
    _: Acting,
    Path(department): Path<i64>,
    Json(n): Json<NameBody>,
) -> ApiResult<Team> {
    let t = service::add_team(&app.pool, DepartmentId(department), &n.name, BY)
        .await
        .map_err(refused)?;
    Ok(Json(t.into()))
}

#[utoipa::path(put, path = "/teams/{id}", operation_id = "updateTeam", tag = "org",
    params(("id" = i64, Path, description = "Team id")), request_body = NameBody,
    responses((status = 200, description = "The team as renamed", body = Team)))]
pub async fn rename_team(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(n): Json<NameBody>,
) -> ApiResult<Team> {
    let t = service::rename_team(&app.pool, TeamId(id), &n.name, BY)
        .await
        .map_err(refused)?;
    Ok(Json(found(t, "team")?.into()))
}

#[utoipa::path(delete, path = "/teams/{id}", operation_id = "deleteTeam", tag = "org",
    params(("id" = i64, Path, description = "Team id")),
    responses((status = 200, description = "Deleted; needs a step-up", body = Deleted)))]
pub async fn remove_team(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Deleted> {
    let gone = service::remove_team(&app.pool, TeamId(id), BY)
        .await
        .map_err(refused)?;
    found(gone.then_some(()), "team")?;
    Ok(Json(Deleted { deleted: id }))
}

#[utoipa::path(get, path = "/companies/{id}/agents", operation_id = "listAgents", tag = "org",
    params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "Its agents", body = Vec<Agent>)))]
pub async fn list_agents(
    State(app): State<App>,
    _: Acting,
    Path(company): Path<i64>,
) -> ApiResult<Vec<Agent>> {
    let all = org::list_agents(&app.pool, CompanyId(company)).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(get, path = "/agents/{id}", operation_id = "getAgent", tag = "org",
    params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The agent", body = Agent)))]
pub async fn get_agent(State(app): State<App>, _: Acting, Path(id): Path<i64>) -> ApiResult<Agent> {
    let a = found(org::get_agent(&app.pool, AgentId(id)).await?, "agent")?;
    Ok(Json(a.into()))
}
