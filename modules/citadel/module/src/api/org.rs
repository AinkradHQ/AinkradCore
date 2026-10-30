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
use super::model::org_admin::{NewDepartment, serde_with_none};
use super::model::{Agent, Company, Deleted, Department, Team};
use super::org_admin::{agent_out, agent_out_all, failed, org_refused};
use super::scope::Acting;
use super::types::CompanyKind;
use crate::domain::org::{
    AgentId, CompanyId, CompanyKind as Kind, CompanyProfile, DepartmentId, TeamId,
};
use crate::store::org::{self, service};

fn kind(text: Option<&str>) -> Result<Option<Kind>, ApiError> {
    text.map(|t| {
        t.parse()
            .map_err(|_| ApiError::bad_request("kind is `own` or `client`"))
    })
    .transpose()
}

async fn company_out(
    pool: &sqlx::SqlitePool,
    c: crate::domain::org::Company,
) -> Result<Company, sqlx::Error> {
    let account_ids: Vec<i64> = sqlx::query_scalar(
        "SELECT account_id FROM citadel_account_companies WHERE company_id = ? ORDER BY account_id",
    )
    .bind(c.id.0)
    .fetch_all(pool)
    .await?;
    let mut out = Company::from(c);
    out.account_ids = account_ids;
    Ok(out)
}

#[utoipa::path(get, path = "/companies", operation_id = "listCompanies", tag = "org",
    responses((status = 200, description = "Every company, own or client (only the one named \
        in `X-Citadel-Company`, when it is sent): the company switcher", body = Vec<Company>)))]
pub async fn list_companies(State(app): State<App>, acting: Acting) -> ApiResult<Vec<Company>> {
    let all = org::list_companies(&app.pool).await?;
    let mut out = Vec::new();
    for c in all.into_iter().filter(|c| acting.sees(Some(c.id.0))) {
        out.push(company_out(&app.pool, c).await?);
    }
    Ok(Json(out))
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
    Ok(Json(company_out(&app.pool, c).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewCompany {
    pub name: String,
    /// `own` (the default) or `client`; anything else is a 400.
    #[schema(value_type = Option<CompanyKind>)]
    pub kind: Option<String>,
    /// The profile fields (API minor 17) are optional; a field out of shape is a 400.
    pub color: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub industries: Vec<String>,
    pub website: Option<String>,
    pub timezone: Option<String>,
    pub work_start: Option<u16>,
    pub work_end: Option<u16>,
    pub work_days: Option<u8>,
}

#[utoipa::path(post, path = "/companies", operation_id = "createCompany", tag = "org",
    request_body = NewCompany,
    responses((status = 200, description = "The new company (audited as `citadel.company.created`)",
        body = Company)))]
pub async fn create_company(
    State(app): State<App>,
    _: Acting,
    Json(n): Json<NewCompany>,
) -> ApiResult<Company> {
    let kind = kind(n.kind.as_deref())?.unwrap_or(Kind::Own);
    let profile = CompanyProfile {
        color: n.color,
        description: n.description,
        industries: n.industries,
        website: n.website,
        timezone: n.timezone,
        work_start: n.work_start,
        work_end: n.work_end,
        work_days: n.work_days,
        logo_sha256: None,
    };
    let c = org::add_company_with(&app.pool, &n.name, kind, &profile, BY)
        .await
        .map_err(failed)?;
    Ok(Json(company_out(&app.pool, c).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CompanyChange {
    pub name: Option<String>,
    #[schema(value_type = Option<CompanyKind>)]
    pub kind: Option<String>,
    /// The profile fields (API minor 17): absent stays, `null` clears an optional one.
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<String>)]
    pub color: Option<Option<String>>,
    pub description: Option<String>,
    pub industries: Option<Vec<String>>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<String>)]
    pub website: Option<Option<String>>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<String>)]
    pub timezone: Option<Option<String>>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<u16>)]
    pub work_start: Option<Option<u16>>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<u16>)]
    pub work_end: Option<Option<u16>>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<u8>)]
    pub work_days: Option<Option<u8>>,
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
    let mut co = found(org::get_company(&app.pool, CompanyId(id)).await?, "company")?;
    if let Some(name) = c.name {
        co.name = name;
    }
    co.kind = kind.unwrap_or(co.kind);
    let p = &mut co.profile;
    if let Some(v) = c.color {
        p.color = v;
    }
    if let Some(v) = c.website {
        p.website = v;
    }
    if let Some(v) = c.timezone {
        p.timezone = v;
    }
    p.description = c.description.unwrap_or_else(|| p.description.clone());
    p.industries = c.industries.unwrap_or_else(|| p.industries.clone());
    p.work_start = c.work_start.unwrap_or(p.work_start);
    p.work_end = c.work_end.unwrap_or(p.work_end);
    p.work_days = c.work_days.unwrap_or(p.work_days);
    if !org::edit_company(&app.pool, &co, BY)
        .await
        .map_err(failed)?
    {
        return Err(ApiError::not_found("no such company"));
    }
    let now = found(org::get_company(&app.pool, CompanyId(id)).await?, "company")?;
    Ok(Json(company_out(&app.pool, now).await?))
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
    tag = "org", params(("id" = i64, Path, description = "Company id")), request_body = NewDepartment,
    responses((status = 200, description = "The new department (audited as \
        `citadel.department.added`)", body = Department)))]
pub async fn add_department(
    State(app): State<App>,
    _: Acting,
    Path(company): Path<i64>,
    Json(n): Json<NewDepartment>,
) -> ApiResult<Department> {
    let head = n.head_agent_id.map(AgentId);
    let d = org::create_department_with(&app.pool, CompanyId(company), &n.name, &n.about, head, BY)
        .await
        .map_err(org_refused)?;
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
    // The monolith's 404 for a company that is not there.
    found(
        org::get_company(&app.pool, CompanyId(company)).await?,
        "company",
    )?;
    Ok(Json(agent_out_all(&app, CompanyId(company)).await?))
}

#[utoipa::path(get, path = "/agents/{id}", operation_id = "getAgent", tag = "org",
    params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The agent", body = Agent)))]
pub async fn get_agent(State(app): State<App>, _: Acting, Path(id): Path<i64>) -> ApiResult<Agent> {
    let a = found(org::get_agent(&app.pool, AgentId(id)).await?, "agent")?;
    agent_out(&app, a).await.map(Json)
}
