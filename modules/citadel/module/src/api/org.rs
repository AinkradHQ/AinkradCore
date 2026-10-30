//! Companies, departments, teams and agents (read). Bodies are JSON values shaped as the
//! monolith's `Company`, `Department`, `Team` and `Agent`; their OpenAPI schemas are merged
//! into the Core contract in the contract slice.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::domain::org::{
    Agent, AgentId, Company, CompanyId, CompanyKind, Department, DepartmentId, Team, TeamId,
};
use crate::store::org::{self, service};

fn company_json(c: &Company) -> Value {
    json!({
        "id": c.id.0, "name": c.name, "kind": c.kind.as_str(), "color": c.profile.color,
        "description": c.profile.description, "industries": c.profile.industries,
        "website": c.profile.website, "timezone": c.profile.timezone,
        "work_start": c.profile.work_start, "work_end": c.profile.work_end,
        "work_days": c.profile.work_days, "logo_sha256": c.profile.logo_sha256,
    })
}

fn department_json(d: &Department) -> Value {
    json!({
        "id": d.id.0, "company_id": d.company_id.0, "name": d.name, "about": d.about,
        "head_agent_id": d.head_agent_id.map(|a| a.0),
    })
}

fn team_json(t: &Team) -> Value {
    json!({"id": t.id.0, "department_id": t.department_id.0, "name": t.name})
}

fn agent_json(a: &Agent) -> Value {
    json!({
        "id": a.id.0, "company_id": a.company_id.0, "name": a.name, "role": a.role,
        "org_role": a.org_role.as_str(), "reports_to": a.reports_to.map(|r| r.0),
        "harness": a.harness.as_str(), "model": a.model, "runner_tags": a.runner_tags,
        "status": a.status.as_str(), "description": a.profile.description,
        "figure_version": a.figure_version, "palette_id": a.palette_id,
        "avatar_sha256": a.avatar_sha256, "paused_at": a.paused_at, "created_at": a.created_at,
    })
}

/// A write refused by a constraint is a 409, a missing name a 400; anything else is internal.
fn refused(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Protocol(why) => ApiError::bad_request(why),
        e if service::is_constraint(&e) => {
            ApiError::conflict("the change breaks a rule (a duplicate name or a missing parent)")
        }
        e => e.into(),
    }
}

fn kind(text: Option<&str>) -> Result<Option<CompanyKind>, ApiError> {
    text.map(|t| {
        t.parse()
            .map_err(|_| ApiError::bad_request("kind is `own` or `client`"))
    })
    .transpose()
}

pub async fn list_companies(State(app): State<App>) -> ApiResult<Vec<Value>> {
    let all = org::list_companies(&app.pool).await?;
    Ok(Json(all.iter().map(company_json).collect()))
}

pub async fn get_company(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Value> {
    match org::get_company(&app.pool, CompanyId(id)).await? {
        Some(c) => Ok(Json(company_json(&c))),
        None => Err(ApiError::not_found("no such company")),
    }
}

#[derive(Deserialize)]
pub struct NewCompany {
    name: String,
    kind: Option<String>,
}

pub async fn create_company(State(app): State<App>, Json(n): Json<NewCompany>) -> ApiResult<Value> {
    let kind = kind(n.kind.as_deref())?.unwrap_or(CompanyKind::Own);
    let c = service::add_company(&app.pool, &n.name, kind, BY)
        .await
        .map_err(refused)?;
    Ok(Json(company_json(&c)))
}

#[derive(Deserialize)]
pub struct CompanyChange {
    name: Option<String>,
    kind: Option<String>,
}

pub async fn update_company(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(c): Json<CompanyChange>,
) -> ApiResult<Value> {
    let kind = kind(c.kind.as_deref())?;
    match service::change_company(&app.pool, CompanyId(id), c.name.as_deref(), kind, BY)
        .await
        .map_err(refused)?
    {
        Some(c) => Ok(Json(company_json(&c))),
        None => Err(ApiError::not_found("no such company")),
    }
}

#[derive(Deserialize)]
pub struct Named {
    name: String,
}

pub async fn list_departments(
    State(app): State<App>,
    Path(company): Path<i64>,
) -> ApiResult<Vec<Value>> {
    let all = org::list_departments(&app.pool, CompanyId(company)).await?;
    Ok(Json(all.iter().map(department_json).collect()))
}

pub async fn add_department(
    State(app): State<App>,
    Path(company): Path<i64>,
    Json(n): Json<Named>,
) -> ApiResult<Value> {
    let d = service::add_department(&app.pool, CompanyId(company), &n.name, BY)
        .await
        .map_err(refused)?;
    Ok(Json(department_json(&d)))
}

pub async fn rename_department(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(n): Json<Named>,
) -> ApiResult<Value> {
    match service::rename_department(&app.pool, DepartmentId(id), &n.name, BY)
        .await
        .map_err(refused)?
    {
        Some(d) => Ok(Json(department_json(&d))),
        None => Err(ApiError::not_found("no such department")),
    }
}

pub async fn remove_department(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Value> {
    match service::remove_department(&app.pool, DepartmentId(id), BY)
        .await
        .map_err(refused)?
    {
        true => Ok(Json(json!({"deleted": id}))),
        false => Err(ApiError::not_found("no such department")),
    }
}

pub async fn list_teams(
    State(app): State<App>,
    Path(department): Path<i64>,
) -> ApiResult<Vec<Value>> {
    let all = org::list_teams(&app.pool, DepartmentId(department)).await?;
    Ok(Json(all.iter().map(team_json).collect()))
}

pub async fn add_team(
    State(app): State<App>,
    Path(department): Path<i64>,
    Json(n): Json<Named>,
) -> ApiResult<Value> {
    let t = service::add_team(&app.pool, DepartmentId(department), &n.name, BY)
        .await
        .map_err(refused)?;
    Ok(Json(team_json(&t)))
}

pub async fn rename_team(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(n): Json<Named>,
) -> ApiResult<Value> {
    match service::rename_team(&app.pool, TeamId(id), &n.name, BY)
        .await
        .map_err(refused)?
    {
        Some(t) => Ok(Json(team_json(&t))),
        None => Err(ApiError::not_found("no such team")),
    }
}

pub async fn remove_team(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Value> {
    match service::remove_team(&app.pool, TeamId(id), BY)
        .await
        .map_err(refused)?
    {
        true => Ok(Json(json!({"deleted": id}))),
        false => Err(ApiError::not_found("no such team")),
    }
}

pub async fn list_agents(
    State(app): State<App>,
    Path(company): Path<i64>,
) -> ApiResult<Vec<Value>> {
    let all = org::list_agents(&app.pool, CompanyId(company)).await?;
    Ok(Json(all.iter().map(agent_json).collect()))
}

pub async fn get_agent(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Value> {
    match org::get_agent(&app.pool, AgentId(id)).await? {
        Some(a) => Ok(Json(agent_json(&a))),
        None => Err(ApiError::not_found("no such agent")),
    }
}
