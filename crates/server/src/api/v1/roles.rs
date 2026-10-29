//! Roles (API minor 18): what a company hires for, with the defaults a new agent of the role
//! starts on (harness, model, token budget, skills, instructions). Audited as `role.created`,
//! `.updated` and `.deleted`, each an event on the stream.

use ainkrad_core::ops::{NewRole, Role};
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::org::company;
use super::types::Harness;
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::org;

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleOut {
    pub id: i64,
    pub company_id: i64,
    pub name: String,
    pub purpose: String,
    /// A glyph name the client draws; free text.
    pub icon: String,
    /// What a new agent of the role starts on; absent: the client's choice.
    pub harness: Option<Harness>,
    pub model: Option<String>,
    /// Its token budget per month, when the role has a default.
    pub budget_tokens: Option<i64>,
    /// Skill names.
    pub skills: Vec<String>,
    pub instructions: String,
}

impl From<Role> for RoleOut {
    fn from(r: Role) -> Self {
        Self {
            id: r.id,
            company_id: r.company_id,
            name: r.name,
            purpose: r.purpose,
            icon: r.icon,
            harness: r.harness.map(Into::into),
            model: r.model,
            budget_tokens: r.budget_tokens,
            skills: r.skills,
            instructions: r.instructions,
        }
    }
}

/// A role to store; `PUT` replaces all of it.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RoleBody {
    /// 1-100 characters, unique within the company.
    pub name: String,
    /// At most 500 characters.
    #[serde(default)]
    pub purpose: String,
    /// At most 40 characters.
    #[serde(default)]
    pub icon: String,
    pub harness: Option<Harness>,
    /// 1-200 characters.
    pub model: Option<String>,
    /// 0 or more.
    pub budget_tokens: Option<i64>,
    /// At most 50 skill names.
    #[serde(default)]
    pub skills: Vec<String>,
    /// At most 20000 characters.
    #[serde(default)]
    pub instructions: String,
}

impl From<RoleBody> for NewRole {
    fn from(b: RoleBody) -> Self {
        Self {
            name: b.name,
            purpose: b.purpose,
            icon: b.icon,
            harness: b.harness.map(Into::into),
            model: b.model,
            budget_tokens: b.budget_tokens,
            skills: b.skills,
            instructions: b.instructions,
        }
    }
}

fn failed(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
        sqlx::Error::Database(d) if d.message().contains("UNIQUE") => {
            ApiError::conflict("the company has a role of that name already")
        }
        e => e.into(),
    }
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/roles", operation_id = "listRoles", tag = "org",
    params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company's roles, by name", body = Vec<RoleOut>)))]
pub async fn list(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<RoleOut>> {
    let c = company(&app, id).await?;
    let all = org::list_roles(&app.pool, c.id).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(post, path = "/api/v1/companies/{id}/roles", operation_id = "createRole", tag = "org",
    params(("id" = i64, Path, description = "Company id")), request_body = RoleBody,
    responses((status = 200, description = "The role (audited as `role.created`); 409 for a name \
        the company has, 400 for an invalid role", body = RoleOut)))]
pub async fn create(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<RoleBody>,
) -> ApiResult<RoleOut> {
    let c = company(&app, id).await?;
    let made = org::create_role(&app.pool, c.id, &b.into(), BY)
        .await
        .map_err(failed)?;
    Ok(Json(made.into()))
}

#[utoipa::path(put, path = "/api/v1/roles/{id}", operation_id = "updateRole", tag = "org",
    params(("id" = i64, Path, description = "Role id")), request_body = RoleBody,
    responses((status = 200, description = "The role as replaced (audited as `role.updated`)",
        body = RoleOut)))]
pub async fn update(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<RoleBody>,
) -> ApiResult<RoleOut> {
    let made = org::update_role(&app.pool, id, &b.into(), BY)
        .await
        .map_err(failed)?
        .ok_or_else(|| ApiError::not_found(format!("no role {id}")))?;
    Ok(Json(made.into()))
}

#[utoipa::path(delete, path = "/api/v1/roles/{id}", operation_id = "deleteRole", tag = "org",
    params(("id" = i64, Path, description = "Role id")),
    responses((status = 200, description = "Deleted (audited as `role.deleted`); agents keep \
        their role title", body = super::chains::Deleted)))]
pub async fn delete(
    State(app): State<App>,
    Path(id): Path<i64>,
) -> ApiResult<super::chains::Deleted> {
    match org::delete_role(&app.pool, id, BY).await? {
        true => Ok(Json(super::chains::Deleted { id })),
        false => Err(ApiError::not_found(format!("no role {id}"))),
    }
}
