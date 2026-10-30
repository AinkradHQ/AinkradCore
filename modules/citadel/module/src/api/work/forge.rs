//! Forge hosts and a project's Linear link (S6). A forge's API URL must be on the call policy's
//! allow-list (`ainkrad_providers::guard`: the public hosts and the hosts added here), and a
//! Linear link names a broker secret, never a token. Changing either widens where the server
//! sends a credential, so every write is a step-up route.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::util::{project, rule};
use crate::api::scope::Acting;
use crate::domain::work::ProjectId;
use crate::store::linear::{self, LINEAR_API, ProjectLinear};

/// The hosts allowed besides the public ones.
#[derive(Debug, Serialize, ToSchema)]
pub struct ForgeHosts {
    /// Always allowed: GitHub, GitLab.com and Linear.
    pub public: Vec<String>,
    /// Added by an operator, e.g. a self-hosted GitLab.
    pub added: Vec<String>,
}

#[utoipa::path(get, path = "/forge/hosts", operation_id = "listForgeHosts", tag = "forge",
    responses((status = 200, description = "The hosts a forge or Linear API may be on", body = ForgeHosts)))]
pub async fn list_hosts(State(app): State<App>, _: Acting) -> ApiResult<ForgeHosts> {
    Ok(Json(ForgeHosts {
        public: ["api.github.com", "gitlab.com", "api.linear.app"]
            .map(str::to_owned)
            .to_vec(),
        added: crate::store::forge::list_hosts(&app.pool).await?,
    }))
}

#[utoipa::path(put, path = "/forge/hosts/{host}", operation_id = "addForgeHost", tag = "forge",
    params(("host" = String, Path, description = "A lowercase host name, never an IP address")),
    responses((status = 200, description = "The hosts after it (idempotent); refused (400) for a \
        name that is not a public-looking host name", body = ForgeHosts)))]
pub async fn add_host(
    State(app): State<App>,
    acting: Acting,
    Path(host): Path<String>,
) -> ApiResult<ForgeHosts> {
    crate::store::forge::add_host(&app.pool, &host, BY)
        .await
        .map_err(rule)?;
    list_hosts(State(app), acting).await
}

#[utoipa::path(delete, path = "/forge/hosts/{host}", operation_id = "removeForgeHost", tag = "forge",
    params(("host" = String, Path, description = "A host added earlier")),
    responses((status = 200, description = "The hosts after it", body = ForgeHosts)))]
pub async fn remove_host(
    State(app): State<App>,
    acting: Acting,
    Path(host): Path<String>,
) -> ApiResult<ForgeHosts> {
    crate::store::forge::remove_host(&app.pool, &host, BY).await?;
    list_hosts(State(app), acting).await
}

/// A project's Linear link.
#[derive(Debug, Serialize, ToSchema)]
pub struct LinearLink {
    pub project_id: i64,
    pub team_id: String,
    pub api_url: String,
    /// The broker secret holding the API token (never the token).
    pub secret_name: String,
    /// The latest `updatedAt` read from Linear.
    pub cursor: Option<String>,
}

impl From<ProjectLinear> for LinearLink {
    fn from(l: ProjectLinear) -> Self {
        Self {
            project_id: l.project_id.0,
            team_id: l.team_id,
            api_url: l.api_url,
            secret_name: l.secret,
            cursor: l.cursor,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LinearBody {
    pub team_id: String,
    /// Absent: Linear's public API.
    pub api_url: Option<String>,
    /// The broker secret holding the API token, `citadel.<name>`.
    pub secret_name: String,
}

#[utoipa::path(get, path = "/projects/{id}/linear", operation_id = "getProjectLinear",
    tag = "forge", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project's Linear link", body = LinearLink),
        (status = 404, description = "No such project, or it is not synced with Linear")))]
pub async fn get_linear(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<LinearLink> {
    let p = project(&app, id).await?;
    linear::project_linear(&app.pool, p.id)
        .await?
        .map(|l| Json(l.into()))
        .ok_or_else(|| ApiError::not_found(format!("project {id} is not synced with Linear")))
}

#[utoipa::path(put, path = "/projects/{id}/linear", operation_id = "setProjectLinear",
    tag = "forge", params(("id" = i64, Path, description = "Project id")), request_body = LinearBody,
    responses((status = 200, description = "The link; the sync's cursor starts over", body = LinearLink)))]
pub async fn set_linear(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(b): Json<LinearBody>,
) -> ApiResult<LinearLink> {
    let p = project(&app, id).await?;
    let api_url = b.api_url.unwrap_or_else(|| LINEAR_API.to_owned());
    let hosts = crate::store::forge::list_hosts(&app.pool).await?;
    let policy = ainkrad_providers::guard::Policy::public().with_hosts(hosts);
    policy
        .check_url(&api_url)
        .map_err(|why| ApiError::bad_request(format!("the API URL is not allowed: {why}")))?;
    let link = ProjectLinear {
        project_id: ProjectId(p.id.0),
        team_id: b.team_id,
        api_url,
        secret: b.secret_name,
        cursor: None,
    };
    linear::set_project_linear(&app.pool, &link, BY)
        .await
        .map_err(rule)?;
    get_linear(State(app), Acting::default(), Path(id)).await
}

#[utoipa::path(delete, path = "/projects/{id}/linear", operation_id = "removeProjectLinear",
    tag = "forge", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "Whether a link was removed", body = bool)))]
pub async fn remove_linear(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<bool> {
    let p = project(&app, id).await?;
    Ok(Json(
        linear::remove_project_linear(&app.pool, p.id, BY).await?,
    ))
}
