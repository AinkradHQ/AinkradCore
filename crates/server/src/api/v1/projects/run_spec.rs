//! A project's run spec over the API (Core 0.9, P4-01; store `store::run_specs`). Reading is
//! `read`; saving is `admin` and destructive (a step-up): the spec decides what containers run on
//! a runner. A save is a new version, never a change to an old one. The body is checked field by
//! field; a 400 `invalid_spec` names the path of the first bad field in its message.

use axum::Json;
use axum::extract::{Extension, Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::super::types::{Timestamp, ts};
use super::super::{ApiResult, Caller};
use super::{num, who};
use crate::api::App;
use crate::store::run_specs::{self as store, RunSpec, SpecSummary, SpecVersion};

#[derive(Debug, Serialize, ToSchema)]
pub struct RunSpecVersion {
    /// 1 for the first save, then one more each time.
    pub version: i64,
    pub spec: RunSpec,
    /// `manual`, `compose`, `package_json`, `makefile` or `run_sh`.
    pub origin: String,
    /// The device that saved it.
    pub created_by: String,
    pub created_at: Timestamp,
}

impl From<SpecVersion> for RunSpecVersion {
    fn from(v: SpecVersion) -> Self {
        Self {
            version: v.version,
            spec: v.spec,
            origin: v.origin,
            created_by: v.created_by,
            created_at: ts(&v.created_at),
        }
    }
}

/// A version without its spec.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunSpecSummary {
    pub version: i64,
    pub origin: String,
    pub created_by: String,
    pub created_at: Timestamp,
}

impl From<SpecSummary> for RunSpecSummary {
    fn from(v: SpecSummary) -> Self {
        Self {
            version: v.version,
            origin: v.origin,
            created_by: v.created_by,
            created_at: ts(&v.created_at),
        }
    }
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/spec", operation_id = "getProjectSpec",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "The newest run spec version. 404 for no such project \
        or when it has no spec yet", body = RunSpecVersion)))]
pub async fn latest(State(app): State<App>, Path(id): Path<String>) -> ApiResult<RunSpecVersion> {
    Ok(Json(
        store::latest(&app.pool, num(&id, "project")?).await?.into(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewRunSpec {
    /// The spec; see `RunSpec`.
    #[schema(value_type = RunSpec)]
    pub spec: serde_json::Value,
    /// Where it came from; default `manual`.
    pub origin: Option<String>,
}

#[utoipa::path(put, path = "/api/v1/projects/{id}/spec", operation_id = "saveProjectSpec",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    request_body = NewRunSpec,
    responses((status = 200, description = "Saved as the next version (audited and emitted as \
        `project.spec_saved`). 400 `invalid_spec` names the bad field (unknown or forbidden key, \
        more than 16 services or 8 ports, a bad image, a malformed `${secret:NAME}`, a repo the \
        project does not have); 404 for no such project; 409 `conflict` when it is archived",
        body = RunSpecVersion)))]
pub async fn save(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<NewRunSpec>,
) -> ApiResult<RunSpecVersion> {
    let now = app.clock.now();
    let v = store::save(
        &app.pool,
        num(&id, "project")?,
        &b.spec,
        b.origin.as_deref().unwrap_or("manual"),
        who(&me, &now),
    )
    .await?;
    Ok(Json(v.into()))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/spec/versions",
    operation_id = "listProjectSpecVersions", tag = "projects",
    params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "Every version, newest first, without the spec. 404 \
        for no such project", body = Vec<RunSpecSummary>)))]
pub async fn versions(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Vec<RunSpecSummary>> {
    let v = store::versions(&app.pool, num(&id, "project")?).await?;
    Ok(Json(v.into_iter().map(Into::into).collect()))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/spec/versions/{version}",
    operation_id = "getProjectSpecVersion", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("version" = String, Path, description = "The version number")),
    responses((status = 200, description = "That version. 404 for no such project or version",
        body = RunSpecVersion)))]
pub async fn version(
    State(app): State<App>,
    Path((id, version)): Path<(String, String)>,
) -> ApiResult<RunSpecVersion> {
    let v = store::version(&app.pool, num(&id, "project")?, num(&version, "version")?).await?;
    Ok(Json(v.into()))
}
