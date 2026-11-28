//! Project-level variables of a run environment (API 112): `…/run-envs/{name}/env`. They are laid
//! over the project's run spec when it starts (`run/start`, with that environment), and under a run
//! configuration's own variables when it starts one. Same rules and shapes as a configuration's
//! variables (`run_configs`); values are never returned.

use axum::Json;
use axum::extract::{Extension, Path, State};

use super::run_configs::{RunConfigDeleted, RunVar, SetRunVar};
use super::{num, who};
use crate::api::App;
use crate::api::v1::{ApiError, ApiResult, Caller};
use crate::store::run_configs as store;

#[utoipa::path(get, path = "/api/v1/projects/{id}/run-envs/{name}/env",
    operation_id = "listRunEnvVars", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("name" = String, Path, description = "The environment")),
    responses((status = 200, description = "The environment's project-level variables by name, \
        without values (they apply to a run of the project in that environment). 404 for no such \
        project or environment", body = Vec<RunVar>)))]
pub async fn list(
    State(app): State<App>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<Vec<RunVar>> {
    let p = num(&id, "project")?;
    if !store::environments(&app.pool, p).await?.contains(&name) {
        return Err(ApiError::not_found("no such environment"));
    }
    let all = store::project_vars(&app.pool, p, &name).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(put, path = "/api/v1/projects/{id}/run-envs/{name}/env/{key}",
    operation_id = "setRunEnvVar", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("name" = String, Path, description = "The environment"),
           ("key" = String, Path, description = "The variable name")),
    request_body = SetRunVar,
    responses((status = 200, description = "Set or replaced (audited without the value). 400 \
        `bad_request` for a bad name or value or neither/both; 400/409 `invalid_spec` when \
        `secret` is not one of the project's; 409 `conflict` for an archived project; 409 \
        `limit_reached` at 64; 404 for no such environment", body = RunVar)))]
pub async fn set(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, name, key)): Path<(String, String, String)>,
    Json(b): Json<SetRunVar>,
) -> ApiResult<RunVar> {
    let now = app.clock.now();
    let v = store::set_project_var(
        &app.pool,
        num(&id, "project")?,
        &name,
        &key,
        b.value.as_deref(),
        b.secret.as_deref(),
        who(&me, &now),
    )
    .await?;
    Ok(Json(v.into()))
}

#[utoipa::path(delete, path = "/api/v1/projects/{id}/run-envs/{name}/env/{key}",
    operation_id = "deleteRunEnvVar", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("name" = String, Path, description = "The environment"),
           ("key" = String, Path, description = "The variable name")),
    responses((status = 200, description = "Deleted; 404 for no such variable or environment",
        body = RunConfigDeleted)))]
pub async fn delete(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, name, key)): Path<(String, String, String)>,
) -> ApiResult<RunConfigDeleted> {
    let now = app.clock.now();
    store::delete_project_var(&app.pool, num(&id, "project")?, &name, &key, who(&me, &now)).await?;
    Ok(Json(RunConfigDeleted { deleted: true }))
}
