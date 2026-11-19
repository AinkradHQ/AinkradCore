//! Run configurations and environments over the API (Core 0.10, E11-3; store
//! `store::run_configs`). Reading is `read`; writing is `admin`; starting one is `admin` and
//! destructive like every start. SECURITY: no list returns a value. A variable shows its name,
//! whether it is a plain value or a link to one of the project's secrets (and which), and the
//! length of a plain value. The one route that returns a plain value is the explicit reveal
//! (`admin`); a linked variable has no value to show.

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::super::types::{Timestamp, ts};
use super::super::{ApiError, ApiResult, Caller};
use super::runs::{ProjectRun, start_with};
use super::{num, who};
use crate::api::App;
use crate::runs::StartOpts;
use crate::store::run_configs::{self as store, Config, Input, Var};

#[derive(Debug, Serialize, ToSchema)]
pub struct RunConfig {
    pub id: i64,
    pub name: String,
    /// Run in the service's shell.
    pub command: String,
    /// A folder in the service's repo checkout (`./app`), or an absolute path in the container.
    pub workdir: String,
    /// `automatic`, or the id of a runner.
    pub runner: String,
    /// The service of the run spec it is laid over; none lets the Core pick (the first that
    /// mounts a repo).
    pub service: Option<String>,
    pub port: Option<i64>,
    /// Come back after a crash: the Core restarts it after 2 s, 4 s, ... up to 60 s, at most 5
    /// times in 10 minutes, then gives up (event `project.run_gave_up`). A run a person stopped
    /// does not restart.
    pub restart: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<Config> for RunConfig {
    fn from(c: Config) -> Self {
        Self {
            id: c.id,
            name: c.name,
            command: c.command,
            workdir: c.workdir,
            runner: c.runner,
            service: c.service,
            port: c.port,
            restart: c.restart,
            created_at: ts(&c.created_at),
            updated_at: ts(&c.updated_at),
        }
    }
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct RunConfigBody {
    /// Required to create.
    pub name: Option<String>,
    /// Required to create.
    pub command: Option<String>,
    pub workdir: Option<String>,
    pub runner: Option<String>,
    /// Empty clears it.
    pub service: Option<String>,
    /// 0 clears it.
    pub port: Option<i64>,
    pub restart: Option<bool>,
}

impl From<RunConfigBody> for Input {
    fn from(b: RunConfigBody) -> Self {
        Self {
            name: b.name,
            command: b.command,
            workdir: b.workdir,
            runner: b.runner,
            service: b.service,
            port: b.port,
            restart: b.restart,
        }
    }
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/run-configs",
    operation_id = "listRunConfigs", tag = "projects",
    params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "The project's run configurations in order. 404 for \
        no such project", body = Vec<RunConfig>)))]
pub async fn list(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Vec<RunConfig>> {
    let all = store::list(&app.pool, num(&id, "project")?).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/run-configs",
    operation_id = "createRunConfig", tag = "projects",
    params(("id" = String, Path, description = "The project's id")),
    request_body = RunConfigBody,
    responses((status = 200, description = "Created (audited as `project.updated`). 400 \
        `bad_request`; 409 `conflict` for a name already used or an archived project; 409 \
        `limit_reached` at 32; 404 for no such project", body = RunConfig)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<RunConfigBody>,
) -> ApiResult<RunConfig> {
    let now = app.clock.now();
    let c = store::create(&app.pool, num(&id, "project")?, &b.into(), who(&me, &now)).await?;
    Ok(Json(c.into()))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/run-configs/{config}",
    operation_id = "getRunConfig", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("config" = String, Path, description = "The configuration's id")),
    responses((status = 200, description = "The configuration; 404 for no such project or \
        configuration", body = RunConfig)))]
pub async fn get(
    State(app): State<App>,
    Path((id, cid)): Path<(String, String)>,
) -> ApiResult<RunConfig> {
    let c = store::get(&app.pool, num(&id, "project")?, num(&cid, "configuration")?).await?;
    Ok(Json(c.into()))
}

#[utoipa::path(patch, path = "/api/v1/projects/{id}/run-configs/{config}",
    operation_id = "updateRunConfig", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("config" = String, Path, description = "The configuration's id")),
    request_body = RunConfigBody,
    responses((status = 200, description = "Changed: only the fields sent. Errors as create",
        body = RunConfig)))]
pub async fn update(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, cid)): Path<(String, String)>,
    Json(b): Json<RunConfigBody>,
) -> ApiResult<RunConfig> {
    let now = app.clock.now();
    let c = store::update(
        &app.pool,
        num(&id, "project")?,
        num(&cid, "configuration")?,
        &b.into(),
        who(&me, &now),
    )
    .await?;
    Ok(Json(c.into()))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Deleted {
    pub deleted: bool,
}

#[utoipa::path(delete, path = "/api/v1/projects/{id}/run-configs/{config}",
    operation_id = "deleteRunConfig", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("config" = String, Path, description = "The configuration's id")),
    responses((status = 200, description = "Deleted with its variables; a live run of it keeps \
        running. 404 for no such project or configuration", body = Deleted)))]
pub async fn delete(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, cid)): Path<(String, String)>,
) -> ApiResult<Deleted> {
    let now = app.clock.now();
    store::delete(
        &app.pool,
        num(&id, "project")?,
        num(&cid, "configuration")?,
        who(&me, &now),
    )
    .await?;
    Ok(Json(Deleted { deleted: true }))
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/run-configs/{config}/duplicate",
    operation_id = "duplicateRunConfig", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("config" = String, Path, description = "The configuration's id")),
    responses((status = 200, description = "A copy named `<name> copy` with every variable, \
        Secret links included. Errors as create", body = RunConfig)))]
pub async fn duplicate(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, cid)): Path<(String, String)>,
) -> ApiResult<RunConfig> {
    let now = app.clock.now();
    let c = store::duplicate(
        &app.pool,
        num(&id, "project")?,
        num(&cid, "configuration")?,
        who(&me, &now),
    )
    .await?;
    Ok(Json(c.into()))
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct RunConfigStart {
    /// The environment to run in; default the project's first.
    pub environment: Option<String>,
    /// Stop this configuration's live run first (other configurations keep running); default
    /// false.
    pub replace: Option<bool>,
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/run-configs/{config}/run",
    operation_id = "startRunConfig", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("config" = String, Path, description = "The configuration's id")),
    request_body = RunConfigStart,
    responses((status = 200, description = "The run, `starting` (as `startProjectRun`), with \
        the configuration and environment laid over the spec: its command, folder and port, and \
        the environment's variables (a Secret link is leased to the runner as `${secret:NAME}`, \
        never sent as a value). The configuration's runner is used when it is online. 409 \
        `conflict` while this configuration has a live run unless `replace`; 409 `no_runner`; 400/409 \
        `invalid_spec` when the result is not a valid spec or links a Secret the project no \
        longer has; 404 for no such configuration or environment", body = ProjectRun)))]
pub async fn run(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, cid)): Path<(String, String)>,
    body: Option<Json<RunConfigStart>>,
) -> ApiResult<ProjectRun> {
    let b = body.map(|Json(b)| b).unwrap_or_default();
    let opts = StartOpts {
        config: Some(num(&cid, "configuration")?),
        environment: b.environment,
    };
    Ok(Json(
        start_with(
            &app,
            &me,
            num(&id, "project")?,
            &opts,
            b.replace.unwrap_or(false),
        )
        .await?,
    ))
}

// ---- environments --------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct RunEnvs {
    /// In order; the first is the default. A new project has `Development` and `Staging`.
    pub environments: Vec<String>,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/run-envs", operation_id = "listRunEnvs",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "The project's environments. 404 for no such \
        project", body = RunEnvs)))]
pub async fn envs(State(app): State<App>, Path(id): Path<String>) -> ApiResult<RunEnvs> {
    let environments = store::environments(&app.pool, num(&id, "project")?).await?;
    Ok(Json(RunEnvs { environments }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewRunEnv {
    /// 1-40 characters on one line.
    pub name: String,
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/run-envs", operation_id = "addRunEnv",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    request_body = NewRunEnv,
    responses((status = 200, description = "Added at the end; the environments now. 409 \
        `conflict` for a name in use; 409 `limit_reached` at 8", body = RunEnvs)))]
pub async fn add_env(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<NewRunEnv>,
) -> ApiResult<RunEnvs> {
    let now = app.clock.now();
    let environments =
        store::add_environment(&app.pool, num(&id, "project")?, &b.name, who(&me, &now)).await?;
    Ok(Json(RunEnvs { environments }))
}

#[utoipa::path(delete, path = "/api/v1/projects/{id}/run-envs/{name}",
    operation_id = "deleteRunEnv", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("name" = String, Path, description = "The environment")),
    responses((status = 200, description = "Removed with every variable kept for it; the \
        environments now. 409 `conflict` for the last one; 404 for no such environment",
        body = RunEnvs)))]
pub async fn delete_env(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<RunEnvs> {
    let now = app.clock.now();
    let environments =
        store::delete_environment(&app.pool, num(&id, "project")?, &name, who(&me, &now)).await?;
    Ok(Json(RunEnvs { environments }))
}

// ---- variables -----------------------------------------------------------------------------

/// A variable, never its value.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunVar {
    pub key: String,
    /// `plain` or `secret`.
    pub kind: String,
    /// For `secret`: the project secret it comes from. Its value is never returned.
    pub secret: Option<String>,
    /// For `plain`: the value's length in bytes (a client may draw dots); the value itself comes
    /// from the reveal route only.
    pub size: Option<i64>,
}

impl From<Var> for RunVar {
    fn from(v: Var) -> Self {
        Self {
            key: v.key,
            kind: if v.secret.is_some() {
                "secret"
            } else {
                "plain"
            }
            .to_owned(),
            size: v.value.as_ref().map(|x| x.len() as i64),
            secret: v.secret,
        }
    }
}

fn ids(id: &str, cid: &str) -> Result<(i64, i64), ApiError> {
    Ok((num(id, "project")?, num(cid, "configuration")?))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/run-configs/{config}/env/{env}",
    operation_id = "listRunVars", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("config" = String, Path, description = "The configuration's id"),
           ("env" = String, Path, description = "The environment")),
    responses((status = 200, description = "The variables by name, without values. 404 for no \
        such configuration or environment", body = Vec<RunVar>)))]
pub async fn vars(
    State(app): State<App>,
    Path((id, cid, env)): Path<(String, String, String)>,
) -> ApiResult<Vec<RunVar>> {
    let (p, c) = ids(&id, &cid)?;
    store::get(&app.pool, p, c).await?;
    if !store::environments(&app.pool, p).await?.contains(&env) {
        return Err(ApiError::not_found("no such environment"));
    }
    let all = store::vars(&app.pool, c, &env).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

/// A value to set. Deliberately no `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct SetRunVar {
    /// A plain value (not holding `${`). Give this or `secret`.
    pub value: Option<String>,
    /// The name of one of the project's secrets: the value then comes from Secrets.
    pub secret: Option<String>,
}

#[utoipa::path(put, path = "/api/v1/projects/{id}/run-configs/{config}/env/{env}/{key}",
    operation_id = "setRunVar", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("config" = String, Path, description = "The configuration's id"),
           ("env" = String, Path, description = "The environment"),
           ("key" = String, Path, description = "The variable name")),
    request_body = SetRunVar,
    responses((status = 200, description = "Set or replaced (audited without the value). 400 \
        `bad_request` for a bad name or value or neither/both; 400/409 `invalid_spec` when \
        `secret` is not one of the project's; 409 `limit_reached` at 64", body = RunVar)))]
pub async fn set_var(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, cid, env, key)): Path<(String, String, String, String)>,
    Json(b): Json<SetRunVar>,
) -> ApiResult<RunVar> {
    let (p, c) = ids(&id, &cid)?;
    let now = app.clock.now();
    let v = store::set_var(
        &app.pool,
        p,
        c,
        &env,
        &key,
        b.value.as_deref(),
        b.secret.as_deref(),
        who(&me, &now),
    )
    .await?;
    Ok(Json(v.into()))
}

#[utoipa::path(delete, path = "/api/v1/projects/{id}/run-configs/{config}/env/{env}/{key}",
    operation_id = "deleteRunVar", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("config" = String, Path, description = "The configuration's id"),
           ("env" = String, Path, description = "The environment"),
           ("key" = String, Path, description = "The variable name")),
    responses((status = 200, description = "Deleted; 404 for no such variable", body = Deleted)))]
pub async fn delete_var(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, cid, env, key)): Path<(String, String, String, String)>,
) -> ApiResult<Deleted> {
    let (p, c) = ids(&id, &cid)?;
    let now = app.clock.now();
    store::delete_var(&app.pool, p, c, &env, &key, who(&me, &now)).await?;
    Ok(Json(Deleted { deleted: true }))
}

/// A plain value, on request.
#[derive(Serialize, ToSchema)]
pub struct RunVarValue {
    pub value: String,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/run-configs/{config}/env/{env}/{key}/value",
    operation_id = "revealRunVar", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("config" = String, Path, description = "The configuration's id"),
           ("env" = String, Path, description = "The environment"),
           ("key" = String, Path, description = "The variable name")),
    responses((status = 200, description = "The plain value, for the Show button. 409 \
        `conflict` for a variable linked to a Secret (it has no value to show); 404 for no such \
        variable", body = RunVarValue)))]
pub async fn reveal(
    State(app): State<App>,
    Path((id, cid, env, key)): Path<(String, String, String, String)>,
) -> ApiResult<RunVarValue> {
    let (p, c) = ids(&id, &cid)?;
    let value = store::reveal(&app.pool, p, c, &env, &key).await?;
    Ok(Json(RunVarValue { value }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportEnv {
    /// The `.env` file's text (`KEY=value` lines; `export`, quotes and `#` comments are read).
    pub text: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImportSkipped {
    pub line: i64,
    pub reason: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImportedEnv {
    pub imported: i64,
    /// Lines that were not taken, with why (a bad name, or a value holding `${`).
    pub skipped: Vec<ImportSkipped>,
}

#[utoipa::path(post,
    path = "/api/v1/projects/{id}/run-configs/{config}/env/{env}/import",
    operation_id = "importRunEnv", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("config" = String, Path, description = "The configuration's id"),
           ("env" = String, Path, description = "The environment")),
    request_body = ImportEnv,
    responses((status = 200, description = "Read into the environment as plain values (a key \
        already there is replaced). 409 `limit_reached` when it would pass 64 variables; the \
        file is not applied then", body = ImportedEnv)))]
pub async fn import(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, cid, env)): Path<(String, String, String)>,
    Json(b): Json<ImportEnv>,
) -> ApiResult<ImportedEnv> {
    let (p, c) = ids(&id, &cid)?;
    let now = app.clock.now();
    let r = store::import(&app.pool, p, c, &env, &b.text, who(&me, &now)).await?;
    Ok(Json(ImportedEnv {
        imported: r.imported,
        skipped: r
            .skipped
            .into_iter()
            .map(|(line, reason)| ImportSkipped {
                line: line as i64,
                reason,
            })
            .collect(),
    }))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DiffQuery {
    /// One environment.
    pub a: String,
    /// The one to compare it with.
    pub b: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EnvDiffRow {
    pub key: String,
    /// `same`, `different`, `only_a` or `only_b`.
    pub change: String,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/run-configs/{config}/env-diff",
    operation_id = "diffRunEnvs", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("config" = String, Path, description = "The configuration's id"), DiffQuery),
    responses((status = 200, description = "Every key of either environment, by name, with how \
        it compares (a plain value against a Secret link, or two different values or secrets, \
        is `different`). Values are never shown. 404 for no such environment",
        body = Vec<EnvDiffRow>)))]
pub async fn env_diff(
    State(app): State<App>,
    Path((id, cid)): Path<(String, String)>,
    Query(q): Query<DiffQuery>,
) -> ApiResult<Vec<EnvDiffRow>> {
    let (p, c) = ids(&id, &cid)?;
    store::get(&app.pool, p, c).await?;
    let have = store::environments(&app.pool, p).await?;
    if !have.contains(&q.a) || !have.contains(&q.b) {
        return Err(ApiError::not_found("no such environment"));
    }
    let a = store::vars(&app.pool, c, &q.a).await?;
    let b = store::vars(&app.pool, c, &q.b).await?;
    Ok(Json(
        store::diff(&a, &b)
            .into_iter()
            .map(|(key, c)| EnvDiffRow {
                key,
                change: c.code().to_owned(),
            })
            .collect(),
    ))
}
