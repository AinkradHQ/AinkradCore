//! A project's secrets over the API (Core 0.9, P4-04; store `store::project_secrets`). Listing
//! and writing are `admin` (writing also a step-up), like the broker's own routes. SECURITY: no
//! route returns a value; a value is parsed by hand (a serde error can quote its input) and held
//! in `Zeroizing`; a delete refuses while a spec version still uses the secret, unless `force`.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use zeroize::Zeroizing;

use super::super::secrets::{mode, parse, sealer};
use super::super::types::{Timestamp, opt_ts, ts};
use super::super::{ApiResult, Caller};
use super::{num, who};
use crate::api::App;
use crate::store::project_secrets::{self as store, Input, ProjectSecret};

/// A project secret, never its value.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectSecretInfo {
    /// `[a-z][a-z0-9_.-]{0,63}`; what a spec writes as `${secret:NAME}`.
    pub name: String,
    /// `text`, `multiline`, `file` or `env_bundle`.
    pub kind: String,
    pub description: String,
    /// 1 when stored, one more per rotation.
    pub version: i64,
    /// The value's length in bytes.
    pub size: i64,
    pub updated_at: Timestamp,
    /// When a runner last redeemed it; none before the first redemption.
    pub last_used_at: Option<Timestamp>,
    pub use_count: i64,
}

impl From<ProjectSecret> for ProjectSecretInfo {
    fn from(s: ProjectSecret) -> Self {
        Self {
            name: s.name,
            kind: s.kind,
            description: s.description,
            version: s.version,
            size: s.size,
            updated_at: ts(&s.updated_at),
            last_used_at: opt_ts(s.last_used_at.as_deref()),
            use_count: s.use_count,
        }
    }
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/secrets",
    operation_id = "listProjectSecrets", tag = "projects",
    params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "The project's secrets by name, without their \
        values; 404 for no such project", body = Vec<ProjectSecretInfo>)))]
pub async fn list(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Vec<ProjectSecretInfo>> {
    let all = store::list(&app.pool, num(&id, "project")?).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

/// A value to store or replace. Deliberately no `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct SetProjectSecret {
    /// UTF-8 text, at most `secrets.max_bytes`; for kind `file` standard base64 (at most 1 MiB
    /// decoded); written, never read back.
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    /// `text` (the default for a new secret), `multiline`, `file` or `env_bundle`.
    pub kind: Option<String>,
    /// One line, at most 200 characters.
    pub description: Option<String>,
    /// Required for kind `file`: `[A-Za-z0-9._-]{1,64}`.
    pub file_name: Option<String>,
    /// Kind `file`: an octal mode such as `0600`.
    pub file_mode: Option<String>,
}

#[utoipa::path(put, path = "/api/v1/projects/{id}/secrets/{name}",
    operation_id = "setProjectSecret", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("name" = String, Path, description = "The secret's name in the project")),
    request_body = SetProjectSecret,
    responses((status = 200, description = "Stored sealed as a new secret, or rotated to its \
        next version (audited as `secret.created` / `secret.rotated`; the Core's own secret is \
        named `<slug>.<name>`). The broker's refusals apply: 409 `secrets_disabled`, \
        `real_secret_refused`, `limit_reached`; 400 `bad_request` or `too_large`; 404 for no such \
        project; 409 `conflict` for an archived project; 503 `secrets_unavailable`",
        body = ProjectSecretInfo)))]
pub async fn set(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, name)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<ProjectSecretInfo> {
    let b: SetProjectSecret = parse(&body)?;
    let now = app.clock.now();
    let s = store::set(
        &app.pool,
        sealer(&app)?,
        num(&id, "project")?,
        &name,
        &Input {
            value: &b.value,
            kind: b.kind.as_deref(),
            description: b.description.as_deref(),
            file_name: b.file_name.as_deref(),
            file_mode: mode(b.file_mode.as_deref())?,
        },
        who(&me, &now),
    )
    .await?;
    Ok(Json(s.into()))
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DeleteQuery {
    /// Delete although a spec version uses it; default false.
    pub force: Option<bool>,
}

/// What a delete answers.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectSecretDeleted {
    pub deleted: bool,
}

#[utoipa::path(delete, path = "/api/v1/projects/{id}/secrets/{name}",
    operation_id = "deleteProjectSecret", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("name" = String, Path, description = "The secret's name in the project"),
           DeleteQuery),
    responses((status = 200, description = "Deleted with its leases (audited as \
        `secret.deleted`). 409 `conflict` while a spec version refers to it, the message naming \
        the newest such version, unless `force=true`; 404 for no \
        such project or secret", body = ProjectSecretDeleted)))]
pub async fn delete(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, name)): Path<(String, String)>,
    Query(q): Query<DeleteQuery>,
) -> ApiResult<ProjectSecretDeleted> {
    let now = app.clock.now();
    store::delete(
        &app.pool,
        num(&id, "project")?,
        &name,
        q.force.unwrap_or(false),
        who(&me, &now),
    )
    .await?;
    Ok(Json(ProjectSecretDeleted { deleted: true }))
}
