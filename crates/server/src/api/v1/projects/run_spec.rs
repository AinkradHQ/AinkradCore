//! A project's run spec over the API (Core 0.9, P4-01; store `store::run_specs`). Reading is
//! `read`; saving is `admin` and destructive (a step-up): the spec decides what containers run on
//! a runner. A save is a new version, never a change to an old one. The body is checked field by
//! field; a 400 `invalid_spec` names the path of the first bad field in its message.

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::super::types::{Timestamp, ts};
use super::super::{ApiError, ApiResult, Caller};
use super::{num, who};
use crate::api::App;
use crate::mirrors::{self, path_ok};
use crate::store::projects as projects_store;
use crate::store::run_specs::scripts::{self, FILES};
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

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct DraftRequest {
    /// The project repo to read; default the primary one.
    pub repo: Option<String>,
    /// The file to draft from, as a path inside the repo (`docker-compose.yml`, `run.sh`,
    /// `Makefile` or `package.json`, in a folder or not). Default: the first of those found at
    /// the repo's root, compose first.
    pub file: Option<String>,
    /// The image to run a `Makefile`, `run.sh` or `package.json` in; required for a Makefile.
    pub image: Option<String>,
}

/// One thing in the file that the draft does not carry over.
#[derive(Debug, Serialize, ToSchema)]
pub struct DraftNote {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RunSpecDraft {
    /// The draft, saved as the project's next spec version; its `origin` names the converter.
    pub version: RunSpecVersion,
    /// The repo it was read from.
    pub repo: String,
    /// The file it was drafted from, as a path inside the repo.
    pub file: String,
    pub not_converted: Vec<DraftNote>,
}

/// `(folder, file name)` of a repo path (`"apps/web/run.sh"` is `("apps/web", "run.sh")`).
fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn could_not(why: String) -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "could_not_draft", why)
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/run/spec/draft",
    operation_id = "draftProjectSpec", tag = "projects",
    params(("id" = String, Path, description = "The project's id")),
    request_body = DraftRequest,
    responses((status = 200, description = "A draft drawn from a compose file, `run.sh`, \
        `Makefile` or `package.json` in the Core's copy of a project repo (read as text only, \
        never run), saved as the next spec version with the converter as its origin \
        (`compose`, `run_sh`, `makefile` or `package_json`; audited and emitted as \
        `project.spec_saved`). 422 `could_not_draft` says why a file could not be drafted; 409 \
        `conflict` when the Core has not fetched the repo yet or the project is archived; 404 \
        for no such project", body = RunSpecDraft)))]
pub async fn draft(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Option<Json<DraftRequest>>,
) -> ApiResult<RunSpecDraft> {
    let b = body.map(|Json(b)| b).unwrap_or_default();
    let project = num(&id, "project")?;
    let repos = {
        let mut conn = app.pool.acquire().await?;
        let p = projects_store::get(&mut conn, project).await?;
        if p.state == "archived" {
            return Err(ApiError::conflict("the project is archived"));
        }
        projects_store::repos(&mut conn, project).await?
    };
    let repo = match &b.repo {
        Some(n) => repos.iter().find(|r| r.name == *n),
        None => repos.first(), // the primary repo sorts first
    }
    .ok_or_else(|| ApiError::bad_request("the project has no such repo"))?;
    let Some(mirrors) = app.mirrors.as_ref() else {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_mirror",
            "this Core keeps no repo copies",
        ));
    };
    let key = mirrors::key(project, &repo.remote_url);
    if !mirrors.has_copy(repo.id, &key) {
        return Err(ApiError::conflict(
            "the Core has not fetched this repo yet; fetch it first",
        ));
    }
    let named = b.file.as_deref().map(str::to_owned);
    let candidates: Vec<String> = match &named {
        Some(f) if !path_ok(f) || scripts::origin_of(split(f).1).is_none() => {
            return Err(ApiError::bad_request(format!(
                "file is a path inside the repo to one of {}",
                FILES.join(", ")
            )));
        }
        Some(f) => vec![f.clone()],
        None => FILES.iter().map(|f| (*f).to_owned()).collect(),
    };
    let mut why = Vec::new();
    let mut found = None;
    for path in &candidates {
        let text = match mirrors.read_file(repo.id, &key, path).await {
            Ok(Some(t)) => t,
            Ok(None) => continue,
            Err(e) if named.is_some() => return Err(could_not(e)),
            Err(e) => {
                why.push(e);
                continue;
            }
        };
        let (dir, name) = split(path);
        match scripts::draft(name, &text, &repo.name, dir, b.image.as_deref()) {
            Ok(d) => {
                found = Some((path.clone(), d));
                break;
            }
            Err(e) => why.push(e),
        }
    }
    let Some((file, (origin, conv))) = found else {
        return Err(could_not(match why.is_empty() {
            true => "no compose file, run.sh, Makefile or package.json was found".to_owned(),
            false => why.join("; "),
        }));
    };
    let now = app.clock.now();
    let spec =
        serde_json::to_value(&conv.spec).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let v = store::save(&app.pool, project, &spec, origin, who(&me, &now)).await?;
    Ok(Json(RunSpecDraft {
        version: v.into(),
        repo: repo.name.clone(),
        file,
        not_converted: conv
            .not_converted
            .into_iter()
            .map(|n| DraftNote {
                path: n.path,
                reason: n.reason,
            })
            .collect(),
    }))
}
