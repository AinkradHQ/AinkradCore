//! Projects over the API (Core 0.9, P1-02; store `store::projects`). Reading is `read`; creating,
//! changing, archiving and every repo change is `admin` and destructive (a step-up): a project
//! decides which remotes the Core fetches and which repos a session gets. A project is archived,
//! never deleted. A repo's mirror state (the Core's copy: head, fetched at, last error) is
//! read-only here; the mirror scheduler writes it (P3-01). Every remote goes through
//! `repo_url_problem` here and again in the store, so no credential or odd scheme gets in.

pub mod insight;
pub mod run_configs;
pub mod run_logs;
pub mod run_spec;
pub mod runs;
pub mod secrets;

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::types::{Timestamp, opt_ts, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::store::projects::{self as store, Mirror, Project, Repo, Who};
use ainkrad_proto::runner::repo_url_problem;

/// The Core's copy of a repo.
#[derive(Debug, Serialize, ToSchema)]
pub struct MirrorState {
    /// The commit the last fetch ended at.
    pub head: Option<String>,
    pub fetched_at: Option<Timestamp>,
    /// Why the last fetch failed; the older head is kept.
    pub error: Option<String>,
    /// `fetching`, `ready` or `failed`.
    #[schema(required = false)]
    pub state: Option<String>,
    /// Why the last fetch failed: `needs_github`, `not_found_or_private`, `auth_failed`,
    /// `timeout`, `ssh_not_supported` or `other`. `error` is the same in one plain sentence.
    #[schema(required = false)]
    pub reason: Option<String>,
    /// When the running fetch began (state `fetching`).
    #[schema(required = false)]
    pub started_at: Option<Timestamp>,
}

impl From<Mirror> for MirrorState {
    fn from(m: Mirror) -> Self {
        Self {
            head: m.head,
            fetched_at: opt_ts(m.fetched_at.as_deref()),
            error: m.error,
            state: Some(m.state),
            reason: m.reason,
            started_at: opt_ts(m.started_at.as_deref()),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectRepo {
    pub id: i64,
    /// The folder name in a multi-repo checkout.
    pub name: String,
    /// The source of truth; never carries a credential.
    pub remote_url: String,
    pub default_branch: String,
    pub is_primary: bool,
    /// None until the Core has tried to fetch it.
    pub mirror: Option<MirrorState>,
}

impl ProjectRepo {
    fn new(r: Repo, m: Option<Mirror>) -> Self {
        Self {
            id: r.id,
            name: r.name,
            remote_url: r.remote_url,
            default_branch: r.default_branch,
            is_primary: r.is_primary,
            mirror: m.map(Into::into),
        }
    }
}

/// The Brain room linked to a project (strictly 1:1).
#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectRoom {
    pub room_id: String,
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectInfo {
    pub id: i64,
    /// A DNS label, 2-40 of `a-z0-9-`, starting with a letter; not a reserved name.
    pub slug: String,
    pub name: String,
    pub description: String,
    /// `active` or `archived`.
    pub state: String,
    /// `manual` or `github`.
    pub source: String,
    /// Whether the running project gets a public link.
    pub expose: bool,
    pub idle_minutes: i64,
    pub cpu_limit: f64,
    pub mem_limit_mb: i64,
    /// Where it prefers to run: `auto`, `this_mac` or `home_server`.
    #[schema(required = false)]
    pub runner: String,
    /// Minutes between automatic fetches: 10, 15, 60, or 0 for only when asked.
    #[schema(required = false)]
    pub fetch_interval_minutes: i64,
    /// The run environment a Run button uses by default; one of the project's.
    #[schema(required = false)]
    pub default_environment: Option<String>,
    /// The primary repo first, then by name.
    pub repos: Vec<ProjectRepo>,
    /// The linked Brain room; null when the Brain is off or the project has none.
    pub room: Option<ProjectRoom>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

pub(super) async fn info(app: &App, p: Project) -> Result<ProjectInfo, ApiError> {
    let mut conn = app.pool.acquire().await?;
    let mut repos = Vec::new();
    for r in store::repos(&mut conn, p.id).await? {
        let m = store::mirror(&app.pool, r.id).await?;
        repos.push(ProjectRepo::new(r, m));
    }
    // The link is a Brain table: without the Brain module there is no table and no room.
    let brain: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'brain_project_rooms'",
    )
    .fetch_one(&mut *conn)
    .await?;
    let room = match brain {
        0 => None,
        _ => sqlx::query_as::<_, (String, String)>(
            "SELECT r.id, r.name FROM brain_project_rooms l JOIN brain_rooms r ON r.id = l.room \
             WHERE l.project = ?",
        )
        .bind(p.id.to_string())
        .fetch_optional(&mut *conn)
        .await?
        .map(|(room_id, name)| ProjectRoom { room_id, name }),
    };
    Ok(ProjectInfo {
        id: p.id,
        slug: p.slug,
        name: p.name,
        description: p.description,
        state: p.state,
        source: p.source,
        expose: p.expose,
        idle_minutes: p.idle_minutes,
        cpu_limit: p.cpu_limit,
        mem_limit_mb: p.mem_limit_mb,
        runner: p.runner_pref.clone(),
        fetch_interval_minutes: p.fetch_interval_minutes,
        default_environment: p.default_environment.clone(),
        repos,
        room,
        created_at: ts(&p.created_at),
        updated_at: ts(&p.updated_at),
    })
}

/// The project as it now is, after a change to it.
async fn current(app: &App, id: i64) -> ApiResult<ProjectInfo> {
    let mut conn = app.pool.acquire().await?;
    let p = store::get(&mut conn, id).await?;
    drop(conn);
    Ok(Json(info(app, p).await?))
}

fn num(s: &str, what: &str) -> Result<i64, ApiError> {
    s.parse::<u64>()
        .ok()
        .and_then(|n| i64::try_from(n).ok())
        .ok_or_else(|| ApiError::not_found(format!("no such {what}")))
}

pub(super) fn who<'a>(me: &'a Caller, now: &'a str) -> Who<'a> {
    Who {
        by_device: &me.device.id,
        actor: BY,
        now,
    }
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ProjectsQuery {
    /// Include archived projects; default false.
    pub archived: Option<bool>,
}

#[utoipa::path(get, path = "/api/v1/projects", operation_id = "listProjects", tag = "projects",
    params(ProjectsQuery),
    responses((status = 200, description = "Projects by slug, each with its repos and their \
        mirror state; archived ones only with `archived=true`", body = Vec<ProjectInfo>)))]
pub async fn list(
    State(app): State<App>,
    Query(q): Query<ProjectsQuery>,
) -> ApiResult<Vec<ProjectInfo>> {
    let mut out = Vec::new();
    for p in store::list(&app.pool, q.archived.unwrap_or(false)).await? {
        out.push(info(&app, p).await?);
    }
    Ok(Json(out))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}", operation_id = "getProject", tag = "projects",
    params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "The project with its repos and their mirror state; \
        404 for no such project", body = ProjectInfo)))]
pub async fn get(State(app): State<App>, Path(id): Path<String>) -> ApiResult<ProjectInfo> {
    current(&app, num(&id, "project")?).await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewProject {
    /// See `ProjectInfo.slug`; it is the project's public host name.
    pub slug: String,
    /// One line, 1-100 characters.
    pub name: String,
    /// Default empty.
    pub description: Option<String>,
    /// `auto` (default), `this_mac` or `home_server`.
    pub runner: Option<String>,
}

#[utoipa::path(post, path = "/api/v1/projects", operation_id = "createProject", tag = "projects",
    request_body = NewProject,
    responses((status = 200, description = "Created as a manual project (audited and emitted as \
        `project.created`). 400 `bad_request` for a bad or reserved slug or a bad name; 409 \
        `conflict` when the slug is taken", body = ProjectInfo)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(b): Json<NewProject>,
) -> ApiResult<ProjectInfo> {
    let now = app.clock.now();
    let p = store::create(
        &app.pool,
        &b.slug,
        &b.name,
        b.description.as_deref().unwrap_or(""),
        "manual",
        who(&me, &now),
    )
    .await?;
    let p = match b.runner.as_deref() {
        Some(r) => {
            let c = store::Change {
                runner: Some(r),
                ..store::Change::default()
            };
            store::change(&app.pool, p.id, &c, who(&me, &now)).await?
        }
        None => p,
    };
    Ok(Json(info(&app, p).await?))
}

/// What changes; an omitted field is kept.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateProject {
    pub name: Option<String>,
    pub description: Option<String>,
    pub expose: Option<bool>,
    /// The link name (the slug); refused while the project runs or holds secrets.
    pub slug: Option<String>,
    /// Idle stop, 5 to 1440 minutes.
    pub idle_minutes: Option<i64>,
    /// CPUs a run may use, 0.1 to 16.
    pub cpu_limit: Option<f64>,
    /// Memory a run may use, 64 to 32768 MB.
    pub mem_limit_mb: Option<i64>,
    /// Where it prefers to run: `auto`, `this_mac` or `home_server`.
    pub runner: Option<String>,
    /// Minutes between automatic fetches: 10, 15, 60, or 0 for only when asked.
    #[schema(required = false)]
    pub fetch_interval_minutes: Option<i64>,
    /// One of the project's run environments; an empty string clears it.
    #[schema(required = false)]
    pub default_environment: Option<String>,
}

#[utoipa::path(patch, path = "/api/v1/projects/{id}", operation_id = "updateProject",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    request_body = UpdateProject,
    responses((status = 200, description = "Changed (audited and emitted as `project.updated`). \
        404 for no such project; 409 `conflict` when it is archived; 400 for a bad name",
        body = ProjectInfo)))]
pub async fn update(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<UpdateProject>,
) -> ApiResult<ProjectInfo> {
    let now = app.clock.now();
    let c = store::Change {
        name: b.name.as_deref(),
        description: b.description.as_deref(),
        expose: b.expose,
        slug: b.slug.as_deref(),
        idle_minutes: b.idle_minutes,
        cpu_limit: b.cpu_limit,
        mem_limit_mb: b.mem_limit_mb,
        runner: b.runner.as_deref(),
        fetch_interval_minutes: b.fetch_interval_minutes,
        default_environment: b.default_environment.as_deref(),
    };
    let p = store::change(&app.pool, num(&id, "project")?, &c, who(&me, &now)).await?;
    Ok(Json(info(&app, p).await?))
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/archive", operation_id = "archiveProject",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "Archived; its repos, mirrors and sessions stay \
        (audited and emitted as `project.archived`). 404 for no such project; 409 `conflict` \
        when it already is", body = ProjectInfo)))]
pub async fn archive(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<ProjectInfo> {
    let now = app.clock.now();
    let p = store::archive(&app.pool, num(&id, "project")?, who(&me, &now)).await?;
    Ok(Json(info(&app, p).await?))
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/unarchive", operation_id = "unarchiveProject",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "Back to `active` (the undo of an archive; audited \
        and emitted as `project.updated`). 404 for no such project; 409 `conflict` when it is \
        not archived", body = ProjectInfo)))]
pub async fn unarchive(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<ProjectInfo> {
    let now = app.clock.now();
    let p = store::unarchive(&app.pool, num(&id, "project")?, who(&me, &now)).await?;
    Ok(Json(info(&app, p).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewProjectRepo {
    /// The folder name: 1-100 of `[A-Za-z0-9._-]`, not starting with `.` or `-`.
    pub name: String,
    /// An `https://`, `ssh://` or scp-style remote with no credential in it.
    pub remote_url: String,
    pub default_branch: String,
    /// Make it the primary repo (the first repo always is).
    pub primary: Option<bool>,
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/repos", operation_id = "addProjectRepo",
    tag = "projects", params(("id" = String, Path, description = "The project's id")),
    request_body = NewProjectRepo,
    responses((status = 200, description = "Added (audited as `project.repo_added`); the project \
        as it now is. 400 for a bad name, remote or branch; 404 for no such project; 409 \
        `conflict` for an archived project or a repeated name or remote. An ssh remote is 400: the \
        Core holds no key. The Core starts copying the repo at once (`mirror.state`)", body = ProjectInfo)))]
pub async fn add_repo(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<NewProjectRepo>,
) -> ApiResult<ProjectInfo> {
    let id = num(&id, "project")?;
    if let Some(why) = repo_url_problem(&b.remote_url) {
        return Err(ApiError::bad_request(why));
    }
    if let Some(why) = crate::mirrors::ssh_problem(&b.remote_url) {
        return Err(ApiError::bad_request(why));
    }
    let now = app.clock.now();
    let r = store::add_repo(
        &app.pool,
        id,
        &b.name,
        &b.remote_url,
        &b.default_branch,
        b.primary.unwrap_or(false),
        who(&me, &now),
    )
    .await?;
    // The copy starts now; `mirror.state` says `fetching` until it ends.
    crate::mirrors::start(&app, r.id).await;
    current(&app, id).await
}

#[utoipa::path(delete, path = "/api/v1/projects/{id}/repos/{repo}",
    operation_id = "removeProjectRepo", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("repo" = String, Path, description = "The repo's id")),
    responses((status = 200, description = "Removed with its mirror row (audited as \
        `project.repo_removed`); the project as it now is. 404 for no such project or repo; 409 \
        `conflict` for an archived project or the primary while others remain",
        body = ProjectInfo)))]
pub async fn remove_repo(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, repo)): Path<(String, String)>,
) -> ApiResult<ProjectInfo> {
    let id = num(&id, "project")?;
    let now = app.clock.now();
    let repo = num(&repo, "repo")?;
    store::remove_repo(&app.pool, id, repo, who(&me, &now)).await?;
    // The Core's copy goes with the repo (its id can be handed out again), in a task a dropped
    // request cannot cancel; the mirror's marker covers a cleanup that never ran.
    if let Some(mirrors) = app.mirrors.clone() {
        let _ = tokio::spawn(async move { mirrors.forget(repo).await }).await;
    }
    current(&app, id).await
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/repos/{repo}/primary",
    operation_id = "setProjectRepoPrimary", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("repo" = String, Path, description = "The repo's id")),
    responses((status = 200, description = "The repo is the one primary (audited as \
        `project.repo_primary_set`); the project as it now is. 404 for no such project or repo; \
        409 `conflict` for an archived project", body = ProjectInfo)))]
pub async fn set_primary(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, repo)): Path<(String, String)>,
) -> ApiResult<ProjectInfo> {
    let id = num(&id, "project")?;
    let now = app.clock.now();
    store::set_primary(&app.pool, id, num(&repo, "repo")?, who(&me, &now)).await?;
    current(&app, id).await
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/repos/{repo}/fetch",
    operation_id = "fetchProjectRepo", tag = "projects",
    params(("id" = String, Path, description = "The project's id"),
           ("repo" = String, Path, description = "The repo's id")),
    responses((status = 200, description = "The Core fetched the repo's remote now (\"Fetch now\"); \
        the project as it now is. A fetch that failed is still 200: the repo's `mirror.error` says \
        why and `mirror.head` is the older head, kept. A fetch already running for the repo is not \
        started again nor waited for: the state as it is comes back. 404 for no such project or repo; 409 \
        `conflict` for an archived project; 503 `mirrors_unavailable` when this Core keeps no repo \
        copies", body = ProjectInfo)))]
pub async fn fetch_now(
    State(app): State<App>,
    Path((id, repo)): Path<(String, String)>,
) -> ApiResult<ProjectInfo> {
    use crate::mirrors::{Refused, fetch_now as fetch};
    let (id, repo) = (num(&id, "project")?, num(&repo, "repo")?);
    let mut conn = app.pool.acquire().await?;
    let found = store::repos(&mut conn, id)
        .await?
        .iter()
        .any(|r| r.id == repo);
    drop(conn);
    if !found {
        return Err(ApiError::not_found("no such repo"));
    }
    match fetch(&app, repo).await {
        Ok(_) => current(&app, id).await,
        Err(Refused::Off) => Err(super::mirrors::mirrors(&app).err().expect("off")),
        Err(Refused::Archived) => Err(ApiError::conflict("the project is archived")),
        Err(Refused::NoRepo) => Err(ApiError::not_found("no such repo")),
        Err(Refused::Db(why)) => {
            tracing::error!(why, "fetching a repo");
            Err(ApiError::new(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "could not fetch",
            ))
        }
    }
}
