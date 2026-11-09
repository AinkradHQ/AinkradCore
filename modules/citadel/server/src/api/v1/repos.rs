//! A project's repositories (E15.16): each with its forge and commands, their order (the order
//! PRs merge in) and primary; the repos an issue touches and agents' requests for more. Writes
//! go through the store's rules as the admin and are audited.

use std::path::PathBuf;

use citadel_core::work::{IssueId, ProjectId};
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::forge::ProjectForge;
use crate::store::work::{self, Commands, Repo as StoredRepo};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RepoForge {
    /// `github` or `gitlab`.
    pub kind: String,
    /// Absent (when setting): the host's public API.
    pub api_url: Option<String>,
    /// `owner/name`, or a GitLab project path.
    pub repo: String,
    /// The server-side file holding the API token (never the token).
    pub token_file: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct RepoCommands {
    pub build: String,
    pub test: String,
    pub lint: String,
    pub format: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Repo {
    pub id: i64,
    pub project_id: i64,
    pub name: String,
    pub url: String,
    pub default_branch: String,
    /// Its place in the project's order: the order agents see repos and PRs merge in.
    pub position: i64,
    pub primary: bool,
    pub forge: Option<RepoForge>,
    pub commands: RepoCommands,
    /// What it is built with, "Rust · Node" (API minor 18); empty when unknown.
    #[schema(required = false)]
    pub stack: String,
    /// The keys of the issues working it now (API minor 18): in progress or in review, and
    /// approved for it, or, with none approved, on the primary repo.
    #[schema(required = false)]
    pub in_use_by: Vec<String>,
}

impl From<StoredRepo> for Repo {
    fn from(r: StoredRepo) -> Self {
        Self {
            id: r.id,
            project_id: r.project_id.0,
            name: r.name,
            url: r.url,
            default_branch: r.default_branch,
            position: r.position,
            primary: r.primary,
            forge: r.forge.map(|f| RepoForge {
                kind: f.kind.as_str().to_owned(),
                api_url: Some(f.api_url),
                repo: f.repo,
                token_file: f.token_file.to_string_lossy().into_owned(),
            }),
            commands: RepoCommands {
                build: r.commands.build,
                test: r.commands.test,
                lint: r.commands.lint,
                format: r.commands.format,
            },
            stack: String::new(),
            in_use_by: vec![],
        }
    }
}

/// A repo to add, or a repo's new values.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RepoBody {
    pub name: String,
    pub url: String,
    /// Absent: `main`.
    pub default_branch: Option<String>,
    pub forge: Option<RepoForge>,
    #[serde(default)]
    pub commands: RepoCommands,
    /// Absent: a repo keeps its stack, a new one has none.
    pub stack: Option<String>,
}

fn invalid(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
        e => e.into(),
    }
}

fn stored(project: ProjectId, id: i64, b: RepoBody) -> Result<StoredRepo, ApiError> {
    let forge = match b.forge {
        Some(f) => {
            let kind: ainkrad_providers::Kind = f.kind.parse().map_err(ApiError::bad_request)?;
            Some(ProjectForge {
                project_id: project,
                kind,
                api_url: f.api_url.unwrap_or_else(|| kind.default_api().to_owned()),
                repo: f.repo,
                token_file: PathBuf::from(f.token_file),
            })
        }
        None => None,
    };
    Ok(StoredRepo {
        id,
        project_id: project,
        name: b.name,
        url: b.url,
        default_branch: b.default_branch.unwrap_or_else(|| "main".to_owned()),
        position: 0,
        primary: false,
        forge,
        commands: Commands {
            build: b.commands.build,
            test: b.commands.test,
            lint: b.commands.lint,
            format: b.commands.format,
        },
    })
}

async fn repo(app: &App, id: i64) -> Result<StoredRepo, ApiError> {
    work::get_repo(&app.pool, id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no repo {id}")))
}

/// `repos` with their stacks and the issues using them.
async fn decorated(
    app: &App,
    project: ProjectId,
    mut repos: Vec<Repo>,
) -> Result<Vec<Repo>, ApiError> {
    let stacks = work::repo_stacks(&app.pool, project).await?;
    let in_use = work::repos_in_use(&app.pool, project).await?;
    for r in &mut repos {
        r.stack = stacks
            .iter()
            .find(|s| s.0 == r.id)
            .map(|s| s.1.clone())
            .unwrap_or_default();
        r.in_use_by = in_use
            .iter()
            .filter(|u| u.0 == r.id)
            .map(|u| u.1.clone())
            .collect();
    }
    Ok(repos)
}

async fn all(app: &App, project: ProjectId) -> ApiResult<Vec<Repo>> {
    let all = work::list_repos(&app.pool, project).await?;
    decorated(app, project, all.into_iter().map(Into::into).collect())
        .await
        .map(Json)
}

async fn one(app: &App, r: StoredRepo) -> ApiResult<Repo> {
    let project = r.project_id;
    let mut all = decorated(app, project, vec![r.into()]).await?;
    Ok(Json(all.remove(0)))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/repos", operation_id = "listRepos",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project's repos, in order", body = Vec<Repo>)))]
pub async fn list(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<Repo>> {
    let p = super::projects::project(&app, id).await?;
    all(&app, p.id).await
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/repos", operation_id = "addRepo",
    tag = "projects", params(("id" = i64, Path, description = "Project id")), request_body = RepoBody,
    responses((status = 200, description = "The new repo: last in order, primary when it is the \
        project's first", body = Repo)))]
pub async fn add(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<RepoBody>,
) -> ApiResult<Repo> {
    let stack = b.stack.clone();
    let r = stored(ProjectId(id), 0, b)?;
    let added = work::add_repo(&app.pool, &r, BY)
        .await
        .map_err(invalid)?
        .ok_or_else(|| ApiError::not_found(format!("no project {id}")))?;
    if let Some(stack) = stack {
        work::set_repo_stack(&app.pool, added.id, &stack)
            .await
            .map_err(invalid)?;
    }
    one(&app, added).await
}

#[utoipa::path(put, path = "/api/v1/repos/{id}", operation_id = "updateRepo", tag = "projects",
    params(("id" = i64, Path, description = "Repo id")), request_body = RepoBody,
    responses((status = 200, description = "The repo with its new values", body = Repo)))]
pub async fn update(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<RepoBody>,
) -> ApiResult<Repo> {
    let current = repo(&app, id).await?;
    let stack = b.stack.clone();
    let r = stored(current.project_id, id, b)?;
    work::update_repo(&app.pool, &r, BY)
        .await
        .map_err(invalid)?;
    if let Some(stack) = stack {
        work::set_repo_stack(&app.pool, id, &stack)
            .await
            .map_err(invalid)?;
    }
    one(&app, repo(&app, id).await?).await
}

#[utoipa::path(delete, path = "/api/v1/repos/{id}", operation_id = "removeRepo", tag = "projects",
    params(("id" = i64, Path, description = "Repo id")),
    responses((status = 200, description = "The project's repos left; refused (400) while an \
        open issue touches it, or for the primary while there are others", body = Vec<Repo>)))]
pub async fn remove(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<Repo>> {
    let r = repo(&app, id).await?;
    work::remove_repo(&app.pool, id, BY)
        .await
        .map_err(invalid)?;
    all(&app, r.project_id).await
}

#[utoipa::path(post, path = "/api/v1/repos/{id}/primary", operation_id = "setPrimaryRepo",
    tag = "projects", params(("id" = i64, Path, description = "Repo id")),
    responses((status = 200, description = "The project's repos", body = Vec<Repo>)))]
pub async fn primary(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<Repo>> {
    let r = repo(&app, id).await?;
    work::set_primary_repo(&app.pool, id, BY).await?;
    all(&app, r.project_id).await
}

/// Names, in order.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RepoNames {
    pub repos: Vec<String>,
}

#[utoipa::path(put, path = "/api/v1/projects/{id}/repo-order", operation_id = "orderRepos",
    tag = "projects", params(("id" = i64, Path, description = "Project id")), request_body = RepoNames,
    responses((status = 200, description = "The project's repos in the new order", body = Vec<Repo>)))]
pub async fn order(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<RepoNames>,
) -> ApiResult<Vec<Repo>> {
    let p = super::projects::project(&app, id).await?;
    work::order_repos(&app.pool, p.id, &b.repos, BY)
        .await
        .map_err(invalid)?;
    all(&app, p.id).await
}

/// An agent's request for another repo, waiting for its team lead (or the admin).
#[derive(Debug, Serialize, ToSchema)]
pub struct RepoRequest {
    pub repo: String,
    pub requested_by: Option<i64>,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IssueRepos {
    /// The repos it touches, in the project's order.
    pub repos: Vec<String>,
    pub requests: Vec<RepoRequest>,
}

async fn issue_repos_out(app: &App, issue: IssueId) -> ApiResult<IssueRepos> {
    let repos = work::issue_repos(&app.pool, issue).await?;
    let requests = work::repo_requests(&app.pool, issue).await?;
    Ok(Json(IssueRepos {
        repos: repos.into_iter().map(|r| r.name).collect(),
        requests: requests
            .into_iter()
            .map(|(repo, by, reason)| RepoRequest {
                repo,
                requested_by: by.map(|a| a.0),
                reason,
            })
            .collect(),
    }))
}

async fn issue(app: &App, id: i64) -> Result<IssueId, ApiError> {
    work::get_issue(&app.pool, IssueId(id))
        .await?
        .map(|i| i.id)
        .ok_or_else(|| ApiError::not_found(format!("no issue {id}")))
}

#[utoipa::path(get, path = "/api/v1/issues/{id}/repos", operation_id = "getIssueRepos",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The repos the issue touches, and agents' pending \
        requests for more", body = IssueRepos)))]
pub async fn get_issue_repos(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<IssueRepos> {
    let i = issue(&app, id).await?;
    issue_repos_out(&app, i).await
}

#[utoipa::path(put, path = "/api/v1/issues/{id}/repos", operation_id = "setIssueRepos",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")), request_body = RepoNames,
    responses((status = 200, description = "The repos it touches now; none means the primary",
        body = IssueRepos)))]
pub async fn set_issue_repos(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<RepoNames>,
) -> ApiResult<IssueRepos> {
    let i = issue(&app, id).await?;
    work::set_issue_repos(&app.pool, i, &b.repos, BY)
        .await
        .map_err(invalid)?;
    issue_repos_out(&app, i).await
}

/// A repo to look at before it is added.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ProbeBody {
    /// An https, http or ssh URL, or an absolute path.
    pub url: String,
    /// Absent: git alone is asked. With it, the forge says whether the token may push, and git
    /// uses the token for a private repo.
    pub forge: Option<RepoForge>,
}

/// What a probe found; nothing was saved.
#[derive(Debug, Serialize, ToSchema)]
pub struct Probed {
    pub reachable: bool,
    pub default_branch: Option<String>,
    /// Absent when unknown: no forge given, or the forge could not say.
    pub can_push: Option<bool>,
    /// Detected from a shallow clone's files, "Rust · Node"; empty when none was recognised.
    pub stack: String,
    pub commands: RepoCommands,
    /// Why something is unknown, in a line.
    pub note: Option<String>,
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/repos/probe", operation_id = "probeRepo",
    tag = "projects", params(("id" = i64, Path, description = "Project id")), request_body = ProbeBody,
    responses((status = 200, description = "Whether the repo is reachable, its default branch, \
        whether the forge token may push, its stack and commands (API minor 18); nothing is \
        saved. An unusable URL or forge is a 400", body = Probed)))]
pub async fn probe(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<ProbeBody>,
) -> ApiResult<Probed> {
    super::projects::project(&app, id).await?;
    if let Some(why) = super::probe::url_problem(&b.url) {
        return Err(ApiError::bad_request(why));
    }
    let forge = match &b.forge {
        Some(f) => {
            let kind: ainkrad_providers::Kind = f.kind.parse().map_err(ApiError::bad_request)?;
            let token = ainkrad_providers::Secret::from_file(std::path::Path::new(&f.token_file))
                .map_err(|why| ApiError::bad_request(format!("the token file: {why}")))?;
            let api = f
                .api_url
                .clone()
                .unwrap_or_else(|| kind.default_api().to_owned());
            let auth = super::probe::GitAuth::new(kind, &token);
            let client = ainkrad_providers::client();
            Some((
                ainkrad_providers::AnyForge::new(&client, kind, &api, &f.repo, token),
                auth,
            ))
        }
        None => None,
    };
    let found = super::probe::probe(&b.url, forge.as_ref().map(|(f, a)| (f, a))).await;
    Ok(Json(Probed {
        reachable: found.reachable,
        default_branch: found.default_branch,
        can_push: found.can_push,
        stack: found.stack,
        commands: found.commands,
        note: found.note,
    }))
}
