//! A project's repositories (E15.16): each with its forge and commands, their order (the order
//! PRs merge in) and primary; the repos an issue touches and agents' requests for more. Writes
//! go through the store's rules as the admin and are audited.
//!
//! Not here: `probeRepo` (`POST /projects/{id}/repos/probe`), which clones and asks the forge:
//! it needs the git workspace and the forge clients (E2-10, S6).

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::util::{issue as issue_row, project, rule};
use crate::api::scope::Acting;
use crate::domain::work::{IssueId, ProjectId};
use crate::store::work::{self, Commands, ProjectForge, Repo as StoredRepo};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RepoForge {
    /// `github` or `gitlab`.
    pub kind: String,
    /// Absent (when setting): the host's public API.
    pub api_url: Option<String>,
    /// `owner/name`, or a GitLab project path.
    pub repo: String,
    /// Retired: credentials live in the secrets broker. Always empty in answers; a non-empty
    /// value in a request is refused.
    #[serde(default)]
    #[schema(required = false)]
    pub token_file: String,
    /// The broker secret holding the API token, `citadel.forge.<name>` (never the token). Required
    /// when setting.
    #[serde(default)]
    #[schema(required = false)]
    pub secret_name: Option<String>,
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
                kind: f.kind,
                api_url: Some(f.api_url),
                repo: f.repo,
                token_file: String::new(),
                secret_name: Some(f.secret),
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

/// What a repo body may carry. A repo's commands run on a runner, and its forge settings name a
/// broker secret and an API URL the forge client will call with that secret's value, so both are
/// checked here (and the routes are step-up routes): no control characters in a command; a
/// secret in the module's own namespace and no token file; and an API URL that passes the call
/// policy (https, a host name on the allow-list: the public hosts and `citadel_forge_hosts`).
/// The poller checks the URL again on every pass.
pub(super) async fn check_body(app: &App, b: &RepoBody) -> Result<(), ApiError> {
    let bad = |why: String| Err(ApiError::bad_request(why));
    let c = &b.commands;
    for (name, cmd) in [
        ("build", &c.build),
        ("test", &c.test),
        ("lint", &c.lint),
        ("format", &c.format),
    ] {
        if cmd.len() > 2048 || cmd.chars().any(|ch| ch == '\0' || ch == '\n' || ch == '\r') {
            return bad(format!(
                "the {name} command must be one line of at most 2048 characters"
            ));
        }
    }
    if let Some(f) = &b.forge {
        if !f.token_file.is_empty() {
            return bad(
                "token files are retired: store the token in the secrets broker and \
                        name it in secret_name"
                    .to_owned(),
            );
        }
        match &f.secret_name {
            Some(n) if work::secret_name_ok(n) => {}
            _ => {
                return bad(
                    "secret_name must be a broker secret named citadel.forge.<name>".to_owned(),
                );
            }
        }
        let name = f.secret_name.as_deref().unwrap_or_default();
        if crate::store::forge::is_account_secret(&app.pool, name).await? {
            return bad("that secret is a provider account's, not a forge's".to_owned());
        }
        let url = match &f.api_url {
            Some(url) => url.clone(),
            None => work::default_api(&f.kind).unwrap_or_default().to_owned(),
        };
        if !url.is_empty() {
            let hosts: Vec<String> = sqlx::query_scalar("SELECT host FROM citadel_forge_hosts")
                .fetch_all(&app.pool)
                .await
                .map_err(|e| ApiError::from(e))?;
            let policy = ainkrad_providers::guard::Policy::public().with_hosts(hosts);
            if let Err(why) = policy.check_url(&url) {
                return bad(format!(
                    "the API URL {url:?} is not an allowed forge URL: {why}"
                ));
            }
        }
    }
    Ok(())
}

fn stored(project: ProjectId, id: i64, b: RepoBody) -> Result<StoredRepo, ApiError> {
    let forge = match b.forge {
        Some(f) => {
            let default = work::default_api(&f.kind)
                .ok_or_else(|| ApiError::bad_request(format!("unknown forge kind {:?}", f.kind)))?;
            Some(ProjectForge {
                project_id: project,
                kind: f.kind,
                api_url: f.api_url.unwrap_or_else(|| default.to_owned()),
                repo: f.repo,
                secret: f.secret_name.unwrap_or_default(),
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

#[utoipa::path(get, path = "/projects/{id}/repos", operation_id = "listRepos",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project's repos, in order", body = Vec<Repo>)))]
pub async fn list(State(app): State<App>, _: Acting, Path(id): Path<i64>) -> ApiResult<Vec<Repo>> {
    let p = project(&app, id).await?;
    all(&app, p.id).await
}

#[utoipa::path(post, path = "/projects/{id}/repos", operation_id = "addRepo",
    tag = "projects", params(("id" = i64, Path, description = "Project id")), request_body = RepoBody,
    responses((status = 200, description = "The new repo: last in order, primary when it is the \
        project's first", body = Repo)))]
pub async fn add(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(b): Json<RepoBody>,
) -> ApiResult<Repo> {
    check_body(&app, &b).await?;
    let stack = b.stack.clone();
    let r = stored(ProjectId(id), 0, b)?;
    let added = work::add_repo(&app.pool, &r, BY)
        .await
        .map_err(rule)?
        .ok_or_else(|| ApiError::not_found(format!("no project {id}")))?;
    if let Some(stack) = stack {
        work::set_repo_stack(&app.pool, added.id, &stack)
            .await
            .map_err(rule)?;
    }
    one(&app, added).await
}

#[utoipa::path(put, path = "/repos/{id}", operation_id = "updateRepo", tag = "projects",
    params(("id" = i64, Path, description = "Repo id")), request_body = RepoBody,
    responses((status = 200, description = "The repo with its new values", body = Repo)))]
pub async fn update(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(b): Json<RepoBody>,
) -> ApiResult<Repo> {
    check_body(&app, &b).await?;
    let current = repo(&app, id).await?;
    let stack = b.stack.clone();
    let r = stored(current.project_id, id, b)?;
    work::update_repo(&app.pool, &r, BY).await.map_err(rule)?;
    if let Some(stack) = stack {
        work::set_repo_stack(&app.pool, id, &stack)
            .await
            .map_err(rule)?;
    }
    one(&app, repo(&app, id).await?).await
}

#[utoipa::path(delete, path = "/repos/{id}", operation_id = "removeRepo", tag = "projects",
    params(("id" = i64, Path, description = "Repo id")),
    responses((status = 200, description = "The project's repos left; refused (400) while an \
        open issue touches it, or for the primary while there are others", body = Vec<Repo>)))]
pub async fn remove(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Vec<Repo>> {
    let r = repo(&app, id).await?;
    work::remove_repo(&app.pool, id, BY).await.map_err(rule)?;
    all(&app, r.project_id).await
}

#[utoipa::path(post, path = "/repos/{id}/primary", operation_id = "setPrimaryRepo",
    tag = "projects", params(("id" = i64, Path, description = "Repo id")),
    responses((status = 200, description = "The project's repos", body = Vec<Repo>)))]
pub async fn primary(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Vec<Repo>> {
    let r = repo(&app, id).await?;
    work::set_primary_repo(&app.pool, id, BY).await?;
    all(&app, r.project_id).await
}

/// Names, in order.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RepoNames {
    pub repos: Vec<String>,
}

#[utoipa::path(put, path = "/projects/{id}/repo-order", operation_id = "orderRepos",
    tag = "projects", params(("id" = i64, Path, description = "Project id")), request_body = RepoNames,
    responses((status = 200, description = "The project's repos in the new order", body = Vec<Repo>)))]
pub async fn order(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(b): Json<RepoNames>,
) -> ApiResult<Vec<Repo>> {
    let p = project(&app, id).await?;
    work::order_repos(&app.pool, p.id, &b.repos, BY)
        .await
        .map_err(rule)?;
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

#[utoipa::path(get, path = "/issues/{id}/repos", operation_id = "getIssueRepos",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The repos the issue touches, and agents' pending \
        requests for more", body = IssueRepos)))]
pub async fn get_issue_repos(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<IssueRepos> {
    let i = issue_row(&app, id).await?;
    issue_repos_out(&app, i.id).await
}

#[utoipa::path(put, path = "/issues/{id}/repos", operation_id = "setIssueRepos",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")), request_body = RepoNames,
    responses((status = 200, description = "The repos it touches now; none means the primary",
        body = IssueRepos)))]
pub async fn set_issue_repos(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(b): Json<RepoNames>,
) -> ApiResult<IssueRepos> {
    let i = issue_row(&app, id).await?;
    work::set_issue_repos(&app.pool, i.id, &b.repos, BY)
        .await
        .map_err(rule)?;
    issue_repos_out(&app, i.id).await
}
