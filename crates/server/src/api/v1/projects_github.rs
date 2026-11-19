//! Projects from GitHub (P2-01). Both routes are `admin`; creating is also a step-up.
//!
//! Security model: the connection's token is opened here and handed to the GitHub adapter only; no
//! route, event, audit row or error carries it or a URL (upstream failures are the adapter's fixed
//! sentences). The connection is the explicit one, else the project's binding (`scope_kind`
//! `project`), else the workspace default of kind `github`. Creating asks GitHub for each repo
//! (`github.get_repo`), so the default branch and the name are GitHub's, never the caller's, and a
//! repo the connection cannot see is refused. The connection is then bound to the new project.

use axum::Json;
use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};

use super::connections::{sealer, who as conn_who, workspace};
use super::projects::{ProjectInfo, info, who};
use super::{ApiError, ApiResult, Caller};
use crate::api::App;
use crate::connections::github::repos::RepoSummary;
use crate::connections::github::{Outcome, build};
use crate::connections::material::Material;
use crate::store::connections::{self as conns, bindings, secret};
use crate::store::projects::{self as store, NewGithubRepo};

const MAX_REPOS: usize = 10;

fn upstream(o: &Outcome) -> ApiError {
    let status = match o.code() {
        "rate_limited" => StatusCode::TOO_MANY_REQUESTS,
        "not_found" => StatusCode::NOT_FOUND,
        _ => StatusCode::BAD_GATEWAY,
    };
    ApiError::new(status, o.code(), o.message())
}

/// The GitHub connection to use, and its token.
async fn pick(
    app: &App,
    w: conns::Who<'_>,
    explicit: Option<i64>,
    project: Option<&str>,
) -> Result<(conns::Connection, Material, i64), ApiError> {
    let user = w.workspace;
    let id = match explicit {
        Some(id) => id,
        None => {
            let all = bindings::list(&app.pool, user, Some("github")).await?;
            let scoped = project.and_then(|p| {
                all.iter()
                    .find(|b| b.scope_kind == "project" && b.scope_ref == p)
            });
            let default = all.iter().find(|b| b.scope_kind == "workspace");
            match scoped.or(default) {
                Some(b) => b.connection_id,
                None => {
                    return Err(ApiError::new(
                        StatusCode::CONFLICT,
                        "no_connection",
                        "no GitHub connection is set up: connect GitHub first",
                    ));
                }
            }
        }
    };
    let c = conns::get(&app.pool, user, id).await?;
    if c.kind != "github" {
        return Err(ApiError::bad_request("that connection is not a GitHub one"));
    }
    if c.disabled {
        return Err(ApiError::conflict("that connection is disabled"));
    }
    let sealer = sealer(app)?;
    // An installation token is minted again before it ends; a failure leaves the old token.
    let _ = app
        .connections
        .github()
        .renew_installation(&app.pool, sealer, w, id)
        .await;
    let (m, version) = secret::open(&app.pool, sealer, user, id).await?;
    Ok((c, m, version))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GithubRepo {
    pub name: String,
    /// `owner/name`.
    pub full_name: String,
    pub default_branch: String,
    pub private: bool,
    pub description: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GithubOwner {
    /// The user or organisation.
    pub owner: String,
    pub repos: Vec<GithubRepo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GithubRepoList {
    /// The connection the repos were read with.
    pub connection_id: i64,
    /// This page's repos grouped by owner; owners and repos by name.
    pub owners: Vec<GithubOwner>,
    /// Repos matching `q`, over all pages.
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
    pub has_more: bool,
    /// GitHub has more repos than Core reads (1000); use `q` to narrow.
    pub truncated: bool,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct GithubReposQuery {
    /// A connection id; default the project's, else the workspace default.
    pub connection: Option<i64>,
    /// The project's id, to prefer the connection bound to it.
    pub project: Option<String>,
    /// Case-insensitive text in `owner/name`.
    pub q: Option<String>,
    /// From 1; default 1.
    pub page: Option<i64>,
    /// 1-100; default 30.
    pub per_page: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/projects/github/repos", operation_id = "listGithubRepos",
    tag = "projects", params(GithubReposQuery),
    responses((status = 200, description = "The repos visible to the project's GitHub \
        connection (else the workspace default), grouped by owner, searchable and paged. 409 \
        `no_connection` when none is set up; GitHub's own failures are `auth_failed` or \
        `unreachable` (502) and `rate_limited` (429), each a fixed sentence",
        body = GithubRepoList)))]
pub async fn list(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Query(q): Query<GithubReposQuery>,
) -> ApiResult<GithubRepoList> {
    let user = workspace(&app, &me).await?;
    let now = app.clock.now();
    let (c, m, version) = pick(
        &app,
        conn_who(&me, user, &now),
        q.connection,
        q.project.as_deref(),
    )
    .await?;
    let installation = c.auth_method == "app_install";
    let listed = app
        .connections
        .github()
        .all_repos(c.id, version, &m, installation)
        .await
        .map_err(|o| upstream(&o))?;
    let truncated = listed.1;
    let mut all: Vec<RepoSummary> = listed.0.clone();
    let needle = q.q.as_deref().unwrap_or("").trim().to_lowercase();
    all.retain(|r| {
        format!("{}/{}", r.owner, r.name)
            .to_lowercase()
            .contains(&needle)
    });
    all.sort_by_key(|r| (r.owner.to_lowercase(), r.name.to_lowercase()));
    let per_page = q.per_page.unwrap_or(30).clamp(1, 100);
    let page = q.page.unwrap_or(1).max(1);
    let total = all.len() as i64;
    let from = (page - 1).saturating_mul(per_page);
    let mut owners: Vec<GithubOwner> = Vec::new();
    let skip = usize::try_from(from).unwrap_or(usize::MAX);
    for r in all.into_iter().skip(skip).take(per_page as usize) {
        let repo = GithubRepo {
            full_name: format!("{}/{}", r.owner, r.name),
            name: r.name,
            default_branch: r.default_branch,
            private: r.private,
            description: r.description,
        };
        match owners.last_mut().filter(|o| o.owner == r.owner) {
            Some(o) => o.repos.push(repo),
            None => owners.push(GithubOwner {
                owner: r.owner,
                repos: vec![repo],
            }),
        }
    }
    Ok(Json(GithubRepoList {
        connection_id: c.id,
        owners,
        total,
        page,
        per_page,
        has_more: from.saturating_add(per_page) < total,
        truncated,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewGithubProject {
    /// 1-10 repos as `owner/name`; the first is primary.
    pub repos: Vec<String>,
    /// Default: the first repo's name.
    pub name: Option<String>,
    /// Default: made from the name; a taken or reserved one gets `-2`, `-3`, ... An explicit slug
    /// that is taken is 409 `conflict`.
    pub slug: Option<String>,
    /// Default: the workspace's GitHub default.
    pub connection_id: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/projects/from-github",
    operation_id = "createProjectFromGithub", tag = "projects", request_body = NewGithubProject,
    responses((status = 200, description = "Created with source `github` (audited and emitted as \
        `project.created`), its repos added with GitHub's names and default branches, and the \
        connection bound to it (scope `project`, audited `connection.bound`). 400 for a bad repo, \
        name or slug; 404 for a repo the connection cannot see; 409 `conflict` for a taken \
        explicit slug or a repeated repo, `no_connection` when none is set up", body = ProjectInfo)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(b): Json<NewGithubProject>,
) -> ApiResult<ProjectInfo> {
    if !(1..=MAX_REPOS).contains(&b.repos.len()) {
        return Err(ApiError::bad_request(format!("name 1-{MAX_REPOS} repos")));
    }
    // Cheap check first, before any GitHub call.
    if let Some(n) = &b.name {
        store::name_ok(n)?;
    }
    if let Some(why) = b.slug.as_deref().and_then(store::slug_problem) {
        return Err(ApiError::bad_request(why));
    }
    let user = workspace(&app, &me).await?;
    let now = app.clock.now();
    let (c, m, _) = pick(&app, conn_who(&me, user, &now), b.connection_id, None).await?;
    let mut repos = Vec::new();
    for full in &b.repos {
        let built = build("github.get_repo", &json!({ "repo": full }))
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        let done = app
            .connections
            .github()
            .execute(&m, &built)
            .await
            .map_err(|o| upstream(&o))?;
        let v: Value =
            serde_json::from_slice(&done.body).map_err(|_| upstream(&Outcome::Unexpected))?;
        let field = |x: &Value| x.as_str().filter(|s| !s.is_empty()).map(str::to_owned);
        let (Some(owner), Some(name), Some(branch)) = (
            field(&v["owner"]["login"]),
            field(&v["name"]),
            field(&v["default_branch"]),
        ) else {
            return Err(upstream(&Outcome::Unexpected));
        };
        repos.push(NewGithubRepo {
            remote_url: format!("https://github.com/{owner}/{name}.git"),
            name,
            default_branch: branch,
        });
    }
    let name = b.name.clone().unwrap_or_else(|| repos[0].name.clone());
    // The workspace default needs no per-project binding.
    let is_default = bindings::list(&app.pool, user, Some("github"))
        .await?
        .iter()
        .any(|x| x.scope_kind == "workspace" && x.connection_id == c.id);
    let bind = (!is_default).then(|| (c.id, conn_who(&me, user, &now)));
    let p = store::create_from_github(
        &app.pool,
        b.slug.as_deref(),
        &name,
        &repos,
        who(&me, &now),
        bind,
    )
    .await?;
    let mut conn = app.pool.acquire().await?;
    let made = store::repos(&mut conn, p.id).await?;
    drop(conn);
    for r in made {
        crate::mirrors::start(&app, r.id).await;
    }
    Ok(Json(info(&app, p).await?))
}
