//! Work: projects, repos, epics, issues (state machine, kanban, backlog, sprints), charts.
//!
//! Slice S4 (work half) of the port (`Docs/Plans/2026-10-30-citadel-port-slices.md`). This file is
//! the slice's seam with the rest of the module: it exports its routes, its per-route scopes, its
//! destructive routes, its company-owner rows and its OpenAPI document, and `api.rs`, `scopes.rs`,
//! `scope.rs` and `spec.rs` aggregate them. Handlers live in submodules next to this file.
//!
//! Not here, and why: `probeRepo` (clones the repo through the git workspace, then asks the
//! forge: the workspace lives on a runner (E2-10), so the probe comes with the run engine, S7); the project logo
//! routes (`getProjectLogo`, `uploadProjectLogo`, `resetProjectLogo`: the Core has no artifacts
//! root to store the image under, and the avatar image helpers are S3's); `checkoutIssue` (the
//! run engine, S7).

use ainkrad_core_server::api::App;
use axum::Router;
use axum::routing::{delete, get, patch, post, put};
use utoipa::OpenApi;

mod charts;
mod forge;
mod issues;
pub(crate) use issues::issue_out;
mod projects;
mod repos;
mod thread;
mod util;

/// The slice's routes, relative to `/modules/citadel/v1`.
pub fn routes() -> Router<App> {
    Router::new()
        .route(
            "/companies/{id}/projects",
            get(projects::list_projects).post(projects::create_project),
        )
        .route("/projects/{id}", get(projects::get_project))
        .route(
            "/projects/{id}/issues",
            get(projects::list_issues).post(issues::create_issue),
        )
        .route("/projects/{id}/backlog", get(projects::backlog))
        .route("/projects/{id}/repos", get(repos::list).post(repos::add))
        .route("/projects/{id}/repo-order", put(repos::order))
        .route("/repos/{id}", put(repos::update).delete(repos::remove))
        .route("/repos/{id}/primary", post(repos::primary))
        .route(
            "/issues/{id}/repos",
            get(repos::get_issue_repos).put(repos::set_issue_repos),
        )
        .route("/forge/hosts", get(forge::list_hosts))
        .route(
            "/forge/hosts/{host}",
            put(forge::add_host).delete(forge::remove_host),
        )
        .route(
            "/projects/{id}/linear",
            get(forge::get_linear)
                .put(forge::set_linear)
                .delete(forge::remove_linear),
        )
        .route("/projects/{id}/cfd", get(charts::cfd))
        .route("/projects/{id}/profile/preview", get(charts::preview))
        .route(
            "/projects/{id}/epics",
            get(projects::list_epics).post(projects::create_epic),
        )
        .route("/epics/{id}", patch(projects::update_epic))
        .route(
            "/projects/{id}/sprints",
            get(projects::list_sprints).post(projects::plan_sprint),
        )
        .route("/projects/{id}/velocity", get(projects::velocity))
        .route(
            "/projects/{id}/wip",
            get(projects::wip_limits).post(projects::set_wip_limit),
        )
        .route("/sprints/{id}", delete(projects::delete_sprint))
        .route("/sprints/{id}/close", post(projects::close_sprint))
        .route("/sprints/{id}/report", get(projects::sprint_report))
        .route(
            "/issues/{id}",
            get(issues::get_issue).patch(issues::update_issue),
        )
        .route("/issues/{id}/activity", get(thread::activity))
        .route("/issues/{id}/transition", post(issues::transition))
        .route("/issues/{id}/blockers", get(issues::list_blockers))
        .route(
            "/issues/{id}/blockers/{blocker_id}",
            put(issues::link_blocker).delete(issues::unlink_blocker),
        )
        .route("/issues/{id}/move", post(issues::move_issue))
        .route("/issues/{id}/estimate", post(issues::estimate))
        .route("/issues/{id}/epic", post(issues::set_epic))
        .route("/issues/{id}/sprint", post(issues::set_sprint))
        .route(
            "/issues/{id}/comments",
            get(thread::list_comments).post(thread::post_comment),
        )
}

/// `(method, template, scope)` of the slice's routes below `admin` (`api::scopes`): the reads a
/// phone may see. Every write needs `admin`.
pub const SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/companies/{id}/projects", "read"),
    ("GET", "/projects/{id}", "read"),
    ("GET", "/projects/{id}/issues", "read"),
    ("GET", "/projects/{id}/backlog", "read"),
    ("GET", "/projects/{id}/epics", "read"),
    ("GET", "/projects/{id}/sprints", "read"),
    ("GET", "/projects/{id}/velocity", "read"),
    ("GET", "/projects/{id}/wip", "read"),
    ("GET", "/projects/{id}/cfd", "read"),
    ("GET", "/sprints/{id}/report", "read"),
    ("GET", "/issues/{id}", "read"),
    ("GET", "/issues/{id}/activity", "read"),
    ("GET", "/issues/{id}/blockers", "read"),
    ("GET", "/issues/{id}/comments", "read"),
    ("GET", "/issues/{id}/repos", "read"),
];

/// GET templates that deliberately stay `admin` (`api::scopes::ADMIN_READS`): a repo shows the
/// path of its forge token file, and the profile preview is the text a run is instructed with.
pub const ADMIN_READS: &[&str] = &[
    "/projects/{id}/repos",
    "/projects/{id}/profile/preview",
    // Where credentials are sent: the allowed hosts, and a project's Linear secret name.
    "/forge/hosts",
    "/projects/{id}/linear",
];

/// `(method, template)` of the slice's routes that need a live step-up (`Module::destructive`):
/// the two that delete data (an empty sprint, a repo).
pub const DESTRUCTIVE: &[(&str, &str)] = &[
    ("DELETE", "/sprints/{id}"),
    ("DELETE", "/repos/{id}"),
    // A repo sets the commands a runner runs, a token file path and a forge URL.
    ("POST", "/projects/{id}/repos"),
    ("PUT", "/repos/{id}"),
    // Where the server sends a credential: a forge host, and a project's Linear link.
    ("PUT", "/forge/hosts/{host}"),
    ("DELETE", "/forge/hosts/{host}"),
    ("PUT", "/projects/{id}/linear"),
    ("DELETE", "/projects/{id}/linear"),
];

/// `(path segment, SQL)` rows for `scope::OWNERS`: the company that owns what `segment/{id}` names.
/// Every `{id}` of the slice's routes is a company, project, issue, epic, sprint or repo, and the
/// `blocker_id` of a link is an issue: all in `scope::OWNERS` already.
pub const OWNERS: &[(&str, &str)] = &[];

/// The slice's `#[utoipa::path]` routes and schemas (operation ids unprefixed: `spec` adds
/// `citadel`; schema names must not clash with the Core's or another slice's).
#[derive(OpenApi)]
#[openapi(
    paths(
        projects::list_projects,
        projects::create_project,
        projects::get_project,
        projects::list_issues,
        projects::backlog,
        projects::list_epics,
        projects::create_epic,
        projects::update_epic,
        projects::list_sprints,
        projects::plan_sprint,
        projects::close_sprint,
        projects::delete_sprint,
        projects::sprint_report,
        projects::velocity,
        projects::wip_limits,
        projects::set_wip_limit,
        issues::get_issue,
        issues::update_issue,
        issues::create_issue,
        issues::transition,
        issues::list_blockers,
        issues::link_blocker,
        issues::unlink_blocker,
        issues::move_issue,
        issues::estimate,
        issues::set_epic,
        issues::set_sprint,
        thread::list_comments,
        thread::post_comment,
        thread::activity,
        repos::list,
        repos::add,
        repos::update,
        repos::remove,
        repos::primary,
        repos::order,
        repos::get_issue_repos,
        repos::set_issue_repos,
        charts::cfd,
        charts::preview,
        forge::list_hosts,
        forge::add_host,
        forge::remove_host,
        forge::get_linear,
        forge::set_linear,
        forge::remove_linear,
    ),
    components(schemas(
        super::model::work::Project,
        super::model::work::Epic,
        super::model::work::Sprint,
        super::model::work::Issue,
        super::model::work::Criterion,
        super::model::work::Label,
        super::model::work::Comment,
        projects::NewProjectBody,
        projects::NewEpicBody,
        projects::EpicPatchBody,
        projects::NewSprintBody,
        projects::CloseSprintBody,
        projects::BurndownDay,
        projects::SprintReport,
        projects::SprintPoints,
        projects::Velocity,
        projects::WipLimit,
        projects::WipLimitBody,
        issues::IssuePatchBody,
        issues::NewIssueBody,
        issues::Transition,
        issues::MoveTo,
        issues::MoveBody,
        issues::EstimateBody,
        issues::EpicBody,
        issues::SprintBody,
        thread::NewComment,
        thread::Posted,
        thread::ActivityActor,
        thread::ActivityEntry,
        thread::ActivityPage,
        repos::RepoForge,
        repos::RepoCommands,
        repos::Repo,
        repos::RepoBody,
        repos::RepoNames,
        repos::RepoRequest,
        repos::IssueRepos,
        forge::ForgeHosts,
        forge::LinearLink,
        forge::LinearBody,
        charts::CfdDay,
        charts::ProfilePreview,
    ))
)]
pub struct Doc;
