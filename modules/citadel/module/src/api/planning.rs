//! Planning: requirements and plans, the hub thread, quest (labels, capacity, flow, sprint
//! commit and review), the project profile.
//!
//! Slice S4 (planning half) of the port (`Docs/Plans/2026-10-30-citadel-port-slices.md`). This
//! file is the slice's seam with the rest of the module: it exports its routes, its per-route
//! scopes, its destructive routes, its company-owner rows and its OpenAPI document, and
//! `api.rs`, `scopes.rs`, `scope.rs` and `spec.rs` aggregate them. Handlers live in
//! `planning/`, the response models in `model/planning.rs`.
//!
//! Not here: `attachToRequirement` (the artifact store's publish path, S5); the intake request
//! route (`POST /companies/{id}/requests`) and project creation live with the org and work
//! seams.

use ainkrad_core_server::api::App;
use axum::Router;
use axum::routing::{get, post, put};
use utoipa::OpenApi;

mod flow;
mod hub;
mod profile;
pub(crate) mod quest;
mod requirements;

/// The slice's routes, relative to `/modules/citadel/v1`.
pub fn routes() -> Router<App> {
    Router::new()
        .route("/requirements", get(requirements::list))
        .route(
            "/requirements/{id}",
            get(requirements::get).put(requirements::rename),
        )
        .route("/requirements/{id}/tree", get(requirements::tree))
        .route("/requirements/{id}/cancel", post(requirements::cancel))
        .route("/requirements/{id}/pause", post(requirements::pause))
        .route("/requirements/{id}/resume", post(requirements::resume))
        .route("/requirements/{id}/done", post(requirements::finish))
        .route("/requirements/{id}/thread", get(hub::get).post(hub::post))
        .route("/companies/{id}/questions", get(hub::open_questions))
        .route("/projects/{id}", put(quest::update_project))
        .route(
            "/projects/{id}/labels",
            get(quest::list_labels).post(quest::add_label),
        )
        .route(
            "/projects/{id}/labels/{label_id}",
            put(quest::rename_label).delete(quest::delete_label),
        )
        .route(
            "/issues/{id}/labels/{label_id}",
            put(quest::label_issue).delete(quest::unlabel_issue),
        )
        .route("/projects/{id}/capacity", get(flow::capacity))
        .route(
            "/projects/{id}/capacity/{agent_id}",
            put(flow::set_capacity),
        )
        .route("/projects/{id}/flow", get(flow::project_flow))
        .route("/issues/{id}/flow", get(flow::issue_flow))
        .route("/sprints/{id}/commit", post(flow::commit_sprint))
        .route("/sprints/{id}/review", get(flow::sprint_review))
        .route(
            "/projects/{id}/profile",
            get(profile::get).put(profile::update),
        )
        .route(
            "/projects/{id}/profile/proposals/{proposal_id}/decision",
            post(profile::decide),
        )
        .route("/projects/{id}/profile/history", get(profile::history))
}

/// `(method, template, scope)` of the slice's routes below `admin` (`api::scopes`): the reads a
/// phone may see. Every write stays `admin`.
pub const SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/requirements", "read"),
    ("GET", "/requirements/{id}", "read"),
    ("GET", "/requirements/{id}/tree", "read"),
    ("GET", "/requirements/{id}/thread", "read"),
    ("GET", "/companies/{id}/questions", "read"),
    ("GET", "/projects/{id}/labels", "read"),
    ("GET", "/projects/{id}/capacity", "read"),
    ("GET", "/projects/{id}/flow", "read"),
    ("GET", "/issues/{id}/flow", "read"),
    ("GET", "/sprints/{id}/review", "read"),
    ("GET", "/projects/{id}/profile", "read"),
];

/// GET templates that deliberately stay `admin` (`api::scopes::ADMIN_READS`): the profile's
/// history is audit content.
pub const ADMIN_READS: &[&str] = &["/projects/{id}/profile/history"];

/// `(method, template)` of the slice's routes that need a live step-up (`Module::destructive`):
/// cancelling a requirement cancels every open issue of it, deleting a label strips it from
/// every issue, and a profile edit may widen what a run may do (`permission_mode`).
pub const DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/requirements/{id}/cancel"),
    ("DELETE", "/projects/{id}/labels/{label_id}"),
    ("PUT", "/projects/{id}/profile"),
];

/// `(path segment, SQL)` rows for `scope::OWNERS`: the company that owns what `segment/{id}` names
/// (`requirements`, `projects`, `issues` and `sprints` are in the base list).
pub const OWNERS: &[(&str, &str)] = &[
    (
        "labels",
        "SELECT p.company_id FROM citadel_labels l JOIN citadel_projects p \
         ON p.id = l.project_id WHERE l.id = ?",
    ),
    // `/projects/{id}/capacity/{agent_id}`: the value after `capacity` is an agent.
    (
        "capacity",
        "SELECT company_id FROM citadel_agents WHERE id = ?",
    ),
    // `/projects/{id}/profile/proposals/{proposal_id}/decision`: a knowledge entry.
    (
        "proposals",
        "SELECT p.company_id FROM citadel_knowledge_entries k JOIN citadel_projects p \
         ON p.id = k.project_id WHERE k.id = ?",
    ),
];

/// The slice's `#[utoipa::path]` routes and schemas (operation ids unprefixed: `spec` adds
/// `citadel`; schema names must not clash with the Core's or another slice's).
#[derive(OpenApi)]
#[openapi(
    paths(
        requirements::list,
        requirements::get,
        requirements::tree,
        requirements::rename,
        requirements::cancel,
        requirements::pause,
        requirements::resume,
        requirements::finish,
        hub::get,
        hub::post,
        hub::open_questions,
        quest::update_project,
        quest::list_labels,
        quest::add_label,
        quest::rename_label,
        quest::delete_label,
        quest::label_issue,
        quest::unlabel_issue,
        flow::capacity,
        flow::set_capacity,
        flow::project_flow,
        flow::issue_flow,
        flow::commit_sprint,
        flow::sprint_review,
        profile::get,
        profile::update,
        profile::decide,
        profile::history,
    ),
    components(schemas(
        super::model::planning::Requirement,
        super::model::planning::TreeTask,
        super::model::planning::TreeEpic,
        super::model::planning::PlanTask,
        super::model::planning::PlanDiff,
        super::model::planning::PlanBurndownDay,
        super::model::planning::RequirementTree,
        super::model::planning::Question,
        super::model::planning::ThreadItem,
        super::model::planning::Thread,
        super::model::planning::ProfileProposal,
        super::model::planning::ProjectProfile,
        super::model::planning::ProfileActor,
        super::model::planning::ProfileChange,
        requirements::RequirementRename,
        requirements::RequirementCancel,
        hub::ThreadPost,
        hub::ThreadPosted,
        quest::ProjectSettings,
        quest::LabelName,
        flow::MemberCapacity,
        flow::TeamCapacity,
        flow::CapacityBody,
        flow::ProjectFlow,
        flow::IssueTimes,
        flow::IssueFlow,
        flow::SprintCommit,
        flow::RetroProposal,
        flow::SprintReview,
        profile::ProposalDecision,
        crate::profile::Profile,
        crate::profile::ProfilePatch,
        crate::profile::MergeMethod,
        crate::profile::Merger,
        crate::profile::Deploy,
        crate::profile::Network,
        crate::profile::Environment,
        crate::profile::RoleModel,
        crate::profile::DodRule,
    ))
)]
pub struct Doc;
