//! The module's routes, relative to `/modules/citadel/v1`. They run inside the Core's client gate
//! (host, origin, signature, rate limits, scope), so no handler authenticates; the audit actor is
//! the admin user, as everywhere on the Core until users arrive.
//!
//! Slice 1 (org): companies, departments, teams, agents (read). The rest of the monolith's
//! `api/v1` follows in the slices of the port plan.

use std::sync::LazyLock;

use ainkrad_core_server::api::App;
use axum::Router;
use axum::routing::{get, put};

pub mod accounts;
mod error;
pub mod governance;
pub mod model;
mod org;
pub mod org_admin;
pub mod planning;
pub mod runs;
pub mod scope;
pub mod scopes;
pub mod spec;
pub mod types;
pub mod work;
pub mod writes;

/// Query names the module's routes take besides the Core's (`Module::query_names`): the
/// monolith's filter names. Appended by the slices that add a filter.
pub const QUERY: &[&str] = &[
    "pending",
    "since",
    "requirement",
    "issue",
    "agent",
    "live",
    "state",
    "bucket",
    "until",
    "harness",
    "model",
    "name",
    "kind",
];

/// The routes of slices 1 and 2 that need a live step-up.
const DESTRUCTIVE_ORG: &[(&str, &str)] =
    &[("DELETE", "/departments/{id}"), ("DELETE", "/teams/{id}")];

/// Route-table audit (F-01..F-04): a write that changes what an agent may do (sandbox, role,
/// instructions, skills), which model runs (chains, tiers, presets), what a token costs (prices,
/// budgets), project policy (settings, sprint gate), or starts work in bulk (sprint commit, resume)
/// needs a step-up. Ordinary work-item writes stay open, see `writes::NON_DESTRUCTIVE`.
const DESTRUCTIVE_AUDIT: &[(&str, &str)] = &[
    // F-01: `sandbox` may be `full_access`.
    ("PATCH", "/agents/{id}"),
    ("POST", "/companies/{id}/templates/{template}"),
    ("POST", "/companies/{id}/roles"),
    ("PUT", "/roles/{id}"),
    ("POST", "/companies/{id}/skills"),
    ("POST", "/knowledge/{id}/supersede"),
    // F-04: model routing is spend.
    ("PUT", "/agents/{id}/chain"),
    ("PUT", "/agents/{id}/fallbacks"),
    ("PUT", "/agents/{id}/tiers"),
    ("PUT", "/projects/{id}/tier-rules"),
    ("POST", "/companies/{id}/chain-presets"),
    ("PUT", "/chain-presets/{id}"),
    // F-04: price and budget accounting.
    ("POST", "/prices"),
    ("POST", "/companies/{id}/budgets"),
    // F-04: project settings carry `sprint_approval`, `max_parallel_runs`, `run_timeout_secs`.
    ("POST", "/companies/{id}/projects"),
    ("PUT", "/projects/{id}"),
    // F-03: bulk starts of agent runs.
    ("POST", "/sprints/{id}/commit"),
    ("POST", "/requirements/{id}/resume"),
];

/// Every route that needs a live step-up (`Module::destructive`): the slices' lists together.
pub static DESTRUCTIVE: LazyLock<Vec<(&str, &str)>> = LazyLock::new(|| {
    [
        DESTRUCTIVE_ORG,
        org_admin::DESTRUCTIVE,
        work::DESTRUCTIVE,
        planning::DESTRUCTIVE,
        governance::DESTRUCTIVE,
        accounts::DESTRUCTIVE,
        runs::DESTRUCTIVE,
        DESTRUCTIVE_AUDIT,
    ]
    .concat()
});

pub fn routes() -> Router<App> {
    Router::new()
        .merge(org_admin::routes())
        .merge(work::routes())
        .merge(planning::routes())
        .merge(governance::routes())
        .merge(accounts::routes())
        .merge(runs::routes())
        .route(
            "/companies",
            get(org::list_companies).post(org::create_company),
        )
        .route(
            "/companies/{id}",
            get(org::get_company).put(org::update_company),
        )
        .route(
            "/companies/{id}/departments",
            get(org::list_departments).post(org::add_department),
        )
        .route(
            "/departments/{id}",
            put(org::rename_department).delete(org::remove_department),
        )
        .route(
            "/departments/{id}/teams",
            get(org::list_teams).post(org::add_team),
        )
        .route(
            "/teams/{id}",
            put(org::rename_team).delete(org::remove_team),
        )
        .route("/companies/{id}/agents", get(org::list_agents))
        .route("/agents/{id}", get(org::get_agent))
}
