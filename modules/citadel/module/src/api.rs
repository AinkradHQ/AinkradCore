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
pub mod controls;
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
        controls::DESTRUCTIVE,
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
        .merge(controls::routes())
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
