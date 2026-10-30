//! The module's routes, relative to `/modules/citadel/v1`. They run inside the Core's client gate
//! (host, origin, signature, rate limits, scope), so no handler authenticates; the audit actor is
//! the admin user, as everywhere on the Core until users arrive.
//!
//! Slice 1 (org): companies, departments, teams, agents (read). The rest of the monolith's
//! `api/v1` follows in the slices of the port plan.

use ainkrad_core_server::api::App;
use axum::Router;
use axum::routing::{get, put};

mod org;

/// The routes that need a live step-up (`Module::destructive`).
pub const DESTRUCTIVE: &[(&str, &str)] =
    &[("DELETE", "/departments/{id}"), ("DELETE", "/teams/{id}")];

pub fn routes() -> Router<App> {
    Router::new()
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
