//! Citadel as a module of the Core (E2-13): orchestration only, mounted at `/modules/citadel/v1`
//! behind the platform's client gate, on the platform's store, events and audit. Its tables are
//! `citadel_*` and its migrations run in their own namespace (`migrations`).
//!
//! The port is sliced (`Docs/Plans/2026-10-30-citadel-port-slices.md`); the parked monolith in
//! `../core` and `../server` stays the reference until the last slice lands. This crate holds the
//! slices that do not need the agent sessions, git workspace, scheduler or notifications of the
//! platform: the domain model, the baseline schema, the org repository and its first routes.

use ainkrad_core_server::api::App;
use ainkrad_core_server::module::{Module, ModuleSetting};
use ainkrad_core_server::store::Migration;
use axum::Router;

pub mod api;
pub mod domain;
pub mod kinds;
pub mod migrations;
pub mod profile;
pub mod settings;
pub mod store;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

/// The Citadel module: hand it to `module::mount` and `migrate::migrate_modules`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Citadel;

impl Module for Citadel {
    fn id(&self) -> &'static str {
        "citadel"
    }

    fn routes(&self) -> Router<App> {
        api::routes()
    }

    fn migrations(&self) -> &'static [Migration] {
        migrations::MIGRATIONS
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        kinds::EVENT_KINDS
    }

    fn audit_actions(&self) -> &'static [&'static str] {
        kinds::AUDIT_ACTIONS
    }

    // Deny by default: a route that is not in `api::scopes::ROUTE_SCOPES` needs `admin`.
    fn scope(&self) -> &'static str {
        "admin"
    }

    fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
        api::scopes::ALL.as_slice()
    }

    fn openapi(&self) -> serde_json::Value {
        api::spec::document()
    }

    fn query_names(&self) -> &'static [&'static str] {
        api::QUERY
    }

    fn settings(&self) -> &'static [ModuleSetting] {
        settings::SETTINGS
    }

    fn destructive(&self) -> &'static [(&'static str, &'static str)] {
        api::DESTRUCTIVE.as_slice()
    }
}
