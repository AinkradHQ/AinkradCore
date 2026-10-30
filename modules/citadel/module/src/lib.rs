//! Citadel as a module of the Core (E2-13): orchestration only, mounted at `/modules/citadel/v1`
//! behind the platform's client gate, on the platform's store, events and audit. Its tables are
//! `citadel_*` and its migrations run in their own namespace (`migrations`).
//!
//! The port is sliced (`Docs/Plans/2026-10-30-citadel-port-slices.md`); the parked monolith in
//! `../core` and `../server` stays the reference until the last slice lands. This crate holds the
//! slices that do not need the agent sessions, git workspace, scheduler or notifications of the
//! platform: the domain model, the baseline schema, the org repository and its first routes.

use ainkrad_core_server::api::App;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::Migration;
use axum::Router;

pub mod api;
pub mod domain;
pub mod kinds;
pub mod migrations;
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

    // ponytail: one scope for every route (`Module::scope`); a phone that only reads needs
    // per-route scopes, which is a Core change (see the slice plan, open question 1).
    fn scope(&self) -> &'static str {
        "admin"
    }

    fn destructive(&self) -> &'static [(&'static str, &'static str)] {
        api::DESTRUCTIVE
    }
}
