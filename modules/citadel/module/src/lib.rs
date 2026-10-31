//! Citadel as a module of the Core (E2-13): orchestration only, mounted at `/modules/citadel/v1`
//! behind the platform's client gate, on the platform's store, events and audit. Its tables are
//! `citadel_*` and its migrations run in their own namespace (`migrations`).
//!
//! The port is sliced (`Docs/Plans/2026-10-30-citadel-port-slices.md`); the parked monolith in
//! `../core` and `../server` stays the reference until the last slice lands. This crate holds the
//! slices that do not need the agent sessions, git workspace, scheduler or notifications of the
//! platform: the domain model, the baseline schema, the org repository and its first routes.

use ainkrad_core_server::api::App;
use ainkrad_core_server::module::{
    BoxFut, Credential, Module, ModuleSetting, TokenGrant, TokenRoute,
};
use ainkrad_core_server::store::Migration;
use ainkrad_core_server::store::agents::Session;
use ainkrad_core_server::store::events::StoredEvent;
use axum::Router;

pub mod admin;
pub mod api;
pub mod domain;
pub mod engine;
pub mod forge;
pub mod kinds;
pub mod mcp;
pub mod migrations;
pub mod notifications;
pub mod profile;
pub mod settings;
pub mod store;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

/// The module's id: the route prefix, the table prefix and the owner of the sessions its engine starts.
pub const MODULE: &str = "citadel";

/// The Citadel module: hand it to `module::mount` and `migrate::migrate_modules`. `default()`
/// declares no forge jobs; `with_forge` adds the forge and Linear pollers (S6), which need the
/// store and the broker's key.
#[derive(Default, Clone)]
pub struct Citadel {
    forge: Option<std::sync::Arc<forge::Runtime>>,
}

impl Citadel {
    pub fn with_forge(forge: std::sync::Arc<forge::Runtime>) -> Self {
        Self { forge: Some(forge) }
    }
}

impl Module for Citadel {
    fn id(&self) -> &'static str {
        MODULE
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

    fn notification_kinds(&self) -> &'static [(&'static str, &'static str)] {
        notifications::KINDS
    }

    fn classify(&self, e: &StoredEvent) -> Option<ainkrad_core_server::push::Notification> {
        ainkrad_core_server::push::Classifier::notification(&notifications::Citadel, e)
    }

    fn admin_commands(&self) -> &'static [&'static str] {
        &["seed"]
    }

    fn admin<'a>(
        &'a self,
        name: &'a str,
        pool: &'a sqlx::SqlitePool,
        args: &'a [&'a str],
    ) -> BoxFut<'a, Result<String, String>> {
        Box::pin(async move {
            match name {
                "seed" => admin::seed_command(pool, args).await,
                _ => Err("no such command".to_owned()),
            }
        })
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

    fn jobs(&self) -> Vec<ainkrad_core_server::jobs::Job> {
        let mut jobs = engine::jobs();
        if let Some(f) = &self.forge {
            jobs.extend(f.jobs());
        }
        jobs
    }

    fn token_routes(&self) -> &'static [TokenRoute] {
        mcp::ROUTES
    }

    fn token_handler(
        &self,
        method: &str,
        template: &str,
    ) -> Option<axum::routing::MethodRouter<App>> {
        mcp::handler(method, template)
    }

    fn verify_token<'a>(&'a self, app: &'a App, token: &'a str) -> BoxFut<'a, Option<TokenGrant>> {
        Box::pin(mcp::verify(app, token))
    }

    fn credentials<'a>(
        &'a self,
        app: &'a App,
        session: &'a Session,
    ) -> BoxFut<'a, Result<Vec<Credential>, String>> {
        Box::pin(mcp::credentials(app, session))
    }
}
