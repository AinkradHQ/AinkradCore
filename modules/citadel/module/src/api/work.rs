//! Work: projects, repos, epics, issues (state machine, checkout, kanban, backlog, sprints, review), charts, logos, branch names.
//!
//! Slice S4 (work half) of the port (`Docs/Plans/2026-10-30-citadel-port-slices.md`). This file is the
//! slice's seam with the rest of the module: it exports its routes, its per-route scopes, its
//! destructive routes, its company-owner rows and its OpenAPI document, and `api.rs`, `scopes.rs`,
//! `scope.rs` and `spec.rs` aggregate them. Handlers live in submodules next to this file.

use ainkrad_core_server::api::App;
use axum::Router;
use utoipa::OpenApi;

/// The slice's routes, relative to `/modules/citadel/v1`.
pub fn routes() -> Router<App> {
    Router::new()
}

/// `(method, template, scope)` of the slice's routes below `admin` (`api::scopes`).
pub const SCOPES: &[(&str, &str, &str)] = &[];

/// GET templates that deliberately stay `admin` (`api::scopes::ADMIN_READS`).
pub const ADMIN_READS: &[&str] = &[];

/// `(method, template)` of the slice's routes that need a live step-up (`Module::destructive`).
pub const DESTRUCTIVE: &[(&str, &str)] = &[];

/// `(path segment, SQL)` rows for `scope::OWNERS`: the company that owns what `segment/{id}` names.
pub const OWNERS: &[(&str, &str)] = &[];

/// The slice's `#[utoipa::path]` routes and schemas (operation ids unprefixed: `spec` adds
/// `citadel`; schema names must not clash with the Core's or another slice's).
#[derive(OpenApi)]
#[openapi(paths(), components(schemas()))]
pub struct Doc;
