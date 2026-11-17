//! The Design module (V1-01): the Core's store of design documents. This story is the doc store and its
//! API only: docs (design, system, mockup) create/read/change/archive, links to projects (checked
//! through the Projects store; related, not owned), `design.*` events and audit. The CRDT sync (V1-03)
//! and the asset library (V4-01) come later. Designs stay in the Core: nothing is exported to a repo.
//!
//! Module off, the Core is unchanged: the tables are its own `design_` namespace, no Core
//! migration, no Core crate names this module.

mod docs;

use ainkrad_core_server::api::App;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::Migration;
use axum::Router;
use axum::routing::{get, post, put};
use serde_json::Value;
use utoipa::OpenApi;

pub const MODULE: &str = "design";

pub static MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "0001_design",
    up: include_str!("../migrations/0001_design.up.sql"),
    down: include_str!("../migrations/0001_design.down.sql"),
}];

// Archiving hides a design from every list, so it needs a step-up like archiving a project.
const DESTRUCTIVE: &[(&str, &str)] = &[("POST", "/docs/{doc}/archive")];
const NON_DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/docs"),
    ("PATCH", "/docs/{doc}"),
    ("PUT", "/docs/{doc}/projects/{project}"),
    ("DELETE", "/docs/{doc}/projects/{project}"),
];
const ROUTE_SCOPES: &[(&str, &str, &str)] =
    &[("GET", "/docs", "read"), ("GET", "/docs/{doc}", "read")];

#[derive(Default, Clone, Copy)]
pub struct Design;

#[derive(OpenApi)]
#[openapi(
    paths(
        docs::list,
        docs::create,
        docs::get,
        docs::patch,
        docs::archive,
        docs::link,
        docs::unlink
    ),
    components(schemas(docs::DocView, docs::NewDoc, docs::DocPatch))
)]
struct Doc;

impl Module for Design {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn routes(&self) -> Router<App> {
        Router::new()
            .route("/docs", get(docs::list).post(docs::create))
            .route("/docs/{doc}", get(docs::get).patch(docs::patch))
            .route("/docs/{doc}/archive", post(docs::archive))
            .route(
                "/docs/{doc}/projects/{project}",
                put(docs::link).delete(docs::unlink),
            )
    }

    fn migrations(&self) -> &'static [Migration] {
        MIGRATIONS
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["design.doc"]
    }

    /// Ids only, so a read-only device may see them.
    fn event_scope(&self, _kind: &str) -> &'static str {
        "read"
    }

    fn audit_actions(&self) -> &'static [&'static str] {
        &[
            "design.doc.created",
            "design.doc.changed",
            "design.doc.archived",
            "design.doc.linked",
            "design.doc.unlinked",
        ]
    }

    fn query_names(&self) -> &'static [&'static str] {
        &["state", "kind", "project"]
    }

    fn scope(&self) -> &'static str {
        "admin"
    }

    fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
        ROUTE_SCOPES
    }

    fn destructive(&self) -> &'static [(&'static str, &'static str)] {
        DESTRUCTIVE
    }

    fn non_destructive(&self) -> Option<&'static [(&'static str, &'static str)]> {
        Some(NON_DESTRUCTIVE)
    }

    fn openapi(&self) -> Value {
        serde_json::to_value(Doc::openapi()).expect("the design contract serialises")
    }
}
