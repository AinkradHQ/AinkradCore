//! The Leyline module (Y1-01): the Core's address book of SSH hosts. This story is the store and
//! the API only: hosts, groups and tags, label addressing, the validation that keeps argv-injection
//! text out (API and table), `leyline.*` events and audit; and keys (Y1-02): generated or imported,
//! sealed in the Core's secret store, public data only in the API. Attachments (Y1-03), SSH itself
//! (Y2+) and the command gate (Y4) come later.
//!
//! Module off, the Core is unchanged: the tables are its own `leyline_` namespace, no Core
//! migration, no Core crate names this module.

mod address;
mod hosts;
mod keys;
mod valid;

use ainkrad_core_server::api::App;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::Migration;
use axum::Router;
use axum::routing::{get, post};
use serde_json::Value;
use utoipa::OpenApi;

pub const MODULE: &str = "leyline";

pub static MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "0001_leyline",
    up: include_str!("../migrations/0001_leyline.up.sql"),
    down: include_str!("../migrations/0001_leyline.down.sql"),
}];

// A key write is a secret write: importing needs the step-up like the Core's own secret writes.
// Generating does not (the Core makes the key; nothing of the caller's is stored).
const DESTRUCTIVE: &[(&str, &str)] = &[
    ("DELETE", "/hosts/{host}"),
    ("DELETE", "/keys/{key}"),
    ("POST", "/keys/import"),
];
// ponytail: a PATCH can repoint a host's address/key/runner without a step-up; Y4-01 (the gate)
// decides whether that needs one, with the `allowed` rule.
const NON_DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/hosts"),
    ("PATCH", "/hosts/{host}"),
    ("POST", "/keys"),
];
const ROUTE_SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/hosts", "read"),
    ("GET", "/hosts/{host}", "read"),
    ("GET", "/groups", "read"),
    ("GET", "/tags", "read"),
    ("GET", "/keys", "read"),
    ("GET", "/keys/{key}", "read"),
];

#[derive(Default, Clone, Copy)]
pub struct Leyline;

#[derive(OpenApi)]
#[openapi(
    paths(
        hosts::list,
        hosts::create,
        hosts::get,
        hosts::patch,
        hosts::remove,
        hosts::groups,
        hosts::tags,
        keys::list,
        keys::generate,
        keys::import,
        keys::get,
        keys::remove
    ),
    components(schemas(
        hosts::HostView,
        hosts::NewHost,
        hosts::HostPatch,
        hosts::Deleted,
        hosts::Count,
        keys::KeyView,
        keys::NewKey,
        keys::ImportKey,
        keys::KeyDeleted
    ))
)]
struct Doc;

impl Module for Leyline {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn routes(&self) -> Router<App> {
        Router::new()
            .route("/hosts", get(hosts::list).post(hosts::create))
            .route(
                "/hosts/{host}",
                get(hosts::get).patch(hosts::patch).delete(hosts::remove),
            )
            .route("/groups", get(hosts::groups))
            .route("/tags", get(hosts::tags))
            .route("/keys", get(keys::list).post(keys::generate))
            .route("/keys/import", post(keys::import))
            .route("/keys/{key}", get(keys::get).delete(keys::remove))
    }

    fn migrations(&self) -> &'static [Migration] {
        MIGRATIONS
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["leyline.host", "leyline.key"]
    }

    /// Ids only, so a read-only device may see them.
    fn event_scope(&self, _kind: &str) -> &'static str {
        "read"
    }

    fn audit_actions(&self) -> &'static [&'static str] {
        &[
            "leyline.host.created",
            "leyline.host.changed",
            "leyline.host.deleted",
            "leyline.key.created",
            "leyline.key.deleted",
        ]
    }

    fn query_names(&self) -> &'static [&'static str] {
        &["group", "tag"]
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
        serde_json::to_value(Doc::openapi()).expect("the leyline contract serialises")
    }
}
