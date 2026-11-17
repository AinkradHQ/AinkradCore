//! The Leyline module (Y1-01): the Core's address book of SSH hosts. This story is the store and
//! the API only: hosts, groups and tags, label addressing, the validation that keeps argv-injection
//! text out (API and table), `leyline.*` events and audit. Keys (Y1-02), attachments (Y1-03), SSH
//! itself (Y2+) come later; the command gate (`gate`, Y4-01) is here; no secret is handled here.
//!
//! Module off, the Core is unchanged: the tables are its own `leyline_` namespace, no Core
//! migration, no Core crate names this module.

mod address;
pub mod gate;
mod hosts;
mod policy;
mod valid;

use ainkrad_core_server::api::App;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::Migration;
use axum::Router;
use axum::routing::get;
use serde_json::Value;
use utoipa::OpenApi;

pub const MODULE: &str = "leyline";

pub static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "0001_leyline",
        up: include_str!("../migrations/0001_leyline.up.sql"),
        down: include_str!("../migrations/0001_leyline.down.sql"),
    },
    Migration {
        version: 2,
        name: "0002_runs",
        up: include_str!("../migrations/0002_runs.up.sql"),
        down: include_str!("../migrations/0002_runs.down.sql"),
    },
];

const DESTRUCTIVE: &[(&str, &str)] = &[("DELETE", "/hosts/{host}")];
// POST and PATCH need a step-up only for what widens an AI's reach or repoints a host (`allowed`,
// address, port, user, key, jump chain, runner): checked in the handler (`hosts::needs_step_up`).
const NON_DESTRUCTIVE: &[(&str, &str)] = &[("POST", "/hosts"), ("PATCH", "/hosts/{host}")];
const ROUTE_SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/hosts", "read"),
    ("GET", "/hosts/{host}", "read"),
    ("GET", "/groups", "read"),
    ("GET", "/tags", "read"),
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
        hosts::tags
    ),
    components(schemas(
        hosts::HostView,
        hosts::NewHost,
        hosts::HostPatch,
        hosts::Deleted,
        hosts::Count
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
    }

    fn migrations(&self) -> &'static [Migration] {
        MIGRATIONS
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["leyline.host"]
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
            "leyline.run.requested",
            "leyline.run.approval",
            "leyline.run.allowed",
            "leyline.run.refused",
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
