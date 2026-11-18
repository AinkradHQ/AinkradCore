//! The Leyline module (Y1-01): the Core's address book of SSH hosts. This story is the store and
//! the API only: hosts, groups and tags, label addressing, the validation that keeps argv-injection
//! text out (API and table), `leyline.*` events and audit; and keys (Y1-02): generated or imported,
//! sealed in the Core's secret store, public data only in the API; and project attachments (Y1-03).
//! SSH itself (Y2+) comes later; the command gate (`gate`, Y4-01) is here.
//!
//! Module off, the Core is unchanged: the tables are its own `leyline_` namespace, no Core
//! migration, no Core crate names this module.

mod address;
mod attach;
mod commands;
mod exec;
mod fleet;
pub mod gate;
mod hosts;
mod keys;
mod policy;
mod valid;

use ainkrad_core_server::api::App;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::Migration;
use axum::Router;
use axum::routing::{get, post, put};
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
    Migration {
        version: 3,
        name: "0003_commands",
        up: include_str!("../migrations/0003_commands.up.sql"),
        down: include_str!("../migrations/0003_commands.down.sql"),
    },
    Migration {
        version: 4,
        name: "0004_fleet",
        up: include_str!("../migrations/0004_fleet.up.sql"),
        down: include_str!("../migrations/0004_fleet.down.sql"),
    },
];

// A key write is a secret write: importing needs the step-up like the Core's own secret writes.
// Generating does not (the Core makes the key; nothing of the caller's is stored).
const DESTRUCTIVE: &[(&str, &str)] = &[
    ("DELETE", "/hosts/{host}"),
    ("DELETE", "/keys/{key}"),
    ("POST", "/keys/import"),
];
// POST and PATCH need a step-up only for what widens an AI's reach or repoints a host (`allowed`,
// address, port, user, key, jump chain, runner): checked in the handler (`hosts::needs_step_up`).
const NON_DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/hosts"),
    ("PATCH", "/hosts/{host}"),
    ("POST", "/keys"),
    ("POST", "/commands"),
    ("PATCH", "/commands/{command}"),
    ("DELETE", "/commands/{command}"),
    ("POST", "/commands/{command}/run"),
    ("POST", "/fleet/runs"),
    ("POST", "/runs/{run}/cancel"),
    ("PUT", "/projects/{project}/hosts/{host}"),
    ("DELETE", "/projects/{project}/hosts/{host}"),
];
const ROUTE_SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/hosts", "read"),
    ("GET", "/hosts/{host}", "read"),
    ("GET", "/groups", "read"),
    ("GET", "/tags", "read"),
    ("GET", "/keys", "read"),
    ("GET", "/keys/{key}", "read"),
    ("GET", "/projects/{project}/hosts", "read"),
    ("GET", "/commands", "read"),
    ("GET", "/commands/{command}", "read"),
    ("GET", "/runs/{run}", "admin"),
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
        keys::remove,
        attach::list,
        attach::attach,
        attach::detach,
        commands::list,
        commands::create,
        commands::get,
        commands::patch,
        commands::remove,
        commands::run,
        commands::get_run,
        fleet::start,
        fleet::cancel
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
        keys::KeyDeleted,
        attach::ProjectHost,
        attach::HostProject,
        attach::Role,
        attach::Detached,
        commands::CommandView,
        commands::NewCommand,
        commands::CommandPatch,
        commands::CommandDeleted,
        commands::Scope,
        commands::RunRequest,
        commands::RunStarted,
        commands::RunView,
        commands::RunHost,
        fleet::FleetRequest,
        fleet::FleetStarted,
        fleet::Cancelled
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
            .route("/commands", get(commands::list).post(commands::create))
            .route(
                "/commands/{command}",
                get(commands::get)
                    .patch(commands::patch)
                    .delete(commands::remove),
            )
            .route("/commands/{command}/run", post(commands::run))
            .route("/runs/{run}", get(commands::get_run))
            .route("/runs/{run}/cancel", post(fleet::cancel))
            .route("/fleet/runs", post(fleet::start))
            .route("/projects/{project}/hosts", get(attach::list))
            .route(
                "/projects/{project}/hosts/{host}",
                put(attach::attach).delete(attach::detach),
            )
    }

    fn migrations(&self) -> &'static [Migration] {
        MIGRATIONS
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &[
            "leyline.host",
            "leyline.key",
            "leyline.command",
            "leyline.run",
        ]
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
            "leyline.host.attached",
            "leyline.host.detached",
            "leyline.key.created",
            "leyline.key.deleted",
            "leyline.command.created",
            "leyline.command.changed",
            "leyline.command.deleted",
            "leyline.run.requested",
            "leyline.run.approval",
            "leyline.run.allowed",
            "leyline.run.refused",
            "leyline.run.cancelled",
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
