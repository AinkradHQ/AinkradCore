//! The Leyline module (Y1-01): the Core's address book of SSH hosts. This story is the store and
//! the API only: hosts, groups and tags, label addressing, the validation that keeps argv-injection
//! text out (API and table), `leyline.*` events and audit; and keys (Y1-02): generated or imported,
//! sealed in the Core's secret store, public data only in the API; and project attachments (Y1-03).
//! SSH itself runs on a runner (Y2); the command gate (`gate`, Y4-01), host terminals and host-key
//! trust (Y3-01), Mac-direct agent leases (`direct`, Y6-01), making a host a runner (Y8-01), and session
//! history, recording and replay (Y3-02) are here.
//!
//! Module off, the Core is unchanged: the tables are its own `leyline_` namespace, no Core
//! migration, no Core crate names this module.

mod address;
mod ai;
mod alerts;
mod attach;
mod cast;
mod commands;
mod direct;
mod exec;
mod files;
mod fleet;
pub mod gate;
mod health;
mod history;
pub mod hostkeys;
mod hosts;
mod keys;
mod makerunner;
mod policy;
mod ready;
/// Terminal recording; public so `benches/relay_tap.rs` can time the relay's tap.
pub mod record;
mod rsa_import;
mod scrub;
mod terminal;
mod valid;

use ainkrad_core_server::api::App;
use ainkrad_core_server::jobs::Job;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::push::Notification;
use ainkrad_core_server::store::Migration;
use ainkrad_core_server::store::events::StoredEvent;
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
        name: "0003_sessions",
        up: include_str!("../migrations/0003_sessions.up.sql"),
        down: include_str!("../migrations/0003_sessions.down.sql"),
    },
    Migration {
        version: 4,
        name: "0004_commands",
        up: include_str!("../migrations/0004_commands.up.sql"),
        down: include_str!("../migrations/0004_commands.down.sql"),
    },
    Migration {
        version: 5,
        name: "0005_health",
        up: include_str!("../migrations/0005_health.up.sql"),
        down: include_str!("../migrations/0005_health.down.sql"),
    },
    Migration {
        version: 6,
        name: "0006_alerts",
        up: include_str!("../migrations/0006_alerts.up.sql"),
        down: include_str!("../migrations/0006_alerts.down.sql"),
    },
    Migration {
        version: 7,
        name: "0007_fleet",
        up: include_str!("../migrations/0007_fleet.up.sql"),
        down: include_str!("../migrations/0007_fleet.down.sql"),
    },
    Migration {
        version: 8,
        name: "0008_recordings",
        up: include_str!("../migrations/0008_recordings.up.sql"),
        down: include_str!("../migrations/0008_recordings.down.sql"),
    },
    Migration {
        version: 9,
        name: "0009_direct",
        up: include_str!("../migrations/0009_direct.up.sql"),
        down: include_str!("../migrations/0009_direct.down.sql"),
    },
];

// D-4: only a key leaving the Core is danger (a Mac-direct lease hands one to a runner on the
// person's machine). Opening a shell, writing a file and installing the runner run code on a host:
// they need the app unlock and no per-action prompt. Everything else is a normal write.
const DESTRUCTIVE: &[(&str, &str)] = &[("POST", "/hosts/{host}/direct")];
const NEEDS_UNLOCK: &[(&str, &str)] = &[
    ("POST", "/hosts/{host}/terminals"),
    ("PUT", "/hosts/{host}/files/content"),
    ("POST", "/hosts/{host}/runner"),
];
// POST and PATCH need a step-up only for what widens an AI's reach or repoints a host (`allowed`,
// address, port, user, key, jump chain, runner): checked in the handler (`hosts::needs_step_up`).
const NON_DESTRUCTIVE: &[(&str, &str)] = &[
    ("DELETE", "/hosts/{host}"),
    ("DELETE", "/keys/{key}"),
    ("POST", "/keys/import"),
    ("POST", "/hosts/{host}/host-keys/replace"),
    ("PUT", "/hosts/{host}/recording"),
    ("POST", "/sessions/{session}/recording/resume"),
    ("POST", "/hosts"),
    ("PATCH", "/hosts/{host}"),
    ("POST", "/keys"),
    ("POST", "/commands"),
    ("PATCH", "/commands/{command}"),
    ("DELETE", "/commands/{command}"),
    ("POST", "/commands/{command}/run"),
    ("POST", "/fleet/runs"),
    ("POST", "/runs/{run}/cancel"),
    ("POST", "/hosts/{host}/host-keys/trust"),
    // Ending a lease only takes access away.
    ("POST", "/hosts/{host}/direct/revoke"),
    ("POST", "/sessions/{session}/recording/pause"),
    ("PUT", "/projects/{project}/hosts/{host}"),
    ("DELETE", "/projects/{project}/hosts/{host}"),
    ("POST", "/ai/hosts/{host}/exec"),
    ("POST", "/ai/commands/{command}/run"),
];
// The AI routes that reach a host ask a person through the gate itself (T10), never twice, and
// may wait for that person inside the call.
const SELF_APPROVED: &[(&str, &str)] = &[
    ("GET", "/ai/hosts/{host}/files"),
    ("GET", "/ai/hosts/{host}/file"),
    ("POST", "/ai/hosts/{host}/exec"),
    ("POST", "/ai/commands/{command}/run"),
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
    // Code Mode (Y7-01): a session acts as its creator without `admin`, so these name scopes a
    // creator holds. They answer only a session's own calls (`ai::session_only`).
    ("GET", "/ai/runs/{run}", "agent"),
    ("GET", "/ai/hosts/{host}/files", "agent"),
    ("GET", "/ai/hosts/{host}/file", "agent"),
    ("POST", "/ai/hosts/{host}/exec", "agent"),
    ("POST", "/ai/commands/{command}/run", "agent"),
    ("GET", "/hosts/{host}/host-keys", "read"),
    ("GET", "/hosts/{host}/health", "read"),
    // A file on a host is host content: the terminal scope; the gate decides again per call.
    ("GET", "/hosts/{host}/files", "terminal"),
    ("GET", "/hosts/{host}/files/content", "terminal"),
    ("PUT", "/hosts/{host}/files/content", "terminal"),
    // The terminal scope, as the Core's own terminal routes.
    ("POST", "/hosts/{host}/terminals", "terminal"),
    ("POST", "/hosts/{host}/direct", "terminal"),
    ("POST", "/hosts/{host}/direct/revoke", "terminal"),
    ("GET", "/hosts/{host}/sessions", "read"),
    ("GET", "/projects/{project}/sessions", "read"),
    // A recording is terminal content: the terminal scope, and a step-up in the handler.
    ("GET", "/sessions/{session}/recording", "terminal"),
    ("POST", "/sessions/{session}/recording/pause", "terminal"),
    ("POST", "/sessions/{session}/recording/resume", "terminal"),
    ("POST", "/hosts/{host}/runner", "terminal"),
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
        health::read,
        files::list,
        files::read,
        files::write,
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
        fleet::cancel,
        ai::exec,
        ai::get_run,
        ai::run_command,
        ai::list_files,
        ai::read_file,
        hostkeys::list,
        hostkeys::trust_route,
        hostkeys::replace_route,
        terminal::open,
        direct::lease,
        direct::revoke_route,
        history::host_sessions,
        history::project_sessions,
        history::set_recording,
        history::replay,
        history::pause,
        history::resume,
        makerunner::make
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
        fleet::Cancelled,
        ai::ExecRequest,
        ai::AiRunRequest,
        ai::FileList,
        ai::FileText,
        hostkeys::HostKeyView,
        hostkeys::Pick,
        terminal::NewSession,
        terminal::SessionView,
        direct::NewDirect,
        direct::DirectView,
        direct::DirectEnded,
        history::SessionRow,
        history::NewRecording,
        history::HostRecording,
        history::Paused,
        makerunner::Install,
        health::HealthView,
        health::HealthPoint,
        files::RemoteFile,
        files::Chunk,
        files::Put
    ))
)]
struct Doc;

impl Module for Leyline {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn attach(&self, app: &App) {
        history::attach(app);
        health::attach(app);
        // A host terminal's monitor lives in the process: rows left open by the last one are over.
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let app = app.clone();
            rt.spawn(async move {
                if terminal::close_orphans(&app).await.is_err() {
                    tracing::warn!("leyline sessions left open could not be closed");
                }
                // Mac-direct leases outlive the Core: their timers start again.
                if direct::resume(&app).await.is_err() {
                    tracing::warn!("leyline direct leases left open could not be watched");
                }
            });
        }
    }

    fn routes(&self) -> Router<App> {
        Router::new()
            .route("/hosts", get(hosts::list).post(hosts::create))
            .route(
                "/hosts/{host}",
                get(hosts::get).patch(hosts::patch).delete(hosts::remove),
            )
            .route("/hosts/{host}/health", get(health::read))
            .route("/hosts/{host}/files", get(files::list))
            .route(
                "/hosts/{host}/files/content",
                get(files::read).put(files::write),
            )
            .route("/hosts/{host}/host-keys", get(hostkeys::list))
            .route("/hosts/{host}/host-keys/trust", post(hostkeys::trust_route))
            .route(
                "/hosts/{host}/host-keys/replace",
                post(hostkeys::replace_route),
            )
            .route("/hosts/{host}/terminals", post(terminal::open))
            .route("/hosts/{host}/direct", post(direct::lease))
            .route("/hosts/{host}/direct/revoke", post(direct::revoke_route))
            .route("/hosts/{host}/sessions", get(history::host_sessions))
            .route("/hosts/{host}/recording", put(history::set_recording))
            .route(
                "/projects/{project}/sessions",
                get(history::project_sessions),
            )
            .route("/sessions/{session}/recording", get(history::replay))
            .route("/sessions/{session}/recording/pause", post(history::pause))
            .route(
                "/sessions/{session}/recording/resume",
                post(history::resume),
            )
            .route("/hosts/{host}/runner", post(makerunner::make))
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
            .route("/ai/hosts/{host}/exec", post(ai::exec))
            .route("/ai/runs/{run}", get(ai::get_run))
            .route("/ai/hosts/{host}/files", get(ai::list_files))
            .route("/ai/hosts/{host}/file", get(ai::read_file))
            .route("/ai/commands/{command}/run", post(ai::run_command))
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
            "leyline.session",
            "leyline.hostkey",
            "leyline.command",
            "leyline.alert",
            "leyline.run",
            "leyline.direct",
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
            "leyline.alert.opened",
            "leyline.alert.resolved",
            "leyline.hostkey.seen",
            "leyline.hostkey.changed",
            "leyline.hostkey.trusted",
            "leyline.hostkey.replaced",
            "leyline.session.opened",
            "leyline.session.ended",
            "leyline.direct.leased",
            "leyline.direct.revoked",
            "leyline.direct.expired",
            "leyline.direct.failed",
            "leyline.direct.dropped",
            "leyline.recording.on",
            "leyline.recording.off",
            "leyline.recording.replayed",
            "leyline.recording.paused",
            "leyline.recording.resumed",
            "leyline.recording.pruned",
            "leyline.run.requested",
            "leyline.run.approval",
            "leyline.run.allowed",
            "leyline.run.refused",
            "leyline.run.cancelled",
        ]
    }

    fn query_names(&self) -> &'static [&'static str] {
        &["group", "tag", "limit", "path"]
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

    fn needs_unlock(&self) -> &'static [(&'static str, &'static str)] {
        NEEDS_UNLOCK
    }

    fn non_destructive(&self) -> Option<&'static [(&'static str, &'static str)]> {
        Some(NON_DESTRUCTIVE)
    }

    fn self_approved(&self) -> &'static [(&'static str, &'static str)] {
        SELF_APPROVED
    }

    fn notification_kinds(&self) -> &'static [(&'static str, &'static str)] {
        alerts::KINDS
    }

    fn classify(&self, e: &StoredEvent) -> Option<Notification> {
        alerts::classify(e)
    }

    fn jobs(&self) -> Vec<Job> {
        let mut jobs = health::jobs();
        jobs.extend(history::jobs());
        jobs
    }

    fn openapi(&self) -> Value {
        serde_json::to_value(Doc::openapi()).expect("the leyline contract serialises")
    }
}
