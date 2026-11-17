//! The Lore module (R1-01): the Core's store of Markdown notes. This story is the notes store and its
//! API only: notes create/read/list, daily note get-or-create, move to a project (checked through the
//! Projects store), trash and restore with a 30-day sweep, `lore.*` events and audit. R1-02 adds the save
//! path (3-way merge against the head), versions and restore, and the rename rewrite. The parser (R1-03), index and backlinks (R1-04), attachments (R1-05) and export
//! (R1-06) come later; their tables already exist in `0001_lore`.
//!
//! Module off, the Core is unchanged: the tables are its own `lore_` namespace, no Core
//! migration, no Core crate names this module.

mod merge;
mod notes;
mod save;
mod versions;

use std::sync::{Arc, OnceLock};

use ainkrad_core_server::api::App;
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Missed, Run, Schedule};
use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::Migration;
use axum::Router;
use axum::routing::{get, post, put};
use serde_json::Value;
use utoipa::OpenApi;

pub use notes::{TRASH_DAYS, sweep};

pub const MODULE: &str = "lore";

pub static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "0001_lore",
        up: include_str!("../migrations/0001_lore.up.sql"),
        down: include_str!("../migrations/0001_lore.down.sql"),
    },
    Migration {
        version: 2,
        name: "0002_lore_save",
        up: include_str!("../migrations/0002_lore_save.up.sql"),
        down: include_str!("../migrations/0002_lore_save.down.sql"),
    },
];

// The trash is reversible (every row is kept for 30 days), so no write needs a step-up.
const DESTRUCTIVE: &[(&str, &str)] = &[];
const NON_DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/notes"),
    ("PATCH", "/notes/{note}"),
    ("PUT", "/notes/{note}/text"),
    ("POST", "/notes/{note}/versions"),
    ("POST", "/notes/{note}/restore"),
];
// `/today` may create the note, so it keeps the module-wide `admin` scope.
const ROUTE_SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/notes", "read"),
    ("GET", "/notes/{note}", "read"),
    ("GET", "/notes/{note}/versions", "read"),
    ("GET", "/notes/{note}/versions/{version}", "read"),
];

/// The module. `app` is filled by `attach`, so the sweep job (which is handed no `App`) can work.
#[derive(Default, Clone)]
pub struct Lore {
    app: Arc<OnceLock<App>>,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        notes::list,
        notes::create,
        notes::today,
        notes::get,
        notes::patch,
        save::put_text,
        versions::list,
        versions::get,
        versions::create,
        versions::restore
    ),
    components(schemas(
        notes::NoteSummary,
        notes::NoteView,
        notes::NewNote,
        notes::NotePatch,
        save::SaveReq,
        save::SaveOut,
        versions::VersionSummary,
        versions::VersionView,
        versions::NewVersion,
        versions::RestoreReq
    ))
)]
struct Doc;

struct Sweep(Arc<OnceLock<App>>);

impl JobHandler for Sweep {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let app = self.0.get().ok_or("the lore module is not attached")?;
            if sweep(&app.pool).await.map_err(|e| e.to_string())? == 0 {
                run.idle();
            }
            Ok(())
        })
    }
}

impl Module for Lore {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn routes(&self) -> Router<App> {
        Router::new()
            .route("/notes", get(notes::list).post(notes::create))
            .route("/notes/{note}", get(notes::get).patch(notes::patch))
            .route("/notes/{note}/text", put(save::put_text))
            .route(
                "/notes/{note}/versions",
                get(versions::list).post(versions::create),
            )
            .route("/notes/{note}/versions/{version}", get(versions::get))
            .route("/notes/{note}/restore", post(versions::restore))
            .route("/today", get(notes::today))
    }

    fn migrations(&self) -> &'static [Migration] {
        MIGRATIONS
    }

    /// Ids, revisions and the origin only, never a title or text.
    fn event_kinds(&self) -> &'static [&'static str] {
        &["lore.note.changed", "lore.note.trashed", "lore.note.purged"]
    }

    fn event_scope(&self, _kind: &str) -> &'static str {
        "read"
    }

    fn audit_actions(&self) -> &'static [&'static str] {
        &[
            "lore.note.created",
            "lore.note.moved",
            "lore.note.trashed",
            "lore.note.restored",
            "lore.note.purged",
            "lore.note.conflict",
            "lore.note.relinked",
            "lore.note.version",
            "lore.note.reverted",
        ]
    }

    fn query_names(&self) -> &'static [&'static str] {
        &["state", "kind", "project", "day"]
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
        serde_json::to_value(Doc::openapi()).expect("the lore contract serialises")
    }

    fn jobs(&self) -> Vec<Job> {
        let job = Job::new(
            "sweep",
            Schedule::Every(3600),
            Arc::new(Sweep(self.app.clone())),
        );
        vec![Job {
            missed: Missed::Skip,
            ..job
        }]
    }

    fn attach(&self, app: &App) {
        let _ = self.app.set(app.clone());
    }
}
