//! The Lore module (R1-01): the Core's store of Markdown notes. This story is the notes store and its
//! API only: notes create/read/list, daily note get-or-create, move to a project (checked through the
//! Projects store), trash and restore with a 30-day sweep, `lore.*` events and audit. R1-02 adds the save
//! path (3-way merge against the head), versions and restore, and the rename rewrite. The parser (R1-03), the index (links resolved by title, FTS rows) and backlinks (R1-04), attachments (R1-05) and export
//! (R1-06) come later; their tables already exist in `0001_lore`.
//!
//! Module off, the Core is unchanged: the tables are its own `lore_` namespace, no Core
//! migration, no Core crate names this module.

mod attachments;
mod backlinks;
mod embed;
mod export;
mod merge;
mod notes;
mod save;
mod search;
mod versions;

use std::sync::{Arc, OnceLock};

use ainkrad_core_server::api::App;
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Missed, Run, Schedule};
use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::Migration;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use serde_json::Value;
use utoipa::OpenApi;

pub use notes::{TRASH_DAYS, sweep};
pub use save::rebuild_fts;

pub const MODULE: &str = "lore";

impl Lore {
    /// A Lore whose search and embedding use `e` (the Core loads the local model; tests pass a fake).
    pub fn with_embedder(e: Arc<dyn ainkrad_embed::Embedder>) -> Self {
        let l = Self::default();
        embed::set(&l.emb, e);
        l
    }

    /// One embedding pass now, without the 10 s quiet time the job waits for. Returns notes embedded.
    pub async fn embed_now(&self, pool: &sqlx::SqlitePool) -> Result<usize, String> {
        embed::pass(pool, &self.emb, 0, 1000).await
    }

    /// As `embed_now`, leaving notes written less than `quiet` seconds ago (what the job does with 10).
    pub async fn embed_quiet(&self, pool: &sqlx::SqlitePool, quiet: i64) -> Result<usize, String> {
        embed::pass(pool, &self.emb, quiet, 1000).await
    }
}

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
    Migration {
        version: 3,
        name: "0003_lore_attachments",
        up: include_str!("../migrations/0003_lore_attachments.up.sql"),
        down: include_str!("../migrations/0003_lore_attachments.down.sql"),
    },
    Migration {
        version: 4,
        name: "0004_lore_index",
        up: include_str!("../migrations/0004_lore_index.up.sql"),
        down: include_str!("../migrations/0004_lore_index.down.sql"),
    },
    Migration {
        version: 5,
        name: "0005_lore_search",
        up: include_str!("../migrations/0005_lore_search.up.sql"),
        down: include_str!("../migrations/0005_lore_search.down.sql"),
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
    ("POST", "/attachments"),
];
// `/today` may create the note, so it keeps the module-wide `admin` scope.
const ROUTE_SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/notes", "read"),
    ("GET", "/notes/{note}", "read"),
    ("GET", "/notes/{note}/backlinks", "read"),
    ("GET", "/search", "read"),
    ("GET", "/notes/{note}/versions", "read"),
    ("GET", "/notes/{note}/versions/{version}", "read"),
    ("GET", "/attachments/{sha}", "read"),
    ("GET", "/export", "read"),
];

const BODY_LIMITS: &[(&str, &str, usize)] = &[("POST", "/attachments", attachments::BODY_MAX)];

/// The module. `app` is filled by `attach`, so the sweep job (which is handed no `App`) can work.
#[derive(Default, Clone)]
pub struct Lore {
    app: Arc<OnceLock<App>>,
    /// The shared local model once it is loaded (R2-02); `None` = search is FTS only, nothing is embedded.
    emb: embed::Slot,
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
        backlinks::list,
        search::search,
        versions::list,
        versions::get,
        versions::create,
        versions::restore,
        attachments::upload,
        attachments::get,
        export::export
    ),
    components(schemas(
        notes::NoteSummary,
        notes::NoteView,
        notes::NewNote,
        notes::NotePatch,
        save::SaveReq,
        save::SaveOut,
        backlinks::Backlink,
        search::SearchOut,
        search::Hit,
        search::Snippet,
        search::Span,
        versions::VersionSummary,
        versions::VersionView,
        versions::NewVersion,
        versions::RestoreReq,
        attachments::AttachmentView
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
            .route("/notes/{note}/backlinks", get(backlinks::list))
            .route(
                "/notes/{note}/versions",
                get(versions::list).post(versions::create),
            )
            .route("/notes/{note}/versions/{version}", get(versions::get))
            .route("/notes/{note}/restore", post(versions::restore))
            .route("/search", get(search::search))
            .route(
                "/attachments",
                post(attachments::upload).layer(DefaultBodyLimit::max(attachments::BODY_MAX)),
            )
            .route("/attachments/{sha}", get(attachments::get))
            .route("/export", get(export::export))
            .route("/today", get(notes::today))
            .layer(axum::Extension(self.clone()))
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
            "lore.attachment.created",
            "lore.attachment.purged",
        ]
    }

    fn query_names(&self) -> &'static [&'static str] {
        &[
            "state", "kind", "project", "day", "q", "tag", "limit", "note",
        ]
    }

    fn scope(&self) -> &'static str {
        "admin"
    }

    fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
        ROUTE_SCOPES
    }

    fn body_limits(&self) -> &'static [(&'static str, &'static str, usize)] {
        BODY_LIMITS
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
        let embed = Job::new(
            "embed",
            Schedule::Every(30),
            Arc::new(embed::Embed(self.app.clone(), self.emb.clone())),
        );
        vec![
            Job {
                missed: Missed::Skip,
                ..job
            },
            Job {
                missed: Missed::Skip,
                ..embed
            },
        ]
    }

    fn attach(&self, app: &App) {
        let _ = self.app.set(app.clone());
        #[cfg(feature = "semantic")]
        embed::load_in_background(&self.emb);
    }
}
