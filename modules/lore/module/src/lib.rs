//! The Lore module (R1-01): the Core's store of Markdown notes. This story is the notes store and its
//! API only: notes create/read/list, daily note get-or-create, move to a project (checked through the
//! Projects store), trash and restore with a 30-day sweep, `lore.*` events and audit. R1-02 adds the save
//! path (3-way merge against the head), versions and restore, and the rename rewrite. The parser (R1-03), the index (links resolved by title, FTS rows) and backlinks (R1-04), attachments (R1-05) and export
//! (R1-06) come later; their tables already exist in `0001_lore`.
//!
//! Module off, the Core is unchanged: the tables are its own `lore_` namespace, no Core
//! migration, no Core crate names this module.

mod ai;
mod attachments;
mod backlinks;
mod embed;
mod export;
mod import;
mod import_commit;
mod import_read;
mod import_run;
mod import_stage;
mod merge;
mod notes;
mod save;
mod search;
mod session_docs;
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

pub use import_commit::sweep as import_sweep;
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

    /// A Lore that reads repo copies from `root` (tests); the Core uses `mirrors/` next to its database.
    pub fn with_mirror_root(mut self, root: std::path::PathBuf) -> Self {
        self.mirror_root = Some(root);
        self
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
    Migration {
        version: 6,
        name: "0006_lore_import",
        up: include_str!("../migrations/0006_lore_import.up.sql"),
        down: include_str!("../migrations/0006_lore_import.down.sql"),
    },
    Migration {
        version: 7,
        name: "0007_lore_feed_editor",
        up: include_str!("../migrations/0007_lore_feed_editor.up.sql"),
        down: include_str!("../migrations/0007_lore_feed_editor.down.sql"),
    },
    Migration {
        version: 8,
        name: "0008_lore_session_docs_e10",
        up: include_str!("../migrations/0008_lore_session_docs_e10.up.sql"),
        down: include_str!("../migrations/0008_lore_session_docs_e10.down.sql"),
    },
];

// The trash is reversible (every row is kept for 30 days), so no person's write needs a step-up. The one
// AI route that removes a note from view is destructive: Code Mode reaches it only as `risky`, waiting
// for a person's approval (R5-01).
const DESTRUCTIVE: &[(&str, &str)] = &[("POST", "/ai/notes/{note}/trash")];
const NON_DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/notes"),
    ("POST", "/ai/notes"),
    ("POST", "/ai/notes/{note}/append"),
    ("POST", "/ai/notes/{note}/edit"),
    ("PATCH", "/notes/{note}"),
    ("PUT", "/notes/{note}/text"),
    ("POST", "/notes/{note}/versions"),
    ("POST", "/notes/{note}/restore"),
    ("POST", "/attachments"),
    ("POST", "/imports"),
    ("POST", "/imports/{run}/items"),
    ("PATCH", "/imports/{run}/items"),
    ("POST", "/imports/{run}/zip"),
    ("POST", "/imports/{run}/finish"),
    ("POST", "/imports/{run}/commit"),
    ("POST", "/imports/{run}/undo"),
    ("POST", "/imports/{run}/abandon"),
];
// `/today` may create the note, so it keeps the module-wide `admin` scope.
const ROUTE_SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/notes", "read"),
    ("GET", "/notes/{note}", "read"),
    ("GET", "/notes/{note}/backlinks", "read"),
    ("GET", "/search", "read"),
    ("GET", "/tags", "read"),
    ("GET", "/session-docs", "read"),
    ("GET", "/notes/{note}/versions", "read"),
    ("GET", "/notes/{note}/versions/{version}", "read"),
    ("GET", "/attachments/{sha}", "read"),
    ("GET", "/imports", "read"),
    ("GET", "/imports/{run}", "read"),
    ("GET", "/imports/{run}/items", "read"),
    ("GET", "/export", "read"),
    // What AI sessions reach through Code Mode (R5-01); the handlers answer only the dispatcher's caller.
    ("GET", "/ai/search", "read"),
    ("GET", "/ai/notes/{note}", "read"),
    ("GET", "/ai/notes/{note}/links", "read"),
    ("POST", "/ai/notes", "agent"),
    ("POST", "/ai/notes/{note}/append", "agent"),
    ("POST", "/ai/notes/{note}/edit", "agent"),
    ("POST", "/ai/notes/{note}/trash", "agent"),
];

const BODY_LIMITS: &[(&str, &str, usize)] = &[
    ("POST", "/attachments", attachments::BODY_MAX),
    ("POST", "/imports/{run}/zip", import::ZIP_BODY_MAX),
];

/// The module. `app` is filled by `attach`, so the sweep job (which is handed no `App`) can work.
#[derive(Default, Clone)]
pub struct Lore {
    app: Arc<OnceLock<App>>,
    /// The shared local model once it is loaded (R2-02); `None` = search is FTS only, nothing is embedded.
    emb: embed::Slot,
    /// Where the Core keeps its repo copies; `None` = `mirrors/` next to the database (tests set another).
    mirror_root: Option<std::path::PathBuf>,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        notes::list,
        notes::tags,
        session_docs::list,
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
        import::create,
        import::list,
        import::get,
        import::add_items,
        import::add_zip,
        import::finish,
        import::items,
        import::patch_items,
        import::abandon,
        import_commit::commit,
        import_commit::undo,
        export::export,
        ai::search,
        ai::read,
        ai::links,
        ai::create,
        ai::append,
        ai::edit,
        ai::trash
    ),
    components(schemas(
        notes::NoteSummary,
        notes::TagCount,
        session_docs::SessionDoc,
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
        attachments::AttachmentView,
        import::RunView,
        import::NewRun,
        import::UploadItem,
        import::UploadBatch,
        import::ItemSummary,
        import::ItemsPatch,
        ai::LoreAiHit,
        ai::LoreAiHits,
        ai::LoreAiNote,
        ai::LoreAiLink,
        ai::LoreAiLinks,
        ai::LoreAiWrote,
        ai::LoreAiText,
        ai::LoreAiEdit,
        ai::LoreAiTrashed
    ))
)]
struct Doc;

struct Sweep(Arc<OnceLock<App>>);

impl JobHandler for Sweep {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let app = self.0.get().ok_or("the lore module is not attached")?;
            let n = sweep(&app.pool).await.map_err(|e| e.to_string())?
                + import_commit::sweep(&app.pool)
                    .await
                    .map_err(|e| e.to_string())?;
            if n == 0 {
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
            .route("/tags", get(notes::tags))
            .route("/session-docs", get(session_docs::list))
            .route(
                "/attachments",
                post(attachments::upload).layer(DefaultBodyLimit::max(attachments::BODY_MAX)),
            )
            .route("/attachments/{sha}", get(attachments::get))
            .route("/imports", get(import::list).post(import::create))
            .route("/imports/{run}", get(import::get))
            .route(
                "/imports/{run}/items",
                get(import::items)
                    .post(import::add_items)
                    .patch(import::patch_items),
            )
            .route(
                "/imports/{run}/zip",
                post(import::add_zip).layer(DefaultBodyLimit::max(import::ZIP_BODY_MAX)),
            )
            .route("/imports/{run}/finish", post(import::finish))
            .route("/imports/{run}/commit", post(import_commit::commit))
            .route("/imports/{run}/undo", post(import_commit::undo))
            .route("/imports/{run}/abandon", post(import::abandon))
            .route("/export", get(export::export))
            .route("/today", get(notes::today))
            .route("/ai/search", get(ai::search))
            .route("/ai/notes", post(ai::create))
            .route("/ai/notes/{note}", get(ai::read))
            .route("/ai/notes/{note}/links", get(ai::links))
            .route("/ai/notes/{note}/append", post(ai::append))
            .route("/ai/notes/{note}/edit", post(ai::edit))
            .route("/ai/notes/{note}/trash", post(ai::trash))
            .layer(axum::Extension(self.clone()))
    }

    fn migrations(&self) -> &'static [Migration] {
        MIGRATIONS
    }

    /// Ids, revisions and the origin only, never a title or text.
    fn event_kinds(&self) -> &'static [&'static str] {
        &[
            "lore.note.changed",
            "lore.note.trashed",
            "lore.note.purged",
            "lore.import",
        ]
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
            "lore.import.created",
            "lore.import.committed",
            "lore.import.undone",
            "lore.import.abandoned",
        ]
    }

    fn query_names(&self) -> &'static [&'static str] {
        &[
            "state", "kind", "project", "day", "q", "tag", "limit", "note", "flag", "after",
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
        let docs = Job::new(
            "session_docs",
            Schedule::Every(15),
            Arc::new(session_docs::DocsJob(self.app.clone())),
        );
        vec![
            Job {
                missed: Missed::Skip,
                ..docs
            },
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
