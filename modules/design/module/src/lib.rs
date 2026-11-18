//! The Design module (V1-01): the Core's store of design documents. This story is the doc store and its
//! API only: docs (design, system, mockup) create/read/change/archive, links to projects (checked
//! through the Projects store; related, not owned), `design.*` events and audit. The CRDT sync (V1-03)
//! and the asset library (V4-01) come later. Designs stay in the Core: nothing is exported to a repo.
//!
//! Module off, the Core is unchanged: the tables are its own `design_` namespace, no Core
//! migration, no Core crate names this module.

mod apply;
mod asset_links;
mod assets;
mod checks;
mod collections;
mod docs;
mod fidelity;
mod package;
mod review;
mod sniff;
mod svg;
mod sync;
mod versions;
mod ws;

use ainkrad_core_server::api::App;
use ainkrad_core_server::module::{Module, ModuleSetting};
use ainkrad_core_server::store::Migration;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use serde_json::Value;
use std::sync::Arc;
use utoipa::OpenApi;

pub use checks::check_pending;
pub use fidelity::{FLAG_PERCENT, Measured, measure};
pub use package::import_dir;

pub const MODULE: &str = "design";

pub static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "0001_design",
        up: include_str!("../migrations/0001_design.up.sql"),
        down: include_str!("../migrations/0001_design.down.sql"),
    },
    Migration {
        version: 2,
        name: "0002_design_assets",
        up: include_str!("../migrations/0002_design_assets.up.sql"),
        down: include_str!("../migrations/0002_design_assets.down.sql"),
    },
    Migration {
        version: 3,
        name: "0003_design_mockups",
        up: include_str!("../migrations/0003_design_mockups.up.sql"),
        down: include_str!("../migrations/0003_design_mockups.down.sql"),
    },
    Migration {
        version: 4,
        name: "0004_design_review",
        up: include_str!("../migrations/0004_design_review.up.sql"),
        down: include_str!("../migrations/0004_design_review.down.sql"),
    },
    Migration {
        version: 5,
        name: "0005_design_check_attempts",
        up: include_str!("../migrations/0005_design_check_attempts.up.sql"),
        down: include_str!("../migrations/0005_design_check_attempts.down.sql"),
    },
];

/// T8: 25 MB per asset, 2 GB for the library; both can only be lowered by the person (the upload
/// body limit below is the hard ceiling).
const SETTINGS: &[ModuleSetting] = &[
    ModuleSetting {
        name: "asset.max_bytes",
        default: assets::MAX_BODY as i64,
        min: 1,
        max: assets::MAX_BODY as i64,
        description: "The largest file one library asset may be.",
    },
    ModuleSetting {
        name: "library.max_bytes",
        default: 2 * 1024 * 1024 * 1024,
        min: 1,
        max: 64 * 1024 * 1024 * 1024,
        description: "The most bytes the asset library holds in all.",
    },
];

// Archiving hides a design from every list, so it needs a step-up like archiving a project.
// Deleting an asset or a collection is as final as archiving a design.
const DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/docs/{doc}/archive"),
    ("DELETE", "/assets/{sha}"),
    ("DELETE", "/collections/{id}"),
];
const NON_DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/docs"),
    ("PATCH", "/docs/{doc}"),
    ("POST", "/docs/{doc}/take-over"),
    ("POST", "/docs/{doc}/resume"),
    ("PUT", "/docs/{doc}/projects/{project}"),
    ("DELETE", "/docs/{doc}/projects/{project}"),
    ("POST", "/assets"),
    ("PATCH", "/assets/{sha}"),
    ("PUT", "/assets/{sha}/projects/{project}"),
    ("DELETE", "/assets/{sha}/projects/{project}"),
    ("POST", "/collections"),
    ("PATCH", "/collections/{id}"),
    ("PUT", "/collections/{id}/items/{sha}"),
    ("DELETE", "/collections/{id}/items/{sha}"),
    ("PUT", "/collections/{id}/projects/{project}"),
    ("DELETE", "/collections/{id}/projects/{project}"),
    ("PUT", "/docs/{doc}/package/files"),
    ("POST", "/docs/{doc}/package/manifest"),
    ("POST", "/docs/{doc}/apply"),
    ("POST", "/docs/{doc}/versions"),
    ("POST", "/docs/{doc}/versions/{version}/restore"),
    ("POST", "/docs/{doc}/comments"),
    ("PUT", "/docs/{doc}/comments/{comment}/resolved"),
    ("PUT", "/docs/{doc}/screens/{screen}/approval"),
    ("DELETE", "/docs/{doc}/screens/{screen}/approval"),
    ("PUT", "/docs/{doc}/ai-paused"),
];
const ROUTE_SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/docs", "read"),
    ("GET", "/docs/{doc}", "read"),
    ("GET", "/assets", "read"),
    ("GET", "/assets/{sha}", "read"),
    ("GET", "/assets/{sha}/data", "read"),
    ("GET", "/collections", "read"),
    ("GET", "/collections/{id}", "read"),
    ("GET", "/docs/{doc}/package", "read"),
    ("GET", "/docs/{doc}/package/files", "read"),
    ("GET", "/docs/{doc}/versions", "read"),
    ("GET", "/docs/{doc}/comments", "read"),
    ("GET", "/docs/{doc}/approvals", "read"),
];
// A signed upload is read whole to check its signature: the file cap plus nothing else.
const BODY_LIMITS: &[(&str, &str, usize)] = &[
    ("POST", "/assets", assets::MAX_BODY),
    ("PUT", "/docs/{doc}/package/files", assets::MAX_BODY),
];

/// The live documents (`sync`) live in the module value, so each Core has its own.
#[derive(Default, Clone)]
pub struct Design {
    registry: Arc<sync::Registry>,
}

impl Design {
    /// Tighter limits than the defaults, for tests of compaction, unloading and rate caps.
    pub fn with_limits(limits: sync::Limits) -> Self {
        Self {
            registry: Arc::new(sync::Registry::with_limits(limits)),
        }
    }

    /// How many documents are loaded right now.
    pub async fn loaded(&self) -> usize {
        self.registry.loaded().await
    }
}

pub use sync::Limits;

#[derive(OpenApi)]
#[openapi(
    paths(
        docs::list,
        docs::create,
        docs::get,
        docs::patch,
        docs::archive,
        docs::take_over,
        docs::resume,
        docs::link,
        docs::unlink,
        assets::upload,
        assets::list,
        assets::get,
        assets::data,
        assets::patch,
        assets::delete,
        asset_links::link,
        asset_links::unlink,
        collections::list,
        collections::create,
        collections::get,
        collections::patch,
        collections::delete,
        collections::put_item,
        collections::remove_item,
        collections::link,
        collections::unlink,
        package::put,
        package::file,
        package::get,
        package::seal,
        ws::sync,
        apply::apply,
        versions::list,
        versions::create,
        versions::restore,
        review::comments,
        review::add_comment,
        review::resolve,
        review::approvals,
        review::approve,
        review::withdraw,
        review::ai_paused
    ),
    components(schemas(
        docs::DocView,
        docs::NewDoc,
        docs::DocPatch,
        assets::AssetView,
        assets::AssetPatch,
        collections::CollectionView,
        collections::Item,
        collections::NewCollection,
        collections::CollectionPatch,
        collections::ItemBody,
        package::FileView,
        package::PackageView,
        apply::ApplyReq,
        apply::ApplyOut,
        apply::LintDelta,
        apply::FindingView,
        versions::VersionView,
        versions::NewVersion,
        versions::Restored,
        review::CommentView,
        review::NewComment,
        review::Resolve,
        review::ApprovalView,
        review::Paused
    ))
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
            .route("/docs/{doc}/take-over", post(docs::take_over))
            .route("/docs/{doc}/resume", post(docs::resume))
            .route("/docs/{doc}/sync", get(ws::sync))
            .route(
                "/docs/{doc}/projects/{project}",
                put(docs::link).delete(docs::unlink),
            )
            .route("/docs/{doc}/apply", post(apply::apply))
            .route(
                "/docs/{doc}/versions",
                get(versions::list).post(versions::create),
            )
            .route(
                "/docs/{doc}/versions/{version}/restore",
                post(versions::restore),
            )
            .route(
                "/docs/{doc}/comments",
                get(review::comments).post(review::add_comment),
            )
            .route(
                "/docs/{doc}/comments/{comment}/resolved",
                put(review::resolve),
            )
            .route("/docs/{doc}/approvals", get(review::approvals))
            .route(
                "/docs/{doc}/screens/{screen}/approval",
                put(review::approve).delete(review::withdraw),
            )
            .route("/docs/{doc}/ai-paused", put(review::ai_paused))
            .route("/docs/{doc}/package", get(package::get))
            .route(
                "/docs/{doc}/package/files",
                get(package::file)
                    .put(package::put)
                    .layer(DefaultBodyLimit::max(assets::MAX_BODY)),
            )
            .route("/docs/{doc}/package/manifest", post(package::seal))
            .route(
                "/assets",
                get(assets::list)
                    .post(assets::upload)
                    .layer(DefaultBodyLimit::max(assets::MAX_BODY)),
            )
            .route(
                "/assets/{sha}",
                get(assets::get).patch(assets::patch).delete(assets::delete),
            )
            .route("/assets/{sha}/data", get(assets::data))
            .route(
                "/assets/{sha}/projects/{project}",
                put(asset_links::link).delete(asset_links::unlink),
            )
            .route(
                "/collections",
                get(collections::list).post(collections::create),
            )
            .route(
                "/collections/{id}",
                get(collections::get)
                    .patch(collections::patch)
                    .delete(collections::delete),
            )
            .route(
                "/collections/{id}/items/{sha}",
                put(collections::put_item).delete(collections::remove_item),
            )
            .route(
                "/collections/{id}/projects/{project}",
                put(collections::link).delete(collections::unlink),
            )
            .layer(axum::Extension(self.registry.clone()))
    }

    fn migrations(&self) -> &'static [Migration] {
        MIGRATIONS
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &[
            "design.doc",
            "design.asset",
            "design.collection",
            "design.version",
            "design.comment",
            "design.approval",
        ]
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
            "design.doc.taken_over",
            "design.doc.resumed",
            "design.doc.linked",
            "design.doc.unlinked",
            "design.asset.created",
            "design.asset.changed",
            "design.asset.deleted",
            "design.asset.checked",
            "design.asset.linked",
            "design.asset.unlinked",
            "design.collection.created",
            "design.collection.changed",
            "design.collection.deleted",
            "design.collection.linked",
            "design.collection.unlinked",
            "design.version.created",
            "design.version.restored",
            "design.comment.created",
            "design.comment.resolved",
            "design.comment.reopened",
            "design.approval.approved",
            "design.approval.withdrawn",
        ]
    }

    /// V6-01: fonts and Icon Composer zips go to a runner's sandboxed helper (`checks`).
    fn jobs(&self) -> Vec<ainkrad_core_server::jobs::Job> {
        vec![checks::job()]
    }

    fn attach(&self, app: &App) {
        let _ = checks::APP.set(app.clone());
    }

    fn query_names(&self) -> &'static [&'static str] {
        &[
            "state",
            "kind",
            "project",
            "name",
            "tag",
            "q",
            "collection",
            "path",
            "screen",
        ]
    }

    fn scope(&self) -> &'static str {
        "admin"
    }

    fn route_scopes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
        ROUTE_SCOPES
    }

    fn settings(&self) -> &'static [ModuleSetting] {
        SETTINGS
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
        serde_json::to_value(Doc::openapi()).expect("the design contract serialises")
    }
}
