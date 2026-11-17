//! The Design module (V1-01): the Core's store of design documents. This story is the doc store and its
//! API only: docs (design, system, mockup) create/read/change/archive, links to projects (checked
//! through the Projects store; related, not owned), `design.*` events and audit. The CRDT sync (V1-03)
//! and the asset library (V4-01) come later. Designs stay in the Core: nothing is exported to a repo.
//!
//! Module off, the Core is unchanged: the tables are its own `design_` namespace, no Core
//! migration, no Core crate names this module.

mod asset_links;
mod assets;
mod collections;
mod docs;
mod sniff;
mod svg;

use ainkrad_core_server::api::App;
use ainkrad_core_server::module::{Module, ModuleSetting};
use ainkrad_core_server::store::Migration;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use serde_json::Value;
use utoipa::OpenApi;

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
];
const ROUTE_SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/docs", "read"),
    ("GET", "/docs/{doc}", "read"),
    ("GET", "/assets", "read"),
    ("GET", "/assets/{sha}", "read"),
    ("GET", "/assets/{sha}/data", "read"),
    ("GET", "/collections", "read"),
    ("GET", "/collections/{id}", "read"),
];
// A signed upload is read whole to check its signature: the file cap plus nothing else.
const BODY_LIMITS: &[(&str, &str, usize)] = &[("POST", "/assets", assets::MAX_BODY)];

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
        collections::unlink
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
        collections::ItemBody
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
            .route(
                "/docs/{doc}/projects/{project}",
                put(docs::link).delete(docs::unlink),
            )
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
    }

    fn migrations(&self) -> &'static [Migration] {
        MIGRATIONS
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["design.doc", "design.asset", "design.collection"]
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
            "design.asset.created",
            "design.asset.changed",
            "design.asset.deleted",
            "design.asset.linked",
            "design.asset.unlinked",
            "design.collection.created",
            "design.collection.changed",
            "design.collection.deleted",
            "design.collection.linked",
            "design.collection.unlinked",
        ]
    }

    fn query_names(&self) -> &'static [&'static str] {
        &["state", "kind", "project", "name", "tag", "q", "collection"]
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
