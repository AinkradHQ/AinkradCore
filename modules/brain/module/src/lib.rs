//! The Brain module (KAN-476, Phase 1 M1): Claude Code sessions to discovered rooms, reviewed by
//! the user, then stored. Control-plane tables (`brain_*`) live in the Core database and hold ids,
//! names, policy and rules only; every item's text lives in an encrypted file (`files`).
//!
//! Routes (`/modules/brain/v1`): status, import runs, review of proposed rooms, commit, rules and
//! rooms. See `docs/Plans/2026-11-11-brain-phase1-import-plan.md` §5.

use std::collections::HashSet;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};

use ainkrad_core::audit::{NewAuditEvent, OriginKind};
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use ainkrad_core_server::jobs::Job;
use ainkrad_core_server::module::{Module, ModuleSetting, Zeroizing};
use ainkrad_core_server::store::{Migration, audit, events};
use axum::routing::{get, patch, post, put};
use axum::{Extension, Json, Router};
use serde::Serialize;
use serde_json::Value;
use sqlx::SqliteConnection;
use utoipa::{OpenApi, ToSchema};

mod access;
mod ai;
mod ai_semantic;
mod answer;
mod backfill;
pub mod cipher;
mod claim;
pub mod clean;
pub mod collectors;
mod commit;
mod distil;
pub mod files;
mod imports;
mod inbox;
mod index;
pub mod key;
mod policy;
mod review;
pub mod rooms;
mod rules_api;
pub mod semantic;
mod suggest;
mod sync;
mod transcripts;
mod vectors;

pub const MODULE: &str = "brain";

pub static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "brain_0001",
        up: include_str!("../migrations/0001_brain_0001.up.sql"),
        down: include_str!("../migrations/0001_brain_0001.down.sql"),
    },
    Migration {
        version: 2,
        name: "brain_run_cursors",
        up: include_str!("../migrations/0002_brain_run_cursors.up.sql"),
        down: include_str!("../migrations/0002_brain_run_cursors.down.sql"),
    },
    Migration {
        version: 3,
        name: "brain_claims",
        up: include_str!("../migrations/0003_brain_claims.up.sql"),
        down: include_str!("../migrations/0003_brain_claims.down.sql"),
    },
    Migration {
        version: 4,
        name: "brain_ui",
        up: include_str!("../migrations/0004_brain_ui.up.sql"),
        down: include_str!("../migrations/0004_brain_ui.down.sql"),
    },
    Migration {
        version: 5,
        name: "brain_room_access",
        up: include_str!("../migrations/0005_brain_room_access.up.sql"),
        down: include_str!("../migrations/0005_brain_room_access.down.sql"),
    },
];

/// Employer and client rooms are discovered and reviewed in M1 but committed only after the import
/// isolation suite and the `room_backup` job exist (plan §12 answer 2). The isolation suite is in;
/// the backup job (C-10) is not, so this stays false and such proposals wait as `held`.
pub const ROOM_BACKUP_READY: bool = false;

const DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/imports/{run}/commit"),
    ("PATCH", "/rules/{id}"),
    ("POST", "/rooms/{room}/open"),
    ("POST", "/rooms/{room}/claims"),
    ("PATCH", "/rooms/{room}/policy"),
    ("PUT", "/rooms/{room}/access"),
];
const NON_DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/imports"),
    ("POST", "/imports/{run}/items"),
    ("POST", "/imports/{run}/collected"),
    ("PATCH", "/imports/{run}/proposals/{p}"),
    ("POST", "/imports/{run}/proposals/{p}/merge"),
    ("POST", "/imports/{run}/proposals/{p}/split"),
    ("POST", "/imports/{run}/proposals/{p}/refuse"),
    ("PATCH", "/imports/{run}/items"),
    ("POST", "/imports/{run}/regroup"),
    ("PUT", "/settings/{name}"),
    ("POST", "/rules"),
    ("POST", "/sync"),
    ("POST", "/rooms/{room}/distil"),
    ("POST", "/rooms/{room}/inbox/{id}"),
    ("PUT", "/sources/{id}"),
    ("POST", "/ai/rooms/{room}/propose"),
];
/// `module.brain.semantic.strength`: how many sorting suggestions the local model makes.
const SETTINGS: &[ModuleSetting] = &[
    ModuleSetting {
        name: "semantic.enabled",
        default: 1,
        min: 0,
        max: 1,
        description: "Sorting suggestions from the local model (1 on, 0 off). Only has an effect when this Core has the model. Off: nothing is embedded and Review shows semantic: off.",
    },
    ModuleSetting {
        name: "semantic.threads",
        default: 1,
        min: 1,
        max: 2,
        description: "Threads the local model may use (1 or 2). One keeps a small host responsive; two is faster. Applies from the next step.",
    },
    ModuleSetting {
        name: "semantic.max_tokens",
        default: 128,
        min: 128,
        max: 256,
        description: "Tokens of each item the local model reads: 128 (about twice as fast) or 256 (reads more of long items); a value between counts as 256. Applies from the next step; vectors made at the other size are kept.",
    },
    ModuleSetting {
        name: "semantic.strength",
        default: 1,
        min: 0,
        max: 2,
        description: "Sorting suggestions from the local model: 0 low (few, sure), 1 normal, 2 high (more, less sure). Applies from the next re-sort.",
    },
];
const ROUTE_SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/status", "read"),
    ("GET", "/imports/{run}", "read"),
    ("GET", "/rooms", "read"),
    ("GET", "/sync", "read"),
    ("GET", "/rooms/{room}/search", "read"),
    ("GET", "/rooms/{room}/policy", "read"),
    ("GET", "/rooms/{room}/distils", "read"),
    ("GET", "/rooms/{room}/inbox", "read"),
    ("GET", "/rooms/{room}/access", "read"),
    // Code Mode (E4): a session acts as its creator without `admin`, so these name the scopes a
    // creator holds. They answer only a session's own calls (`ai::session_of`).
    ("GET", "/ai/rooms", "read"),
    ("GET", "/ai/search", "read"),
    ("GET", "/ai/rooms/{room}/records/{id}", "read"),
    ("GET", "/ai/decisions", "read"),
    ("GET", "/ai/project-state", "read"),
    ("POST", "/ai/rooms/{room}/propose", "agent"),
];

#[derive(Default)]
struct Inner {
    app: OnceLock<App>,
    key: Mutex<Option<Zeroizing<[u8; 32]>>>,
    rooms: rooms::Rooms,
    syncing: AtomicBool,
    distilling: AtomicBool,
    /// The shared semantic service: model, vector store and background worker (`semantic::service`).
    sem: semantic::service::Service,
    /// Runs whose semantic step is queued or working.
    sem_running: Mutex<HashSet<String>>,
    #[cfg(feature = "test-support")]
    fetch: Mutex<Option<Arc<dyn collectors::Fetch>>>,
    #[cfg(feature = "test-support")]
    history: Mutex<Option<Arc<dyn collectors::RunnerHistory>>>,
}

/// The module. Cheap to clone: handlers reach it as an `Extension`.
#[derive(Default, Clone)]
pub struct Brain {
    inner: Arc<Inner>,
}

impl Brain {
    /// A build whose leases last `secs` seconds (A-3). Never compiled into a release binary.
    #[cfg(feature = "test-support")]
    pub fn with_lease_secs(secs: i64) -> Self {
        let b = Self::default();
        b.inner.rooms.set_lease_override(secs);
        b
    }

    /// A build whose semantic step uses `e` (the Core's loads the local model; tests pass a fake).
    pub fn with_embedder(e: Arc<dyn semantic::Embedder>) -> Self {
        let b = Self::default();
        b.set_embedder(e);
        b
    }

    pub fn set_embedder(&self, e: Arc<dyn semantic::Embedder>) {
        self.inner.sem.set_embedder(e);
    }

    /// Forgets the in-memory vectors, as a restart does (the stored ones stay).
    #[cfg(feature = "test-support")]
    pub fn drop_memory_vectors(&self) {
        *self
            .inner
            .sem
            .cache()
            .lock()
            .unwrap_or_else(|x| x.into_inner()) = semantic::VectorCache::default();
    }

    pub(crate) fn embedder(&self) -> Option<Arc<dyn semantic::Embedder>> {
        self.inner.sem.embedder()
    }

    /// The brain key, opened once and kept in this process's memory.
    pub(crate) async fn key(&self, app: &App) -> Result<Zeroizing<[u8; 32]>, ApiError> {
        self.key_for(app, None).await
    }

    /// As `key`, making it for `owner` (a device id) when it does not exist yet.
    pub(crate) async fn key_for(
        &self,
        app: &App,
        owner: Option<&str>,
    ) -> Result<Zeroizing<[u8; 32]>, ApiError> {
        if let Some(k) = self
            .inner
            .key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            return Ok(Zeroizing::new(**k));
        }
        let k = key::load_or_create(app, owner).await.map_err(|e| match e {
            key::KeyError::LockedMode0 => ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "brain_locked",
                "the brain is locked while secrets.mode is 0",
            ),
            key::KeyError::Missing => ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "brain_key_missing",
                "no brain key yet: start an import first",
            ),
            key::KeyError::Corrupt => ApiError::new(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "brain_key_corrupt",
                "the brain key did not open",
            ),
            key::KeyError::Unavailable => ApiError::new(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "secrets_unavailable",
                "this Core cannot open the brain key",
            ),
        })?;
        *self.inner.key.lock().unwrap_or_else(|e| e.into_inner()) = Some(Zeroizing::new(*k));
        Ok(k)
    }

    /// A build whose connection reads are `fetch` (canned data), never the Core's broker.
    #[cfg(feature = "test-support")]
    pub fn with_fetch(fetch: Arc<dyn collectors::Fetch>) -> Self {
        let b = Self::default();
        *b.inner.fetch.lock().unwrap_or_else(|e| e.into_inner()) = Some(fetch);
        b
    }

    /// A build whose runner history reads are `history` (canned chunks), never the Core's hub.
    #[cfg(feature = "test-support")]
    pub fn with_history(history: Arc<dyn collectors::RunnerHistory>) -> Self {
        let b = Self::default();
        *b.inner.history.lock().unwrap_or_else(|e| e.into_inner()) = Some(history);
        b
    }

    /// Where a runner's history is read: the Core's hub, or the test build's canned chunks.
    pub(crate) fn history_reader(&self, app: &App) -> Arc<dyn collectors::RunnerHistory> {
        #[cfg(feature = "test-support")]
        if let Some(h) = self
            .inner
            .history
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            return h.clone();
        }
        Arc::new(collectors::LiveHistory { app: app.clone() })
    }

    /// Where connection reads go: the Core's broker for the owner (the device's user, else the
    /// first user), or the test build's canned fetch.
    pub(crate) fn fetcher(&self, app: &App, device: Option<&str>) -> Arc<dyn collectors::Fetch> {
        #[cfg(feature = "test-support")]
        if let Some(f) = self
            .inner
            .fetch
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            return f.clone();
        }
        Arc::new(collectors::Live {
            app: app.clone(),
            user: 1,
            device: device.unwrap_or("brain").to_owned(),
        })
    }

    /// Moves every open distillation one step (the `brain_distil` job does this every minute).
    pub async fn distil_step(&self) -> Result<(), ApiError> {
        match self.inner.app.get() {
            Some(app) => distil::advance(app, self).await,
            None => Ok(()),
        }
    }

    pub fn rooms(&self) -> &rooms::Rooms {
        &self.inner.rooms
    }
}

/// An audit row and an event in the caller's transaction: ids, names and counts, never text.
pub(crate) async fn record(
    conn: &mut SqliteConnection,
    action: &str,
    details: Value,
    event: Option<(&str, Value)>,
) -> Result<(), sqlx::Error> {
    // E1: imports and distillation are their own origin; the root is whoever or whatever
    // started the request or job.
    let origin = match action {
        a if a.starts_with("brain.import.") => Some(OriginKind::BrainImport),
        a if a.starts_with("brain.distil.") => Some(OriginKind::BrainDistil),
        _ => None,
    };
    let row = NewAuditEvent {
        actor: BY,
        action: action.to_owned(),
        entity: None,
        details: details.to_string(),
    };
    match origin {
        Some(kind) => audit::append_as(conn, &row, audit::origin::derived(kind, None)).await?,
        None => audit::append(conn, &row).await?,
    };
    if let Some((kind, payload)) = event {
        events::append(conn, kind, &payload).await?;
    }
    Ok(())
}

pub(crate) fn code(status: u16, code: &'static str, why: impl Into<String>) -> ApiError {
    ApiError::new(
        axum::http::StatusCode::from_u16(status).expect("a status"),
        code,
        why,
    )
}

#[derive(Serialize, ToSchema)]
pub struct BrainStatus {
    pub present: bool,
    /// `ok`, `locked_mode0`, `missing` or `unavailable`.
    pub key: String,
    pub rooms: i64,
    pub runs: i64,
}

#[utoipa::path(get, path = "/status", operation_id = "brainStatus", tag = "brain",
    responses((status = 200, description = "Whether the Brain is here, and its key state", body = BrainStatus)))]
async fn status(axum::extract::State(app): axum::extract::State<App>) -> ApiResult<BrainStatus> {
    let rooms: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_rooms")
        .fetch_one(&app.pool)
        .await?;
    let runs: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_import_runs")
        .fetch_one(&app.pool)
        .await?;
    Ok(Json(BrainStatus {
        present: true,
        key: key::state(&app).await.as_str().to_owned(),
        rooms,
        runs,
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        status,
        imports::start,
        imports::items,
        imports::collected,
        imports::get,
        review::proposals,
        review::proposal_items,
        review::patch_proposal,
        review::merge,
        review::split,
        review::refuse,
        review::regroup,
        suggest::get,
        suggest::settings,
        suggest::put_setting,
        review::patch_items,
        commit::commit,
        rules_api::list,
        rules_api::create,
        rules_api::patch,
        rooms::list,
        rooms::open,
        sync::sources,
        sync::put_source,
        sync::status,
        sync::sync_now,
        index::search,
        claim::claim_route,
        inbox::list,
        inbox::decide,
        distil::start,
        distil::list,
        policy::get,
        policy::patch,
        access::get,
        access::put,
        ai::rooms,
        ai::search,
        ai::one,
        ai::decisions,
        ai::project_state,
        ai::propose
    ),
    components(schemas(
        BrainStatus,
        imports::StartRun,
        imports::RunId,
        imports::Batch,
        imports::ItemReply,
        imports::Replies,
        imports::Collected,
        imports::RunView,
        imports::Counts,
        review::ProposalCard,
        review::MergeSuggestion,
        review::Regrouped,
        suggest::SemanticView,
        suggest::DuplicateHint,
        suggest::RoomHint,
        suggest::MergeHint,
        suggest::BrainSetting,
        suggest::BrainSettingBody,
        review::ProposalPatch,
        review::ItemRow,
        review::ItemPage,
        review::MergeInto,
        review::SplitItems,
        review::ItemsPatch,
        review::Changed,
        review::RoomConfig,
        commit::CommitResult,
        commit::RoomMade,
        rules_api::RuleView,
        rules_api::NewRule,
        rules_api::RulePatch,
        rooms::RoomView,
        rooms::Opened,
        sync::SourceView,
        sync::SourcePut,
        sync::RunnerNow,
        sync::SyncRequest,
        sync::SyncResult,
        sync::Routed,
        sync::SyncStatus,
        sync::SyncSource,
        index::Hit,
        index::Hits,
        claim::ClaimRequest,
        claim::RoomClaim,
        distil::DistilView,
        inbox::InboxRecord,
        inbox::InboxPage,
        inbox::Decision,
        policy::PolicyView,
        policy::PolicyPatch,
        policy::PolicyAccount,
        access::RoomAccess,
        ai::AiRoom,
        ai::AiHit,
        ai::AiHits,
        ai::AiRecord,
        ai::AiRecords,
        ai::Propose,
        ai::Proposed
    ))
)]
struct Doc;

impl Module for Brain {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn routes(&self) -> Router<App> {
        Router::new()
            .route("/status", get(status))
            .route("/imports", post(imports::start))
            .route("/imports/{run}", get(imports::get))
            .route(
                "/imports/{run}/items",
                post(imports::items).patch(review::patch_items),
            )
            .route("/imports/{run}/collected", post(imports::collected))
            .route("/imports/{run}/proposals", get(review::proposals))
            .route(
                "/imports/{run}/proposals/{p}",
                patch(review::patch_proposal),
            )
            .route(
                "/imports/{run}/proposals/{p}/items",
                get(review::proposal_items),
            )
            .route("/imports/{run}/proposals/{p}/merge", post(review::merge))
            .route("/imports/{run}/proposals/{p}/split", post(review::split))
            .route("/imports/{run}/proposals/{p}/refuse", post(review::refuse))
            .route("/imports/{run}/regroup", post(review::regroup))
            .route("/imports/{run}/semantic", get(suggest::get))
            .route("/settings", get(suggest::settings))
            .route("/settings/{name}", put(suggest::put_setting))
            .route("/imports/{run}/commit", post(commit::commit))
            .route("/rules", get(rules_api::list).post(rules_api::create))
            .route("/rules/{id}", patch(rules_api::patch))
            .route("/rooms", get(rooms::list))
            .route("/rooms/{room}/open", post(rooms::open))
            .route("/rooms/{room}/search", get(index::search))
            .route("/rooms/{room}/claims", post(claim::claim_route))
            .route("/rooms/{room}/inbox", get(inbox::list))
            .route("/rooms/{room}/inbox/{id}", post(inbox::decide))
            .route("/rooms/{room}/distil", post(distil::start))
            .route("/rooms/{room}/distils", get(distil::list))
            .route(
                "/rooms/{room}/policy",
                get(policy::get).patch(policy::patch),
            )
            .route("/rooms/{room}/access", get(access::get).put(access::put))
            .route("/ai/rooms", get(ai::rooms))
            .route("/ai/search", get(ai::search))
            .route("/ai/rooms/{room}/records/{id}", get(ai::one))
            .route("/ai/decisions", get(ai::decisions))
            .route("/ai/project-state", get(ai::project_state))
            .route("/ai/rooms/{room}/propose", post(ai::propose))
            .route("/sources", get(sync::sources))
            .route("/sources/{id}", put(sync::put_source))
            .route("/sync", get(sync::status).post(sync::sync_now))
            .layer(Extension(self.clone()))
    }

    fn migrations(&self) -> &'static [Migration] {
        MIGRATIONS
    }

    fn event_kinds(&self) -> &'static [&'static str] {
        &["brain.import", "brain.room", "brain.alarm", "brain.inbox"]
    }

    /// Ids, names and counts only (Q-15), so a read-only device may see them.
    fn event_scope(&self, _kind: &str) -> &'static str {
        "read"
    }

    fn audit_actions(&self) -> &'static [&'static str] {
        &[
            "brain.import.started",
            "brain.import.discovered",
            "brain.import.regrouped",
            "brain.import.committed",
            "brain.room.created",
            "brain.room.opened",
            "brain.room.refused",
            "brain.semantic.run",
            "brain.room.centroid_backfilled",
            "brain.rule.created",
            "brain.rule.changed",
            "brain.source.changed",
            "brain.inbox.notice",
            "brain.session.claimed",
            "brain.session.refused",
            "brain.room.policy",
            "brain.inbox.decided",
            "brain.distil.queued",
            "brain.distil.done",
            "brain.distil.rejected",
            "brain.room.access",
            "brain.ai.proposed",
            "brain.ai.refused",
        ]
    }

    fn query_names(&self) -> &'static [&'static str] {
        &["q", "room", "mode"]
    }

    fn jobs(&self) -> Vec<Job> {
        vec![sync::job(self), index::job(self), distil::job(self)]
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
        serde_json::to_value(Doc::openapi()).expect("the brain contract serialises")
    }

    fn settings(&self) -> &'static [ModuleSetting] {
        SETTINGS
    }

    fn attach(&self, app: &App) {
        let _ = self.inner.app.set(app.clone());
        // A step that was queued when the Core stopped is queued again.
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let b = self.clone();
            rt.spawn(async move { b.resume_semantic().await });
        }
        #[cfg(feature = "semantic")]
        semantic::local::load_in_background(self);
    }
}

pub(crate) fn rand_id(prefix: &str) -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("the system random source");
    format!(
        "{prefix}{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}
