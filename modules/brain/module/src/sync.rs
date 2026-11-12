//! Incremental sync (E5-1, E7-2 Core half): per-source cursors, the Core's own collector of AI
//! session transcripts, the schedule, "Sync now", and the rule that an item matching a room the
//! user already accepted goes straight into it while a new room or an Unsorted item waits for
//! review and raises one notice (`brain.inbox`).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::store::{agents, begin_write};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use brain_model::group::UNSORTED;
use brain_model::item::{Item, MAX_BATCH_BYTES, SourceKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use utoipa::ToSchema;

use crate::commit::{close_run, commit_room};
use crate::imports::{mark_done, run_state, stage_items, staging, start_run};
use crate::review::{mixed, room_id};
use crate::transcripts::{self, Meta};
use crate::{Brain, ROOM_BACKUP_READY, record};

/// The one source the Core collects itself.
pub const CORE_SOURCE: &str = "core_transcript";
/// How often the `brain_sync` job runs.
pub const SYNC_EVERY_SECS: u64 = 3600;
/// AI sessions read per sync; the rest wait for the next one (the cursor is per session).
const MAX_SESSIONS: usize = 200;
const MAX_ITEMS: usize = 500;

/// Set while a sync runs, so the schedule and "Sync now" never collect the same sessions twice.
pub(crate) struct Busy<'a>(&'a AtomicBool);

impl<'a> Busy<'a> {
    fn take(flag: &'a AtomicBool) -> Option<Self> {
        (!flag.swap(true, Ordering::SeqCst)).then_some(Self(flag))
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[derive(Serialize, ToSchema)]
pub struct SourceView {
    pub id: String,
    /// `core` for the Core's own collector, else the device that collects.
    pub device: String,
    pub kind: String,
    pub enabled: bool,
    pub roots: Vec<String>,
    /// What the collector has taken so far; opaque to the Core, owned by the collector.
    #[schema(value_type = Object)]
    pub cursor: Value,
    /// When the source last synced (RFC 3339).
    pub last_run: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct SourcePut {
    pub device: String,
    pub kind: String,
    pub enabled: Option<bool>,
    pub roots: Option<Vec<String>>,
    #[schema(value_type = Option<Object>)]
    pub cursor: Option<Value>,
}

fn view(r: &sqlx::sqlite::SqliteRow) -> Result<SourceView, sqlx::Error> {
    let (roots, cursor): (String, String) = (r.try_get("roots")?, r.try_get("cursor")?);
    Ok(SourceView {
        id: r.try_get("id")?,
        device: r.try_get("device")?,
        kind: r.try_get("kind")?,
        enabled: r.try_get::<i64, _>("enabled")? == 1,
        roots: serde_json::from_str(&roots).unwrap_or_default(),
        cursor: serde_json::from_str(&cursor).unwrap_or(json!({})),
        last_run: r.try_get("last_run")?,
    })
}

async fn ensure_core_source(app: &App) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT OR IGNORE INTO brain_sources (id, device, kind) VALUES (?, 'core', ?)")
        .bind(CORE_SOURCE)
        .bind(CORE_SOURCE)
        .execute(&app.pool)
        .await
        .map(drop)
}

#[utoipa::path(get, path = "/sources", operation_id = "brainSources", tag = "brain",
    responses((status = 200, description = "Every collector: its switch, roots and cursor", body = Vec<SourceView>)))]
pub(crate) async fn sources(State(app): State<App>) -> ApiResult<Vec<SourceView>> {
    ensure_core_source(&app).await?;
    let rows = sqlx::query("SELECT * FROM brain_sources ORDER BY id")
        .fetch_all(&app.pool)
        .await?;
    Ok(Json(rows.iter().map(view).collect::<Result<_, _>>()?))
}

#[utoipa::path(put, path = "/sources/{id}", operation_id = "brainPutSource", tag = "brain",
    params(("id" = String, Path, description = "Source id: lowercase letters, digits, `_` and `-`")),
    request_body = SourcePut,
    responses((status = 200, description = "The source, made or changed; a missing field keeps its value", body = SourceView)))]
pub(crate) async fn put_source(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(req): Json<SourcePut>,
) -> ApiResult<SourceView> {
    let kind_ok = serde_json::from_value::<SourceKind>(json!(req.kind)).is_ok();
    let cursor = req.cursor.as_ref().map(Value::to_string);
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
        || !kind_ok
        || req.device.is_empty()
        || req.device.len() > 100
        || req
            .roots
            .as_ref()
            .is_some_and(|r| r.len() > 50 || r.iter().any(|p| p.len() > 2000))
        || cursor.as_ref().is_some_and(|c| c.len() > 64 * 1024)
    {
        return Err(ApiError::bad_request(
            "a source needs a valid id, device and kind, at most 50 roots and a cursor under 64 KiB",
        ));
    }
    // The Core's own collector is always the Core's: only its switch and cursor can change.
    let (device, kind) = if id == CORE_SOURCE {
        ("core".to_owned(), CORE_SOURCE.to_owned())
    } else {
        (req.device, req.kind)
    };
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "INSERT INTO brain_sources (id, device, kind, enabled, roots, cursor) VALUES (?, ?, ?, coalesce(?, 1), coalesce(?, '[]'), coalesce(?, '{}')) \
         ON CONFLICT(id) DO UPDATE SET device = excluded.device, kind = excluded.kind, \
         enabled = coalesce(?, enabled), roots = coalesce(?, roots), cursor = coalesce(?, cursor)",
    )
    .bind(&id)
    .bind(&device)
    .bind(&kind)
    .bind(req.enabled.map(i64::from))
    .bind(req.roots.as_ref().map(|r| json!(r).to_string()))
    .bind(&cursor)
    .bind(req.enabled.map(i64::from))
    .bind(req.roots.as_ref().map(|r| json!(r).to_string()))
    .bind(&cursor)
    .execute(&mut *tx)
    .await?;
    record(
        &mut tx,
        "brain.source.changed",
        json!({"source": id, "enabled": req.enabled}),
        None,
    )
    .await?;
    tx.commit().await?;
    let row = sqlx::query("SELECT * FROM brain_sources WHERE id = ?")
        .bind(&id)
        .fetch_one(&app.pool)
        .await?;
    Ok(Json(view(&row)?))
}

#[derive(Default, Deserialize, ToSchema)]
pub struct SyncRequest {
    /// A full run that is collecting and lists `core_transcript`: take the Core's AI sessions into
    /// it instead of starting an incremental run.
    pub run: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Routed {
    pub room: String,
    /// Sources added to that room.
    pub sources: i64,
}

#[derive(Default, Serialize, ToSchema)]
pub struct SyncResult {
    /// The run that took the new items; none when there was nothing new.
    pub run: Option<String>,
    pub state: Option<String>,
    pub found: u64,
    pub stored: u64,
    pub duplicate: u64,
    pub refused: u64,
    pub rejected: u64,
    /// Rooms the user already accepted that took their new items without a review.
    pub routed: Vec<Routed>,
    /// Items left in Unsorted for review.
    pub unsorted: i64,
    /// Proposed rooms that do not exist yet, left for review.
    pub new_rooms: i64,
    /// True when this sync raised the Inbox notice (`brain.inbox`).
    pub notice: bool,
    /// Why nothing ran: `nothing_new`, `disabled` or `running`.
    pub idle: Option<String>,
}

impl SyncResult {
    fn idle(why: &str) -> Self {
        Self {
            idle: Some(why.to_owned()),
            ..Self::default()
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Cursor {
    /// AI session id to the last transcript entry already taken.
    #[serde(default)]
    sessions: BTreeMap<String, i64>,
}

/// New entries of every finished AI session since the cursor, as items, and the cursor after them.
async fn collect(
    app: &App,
    done: &BTreeMap<String, i64>,
) -> Result<(Vec<Item>, BTreeMap<String, i64>), ApiError> {
    let now_ms = u64::try_from(app.clock.unix()).unwrap_or(0) * 1000;
    let (mut items, mut next, mut taken) = (vec![], done.clone(), 0);
    let mut before = None;
    'pages: loop {
        let page = agents::list(&app.pool, before, 200).await?;
        let Some(last) = page.last() else { break };
        before = Some(last.n);
        for s in &page {
            let from = done.get(&s.id).copied().unwrap_or(0);
            // A Brain-owned session is the Brain's own work: never read back in.
            if s.live() || s.owner_module.as_deref() == Some(crate::MODULE) || s.last_seq <= from {
                continue;
            }
            if taken == MAX_SESSIONS {
                break 'pages;
            }
            taken += 1;
            let mut entries = vec![];
            let mut after = from;
            loop {
                let got = agents::transcript(&app.pool, &s.id, after, 500).await?;
                let Some(end) = got.last() else { break };
                after = i64::try_from(end.seq).unwrap_or(i64::MAX);
                entries.extend(got.into_iter().map(|e| (e.seq, e.body)));
            }
            let title = s
                .title
                .clone()
                .or_else(|| s.prompt.as_deref().and_then(agents::title_of))
                .unwrap_or_else(|| format!("AI session {}", s.id));
            let meta = Meta {
                id: &s.id,
                harness: &s.harness,
                title: &title,
                project_hint: s
                    .workspace
                    .as_ref()
                    .and_then(|w| w["repo"].as_str())
                    .map(str::to_owned),
                started_at: &s.created_at,
                ended_at: s.ended_at.as_deref(),
            };
            items.extend(transcripts::items(&meta, &entries, now_ms));
            next.insert(s.id.clone(), after);
        }
    }
    Ok((items, next))
}

/// Takes the Core's new AI session transcripts: into a new incremental run, or into `into`, a full
/// run that is collecting. `owner` makes the brain key when none exists (a device id; the
/// schedule has none and does nothing until the first import made the key).
pub(crate) async fn sync_core(
    app: &App,
    b: &Brain,
    owner: Option<&str>,
    into: Option<&str>,
) -> Result<SyncResult, ApiError> {
    let Some(_busy) = Busy::take(&b.inner.syncing) else {
        return Ok(SyncResult::idle("running"));
    };
    ensure_core_source(app).await?;
    let row = sqlx::query("SELECT enabled, cursor FROM brain_sources WHERE id = ?")
        .bind(CORE_SOURCE)
        .fetch_one(&app.pool)
        .await?;
    let enabled = row.try_get::<i64, _>("enabled")? == 1;
    let cursor: Cursor =
        serde_json::from_str(&row.try_get::<String, _>("cursor")?).unwrap_or_default();
    let (items, next) = if enabled {
        collect(app, &cursor.sessions).await?
    } else {
        (vec![], cursor.sessions.clone())
    };
    if into.is_none() && items.is_empty() {
        sqlx::query("UPDATE brain_sources SET last_run = ? WHERE id = ?")
            .bind(app.clock.now())
            .bind(CORE_SOURCE)
            .execute(&app.pool)
            .await?;
        return Ok(SyncResult::idle(if enabled {
            "nothing_new"
        } else {
            "disabled"
        }));
    }
    let run = match into {
        Some(r) => {
            let (state, sources) = run_state(app, r).await?;
            if state != "collecting" || !sources.iter().any(|s| s == CORE_SOURCE) {
                return Err(ApiError::conflict("the run is not collecting AI sessions"));
            }
            r.to_owned()
        }
        None => start_run(app, b, "incremental", &[CORE_SOURCE.to_owned()], owner).await?,
    };
    let (mut chunk, mut bytes) = (vec![], 0);
    for item in items {
        let size = item.text.len() + item.title.len();
        if !chunk.is_empty() && (chunk.len() >= MAX_ITEMS || bytes + size > MAX_BATCH_BYTES) {
            stage_items(app, b, &run, &chunk).await?;
            chunk.clear();
            bytes = 0;
        }
        bytes += size;
        chunk.push(item);
    }
    if !chunk.is_empty() {
        stage_items(app, b, &run, &chunk).await?;
    }
    // The cursor moves only once the items are staged: a failure above is retried, not lost.
    sqlx::query("UPDATE brain_sources SET cursor = ?, last_run = ? WHERE id = ?")
        .bind(serde_json::to_string(&Cursor { sessions: next }).expect("cursor"))
        .bind(app.clock.now())
        .bind(CORE_SOURCE)
        .execute(&app.pool)
        .await?;
    let (_, sources) = run_state(app, &run).await?;
    let outcome = if mark_done(app, &run, CORE_SOURCE, &sources).await? {
        crate::review::discover(app, b, &run).await?
    } else {
        None
    };
    let c = crate::imports::load_counts(app, &run).await?;
    let (state, _) = run_state(app, &run).await?;
    let o = outcome.unwrap_or_default();
    Ok(SyncResult {
        run: Some(run),
        state: Some(state),
        found: c.found,
        stored: c.stored,
        duplicate: c.duplicate,
        refused: c.refused,
        rejected: c.rejected,
        routed: o
            .routed
            .iter()
            .map(|(room, sources)| Routed {
                room: room.clone(),
                sources: *sources,
            })
            .collect(),
        unsorted: o.unsorted,
        new_rooms: o.new_rooms,
        notice: o.unsorted + o.new_rooms > 0,
        idle: None,
    })
}

/// What the routing of an incremental run did.
#[derive(Default)]
pub(crate) struct Outcome {
    pub routed: Vec<(String, i64)>,
    pub unsorted: i64,
    pub new_rooms: i64,
}

/// A proposal that names a room the user already has needs no new review (plan §3.2, stage 10):
/// it is accepted and committed into that room as `assigned_by = 'rule'`. A new room or Unsorted
/// stays in review and raises one notice. A run with nothing left to review closes.
pub(crate) async fn route_known(app: &App, b: &Brain, run: &str) -> Result<Outcome, ApiError> {
    let key = b.key(app).await?;
    let st = staging(app, b, run, false).await?;
    let proposals =
        sqlx::query("SELECT * FROM proposals WHERE state = 'proposed' AND id != ? ORDER BY id")
            .bind(UNSORTED)
            .fetch_all(&st)
            .await?;
    let mut out = Outcome::default();
    for p in &proposals {
        let (id, name): (String, String) = (p.try_get("id")?, p.try_get("name")?);
        let kind: Option<String> =
            sqlx::query_scalar("SELECT kind FROM brain_rooms WHERE id = ? AND state = 'active'")
                .bind(room_id(&name))
                .fetch_optional(&app.pool)
                .await?;
        let held = kind
            .as_deref()
            .is_some_and(|k| (k == "employer" || k == "client") && !ROOM_BACKUP_READY);
        if kind.is_none() || held || mixed(&st, &id).await? {
            continue;
        }
        sqlx::query("UPDATE proposals SET state = 'accepted' WHERE id = ?")
            .bind(&id)
            .execute(&st)
            .await?;
        if let Some(made) = commit_room(app, &key, &st, run, p, "rule").await? {
            out.routed.push((made.room, made.sources));
        }
    }
    out.new_rooms =
        sqlx::query_scalar("SELECT count(*) FROM proposals WHERE state = 'proposed' AND id != ?")
            .bind(UNSORTED)
            .fetch_one(&st)
            .await?;
    out.unsorted = sqlx::query_scalar("SELECT count(*) FROM items WHERE proposal = ?")
        .bind(UNSORTED)
        .fetch_one(&st)
        .await?;
    st.close().await;
    if out.new_rooms + out.unsorted == 0 {
        close_run(app, run, out.routed.len()).await?;
        return Ok(out);
    }
    // Ids and counts only (Q-15). There is no Inbox screen in the Core yet: the notice is this
    // event, recorded in the stream and the audit chain, for the app to show.
    let notice = json!({"run": run, "unsorted": out.unsorted, "new_rooms": out.new_rooms});
    let mut tx = begin_write(&app.pool).await?;
    record(
        &mut tx,
        "brain.inbox.notice",
        notice.clone(),
        Some(("brain.inbox", notice)),
    )
    .await?;
    tx.commit().await?;
    Ok(out)
}

#[derive(Serialize, ToSchema)]
pub struct SyncSource {
    pub id: String,
    pub kind: String,
    pub enabled: bool,
    pub last_run: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct SyncStatus {
    /// Seconds between scheduled syncs of the Core's own sources.
    pub every_secs: u64,
    pub sources: Vec<SyncSource>,
    /// Runs waiting for a review (new rooms or Unsorted items), oldest first.
    pub review: Vec<String>,
}

#[utoipa::path(get, path = "/sync", operation_id = "brainSyncStatus", tag = "brain",
    responses((status = 200, description = "The schedule, the last sync per source and runs waiting for review", body = SyncStatus)))]
pub(crate) async fn status(State(app): State<App>) -> ApiResult<SyncStatus> {
    ensure_core_source(&app).await?;
    let rows = sqlx::query("SELECT id, kind, enabled, last_run FROM brain_sources ORDER BY id")
        .fetch_all(&app.pool)
        .await?;
    let sources = rows
        .iter()
        .map(|r| {
            Ok(SyncSource {
                id: r.try_get("id")?,
                kind: r.try_get("kind")?,
                enabled: r.try_get::<i64, _>("enabled")? == 1,
                last_run: r.try_get("last_run")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
    let review = sqlx::query_scalar("SELECT id FROM brain_import_runs WHERE state = 'review' AND kind = 'incremental' ORDER BY started_at")
        .fetch_all(&app.pool)
        .await?;
    Ok(Json(SyncStatus {
        every_secs: SYNC_EVERY_SECS,
        sources,
        review,
    }))
}

#[utoipa::path(post, path = "/sync", operation_id = "brainSyncNow", tag = "brain",
    request_body = SyncRequest,
    responses((status = 200, description = "Sync now: the Core's AI sessions since the last sync, routed into known rooms", body = SyncResult)))]
pub(crate) async fn sync_now(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Json(req): Json<SyncRequest>,
) -> ApiResult<SyncResult> {
    Ok(Json(
        sync_core(&app, &b, Some(&me.device.id), req.run.as_deref()).await?,
    ))
}

struct SyncJob(Brain);

impl JobHandler for SyncJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let Some(app) = self.0.inner.app.get() else {
                return Err("the Core is still starting".to_owned());
            };
            match sync_core(app, &self.0, None, None).await {
                Ok(r) if r.run.is_none() => run.idle(),
                Ok(_) => {}
                // No brain key yet, or the brain is locked: nothing to do, not a failure.
                Err(e) if e.status == axum::http::StatusCode::CONFLICT => run.idle(),
                Err(e) => return Err(format!("{}: {}", e.code, e.message)),
            }
            Ok(())
        })
    }
}

pub(crate) fn job(b: &Brain) -> Job {
    Job::new(
        "brain_sync",
        Schedule::Every(SYNC_EVERY_SECS),
        Arc::new(SyncJob(b.clone())),
    )
}
