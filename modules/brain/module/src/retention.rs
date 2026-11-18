//! Retention (Brain v2, B6-02): a room may compact old, fully distilled sources to citation stubs.
//!
//! Security model. Compaction destroys text for good, so: the default is keep (`retention_days`
//! NULL); turning it on is a person-only PATCH of the room policy behind a step-up (Touch ID); the
//! daily job reads only that setting, never a request; `GET /rooms/{room}/retention` is the dry run
//! and writes nothing. A source is compacted only when ALL hold: it is older than N days (counted from the later of its date and its import), a
//! distillation took it (`distilled`) and that run finished (`done`; a failed or open run does not count), it is not waiting for a
//! re-distil (`redistil`), and no `candidate` record and no record archived inside the 30-day undo
//! window cites it (Undo must find its evidence). The stub keeps title, hash, path, dates and
//! author; `text` becomes '' and `compacted_at` is set, so `brainAiEvidence` answers "compacted".
//! The search index rows and the stored vector of the text are dropped (freed pages zeroed), `brain_seen` keeps the hash so
//! the item is never re-imported. Idempotent (a compacted source is not selected again), audited
//! in the room (`retention.compacted`) and on the Core (`brain.room.compacted`, counts only).

use std::sync::Arc;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::scheduler::iso_of_unix;
use ainkrad_core_server::store::begin_write;
use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqlitePool};
use utoipa::{IntoParams, ToSchema};

use crate::changes::PURGE_DAYS;
use crate::distil::log_op;
use crate::{Brain, files, record, vectors};
use files::{CANON, INDEX};

/// The longest retention a room can set (ten years).
pub const MAX_DAYS: u32 = 3650;
/// Daily, 04:23 UTC (after the 03:17 purge).
const CRON: &str = "23 4 * * *";

/// The most sources one run compacts in one room; the rest wait for the next day.
const PER_RUN: i64 = 500;

/// Which sources may go, as a WHERE over `sources s`. `?1` the age cutoff, `?2` the start of the undo
/// window, `?3` a JSON list of the room's DONE distil run ids (a failed, rejected or open run never
/// counts as having read a source). A source is as old as the later of its own date and the time it
/// was imported (its `source.add`/`source.update` op), so an old chat export is not compacted the day
/// after it arrives. The `source_ids` arm mirrors `brainAiEvidence`: writers may still fill only that
/// list. Every subquery is uncorrelated (read once), except the op-log lookup, which `op_log_ref`
/// serves. One text, used by the read and, with the hash, by the write.
macro_rules! eligible_where {
    () => {
        "s.compacted_at IS NULL AND s.redistil IS NULL AND s.distilled IS NOT NULL \
         AND s.distilled IN (SELECT value FROM json_each(?3)) \
         AND max(coalesce(s.ended_at, s.started_at), \
                 coalesce((SELECT max(o.at) FROM op_log o WHERE o.ref = s.item_id \
                           AND o.op IN ('source.add', 'source.update')), '')) < ?1 \
         AND s.item_id NOT IN ( \
             SELECT rs.source FROM records r JOIN record_sources rs ON rs.record = r.id \
               WHERE r.status = 'candidate' OR (r.archived_at IS NOT NULL AND r.archived_at >= ?2) \
             UNION \
             SELECT j.value FROM records r, \
                    json_each(CASE WHEN json_valid(r.source_ids) THEN r.source_ids ELSE '[]' END) j \
               WHERE r.status = 'candidate' OR (r.archived_at IS NOT NULL AND r.archived_at >= ?2) \
             UNION \
             SELECT json_extract(j.value, '$[0]') FROM change_rows cr JOIN changes c ON c.id = cr.change, \
                    json_each(CASE WHEN json_valid(cr.before) THEN cr.before ELSE '{}' END, '$._sources') j \
               WHERE c.undone_at IS NULL AND c.at >= ?2 AND json_extract(j.value, '$[0]') IS NOT NULL)"
    };
}

/// `?4` is the most sources to return (-1: all).
const ELIGIBLE: &str = concat!(
    "SELECT s.item_id, s.content_hash, length(s.text) AS chars FROM sources s WHERE ",
    eligible_where!(),
    " ORDER BY s.item_id LIMIT ?4"
);

/// The write re-checks everything: `?4` is now, `?5` the item id, `?6` the hash that was read.
const COMPACT: &str = concat!(
    "UPDATE sources AS s SET text = '', compacted_at = ?4 WHERE s.item_id = ?5 AND s.content_hash = ?6 AND ",
    eligible_where!()
);

/// A source the room would compact.
pub struct Candidate {
    pub item_id: String,
    pub content_hash: String,
    pub chars: i64,
}

/// The binds `?1..?3` of the eligibility test.
pub struct Window {
    cutoff: String,
    undo: String,
    done: String,
}

impl Window {
    pub fn new(now_unix: i64, days: u32, done_runs: &str) -> Self {
        Self {
            cutoff: iso_of_unix(now_unix - i64::from(days) * 86_400),
            undo: iso_of_unix(now_unix - PURGE_DAYS * 86_400),
            done: done_runs.to_owned(),
        }
    }
}

/// Runs of `room` that finished well: only their sources count as read.
async fn done_runs(app: &App, room: &str) -> Result<String, sqlx::Error> {
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM brain_distils WHERE room = ? AND state = 'done'")
            .bind(room)
            .fetch_all(&app.pool)
            .await?;
    Ok(json!(ids).to_string())
}

/// Up to `limit` of the sources `w` would compact now (-1: all). Reads only.
pub async fn eligible(
    pool: &SqlitePool,
    w: &Window,
    limit: i64,
) -> Result<Vec<Candidate>, sqlx::Error> {
    let rows = sqlx::query(ELIGIBLE)
        .bind(&w.cutoff)
        .bind(&w.undo)
        .bind(&w.done)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    rows.iter()
        .map(|r| {
            Ok(Candidate {
                item_id: r.try_get("item_id")?,
                content_hash: r.try_get("content_hash")?,
                chars: r.try_get("chars")?,
            })
        })
        .collect()
}

/// What `compact` did.
pub struct Compacted {
    pub ids: Vec<String>,
    pub chars: i64,
}

/// Drops the text of `cands` in one write-locking transaction (`BEGIN IMMEDIATE`), each one
/// re-checked against the whole eligibility test and its content hash in the UPDATE itself: a
/// source that changed, was taken for a re-distil or got cited since the read is left alone. Logs
/// the ops and writes one audit row.
pub async fn compact(
    pool: &SqlitePool,
    w: &Window,
    now: &str,
    cands: &[Candidate],
) -> Result<Compacted, sqlx::Error> {
    let mut tx = begin_write(pool).await?;
    let mut out = Compacted { ids: vec![], chars: 0 };
    for c in cands {
        let done = sqlx::query(COMPACT)
            .bind(&w.cutoff)
            .bind(&w.undo)
            .bind(&w.done)
            .bind(now)
            .bind(&c.item_id)
            .bind(&c.content_hash)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if done == 1 {
            out.chars += c.chars;
            out.ids.push(c.item_id.clone());
            log_op(&mut tx, "source.compacted", &c.item_id, now).await?;
        }
    }
    if !out.ids.is_empty() {
        sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES ('retention.compacted', ?, ?)")
            .bind(json!({"sources": out.ids.len(), "chars": out.chars}).to_string())
            .bind(now)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(out)
}

#[derive(Deserialize, IntoParams)]
pub struct PreviewQuery {
    /// Days to preview; the room's current setting when omitted.
    pub days: Option<u32>,
}

#[derive(Serialize, ToSchema)]
pub struct RetentionPreview {
    pub room: String,
    pub days: u32,
    /// Sources that would lose their text if retention were set to `days` now.
    pub would_compact: u32,
    /// Characters of text that would be dropped.
    pub chars: u64,
}

#[utoipa::path(get, path = "/rooms/{room}/retention", operation_id = "brainRetentionPreview", tag = "brain",
    params(("room" = String, Path, description = "Room id"), PreviewQuery),
    responses((status = 200, description = "Dry run: how many sources retention would compact now, from counts only; writes nothing (person only)", body = RetentionPreview)))]
pub(crate) async fn preview(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path(room): Path<String>,
    Query(q): Query<PreviewQuery>,
) -> ApiResult<RetentionPreview> {
    crate::change_routes::person_only(&me)?;
    let days = match q.days {
        Some(d) => d,
        None => crate::policy::load(&app, &room)
            .await?
            .retention_days
            .ok_or_else(|| ApiError::bad_request("retention is off; pass `days`"))?,
    };
    if !(1..=MAX_DAYS).contains(&days) {
        return Err(ApiError::bad_request("days is 1 to 3650"));
    }
    let access = crate::inbox::open_room(&app, &b, &room).await?;
    let w = Window::new(app.clock.unix(), days, &done_runs(&app, &room).await?);
    let found = eligible(access.pool(), &w, -1).await;
    access.pool().close().await;
    let found = found?;
    Ok(Json(RetentionPreview {
        room,
        days,
        would_compact: u32::try_from(found.len()).unwrap_or(u32::MAX),
        chars: found.iter().map(|c| u64::try_from(c.chars).unwrap_or(0)).sum(),
    }))
}

impl Brain {
    /// Compacts, in every active room that turned retention on, the sources it allows (the daily
    /// `brain_retention` job). Returns the sources compacted. A room whose file is missing or newer
    /// is left for the next run.
    pub async fn retention_step(&self) -> Result<usize, ApiError> {
        let Some(app) = self.inner.app.get() else {
            return Ok(0);
        };
        let Ok(key) = self.key(app).await else {
            return Ok(0);
        };
        let rooms: Vec<(String, i64)> = sqlx::query_as(
            "SELECT r.id, p.retention_days FROM brain_rooms r JOIN brain_room_policy p ON p.room = r.id \
             WHERE r.state = 'active' AND p.retention_days IS NOT NULL ORDER BY r.id",
        )
        .fetch_all(&app.pool)
        .await?;
        let mut total = 0;
        for (room, days) in rooms {
            let Ok(days) = u32::try_from(days) else { continue };
            let Ok(pool) =
                files::open_migrated(&files::room_path(&files::root(app), &room), &key, false, CANON).await
            else {
                continue;
            };
            let done = self.compact_room(app, &key, &room, days, &pool).await;
            pool.close().await;
            // One room's failure is logged; the other rooms still run.
            let (n, chars) = match done {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(room = %room, code = %e.code, error = %e.message, "retention failed for a room");
                    continue;
                }
            };
            if n > 0 {
                total += n;
                let audit = async {
                    let mut ctl = begin_write(&app.pool).await?;
                    record(
                        &mut ctl,
                        "brain.room.compacted",
                        json!({"room": room, "sources": n, "chars": chars, "days": days}),
                        None,
                    )
                    .await?;
                    ctl.commit().await?;
                    Ok::<_, ApiError>(())
                }
                .await;
                if let Err(e) = audit {
                    tracing::warn!(room = %room, error = %e.message, "the Core audit of a compaction failed");
                }
            }
        }
        Ok(total)
    }

    /// One room: compacts up to `PER_RUN` sources, scrubs their text from the search index, then
    /// drops the stored vectors of every compacted source (this run's and any an earlier run left
    /// behind when its delete failed). Returns `(sources compacted, chars)`.
    async fn compact_room(
        &self,
        app: &App,
        key: &[u8; 32],
        room: &str,
        days: u32,
        pool: &SqlitePool,
    ) -> Result<(usize, i64), ApiError> {
        // Freed pages are zeroed, not left holding the text.
        sqlx::query("PRAGMA secure_delete = ON").execute(pool).await?;
        let w = Window::new(app.clock.unix(), days, &done_runs(app, room).await?);
        let found = eligible(pool, &w, PER_RUN).await?;
        let done = if found.is_empty() {
            Compacted { ids: vec![], chars: 0 }
        } else {
            compact(pool, &w, &app.clock.now(), &found).await?
        };
        if !done.ids.is_empty() {
            let file = files::index_path(&files::root(app), room);
            if file.exists() {
                let index = files::open_migrated(&file, key, false, INDEX)
                    .await
                    .map_err(|e| crate::code(500, "index_unavailable", e.to_string()))?;
                let scrub = async {
                    sqlx::query("PRAGMA secure_delete = ON").execute(&index).await?;
                    for id in &done.ids {
                        sqlx::query("DELETE FROM fts WHERE item_id = ?").bind(id).execute(&index).await?;
                    }
                    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(&index).await?;
                    Ok::<_, sqlx::Error>(())
                }
                .await;
                index.close().await;
                scrub?;
            }
        }
        // ponytail: sweeps every compacted source's vector each run; one indexed delete per hash.
        let hashes: Vec<String> =
            sqlx::query_scalar("SELECT content_hash FROM sources WHERE compacted_at IS NOT NULL")
                .fetch_all(pool)
                .await?;
        if !hashes.is_empty() {
            vectors::delete(app, self, &hashes).await?;
        }
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(pool).await?;
        Ok((done.ids.len(), done.chars))
    }
}

struct RetentionJob(Brain);

impl JobHandler for RetentionJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            match self.0.retention_step().await {
                Ok(0) => {
                    run.idle();
                    Ok(())
                }
                Ok(_) => Ok(()),
                Err(e) => Err(e.message),
            }
        })
    }
}

pub(crate) fn job(b: &Brain) -> Job {
    Job::new(
        "brain_retention",
        Schedule::Cron(CRON.to_owned()),
        Arc::new(RetentionJob(b.clone())),
    )
}
