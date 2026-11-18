//! Retention (Brain v2, B6-02): a room may compact old, fully distilled sources to citation stubs.
//!
//! Security model. Compaction destroys text for good, so: the default is keep (`retention_days`
//! NULL); turning it on is a person-only PATCH of the room policy behind a step-up (Touch ID); the
//! daily job reads only that setting, never a request; `GET /rooms/{room}/retention` is the dry run
//! and writes nothing. A source is compacted only when ALL hold: it is older than N days, a
//! distillation took it (`distilled`) and no run of the room is still open, it is not waiting for a
//! re-distil (`redistil`), and no `candidate` record and no record archived inside the 30-day undo
//! window cites it (Undo must find its evidence). The stub keeps title, hash, path, dates and
//! author; `text` becomes '' and `compacted_at` is set, so `brainAiEvidence` answers "compacted".
//! The search index and the stored vector of the text are dropped, `brain_seen` keeps the hash so
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
use files::CANON;

/// The longest retention a room can set (ten years).
pub const MAX_DAYS: u32 = 3650;
/// Daily, 04:23 UTC (after the 03:17 purge).
const CRON: &str = "23 4 * * *";

/// Which sources may go. `?1` the age cutoff, `?2` the start of the undo window, `?3` a JSON list of
/// the room's open distil run ids. The `source_ids` arm mirrors `brainAiEvidence`: writers may still
/// fill only that list.
const ELIGIBLE: &str = "SELECT s.item_id, s.content_hash, length(s.text) AS chars FROM sources s \
    WHERE s.compacted_at IS NULL AND s.redistil IS NULL AND s.distilled IS NOT NULL \
    AND s.distilled NOT IN (SELECT value FROM json_each(?3)) \
    AND coalesce(s.ended_at, s.started_at) < ?1 \
    AND NOT EXISTS (SELECT 1 FROM records r \
        WHERE (r.status = 'candidate' OR (r.archived_at IS NOT NULL AND r.archived_at >= ?2)) \
        AND (EXISTS (SELECT 1 FROM record_sources rs WHERE rs.record = r.id AND rs.source = s.item_id) \
             OR EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(r.source_ids) THEN r.source_ids ELSE '[]' END) j \
                        WHERE j.value = s.item_id))) \
    ORDER BY s.item_id";

/// A source the room would compact.
pub struct Candidate {
    pub item_id: String,
    pub content_hash: String,
    pub chars: i64,
}

/// Runs of `room` that have not finished: their sources are still being read.
async fn open_runs(app: &App, room: &str) -> Result<String, sqlx::Error> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM brain_distils WHERE room = ? AND state IN ('queued','needs_local_model','waiting','running')",
    )
    .bind(room)
    .fetch_all(&app.pool)
    .await?;
    Ok(json!(ids).to_string())
}

/// The sources `days` of retention would compact now. Reads only.
pub async fn eligible(
    pool: &SqlitePool,
    now_unix: i64,
    days: u32,
    open_runs: &str,
) -> Result<Vec<Candidate>, sqlx::Error> {
    let rows = sqlx::query(ELIGIBLE)
        .bind(iso_of_unix(now_unix - i64::from(days) * 86_400))
        .bind(iso_of_unix(now_unix - PURGE_DAYS * 86_400))
        .bind(open_runs)
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

/// Drops the text of `cands` (re-checked in the write, so a source taken for a re-distil since the
/// read is left alone), logs the ops and writes one audit row. Returns how many were compacted.
pub async fn compact(
    pool: &SqlitePool,
    now: &str,
    cands: &[Candidate],
) -> Result<usize, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let mut n = 0;
    let mut chars = 0;
    for c in cands {
        let done = sqlx::query(
            "UPDATE sources SET text = '', compacted_at = ? \
             WHERE item_id = ? AND compacted_at IS NULL AND redistil IS NULL",
        )
        .bind(now)
        .bind(&c.item_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if done == 1 {
            n += 1;
            chars += c.chars;
            log_op(&mut tx, "source.compacted", &c.item_id, now).await?;
        }
    }
    if n > 0 {
        sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES ('retention.compacted', ?, ?)")
            .bind(json!({"sources": n, "chars": chars}).to_string())
            .bind(now)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(n)
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
    let found = eligible(access.pool(), app.clock.unix(), days, &open_runs(&app, &room).await?).await;
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
            let runs = open_runs(app, &room).await?;
            let done = async {
                let found = eligible(&pool, app.clock.unix(), days, &runs).await?;
                if found.is_empty() {
                    return Ok::<_, ApiError>((0, 0));
                }
                // The stored meaning of the text goes first: a failure here compacts nothing, and
                // the next run tries again.
                let hashes: Vec<String> = found.iter().map(|c| c.content_hash.clone()).collect();
                vectors::delete(app, self, &hashes).await?;
                let chars = found.iter().map(|c| c.chars).sum::<i64>();
                Ok((compact(&pool, &app.clock.now(), &found).await?, chars))
            }
            .await;
            pool.close().await;
            let (n, chars) = done?;
            if n > 0 {
                total += n;
                let mut ctl = begin_write(&app.pool).await?;
                record(
                    &mut ctl,
                    "brain.room.compacted",
                    json!({"room": room, "sources": n, "chars": chars, "days": days}),
                    None,
                )
                .await?;
                ctl.commit().await?;
            }
        }
        Ok(total)
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
