//! Automatic distillation (Brain v2, B5-01): a distil is queued for a room when an AI session ends
//! (`agent.ended`) and when a room piles up undistilled sources (a count or an age).
//!
//! Security model (this is a cost and DoS surface, so the whole policy is here):
//! - Only the Core's own event log starts a trigger. No route, no AI op and no session text can ask
//!   for one: an AI session can at most cause its own end, and that is bounded by the caps below.
//! - Caps are counted from `brain_distils` rows of the last 24 hours, so a restart or a crash cannot
//!   reset them: `brain_room_policy.daily_distils` per room and `GLOBAL_DAILY` across rooms. A trigger over
//!   a cap is dropped and audited (`brain.distil.capped`), never turned into a failed distil.
//!   Redistil, tidy and judge runs have their own budget and are not counted. A cap is audited at
//!   most once per room per UTC day. A room whose distil failed is skipped for `FAIL_BACKOFF_SECS`.
//! - One open distil per room: triggers coalesce into it. A session gets one `session_end` distil
//!   (`of_session`), however often its end event is read.
//! - Queueing happens in one write transaction (check, cap, insert), so two ticks or a crash in
//!   between never leave a duplicate or a half-made row; a unique index (one open distil per room)
//!   also settles a race with a manual start. The event cursor moves only past an event that reached
//!   `queue` , so a temporary failure or an unsynced session replays it, and
//!   replays are harmless.
//! - The distil runs as the room owner's (user 1) most recent manual requester that holds `write` or
//!   `admin`, never as a read-only device.
//! - Brain-owned sessions (distil, judge, tidy, overview) are never a trigger, and never a source.
//! - The first run starts at the newest event: history is not distilled by surprise.
//!
//! The clock is a parameter (`step_at`), so tests set the time.
//! ponytail: every tick reads up to 10 pages of events; a session end scans each active room's
//! `canon.db` once. Fine for dozens of rooms; index sources by session if that stops being true.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::scheduler::iso_of_unix;
use ainkrad_core_server::store::{begin_write, events};
use axum::http::StatusCode;
use serde_json::json;

use crate::sync::{Busy, CORE_SOURCE, sync_core};
use crate::{Brain, MODULE, distil, policy, rand_id, record};

/// How often the triggers are looked at.
const EVERY_SECS: u64 = 30;
/// Idle debounce: a session's end is acted on this long after it happened, so a burst of ends in
/// one room (and the sync that collects them) settles into one distil.
const IDLE_SECS: i64 = 45;
/// Import threshold (a Q value): this many undistilled sources in a room ...
const THRESHOLD_SOURCES: i64 = 40;
/// ... or the oldest undistilled source this old.
const THRESHOLD_AGE_SECS: i64 = 6 * 3600;
/// How often the rooms are scanned for the threshold.
const SCAN_EVERY_SECS: i64 = 300;
/// Automatic and manual distils across all rooms per rolling 24 hours.
const GLOBAL_DAILY: i64 = 100;
/// A room whose distil failed is left alone this long (a Q value).
const FAIL_BACKOFF_SECS: i64 = 6 * 3600;
/// An end event this old is set aside rather than waited on for its session to be collected.
const STALE_END_SECS: i64 = 86_400;
const PAGE: u32 = 200;
const MAX_PAGES: u32 = 10;

#[derive(Debug, PartialEq, Eq)]
enum Queued {
    Yes,
    /// A distil of the room is open (it takes the new sources), or this session had its distil.
    Coalesced,
    Capped,
    Nothing,
}

/// Sources of a room still to distil: (count, oldest `started_at`, how many came from `path`).
async fn stats(app: &App, b: &Brain, room: &str, path: &str) -> Option<(i64, Option<String>, i64)> {
    let pool = distil::canon(app, b, room).await.ok()?;
    let r = sqlx::query_as(
        "SELECT count(*), min(started_at), coalesce(sum(path = ?), 0) \
         FROM sources WHERE distilled IS NULL AND pointer = 0",
    )
    .bind(path)
    .fetch_one(&pool)
    .await
    .ok();
    pool.close().await;
    r
}

async fn active_rooms(app: &App) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM brain_rooms WHERE state = 'active' ORDER BY id")
        .fetch_all(&app.pool)
        .await
}

/// The device the distil runs as (its user's fallback chain): the owner's (user 1) active device
/// with a write scope that asked for a distil most recently, else the oldest such device. No device,
/// no distil.
pub(crate) async fn requester(app: &App) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM core_devices WHERE kind = 'device' AND status = 'active' AND revoked_at IS NULL \
         AND user_id = 1 AND EXISTS (SELECT 1 FROM json_each(core_devices.scopes) WHERE value IN ('write','admin')) \
         ORDER BY coalesce((SELECT max(created_at) FROM brain_distils \
                            WHERE \"trigger\" = 'manual' AND requested_by = core_devices.id), '') DESC, seq LIMIT 1",
    )
    .fetch_optional(&app.pool)
    .await
}

/// Queues one distil of `room` (`fresh` undistilled sources) unless a gate says no. One write
/// transaction: the checks and the insert cannot be split by another tick.
async fn queue(
    app: &App,
    room: &str,
    trigger: &str,
    session: Option<&str>,
    fresh: i64,
    now: i64,
) -> Result<Queued, ApiError> {
    if fresh == 0 {
        return Ok(Queued::Nothing);
    }
    let Ok(p) = policy::load(app, room).await else {
        return Ok(Queued::Nothing);
    };
    let Some(by) = requester(app).await? else {
        return Ok(Queued::Nothing);
    };
    let day = iso_of_unix(now - now.rem_euclid(86_400));
    let since = iso_of_unix(now - 86_400);
    let at = iso_of_unix(now);
    let mut tx = begin_write(&app.pool).await?;
    let failed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM brain_distils WHERE room = ? AND state = 'failed' AND updated_at >= ?",
    )
    .bind(room)
    .bind(iso_of_unix(now - FAIL_BACKOFF_SECS))
    .fetch_one(&mut *tx)
    .await?;
    if failed > 0 {
        return Ok(Queued::Nothing);
    }
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM brain_distils WHERE room = ? \
         AND state IN ('queued','needs_local_model','waiting','running')",
    )
    .bind(room)
    .fetch_one(&mut *tx)
    .await?;
    let had: i64 = match session {
        Some(s) => {
            sqlx::query_scalar(
                "SELECT count(*) FROM brain_distils WHERE of_session = ? AND room = ? AND \"trigger\" = 'session_end'",
            )
            .bind(s)
            .bind(room)
            .fetch_one(&mut *tx)
            .await?
        }
        None => 0,
    };
    if open + had > 0 {
        return Ok(Queued::Coalesced);
    }
    let cap: i64 = sqlx::query_scalar("SELECT daily_distils FROM brain_room_policy WHERE room = ?")
        .bind(room)
        .fetch_one(&mut *tx)
        .await?;
    let (in_room, in_all): (i64, i64) = sqlx::query_as(
        "SELECT coalesce(sum(room = ?), 0), count(*) FROM brain_distils \
         WHERE created_at >= ? AND \"trigger\" NOT IN ('redistil','tidy','judge')",
    )
    .bind(room)
    .bind(&since)
    .fetch_one(&mut *tx)
    .await?;
    let over = if in_room >= cap {
        Some(("room_cap", cap))
    } else if in_all >= GLOBAL_DAILY {
        Some(("global_cap", GLOBAL_DAILY))
    } else {
        None
    };
    if let Some((which, limit)) = over {
        // Only a session end says so: the threshold scan runs all day and would fill the audit log.
        if trigger == "session_end" {
            // At most one row per room per UTC day: a busy room must not fill the audit log.
            let said: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM audit_events WHERE action = 'brain.distil.capped' \
                 AND json_extract(details, '$.room') = ? AND json_extract(details, '$.day') = ?",
            )
            .bind(room)
            .bind(&day)
            .fetch_one(&mut *tx)
            .await?;
            if said == 0 {
                record(
                    &mut tx,
                    "brain.distil.capped",
                    json!({"room": room, "trigger": trigger, "session": session, "cap": which, "limit": limit, "day": day}),
                    None,
                )
                .await?;
                tx.commit().await?;
            }
        }
        return Ok(Queued::Capped);
    }
    let id = rand_id("dst-");
    // A local-only room waits for a local model and never claims a cloud account (as `start`).
    let state = if p.local_only() {
        "needs_local_model"
    } else {
        "queued"
    };
    let inserted = sqlx::query(
        "INSERT INTO brain_distils (id, room, state, requested_by, sources, \"trigger\", of_session, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(room)
    .bind(state)
    .bind(&by)
    .bind(fresh.min(30))
    .bind(trigger)
    .bind(session)
    .bind(&at)
    .bind(&at)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        // A manual start won the race (one open distil per room, by index): coalesce into it.
        Err(e) if e.as_database_error().is_some_and(|d| d.is_unique_violation()) => {
            return Ok(Queued::Coalesced);
        }
        Err(e) => return Err(e.into()),
    }
    record(
        &mut tx,
        "brain.distil.queued",
        json!({"room": room, "distil": id, "state": state, "trigger": trigger, "session": session}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Queued::Yes)
}

/// Has the Core sync taken this session's whole transcript (the sync reads at most 200 sessions a
/// time)? Also true when it never will: the source is off, or the transcript is empty.
async fn collected(app: &App, session: &str) -> Result<bool, sqlx::Error> {
    let on: Option<i64> = sqlx::query_scalar("SELECT enabled FROM brain_sources WHERE id = ?")
        .bind(CORE_SOURCE)
        .fetch_optional(&app.pool)
        .await?;
    let last: i64 = sqlx::query_scalar("SELECT last_seq FROM core_agent_sessions WHERE id = ?")
        .bind(session)
        .fetch_optional(&app.pool)
        .await?
        .unwrap_or(0);
    // The source's cursor, and the cursors of runs still open, both hold `{"sessions": {id: seq}}`.
    let have: Option<i64> = sqlx::query_scalar(
        "SELECT max(v) FROM (\
           SELECT json_extract(cursor, '$.sessions.\"' || ?1 || '\"') AS v FROM brain_sources WHERE id = ?2 \
           UNION ALL \
           SELECT json_extract(cursor, '$.sessions.\"' || ?1 || '\"') FROM brain_run_cursors WHERE source = ?2)",
    )
    .bind(session)
    .bind(CORE_SOURCE)
    .fetch_one(&app.pool)
    .await?;
    Ok(on != Some(1) || last <= have.unwrap_or(0))
}

/// A session ended: queue a distil for each room its collected transcript landed in. `None` when
/// the transcript is not collected yet (the event is read again next tick).
async fn session_ended(
    app: &App,
    b: &Brain,
    session: &str,
    now: i64,
    stale: bool,
) -> Result<Option<u32>, ApiError> {
    let owner: Option<Option<String>> =
        sqlx::query_scalar("SELECT owner_module FROM core_agent_sessions WHERE id = ?")
            .bind(session)
            .fetch_optional(&app.pool)
            .await?;
    let claimed: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_session_rooms WHERE session = ?")
        .bind(session)
        .fetch_one(&app.pool)
        .await?;
    // A Brain session (distil, judge, tidy) is never a trigger; an unknown session is nothing.
    match owner {
        Some(o) if o.as_deref() != Some(MODULE) && claimed == 0 => {}
        _ => return Ok(Some(0)),
    }
    if !stale && !collected(app, session).await? {
        return Ok(None);
    }
    let path = format!("core://ai-session/{session}");
    let mut queued = 0;
    for room in active_rooms(app).await? {
        let Some((n, _, from_session)) = stats(app, b, &room, &path).await else {
            continue;
        };
        if from_session > 0
            && queue(app, &room, "session_end", Some(session), n, now).await? == Queued::Yes
        {
            queued += 1;
        }
    }
    Ok(Some(queued))
}

/// Reads the `agent.ended` events after the cursor. Returns how many distils were queued.
async fn ended(app: &App, b: &Brain, now: i64) -> Result<u32, ApiError> {
    let saved: Option<i64> = sqlx::query_scalar("SELECT seq FROM brain_session_cursor")
        .fetch_optional(&app.pool)
        .await?;
    let mut from = match saved {
        Some(s) => s,
        None => {
            let newest: i64 = sqlx::query_scalar("SELECT coalesce(max(seq), 0) FROM events")
                .fetch_one(&app.pool)
                .await?;
            save_cursor(app, newest).await?;
            return Ok(0);
        }
    };
    // Ends younger than this wait (idle debounce): they, and everything after them, are for the next tick.
    let hold = iso_of_unix(now - IDLE_SECS);
    let old = iso_of_unix(now - STALE_END_SECS);
    let (mut queued, mut synced) = (0, false);
    'pages: for _ in 0..MAX_PAGES {
        let batch = events::list_events(&app.pool, from, PAGE).await?;
        let Some(last) = batch.last().map(|e| e.seq) else {
            break;
        };
        for e in &batch {
            if e.kind == "agent.ended" {
                if e.at > hold {
                    break 'pages;
                }
                if let Some(id) = e.payload["session"].as_str() {
                    // An end this old is not waited on: it skips the sync (a failing sync must not
                    // hold it) and is queued from whatever is already collected.
                    let stale = e.at < old;
                    if !stale && !synced {
                        // Collects every finished session, this one among them, into its room.
                        match sync_core(app, b, None, None).await {
                            Ok(r) if r.idle.as_deref() == Some("running") => break 'pages,
                            Ok(_) => synced = true,
                            // The key is missing or locked: wait, nothing is lost.
                            Err(x) if x.status == StatusCode::CONFLICT => break 'pages,
                            // Any other failure may be temporary: log it and stop here. The cursor
                            // stays, the sync ran once this tick, no event is set aside.
                            Err(x) => {
                                tracing::error!(code = %x.code, session = id, "sync_core failed; the end events wait");
                                break 'pages;
                            }
                        }
                    }
                    // Past the cursor only once the event reached `queue`: a session the sync has
                    // not taken yet (200 a time) is read again next tick.
                    match session_ended(app, b, id, now, stale).await? {
                        Some(n) => queued += n,
                        None => break 'pages,
                    }
                }
            }
            from = e.seq;
            save_cursor(app, from).await?;
        }
        if batch.len() < PAGE as usize {
            break;
        }
        from = last;
    }
    Ok(queued)
}

async fn save_cursor(app: &App, seq: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO brain_session_cursor (id, seq) VALUES (1, ?) \
         ON CONFLICT (id) DO UPDATE SET seq = excluded.seq",
    )
    .bind(seq)
    .execute(&app.pool)
    .await
    .map(drop)
}

/// Import threshold: queue a distil for each room with enough, or old enough, undistilled sources.
async fn threshold(app: &App, b: &Brain, now: i64) -> Result<u32, ApiError> {
    if now - b.inner.auto_scan.load(Ordering::SeqCst) < SCAN_EVERY_SECS {
        return Ok(0);
    }
    b.inner.auto_scan.store(now, Ordering::SeqCst);
    let old = iso_of_unix(now - THRESHOLD_AGE_SECS);
    let mut queued = 0;
    for room in active_rooms(app).await? {
        let Some((n, oldest, _)) = stats(app, b, &room, "").await else {
            continue;
        };
        let due = n >= THRESHOLD_SOURCES || oldest.is_some_and(|o| o <= old);
        if due && queue(app, &room, "threshold", None, n, now).await? == Queued::Yes {
            queued += 1;
        }
    }
    Ok(queued)
}

/// One look at the triggers at unix time `now`; returns how many distils it queued.
pub(crate) async fn step(app: &App, b: &Brain, now: i64) -> Result<u32, ApiError> {
    let Some(_busy) = Busy::take(&b.inner.auto_busy) else {
        return Ok(0);
    };
    // No key, no rooms to read: nothing to do until the first import made it.
    if b.key(app).await.is_err() {
        return Ok(0);
    }
    // The threshold scan has its own path: a failure of the event reader never sits in front of it.
    let from_events = ended(app, b, now).await;
    let from_scan = threshold(app, b, now).await;
    Ok(from_events? + from_scan?)
}

struct AutoJob(Brain);

impl JobHandler for AutoJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let Some(app) = self.0.inner.app.get() else {
                return Err("the Core is still starting".to_owned());
            };
            match step(app, &self.0, app.clock.unix()).await {
                Ok(0) => run.idle(),
                // Launch what was queued now, not at the distil job's next tick.
                Ok(_) => {
                    let _ = distil::advance(app, &self.0).await;
                }
                Err(e) => return Err(format!("{}: {}", e.code, e.message)),
            }
            Ok(())
        })
    }
}

pub(crate) fn job(b: &Brain) -> Job {
    Job::new(
        "brain_auto_distil",
        Schedule::Every(EVERY_SECS),
        Arc::new(AutoJob(b.clone())),
    )
}

impl Brain {
    /// Looks at the automatic distil triggers as of unix time `now` (the `brain_auto_distil` job
    /// does this every 30 s with the Core's clock). Returns how many distils it queued.
    pub async fn auto_distil_step_at(&self, now: i64) -> Result<u32, ApiError> {
        match self.inner.app.get() {
            Some(app) => step(app, self, now).await,
            None => Ok(0),
        }
    }
}
