//! Automatic distillation (Brain v2, B5-01): a distil is queued for a room when an AI session ends
//! (`agent.ended`) and when a room piles up undistilled sources (a count or an age).
//!
//! Security model (this is a cost and DoS surface, so the whole policy is here):
//! - Only the Core's own event log starts a trigger. No route, no AI op and no session text can ask
//!   for one: an AI session can at most cause its own end, and that is bounded by the caps below.
//! - Caps are counted from `brain_distils` rows of the UTC day, so a restart or a crash cannot reset
//!   them: `brain_room_policy.daily_distils` per room and `GLOBAL_DAILY` across rooms. A trigger over
//!   a cap is dropped and audited (`brain.distil.capped`), never turned into a failed distil.
//!   Redistil, tidy and judge runs have their own budget and are not counted.
//! - One open distil per room: triggers coalesce into it. A session gets one `session_end` distil
//!   (`of_session`), however often its end event is read.
//! - Queueing happens in one write transaction (check, cap, insert), so two ticks or a crash in
//!   between never leave a duplicate or a half-made row. The event cursor moves only after the
//!   events before it were handled, so a crash replays them, and replays are harmless.
//! - Brain-owned sessions (distil, judge, tidy, overview) are never a trigger, and never a source.
//! - The first run starts at the newest event: history is not distilled by surprise.
//! - Mid-session checkpoints (`checkpoint.rs`) queue through the same `queue`, so they share every cap.
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

use crate::sync::{Busy, sync_core};
use crate::{Brain, MODULE, distil, policy, rand_id, record};

/// How often the triggers are looked at.
const EVERY_SECS: u64 = 30;
/// Idle debounce: a session's end is acted on this long after it happened, so a burst of ends in
/// one room (and the sync that collects them) settles into one distil.
pub(crate) const IDLE_SECS: i64 = 45;
/// Import threshold (a Q value): this many undistilled sources in a room ...
const THRESHOLD_SOURCES: i64 = 40;
/// ... or the oldest undistilled source this old.
const THRESHOLD_AGE_SECS: i64 = 6 * 3600;
/// How often the rooms are scanned for the threshold.
const SCAN_EVERY_SECS: i64 = 300;
/// Automatic and manual distils across all rooms per UTC day.
const GLOBAL_DAILY: i64 = 100;
const PAGE: u32 = 200;
const MAX_PAGES: u32 = 10;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Queued {
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

/// The device the distil runs as (its user's fallback chain): who asked for a distil last, else the
/// oldest active device. No device, no distil.
async fn requester(app: &App) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM core_devices WHERE kind = 'device' AND status = 'active' AND revoked_at IS NULL \
         ORDER BY (id IN (SELECT requested_by FROM brain_distils WHERE \"trigger\" = 'manual')) DESC, seq LIMIT 1",
    )
    .fetch_optional(&app.pool)
    .await
}

/// Queues one distil of `room` (`fresh` undistilled sources) unless a gate says no. One write
/// transaction: the checks and the insert cannot be split by another tick.
pub(crate) async fn queue(
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
    let at = iso_of_unix(now);
    let mut tx = begin_write(&app.pool).await?;
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
                "SELECT count(*) FROM brain_distils WHERE of_session = ? AND \"trigger\" = 'session_end'",
            )
            .bind(s)
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
    .bind(&day)
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
            record(
                &mut tx,
                "brain.distil.capped",
                json!({"room": room, "trigger": trigger, "session": session, "cap": which, "limit": limit}),
                None,
            )
            .await?;
            tx.commit().await?;
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
    sqlx::query(
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
    .await?;
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

/// A session ended: queue a distil for each room its collected transcript landed in.
async fn session_ended(app: &App, b: &Brain, session: &str, now: i64) -> Result<u32, ApiError> {
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
        _ => return Ok(0),
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
    Ok(queued)
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
                    if !synced {
                        // Collects every finished session, this one among them, into its room.
                        match sync_core(app, b, None, None).await {
                            Ok(r) if r.idle.as_deref() == Some("running") => break 'pages,
                            Ok(_) => synced = true,
                            // The brain key is missing or locked: wait, nothing is lost.
                            Err(x) if x.status == StatusCode::CONFLICT => break 'pages,
                            Err(x) => return Err(x),
                        }
                    }
                    queued += session_ended(app, b, id, now).await?;
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
    Ok(ended(app, b, now).await?
        + threshold(app, b, now).await?
        + crate::checkpoint::step(app, b, now).await?)
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
