//! The running half of room tidy (B9-01): what starts a tidy of a room, how a finished session's
//! answer is validated and applied, and the job. The limits live in `room_tidy`.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::scheduler::iso_of_unix;
use ainkrad_core_server::store::agents as store;
use ainkrad_core_server::store::begin_write;
use serde_json::json;
use sqlx::SqlitePool;

use crate::answer::one_line;
use crate::distil::{self, answer_of};
use crate::room_tidy::{
    AGENT, EVERY_SECS, PENDING_SECS, apply, build_prompt, due, shown_in, validate, within_caps,
};
use crate::{Brain, judge, record};

async fn started_since(app: &App, room: Option<&str>, since: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'brain.tidy.started' AND at >= ?1 \
         AND (?2 IS NULL OR json_extract(details, '$.room') = ?2)",
    )
    .bind(since)
    .bind(room)
    .fetch_one(&app.pool)
    .await
}

/// Starts a tidy of `room` when one is due and the caps allow. True when it started.
async fn start(app: &App, room: &str, pool: &SqlitePool, now: i64) -> Result<bool, ApiError> {
    let at = iso_of_unix(now);
    let since = iso_of_unix(now - 86_400);
    let last: Option<String> =
        sqlx::query_scalar("SELECT max(at) FROM room_audit WHERE action = 'tidy.run'")
            .fetch_one(pool)
            .await?;
    let new: i64 = sqlx::query_scalar("SELECT count(*) FROM memory WHERE created_at > ?")
        .bind(last.as_deref().unwrap_or(""))
        .fetch_one(pool)
        .await?;
    let age = last
        .as_deref()
        .and_then(ainkrad_core_server::scheduler::unix_secs)
        .map(|t| now - t);
    if !due(new, age) {
        return Ok(false);
    }
    let in_room = started_since(app, Some(room), &since).await?;
    let in_all = started_since(app, None, &since).await?;
    if !within_caps(in_room, in_all) {
        return Ok(false);
    }
    // The idle gate: not while a distil of the room is open, its records are still landing.
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM brain_distils WHERE room = ? \
         AND state IN ('queued','needs_local_model','waiting','running')",
    )
    .bind(room)
    .fetch_one(&app.pool)
    .await?;
    let Some(by) = crate::auto_distil::requester(app).await? else {
        return Ok(false);
    };
    if open > 0 {
        return Ok(false);
    }
    let shown = {
        let mut c = pool.acquire().await?;
        shown_in(&mut c).await?
    };
    if shown.len() < 2 {
        return Ok(false);
    }
    let name = crate::policy::load(app, room).await?.name;
    let prompt = build_prompt(&name, &shown);
    // The cap counts this row, so it is written BEFORE the session exists: a crash between the two
    // can only cost the day's slot, never let a second tidy start. (A declined launch costs it too.)
    let mut tx = begin_write(&app.pool).await?;
    record(&mut tx, "brain.tidy.started", json!({"room": room}), None).await?;
    tx.commit().await?;
    let Some(session) = judge::launch_as(app, room, &by, &prompt, AGENT).await? else {
        return Ok(false);
    };
    let ids: Vec<&str> = shown.iter().map(|s| s.id.as_str()).collect();
    let detail = json!({"session": session, "shown": ids}).to_string();
    for action in ["tidy.run", "tidy.pending"] {
        sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES (?, ?, ?)")
            .bind(action)
            .bind(&detail)
            .bind(&at)
            .execute(pool)
            .await?;
    }
    Ok(true)
}

/// Finishes a parked tidy whose session is over: validate, apply, say so. Nothing is applied for an
/// answer that does not pass.
async fn finish(
    app: &App,
    room: &str,
    pool: &SqlitePool,
    detail: &str,
    now: i64,
) -> Result<(), ApiError> {
    let v: serde_json::Value = serde_json::from_str(detail).unwrap_or_default();
    let session = v["session"].as_str().unwrap_or_default().to_owned();
    let shown: Vec<String> = v["shown"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let s = store::get(&app.pool, &session).await?;
    if let Some(s) = &s {
        if s.live() {
            let began: Option<String> = sqlx::query_scalar(
                "SELECT at FROM room_audit WHERE action = 'tidy.pending' \
                 AND json_extract(detail, '$.session') = ?",
            )
            .bind(&session)
            .fetch_optional(pool)
            .await?;
            let old = began
                .and_then(|b| ainkrad_core_server::scheduler::unix_secs(&b))
                .is_some_and(|t| now - t > PENDING_SECS);
            if !old {
                return Ok(());
            }
        }
    }
    let verdict = match &s {
        None => Err("the AI session is gone".to_owned()),
        Some(s) if s.live() => Err("the AI session did not end in time".to_owned()),
        Some(s) => match answer_of(app, &s.id).await? {
            None => Err("the AI session gave no answer".to_owned()),
            Some(o) => validate(&o, &shown.iter().map(String::as_str).collect()),
        },
    };
    if let Some(s) = &s {
        store::seal(&app.pool, &s.id).await?;
    }
    let mut tx = begin_write(&app.pool).await?;
    match verdict {
        Err(why) => {
            sqlx::query("DELETE FROM room_audit WHERE action = 'tidy.pending' AND json_extract(detail, '$.session') = ?")
                .bind(&session)
                .execute(pool)
                .await?;
            sqlx::query(
                "INSERT INTO room_audit (action, detail, at) VALUES ('tidy.rejected', ?, ?)",
            )
            .bind(json!({"session": session, "why": one_line(&why, 200)}).to_string())
            .bind(iso_of_unix(now))
            .execute(pool)
            .await?;
            record(
                &mut tx,
                "brain.tidy.rejected",
                json!({"room": room, "session": session}),
                None,
            )
            .await?;
        }
        Ok(a) => {
            let done = apply(pool, &a, &session, &iso_of_unix(now)).await?;
            let bell = done.change.as_ref().map(|c| {
                (
                    "brain.room",
                    json!({"room": room, "op": "tidied", "change": c, "archived": done.archived,
                           "merged": done.merged, "contested": done.contested}),
                )
            });
            record(
                &mut tx,
                "brain.tidy.done",
                json!({"room": room, "session": session, "archived": done.archived, "merged": done.merged,
                       "contested": done.contested, "refused": done.refused, "change": done.change}),
                bell,
            )
            .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

/// One look at every active room at unix time `now`. Returns how many tidies it started.
pub(crate) async fn step(app: &App, b: &Brain, now: i64) -> Result<u32, ApiError> {
    if b.inner.tidying.swap(true, Ordering::SeqCst) {
        return Ok(0);
    }
    let out = step_inner(app, b, now).await;
    b.inner.tidying.store(false, Ordering::SeqCst);
    out
}

async fn step_inner(app: &App, b: &Brain, now: i64) -> Result<u32, ApiError> {
    if b.key(app).await.is_err() {
        return Ok(0);
    }
    let rooms: Vec<String> =
        sqlx::query_scalar("SELECT id FROM brain_rooms WHERE state = 'active' ORDER BY id")
            .fetch_all(&app.pool)
            .await?;
    let mut started = 0;
    for room in rooms {
        let Ok(pool) = distil::canon(app, b, &room).await else {
            continue;
        };
        let parked: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM room_audit WHERE action = 'tidy.pending' ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&pool)
        .await?;
        let r = match parked {
            Some(d) => finish(app, &room, &pool, &d, now).await.map(|()| false),
            None => start(app, &room, &pool, now).await,
        };
        pool.close().await;
        match r {
            Ok(s) => started += u32::from(s),
            // One room's failure never stops the others.
            Err(e) => tracing::warn!(room = %room, code = %e.code, "room tidy step failed"),
        }
    }
    Ok(started)
}

struct TidyJob(Brain);

impl JobHandler for TidyJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let Some(app) = self.0.inner.app.get() else {
                return Err("the Core is still starting".to_owned());
            };
            match step(app, &self.0, app.clock.unix()).await {
                Ok(0) => run.idle(),
                Ok(_) => {}
                Err(e) => return Err(format!("{}: {}", e.code, e.message)),
            }
            Ok(())
        })
    }
}

pub(crate) fn job(b: &Brain) -> Job {
    Job::new(
        "brain_room_tidy",
        Schedule::Every(EVERY_SECS),
        Arc::new(TidyJob(b.clone())),
    )
}

impl Brain {
    /// Looks at the room tidies as of unix time `now` (the `brain_room_tidy` job does this every ten
    /// minutes). Returns how many it started.
    pub async fn room_tidy_step_at(&self, now: i64) -> Result<u32, ApiError> {
        match self.inner.app.get() {
            Some(app) => step(app, self, now).await,
            None => Ok(0),
        }
    }
}
