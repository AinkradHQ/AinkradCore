//! Re-distil and purge (Brain v2, B6-01): every source of a room goes through the whole pipeline
//! again (grounding, admission, judge, merge), then every old fact the pipeline did not re-derive is
//! archived, all in ONE change set with Undo. A dry run does the same and writes nothing.
//!
//! How it runs. A run is a row in `brain_redistils` (ids, states, counts) plus two staging tables in
//! the room file (`redistil_sources`, `redistil_batches`). A background job queues one batch at a
//! time as a distil of trigger `redistil` (`distil::launch` takes up to 30 sources from
//! `redistil_sources`, and `distil::save` hands the admitted answer to `stage` instead of saving
//! it). When every source is read, `commit` saves all staged batches and the archive in ONE
//! transaction: a crash leaves either nothing or all of it, and a run that is picked up again
//! reads only what is still unread (`redistil_sources.batch IS NULL`), so nothing is saved twice.
//! `redistil.applied` in the room's audit makes the commit itself idempotent.
//!
//! Security model (this is a destructive job that spends model calls):
//! - Person only: no AI session may start or read a run (`person_only`), and no AI op exists for it.
//!   Starting a real run (`POST /rooms/{room}/redistil`) needs a step-up; the dry run changes no
//!   memory, so it does not. One room at a time, Core-wide.
//! - Cost: a run's batches are their own budget (not the distil caps), counted from `brain_distils`
//!   rows of the last 24 hours, so a restart cannot reset them: `ROOM_DAILY` per room and
//!   `GLOBAL_DAILY` across rooms. At a cap the run waits for the window to roll over, and resumes.
//! - What is archived: only an accepted, current fact that no source of the run re-derived. Never a
//!   record a person created or edited (`origin = 'person'`, `edited_by_person = 1`), never the
//!   target of a contest (an unresolved conflict stays visible), never a record whose evidence this
//!   run could not read (it cites sources, none of them read: compacted, or not yet distilled).
//!   A run that re-derived nothing archives nothing (a model that answered nothing is not a verdict).
//! - Archived records stay 30 days (`changes::PURGE_DAYS`) and Undo restores them; Undo itself is
//!   capped at the same age (`changes::undo`).
//! - Sources are only read: `sources.text` is never written. `sources.redistil` marks what a real run
//!   will read, so retention does not compact it meanwhile, and is cleared in the commit.
//! - Counts only leave the room: the control DB, the audit and the API carry ids and numbers.

use std::sync::Arc;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, Caller};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::scheduler::iso_of_unix;
use ainkrad_core_server::store::begin_write;
use ainkrad_proto::redact::Redactor;
use brain_model::merge::Grounding;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqliteConnection, SqlitePool};

use crate::answer::{Candidate, Source};
use crate::changes::ChangeSet;
use crate::distil::{self, DistilledBy, log_op};
use crate::judge::Dropped;
use crate::merge::{Memory, Prepared};
use crate::save::{Batch, drop_pending, save_into};
use crate::sync::Busy;
use crate::{Brain, code, policy, rand_id, record};

/// Batches (distils) one room may use per rolling 24 hours, and all rooms together.
pub const ROOM_DAILY: i64 = 60;
pub const GLOBAL_DAILY: i64 = 120;
/// Failures in a row (a batch that failed, or an error) that stop a run; starting it again resumes.
const MAX_FAILURES: i64 = 3;
/// How often the job looks at the run; each look queues at most one batch.
const EVERY_SECS: u64 = 60;
const OPEN: &str = "'queued','needs_local_model','waiting','running'";

/// A run of `brain_redistils`.
#[derive(Clone)]
pub(crate) struct RunRow {
    pub id: String,
    pub room: String,
    pub dry: bool,
    pub state: String,
    pub by: String,
    pub failures: i64,
    pub detail: String,
}

fn row_of(r: &sqlx::sqlite::SqliteRow) -> Result<RunRow, sqlx::Error> {
    Ok(RunRow {
        id: r.try_get("id")?,
        room: r.try_get("room")?,
        dry: r.try_get::<i64, _>("dry_run")? == 1,
        state: r.try_get("state")?,
        by: r.try_get("requested_by")?,
        failures: r.try_get("failures")?,
        detail: r.try_get("detail")?,
    })
}

/// What a pass came to. `kept` counts old facts that stay, `new_facts` the ones written.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct Outcome {
    pub kept: i64,
    pub new_facts: i64,
    pub archived: i64,
    pub reinforced: i64,
    pub dropped: i64,
    pub change: Option<String>,
    pub note: String,
}

/// "Kept 84 facts, archived 1,203 items" (a dry run says "Would keep ..., archive ...").
pub(crate) fn summary_line(facts: i64, archived: i64, dry: bool) -> String {
    let group = |n: i64| {
        let s = n.to_string();
        let mut out = String::new();
        for (i, c) in s.chars().enumerate() {
            if i > 0 && (s.len() - i) % 3 == 0 {
                out.push(',');
            }
            out.push(c);
        }
        out
    };
    let (f, a) = (
        if facts == 1 { "fact" } else { "facts" },
        if archived == 1 { "item" } else { "items" },
    );
    if dry {
        format!(
            "Would keep {} {f}, archive {} {a}",
            group(facts),
            group(archived)
        )
    } else {
        format!(
            "Kept {} {f}, archived {} {a}",
            group(facts),
            group(archived)
        )
    }
}

/// The run a batch distil belongs to.
pub(crate) async fn run_of(app: &App, distil: &str) -> Result<Option<String>, sqlx::Error> {
    let run: Option<Option<String>> =
        sqlx::query_scalar("SELECT redistil FROM brain_distils WHERE id = ?")
            .bind(distil)
            .fetch_optional(&app.pool)
            .await?;
    Ok(run.flatten())
}

/// Gives back what a batch of `distil` took without answering (a launch that did not finish).
pub(crate) async fn release(pool: &SqlitePool, run: &str, distil: &str) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE redistil_sources SET batch = NULL WHERE run = ?1 AND batch IN \
         (SELECT seq FROM redistil_batches WHERE run = ?1 AND distil = ?2 AND payload IS NULL)",
    )
    .bind(run)
    .bind(distil)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM redistil_batches WHERE run = ? AND distil = ? AND payload IS NULL")
        .bind(run)
        .bind(distil)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

/// A batch takes `sources` (the launch's transaction): the next batch number, and each source marked
/// with it. `sources` itself is not written.
pub(crate) async fn take(
    conn: &mut SqliteConnection,
    run: &str,
    distil: &str,
    sources: &[Source],
) -> Result<(), sqlx::Error> {
    let seq: i64 =
        sqlx::query_scalar("SELECT coalesce(max(seq), 0) + 1 FROM redistil_batches WHERE run = ?")
            .bind(run)
            .fetch_one(&mut *conn)
            .await?;
    sqlx::query("INSERT INTO redistil_batches (run, seq, distil) VALUES (?, ?, ?)")
        .bind(run)
        .bind(seq)
        .bind(distil)
        .execute(&mut *conn)
        .await?;
    for s in sources {
        sqlx::query("UPDATE redistil_sources SET batch = ? WHERE run = ? AND item_id = ?")
            .bind(seq)
            .bind(run)
            .bind(&s.item_id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// What a batch answered, as `stage` stores it and `pass` reads it.
#[derive(Serialize, Deserialize)]
struct Staged {
    out: Vec<Candidate>,
    dropped: Vec<Dropped>,
    /// `[user_turn, structured_item]` per candidate.
    grounded: Vec<[bool; 2]>,
    by: DistilledBy,
}

/// Keeps a batch's admitted answer until the run's commit (the same call twice stores it once).
pub(crate) async fn stage(
    pool: &SqlitePool,
    run: &str,
    distil: &str,
    out: &[Candidate],
    dropped: &[Dropped],
    by: &DistilledBy,
    grounded: &[Grounding],
) -> Result<(), sqlx::Error> {
    let payload = json!({
        "out": out, "dropped": dropped, "by": by,
        "grounded": grounded.iter().map(|g| [g.user_turn, g.structured_item]).collect::<Vec<_>>(),
    })
    .to_string();
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE redistil_batches SET payload = ? WHERE run = ? AND distil = ?")
        .bind(payload)
        .bind(run)
        .bind(distil)
        .execute(&mut *tx)
        .await?;
    drop_pending(&mut tx, distil).await?;
    tx.commit().await
}

/// Starts a run of `room`, or resumes the open or failed one of the same kind. One room at a time.
pub(crate) async fn start(
    app: &App,
    b: &Brain,
    me: &Caller,
    room: &str,
    dry: bool,
) -> Result<RunRow, ApiError> {
    policy::load(app, room).await?;
    let pool = distil::canon(app, b, room).await?;
    let eligible: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM sources WHERE {READABLE}"
    )))
    .fetch_one(&pool)
    .await?;
    if eligible == 0 {
        pool.close().await;
        return Err(code(
            409,
            "nothing_to_redistil",
            "the room has no distilled source to read again",
        ));
    }
    let now = app.clock.now();
    let mut tx = begin_write(&app.pool).await?;
    let active = sqlx::query(
        "SELECT * FROM brain_redistils WHERE state IN ('running','committing') ORDER BY started_at LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    .map(|r| row_of(&r))
    .transpose()?;
    let mut run = match active {
        Some(a) if a.room != room => {
            return Err(code(
                409,
                "redistil_busy",
                "a run of another room is open; one room at a time",
            ));
        }
        Some(a) if a.dry != dry => {
            return Err(code(
                409,
                "redistil_open",
                "a run of this room is already open",
            ));
        }
        Some(a) => Some(a),
        None => None,
    };
    if run.is_none() {
        // A failed run of the same kind is resumed: what it read is kept.
        run = sqlx::query(
            "SELECT * FROM brain_redistils WHERE room = ? AND dry_run = ? AND state = 'failed' \
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(room)
        .bind(i64::from(dry))
        .fetch_optional(&mut *tx)
        .await?
        .map(|r| row_of(&r))
        .transpose()?;
        if let Some(r) = &mut run {
            sqlx::query("UPDATE brain_redistils SET state = 'running', failures = 0, detail = '', updated_at = ? WHERE id = ?")
                .bind(&now)
                .bind(&r.id)
                .execute(&mut *tx)
                .await?;
            r.state = "running".into();
            r.failures = 0;
        }
    }
    let run = match run {
        Some(r) => r,
        None => {
            let id = rand_id("rds-");
            sqlx::query(
                "INSERT INTO brain_redistils (id, room, dry_run, state, requested_by, started_at, updated_at) \
                 VALUES (?, ?, ?, 'running', ?, ?, ?)",
            )
            .bind(&id)
            .bind(room)
            .bind(i64::from(dry))
            .bind(&me.device.id)
            .bind(&now)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
            record(
                &mut tx,
                "brain.redistil.started",
                json!({"room": room, "run": id, "dry_run": dry}),
                None,
            )
            .await?;
            RunRow {
                id,
                room: room.to_owned(),
                dry,
                state: "running".into(),
                by: me.device.id.clone(),
                failures: 0,
                detail: String::new(),
            }
        }
    };
    tx.commit().await?;
    // The snapshot of what the run reads (a resumed run keeps its own: the insert ignores known rows),
    // and, for a real run, the mark that keeps retention off those sources until the commit.
    let snap = async {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT OR IGNORE INTO redistil_sources (run, item_id) SELECT ?, item_id FROM sources WHERE {READABLE}"
        )))
        .bind(&run.id)
        .execute(&pool)
        .await?;
        if !run.dry {
            sqlx::query(
                "UPDATE sources SET redistil = ?1 WHERE item_id IN (SELECT item_id FROM redistil_sources WHERE run = ?1)",
            )
            .bind(&run.id)
            .execute(&pool)
            .await?;
        }
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM redistil_sources WHERE run = ?")
            .bind(&run.id)
            .fetch_one(&pool)
            .await
    }
    .await;
    pool.close().await;
    let total = snap?;
    sqlx::query("UPDATE brain_redistils SET total = ? WHERE id = ?")
        .bind(total)
        .bind(&run.id)
        .execute(&app.pool)
        .await?;
    Ok(run)
}

/// The sources a run can read: distilled before (the rest wait for their first distil), still holding
/// their text, not pointers.
const READABLE: &str =
    "pointer = 0 AND compacted_at IS NULL AND text <> '' AND distilled IS NOT NULL";

async fn open_run(app: &App) -> Result<Option<RunRow>, sqlx::Error> {
    sqlx::query("SELECT * FROM brain_redistils WHERE state IN ('running','committing') ORDER BY started_at LIMIT 1")
        .fetch_optional(&app.pool)
        .await?
        .map(|r| row_of(&r))
        .transpose()
}

/// One failure of `run`; the third in a row fails it (its marks are cleared, starting it resumes).
/// Returns whether the run is still going.
async fn bump(app: &App, b: &Brain, run: &RunRow, why: &str) -> Result<bool, ApiError> {
    let failed = run.failures + 1 >= MAX_FAILURES;
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "UPDATE brain_redistils SET failures = failures + 1, detail = ?, updated_at = ?, \
         state = CASE WHEN ? THEN 'failed' ELSE state END WHERE id = ?",
    )
    .bind(why)
    .bind(app.clock.now())
    .bind(failed)
    .bind(&run.id)
    .execute(&mut *tx)
    .await?;
    if failed {
        record(
            &mut tx,
            "brain.redistil.failed",
            json!({"room": run.room, "run": run.id, "dry_run": run.dry}),
            None,
        )
        .await?;
    }
    tx.commit().await?;
    if failed && let Ok(pool) = distil::canon(app, b, &run.room).await {
        let _ = sqlx::query("UPDATE sources SET redistil = NULL WHERE redistil = ?")
            .bind(&run.id)
            .execute(&pool)
            .await;
        pool.close().await;
    }
    Ok(!failed)
}

/// One look at the open run at unix time `now`. Returns what it did: 1 for a batch queued or a
/// commit made, 0 for nothing (waiting on a batch, a cap, or no run).
pub(crate) async fn step(
    app: &App,
    b: &Brain,
    now: i64,
    caps: (i64, i64),
) -> Result<u32, ApiError> {
    let Some(_busy) = Busy::take(&b.inner.redistilling) else {
        return Ok(0);
    };
    if b.key(app).await.is_err() {
        return Ok(0);
    }
    let Some(run) = open_run(app).await? else {
        return Ok(0);
    };
    let done = match distil::canon(app, b, &run.room).await {
        Ok(pool) => {
            let out = drive(app, b, &run, &pool, now, caps).await;
            pool.close().await;
            out
        }
        Err(e) => Err(e),
    };
    match done {
        Ok(n) => Ok(n),
        // An error may be temporary: it counts as one failure, the run goes on until the third.
        Err(e) => {
            tracing::warn!(run = %run.id, code = %e.code, "re-distil step failed");
            bump(app, b, &run, &format!("{}: {}", e.code, e.message)).await?;
            Ok(0)
        }
    }
}

async fn drive(
    app: &App,
    b: &Brain,
    run: &RunRow,
    pool: &SqlitePool,
    now: i64,
    caps: (i64, i64),
) -> Result<u32, ApiError> {
    let p = match policy::load(app, &run.room).await {
        Ok(p) => p,
        Err(e) if e.status == axum::http::StatusCode::NOT_FOUND => {
            for _ in 0..MAX_FAILURES {
                bump(app, b, run, "the room is gone").await?;
            }
            return Ok(0);
        }
        Err(e) => return Err(e),
    };
    if run.state == "running" {
        // A batch of this run is queued or working: the distil job moves it.
        let open: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM brain_distils WHERE redistil = ? AND state IN ({OPEN})"
        )))
        .bind(&run.id)
        .fetch_one(&app.pool)
        .await?;
        if open > 0 {
            return Ok(0);
        }
        if !settle(app, b, run, pool).await? {
            return Ok(0);
        }
        // A source compacted since the snapshot has no text to read.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DELETE FROM redistil_sources WHERE run = ? AND batch IS NULL \
             AND item_id NOT IN (SELECT item_id FROM sources WHERE {READABLE})"
        )))
        .bind(&run.id)
        .execute(pool)
        .await?;
        let (pending, read): (i64, i64) = sqlx::query_as(
            "SELECT coalesce(sum(batch IS NULL), 0), coalesce(sum(batch IS NOT NULL), 0) \
             FROM redistil_sources WHERE run = ?",
        )
        .bind(&run.id)
        .fetch_one(pool)
        .await?;
        // Progress resets the failure count: three in a row stop a run, not three in a long one.
        sqlx::query(
            "UPDATE brain_redistils SET total = ?1, failures = CASE WHEN ?2 > read THEN 0 ELSE failures END, \
             read = ?2, updated_at = ?3 WHERE id = ?4",
        )
        .bind(pending + read)
        .bind(read)
        .bind(iso_of_unix(now))
        .bind(&run.id)
        .execute(&app.pool)
        .await?;
        if pending > 0 {
            return Ok(u32::from(queue(app, run, &p, pending, now, caps).await?));
        }
        sqlx::query("UPDATE brain_redistils SET state = 'committing', detail = '' WHERE id = ?")
            .bind(&run.id)
            .execute(&app.pool)
            .await?;
    }
    commit(app, b, run, pool, &p).await?;
    Ok(1)
}

/// Batches that ended without an answer give their sources back; a failed one is a failure.
/// Returns whether the run is still going.
async fn settle(app: &App, b: &Brain, run: &RunRow, pool: &SqlitePool) -> Result<bool, ApiError> {
    let stale: Vec<(String,)> =
        sqlx::query_as("SELECT distil FROM redistil_batches WHERE run = ? AND payload IS NULL")
            .bind(&run.id)
            .fetch_all(pool)
            .await?;
    for (distil,) in stale {
        let state: Option<String> =
            sqlx::query_scalar("SELECT state FROM brain_distils WHERE id = ?")
                .bind(&distil)
                .fetch_optional(&app.pool)
                .await?;
        release(pool, &run.id, &distil).await?;
        if state.as_deref() != Some("done") && !bump(app, b, run, "a batch failed").await? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Queues the next batch unless a cap says wait. Returns whether one was queued.
async fn queue(
    app: &App,
    run: &RunRow,
    p: &policy::Policy,
    pending: i64,
    now: i64,
    (room_cap, global_cap): (i64, i64),
) -> Result<bool, ApiError> {
    let since = iso_of_unix(now - 86_400);
    let at = iso_of_unix(now);
    let mut tx = begin_write(&app.pool).await?;
    let (in_room, in_all): (i64, i64) = sqlx::query_as(
        "SELECT coalesce(sum(room = ?), 0), count(*) FROM brain_distils \
         WHERE \"trigger\" = 'redistil' AND created_at >= ?",
    )
    .bind(&run.room)
    .bind(&since)
    .fetch_one(&mut *tx)
    .await?;
    if in_room >= room_cap || in_all >= global_cap {
        sqlx::query("UPDATE brain_redistils SET detail = ? WHERE id = ?")
            .bind("daily limit reached; it goes on when the 24 hours roll over")
            .bind(&run.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(false);
    }
    // A local-only room waits for a local model, as any distil does.
    let state = if p.local_only() {
        "needs_local_model"
    } else {
        "queued"
    };
    let inserted = sqlx::query(
        "INSERT INTO brain_distils (id, room, state, requested_by, sources, \"trigger\", redistil, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, 'redistil', ?, ?, ?)",
    )
    .bind(rand_id("dst-"))
    .bind(&run.room)
    .bind(state)
    .bind(&run.by)
    .bind(pending.min(30))
    .bind(&run.id)
    .bind(&at)
    .bind(&at)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        // Another distil of the room is open (one open distil per room, by index): wait for it.
        Err(e)
            if e.as_database_error()
                .is_some_and(|d| d.is_unique_violation()) =>
        {
            return Ok(false);
        }
        Err(e) => return Err(e.into()),
    }
    sqlx::query("UPDATE brain_redistils SET detail = '' WHERE id = ?")
        .bind(&run.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// The write (or, for a dry run, its count), then the run's end.
async fn commit(
    app: &App,
    b: &Brain,
    run: &RunRow,
    pool: &SqlitePool,
    p: &policy::Policy,
) -> Result<(), ApiError> {
    // A commit that landed but whose run row did not move (a crash between) is not made twice.
    let applied: Option<String> = if run.dry {
        None
    } else {
        sqlx::query_scalar(
            "SELECT detail FROM room_audit WHERE action = 'redistil.applied' AND json_extract(detail, '$.run') = ?",
        )
        .bind(&run.id)
        .fetch_optional(pool)
        .await?
    };
    let out = match applied.and_then(|d| serde_json::from_str::<Outcome>(&d).ok()) {
        Some(o) => o,
        None => pass(app, b, run, pool, p, &app.clock.now()).await?,
    };
    sqlx::query("DELETE FROM redistil_batches WHERE run = ?")
        .bind(&run.id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM redistil_sources WHERE run = ?")
        .bind(&run.id)
        .execute(pool)
        .await?;
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "UPDATE brain_redistils SET state = 'done', kept = ?, new_facts = ?, archived = ?, change = ?, \
         detail = ?, updated_at = ? WHERE id = ?",
    )
    .bind(out.kept)
    .bind(out.new_facts)
    .bind(out.archived)
    .bind(&out.change)
    .bind(&out.note)
    .bind(app.clock.now())
    .bind(&run.id)
    .execute(&mut *tx)
    .await?;
    record(
        &mut tx,
        if run.dry {
            "brain.redistil.previewed"
        } else {
            "brain.redistil.done"
        },
        json!({"room": run.room, "run": run.id, "kept": out.kept, "new": out.new_facts,
               "archived": out.archived, "change": out.change}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Saves every staged batch and archives what nothing re-derived, in one transaction and one change
/// set; a dry run rolls it back after counting.
async fn pass(
    app: &App,
    b: &Brain,
    run: &RunRow,
    pool: &SqlitePool,
    p: &policy::Policy,
    now: &str,
) -> Result<Outcome, ApiError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT distil, payload FROM redistil_batches WHERE run = ? AND payload IS NOT NULL ORDER BY seq",
    )
    .bind(&run.id)
    .fetch_all(pool)
    .await?;
    let staged = rows
        .into_iter()
        .map(|(d, j)| {
            serde_json::from_str::<Staged>(&j)
                .map(|s| (d, s))
                .map_err(|e| code(500, "redistil_unreadable", e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let redactor = Redactor::new();
    let mut preps = vec![];
    for (_, s) in &staged {
        let bodies: Vec<String> = s.out.iter().map(|c| redactor.text(c.body.trim())).collect();
        preps.push(crate::merge::prepare(app, b, pool, &bodies).await);
    }
    let none = Prepared::default();
    let mut tx = pool.begin().await?;
    let old: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT id, support, (SELECT count(*) FROM record_sources s WHERE s.record = memory.id) FROM memory",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut cs = ChangeSet::new("archive", now);
    let mut memory = Memory::load(&mut tx, preps.first().unwrap_or(&none)).await?;
    let (mut candidates, mut reinforced, mut dropped) = (0usize, 0, 0);
    for ((distil, s), prep) in staged.iter().zip(&preps) {
        let grounded: Vec<Grounding> = s
            .grounded
            .iter()
            .map(|g| Grounding {
                user_turn: g[0],
                structured_item: g[1],
            })
            .collect();
        let batch = Batch {
            distil,
            out: &s.out,
            dropped: &s.dropped,
            by: &s.by,
            prep,
            grounded: &grounded,
        };
        let saved = save_into(&mut tx, &mut cs, &mut memory, p, now, &batch).await?;
        candidates += s.out.len();
        reinforced += saved.reinforced;
        dropped += saved.dropped;
    }
    // Re-reading the same sources is not new evidence: a re-derived record's support grows only by the
    // sources it newly cites.
    for (id, support, cited) in &old {
        sqlx::query(
            "UPDATE records SET support = ?1 + max(0, (SELECT count(*) FROM record_sources WHERE record = ?2) - ?3) \
             WHERE id = ?2 AND last_seen_at = ?4",
        )
        .bind(support)
        .bind(id)
        .bind(cited)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    let mut note = String::new();
    let old_ids: Vec<&str> = old.iter().map(|(id, _, _)| id.as_str()).collect();
    let mut doomed: Vec<String> = sqlx::query_scalar(
        "SELECT m.id FROM memory m WHERE m.id IN (SELECT value FROM json_each(?1)) \
         AND coalesce(m.last_seen_at, '') <> ?2 \
         AND m.origin <> 'person' AND m.edited_by_person = 0 \
         AND m.id NOT IN (SELECT contests FROM records WHERE contests IS NOT NULL) \
         AND (NOT EXISTS (SELECT 1 FROM record_sources x WHERE x.record = m.id) \
              OR EXISTS (SELECT 1 FROM record_sources x JOIN redistil_sources r \
                         ON r.item_id = x.source AND r.run = ?3 AND r.batch IS NOT NULL WHERE x.record = m.id))",
    )
    .bind(json!(old_ids).to_string())
    .bind(now)
    .bind(&run.id)
    .fetch_all(&mut *tx)
    .await?;
    if candidates == 0 && !doomed.is_empty() {
        doomed.clear();
        note = "the model gave no facts, so nothing was archived".to_owned();
    }
    for id in &doomed {
        cs.touch(&mut tx, id).await?;
        sqlx::query("UPDATE records SET archived_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        log_op(&mut tx, "record.archived", id, now).await?;
    }
    let after: Vec<String> = sqlx::query_scalar("SELECT id FROM memory")
        .fetch_all(&mut *tx)
        .await?;
    let kept = after
        .iter()
        .filter(|id| old_ids.contains(&id.as_str()))
        .count() as i64;
    let new_facts = after.len() as i64 - kept;
    let archived = doomed.len() as i64;
    let mut out = Outcome {
        kept,
        new_facts,
        archived,
        reinforced,
        dropped,
        change: None,
        note,
    };
    if !run.dry {
        let counts = json!({"kept": kept, "new": new_facts, "archived": archived,
            "reinforced": reinforced, "dropped": dropped});
        out.change = cs
            .commit(
                &mut tx,
                &summary_line(kept + new_facts, archived, false),
                counts,
            )
            .await?;
        sqlx::query("UPDATE sources SET redistil = NULL WHERE redistil = ?")
            .bind(&run.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO room_audit (action, detail, at) VALUES ('redistil.applied', ?, ?)",
        )
        .bind(
            json!({"run": run.id, "kept": out.kept, "new_facts": out.new_facts,
                         "archived": out.archived, "reinforced": out.reinforced,
                         "dropped": out.dropped, "change": out.change, "note": out.note})
            .to_string(),
        )
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        let fresh: Vec<(Option<String>, String)> =
            sqlx::query_as("SELECT body_norm, body FROM memory WHERE created_at = ?")
                .bind(now)
                .fetch_all(pool)
                .await?;
        b.queue_record_vectors(&fresh);
    } else {
        tx.rollback().await?;
    }
    Ok(out)
}

struct RedistilJob(Brain);

impl JobHandler for RedistilJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let Some(app) = self.0.inner.app.get() else {
                return Err("the Core is still starting".to_owned());
            };
            match step(app, &self.0, app.clock.unix(), (ROOM_DAILY, GLOBAL_DAILY)).await {
                Ok(0) => run.idle(),
                // Launch the batch now, not at the distil job's next tick.
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
        "brain_redistil",
        Schedule::Every(EVERY_SECS),
        Arc::new(RedistilJob(b.clone())),
    )
}

impl Brain {
    /// Looks at the open re-distil run as of unix time `now` with the default caps (the
    /// `brain_redistil` job does this every minute). Returns 1 when it queued a batch or committed.
    pub async fn redistil_step_at(&self, now: i64) -> Result<u32, ApiError> {
        self.redistil_step_capped(now, ROOM_DAILY, GLOBAL_DAILY)
            .await
    }

    /// As `redistil_step_at`, with the batches allowed per room and across rooms in 24 hours.
    pub async fn redistil_step_capped(
        &self,
        now: i64,
        room: i64,
        global: i64,
    ) -> Result<u32, ApiError> {
        match self.inner.app.get() {
            Some(app) => step(app, self, now, (room, global)).await,
            None => Ok(0),
        }
    }
}
