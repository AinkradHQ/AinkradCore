//! The jobs' tables: registering, firing what is due, the wake queue, claiming with a lease and
//! settling a run. Every function that changes state does so in one write transaction.

use std::collections::HashSet;
use std::sync::Arc;

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::{Value, json};
use sqlx::sqlite::{SqliteConnection, SqlitePool};
use sqlx::{Error, Row};

use super::{Cron, Missed, Run, Schedule};
use crate::module::Module;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::{audit, begin_write};

/// Longest wake payload, in bytes of JSON.
const MAX_PAYLOAD: usize = 16 * 1024;
/// A retry never waits longer than this.
const MAX_BACKOFF: i64 = 3600;
/// Finished runs are kept this long (seconds): 30 days.
const KEEP_SECS: i64 = 30 * 86_400;

fn refuse<T>(why: String) -> Result<T, Error> {
    Err(Error::InvalidArgument(why))
}

fn parts(s: &Schedule) -> (&'static str, String) {
    match s {
        Schedule::Cron(x) => ("cron", x.clone()),
        Schedule::Every(n) => ("every", n.to_string()),
        Schedule::Once(at) => ("once", at.clone()),
        Schedule::Wake => ("wake", String::new()),
    }
}

/// The occurrence after `now` (unix seconds) of a stored schedule; `after` is the occurrence
/// just handled, so an interval keeps its phase. `None` for a one-shot, a wake, or a corrupt row.
fn next(kind: &str, spec: &str, after: i64, now: i64) -> Option<i64> {
    match kind {
        "cron" => Cron::parse(spec).ok()?.next_after(now),
        "every" => {
            let every: i64 = spec.parse().ok().filter(|n| *n >= 1)?;
            Some(after + ((now - after).max(0) / every + 1) * every)
        }
        _ => None,
    }
}

/// The first occurrence of a schedule registered at `now`.
fn first(kind: &str, spec: &str, now: i64) -> Result<Option<i64>, String> {
    match kind {
        "cron" => Ok(Cron::parse(spec)?.next_after(now)),
        "every" => match spec.parse::<i64>() {
            Ok(n) if (1..=366 * 86_400).contains(&n) => Ok(Some(now + n)),
            _ => Err(format!("an interval is 1 second to a year, not {spec:?}")),
        },
        "once" => unix_secs(spec)
            .map(Some)
            .ok_or_else(|| format!("{spec:?} is not an RFC 3339 UTC time")),
        _ => Ok(None),
    }
}

fn name_ok(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Records the jobs `modules` declare: new ones scheduled from `now`, changed schedules
/// rescheduled, unchanged ones left where they are (their next occurrence survives a restart),
/// and jobs no module declares any more disabled. A bad name, schedule or bound refuses all of
/// it (`InvalidArgument`), so a module that declares one stops `serve` at start.
pub async fn register(
    pool: &SqlitePool,
    now: &str,
    modules: &[Arc<dyn Module>],
) -> Result<(), Error> {
    let now_unix = unix_secs(now).ok_or_else(|| Error::InvalidArgument("bad clock".into()))?;
    let mut tx = begin_write(pool).await?;
    let mut declared = HashSet::new();
    for m in modules {
        for j in m.jobs() {
            let owner = m.id();
            if !name_ok(j.name) {
                return refuse(format!(
                    "{owner}: job name {:?} is not 1-64 printable characters",
                    j.name
                ));
            }
            if !(1..=10).contains(&j.max_attempts) || !(1..=3600).contains(&j.backoff_secs) {
                return refuse(format!(
                    "{owner}.{}: attempts are 1-10 and backoff 1-3600 s",
                    j.name
                ));
            }
            if !declared.insert((owner.to_owned(), j.name.to_owned())) {
                return refuse(format!("{owner}.{} is declared twice", j.name));
            }
            let (kind, spec) = parts(&j.schedule);
            let next_at = first(kind, &spec, now_unix)
                .map_err(|why| Error::InvalidArgument(format!("{owner}.{}: {why}", j.name)))?
                .map(iso_of_unix);
            let held: Option<(String, String)> =
                sqlx::query_as("SELECT kind, spec FROM core_jobs WHERE owner = ? AND name = ?")
                    .bind(owner)
                    .bind(j.name)
                    .fetch_optional(&mut *tx)
                    .await?;
            let same = held.as_ref().is_some_and(|(k, s)| k == kind && *s == spec);
            let missed = if j.missed == Missed::Skip {
                "skip"
            } else {
                "run_once"
            };
            // The schedule is what `next_at` follows: it is kept when the schedule is unchanged.
            sqlx::query(
                "INSERT INTO core_jobs (owner, name, kind, spec, missed, grace_secs, max_attempts, \
                 backoff_secs, next_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                 ON CONFLICT (owner, name) DO UPDATE SET kind = ?3, spec = ?4, missed = ?5, \
                 grace_secs = ?6, max_attempts = ?7, backoff_secs = ?8, enabled = 1, \
                 next_at = iif(?10, next_at, ?9)",
            )
            .bind(owner)
            .bind(j.name)
            .bind(kind)
            .bind(&spec)
            .bind(missed)
            .bind(j.grace_secs)
            .bind(j.max_attempts)
            .bind(j.backoff_secs)
            .bind(next_at)
            .bind(same)
            .execute(&mut *tx)
            .await?;
        }
    }
    let all: Vec<(i64, String, String)> = sqlx::query_as("SELECT id, owner, name FROM core_jobs")
        .fetch_all(&mut *tx)
        .await?;
    for (id, owner, name) in all {
        if !declared.contains(&(owner, name)) {
            sqlx::query("UPDATE core_jobs SET enabled = 0 WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await
}

/// Queues a run of `owner`'s job `name` at `at` (now when `None`), carrying `payload`. `key`
/// makes it idempotent: waking twice with the same key queues one run (`false` the second
/// time, even after the first has finished). The job must be registered and enabled. The
/// platform's own jobs (`owner` `core`) are not for a module to wake: `wake_platform`.
pub async fn wake(
    pool: &SqlitePool,
    now: &str,
    owner: &str,
    name: &str,
    key: &str,
    payload: &Value,
    at: Option<&str>,
) -> Result<bool, Error> {
    if owner == crate::store::migrate::CORE {
        return refuse("the platform's jobs are woken by the platform only".to_owned());
    }
    let queued = queue(pool, now, owner, name, key, payload, at, None).await?;
    Ok(queued == Queued::New)
}

/// What [`wake_platform`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Queued {
    New,
    /// The key was used before: nothing queued.
    Duplicate,
    /// The queue holds its bound of waiting wakes: nothing queued.
    Full,
}

/// How many wakes of one platform job may wait (`queued` or `running`) in all, and for one
/// `payload.session`: the queue is bounded however often a client asks.
#[derive(Debug, Clone, Copy)]
pub struct Cap {
    pub total: i64,
    pub per_session: i64,
}

/// [`wake`] for the platform's own job `name`, refusing (`Full`) past `cap`. Only the platform
/// calls it: a handler of that job trusts the payload as the enqueuing route built it.
pub async fn wake_platform(
    pool: &SqlitePool,
    now: &str,
    name: &str,
    key: &str,
    payload: &Value,
    cap: Cap,
) -> Result<Queued, Error> {
    let owner = crate::store::migrate::CORE;
    queue(pool, now, owner, name, key, payload, None, Some(cap)).await
}

#[allow(clippy::too_many_arguments)]
async fn queue(
    pool: &SqlitePool,
    now: &str,
    owner: &str,
    name: &str,
    key: &str,
    payload: &Value,
    at: Option<&str>,
    cap: Option<Cap>,
) -> Result<Queued, Error> {
    if key.is_empty() || key.len() > 128 {
        return refuse("a wake key is 1 to 128 bytes".to_owned());
    }
    let mut payload = payload.clone();
    crate::store::redact::json(&mut payload);
    if payload.to_string().len() > MAX_PAYLOAD {
        return refuse(format!("a wake payload is at most {MAX_PAYLOAD} bytes"));
    }
    let at = match at {
        Some(t) if unix_secs(t).is_none() => return refuse(format!("{t:?} is not a time")),
        Some(t) => t,
        None => now,
    };
    let mut tx = begin_write(pool).await?;
    let job: Option<i64> =
        sqlx::query_scalar("SELECT id FROM core_jobs WHERE owner = ? AND name = ? AND enabled = 1")
            .bind(owner)
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(job) = job else {
        return refuse(format!("no job {owner}.{name} is registered"));
    };
    let idem = format!("wake:{key}");
    if let Some(cap) = cap {
        let seen: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM core_job_runs WHERE job_id = ? AND idem_key = ?",
        )
        .bind(job)
        .bind(&idem)
        .fetch_one(&mut *tx)
        .await?;
        let waiting = "FROM core_job_runs WHERE job_id = ?1 AND status IN ('queued', 'running')";
        let all: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) {waiting}")))
                .bind(job)
                .fetch_one(&mut *tx)
                .await?;
        let mine: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) {waiting} AND json_extract(payload, '$.session') = ?2"
        )))
        .bind(job)
        .bind(payload["session"].as_str().unwrap_or_default())
        .fetch_one(&mut *tx)
        .await?;
        if seen == 0 && (all >= cap.total || mine >= cap.per_session) {
            return Ok(Queued::Full);
        }
    }
    let queued = sqlx::query(
        "INSERT OR IGNORE INTO core_job_runs (job_id, idem_key, payload, due_at, run_at) \
         VALUES (?1, ?2, ?3, ?4, ?4)",
    )
    .bind(job)
    .bind(idem)
    .bind(payload.to_string())
    .bind(at)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(if queued {
        Queued::New
    } else {
        Queued::Duplicate
    })
}

/// Deletes finished runs older than 30 days, at most `limit` at a time; returns how many.
pub async fn prune(pool: &SqlitePool, now: &str, limit: i64) -> Result<u64, Error> {
    let cutoff = iso_of_unix(unix_secs(now).unwrap_or_default() - KEEP_SECS);
    sqlx::query(
        "DELETE FROM core_job_runs WHERE id IN (SELECT id FROM core_job_runs \
         WHERE finished_at IS NOT NULL AND finished_at < ? LIMIT ?)",
    )
    .bind(cutoff)
    .bind(limit)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

async fn note(
    conn: &mut SqliteConnection,
    action: &str,
    job: i64,
    details: Value,
) -> Result<(), Error> {
    let entry = NewAuditEvent {
        actor: AuditActor::System,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "job".to_owned(),
            id: job,
        }),
        details: details.to_string(),
    };
    audit::append(conn, &entry).await.map(drop)
}

/// Queues a run for every occurrence that is due at `now` and moves each job to its next one,
/// in one transaction: a crash leaves either both or neither, and a run is unique per occurrence,
/// so no occurrence is queued twice. Returns how many runs were queued.
pub async fn fire_due(pool: &SqlitePool, now: &str) -> Result<usize, Error> {
    let now_unix = unix_secs(now).unwrap_or_default();
    let mut tx = begin_write(pool).await?;
    let due = sqlx::query(
        "SELECT id, owner, name, kind, spec, missed, grace_secs, next_at FROM core_jobs \
         WHERE enabled = 1 AND next_at IS NOT NULL AND next_at <= ? ORDER BY next_at, id",
    )
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    let mut queued = 0;
    for row in due {
        let id: i64 = row.try_get("id")?;
        let (kind, spec): (String, String) = (row.try_get("kind")?, row.try_get("spec")?);
        let at: String = row.try_get("next_at")?;
        let at_unix = unix_secs(&at).unwrap_or(now_unix);
        let late = now_unix - at_unix;
        let skip = row.try_get::<String, _>("missed")? == "skip"
            && late > row.try_get::<i64, _>("grace_secs")?;
        if skip {
            let (owner, name): (String, String) = (row.try_get("owner")?, row.try_get("name")?);
            let details = json!({"owner": owner, "job": name, "due_at": at, "late_secs": late});
            note(&mut tx, "job.missed", id, details).await?;
        } else {
            let done = sqlx::query(
                "INSERT OR IGNORE INTO core_job_runs (job_id, idem_key, due_at, run_at) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(id)
            .bind(format!("sched:{at}"))
            .bind(&at)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            queued += done.rows_affected() as usize;
        }
        let upcoming = next(&kind, &spec, at_unix, now_unix).map(iso_of_unix);
        sqlx::query("UPDATE core_jobs SET next_at = ? WHERE id = ?")
            .bind(upcoming)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(queued)
}

/// A run a worker holds.
#[derive(Debug, Clone)]
pub struct Claimed {
    pub run: Run,
    pub job_id: i64,
    pub max_attempts: u32,
    pub backoff_secs: i64,
}

/// Settles a run in the audit log: `job.ran` for success, `job.failed` otherwise.
async fn settle(
    conn: &mut SqliteConnection,
    c: &Claimed,
    status: &str,
    error: Option<&str>,
) -> Result<(), Error> {
    let r = &c.run;
    let details = json!({
        "owner": r.owner, "job": r.job, "run": r.id, "key": r.key, "attempt": r.attempt,
        "status": status, "error": error,
    });
    let action = if status == "ok" {
        "job.ran"
    } else {
        "job.failed"
    };
    note(conn, action, c.job_id, details).await
}

/// Claims up to `limit` runs that are ready: queued and past their backoff, or running with a
/// lease that has expired (its worker died). Each gets `lease_secs` from `now`, a new `holder`
/// and one more attempt. A run whose lease expired with its attempts used up is settled `dead`
/// here instead of being run again.
pub async fn claim(
    pool: &SqlitePool,
    now: &str,
    holder: &str,
    lease_secs: i64,
    limit: usize,
) -> Result<Vec<Claimed>, Error> {
    let now_unix = unix_secs(now).unwrap_or_default();
    let lease = iso_of_unix(now_unix + lease_secs);
    let mut tx = begin_write(pool).await?;
    let columns = "r.id AS run_id, r.job_id, j.owner, j.name, r.idem_key, r.attempt, r.due_at, \
                   r.payload, j.max_attempts, j.backoff_secs";
    let from = "FROM core_job_runs r JOIN core_jobs j ON j.id = r.job_id";
    let exhausted = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {columns} {from} WHERE r.status = 'running' AND r.lease_until <= ? \
         AND r.attempt >= j.max_attempts"
    )))
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    for row in exhausted {
        let c = claimed(&row)?;
        sqlx::query(
            "UPDATE core_job_runs SET status = 'dead', holder = NULL, lease_until = NULL, \
             error = 'lease expired', finished_at = ? WHERE id = ?",
        )
        .bind(now)
        .bind(c.run.id)
        .execute(&mut *tx)
        .await?;
        settle(&mut tx, &c, "dead", Some("lease expired")).await?;
    }
    let ids: Vec<i64> = sqlx::query_scalar(
        "UPDATE core_job_runs SET status = 'running', holder = ?1, lease_until = ?2, \
         attempt = attempt + 1, started_at = ?3 WHERE id IN ( \
           SELECT r.id FROM core_job_runs r JOIN core_jobs j ON j.id = r.job_id \
           WHERE j.enabled = 1 AND ((r.status = 'queued' AND r.run_at <= ?3) \
              OR (r.status = 'running' AND r.lease_until <= ?3)) \
           ORDER BY r.run_at, r.id LIMIT ?4) RETURNING id",
    )
    .bind(holder)
    .bind(lease)
    .bind(now)
    .bind(limit as i64)
    .fetch_all(&mut *tx)
    .await?;
    let list: Vec<String> = ids.iter().map(i64::to_string).collect();
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {columns} {from} WHERE r.id IN ({}) ORDER BY r.run_at, r.id",
        list.join(",")
    )))
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    rows.iter().map(claimed).collect()
}

fn claimed(row: &sqlx::sqlite::SqliteRow) -> Result<Claimed, Error> {
    let payload: String = row.try_get("payload")?;
    Ok(Claimed {
        run: Run {
            owner: row.try_get("owner")?,
            job: row.try_get("name")?,
            id: row.try_get("run_id")?,
            key: row.try_get("idem_key")?,
            attempt: row.try_get::<i64, _>("attempt")? as u32,
            due_at: row.try_get("due_at")?,
            payload: serde_json::from_str(&payload).unwrap_or(Value::Null),
            idle: Default::default(),
        },
        job_id: row.try_get("job_id")?,
        max_attempts: row.try_get::<i64, _>("max_attempts")? as u32,
        backoff_secs: row.try_get("backoff_secs")?,
    })
}

/// Extends the lease of a run `holder` still holds; `false` when it no longer does (the lease
/// expired and another worker took the run).
pub async fn heartbeat(
    pool: &SqlitePool,
    now: &str,
    holder: &str,
    run: i64,
    lease_secs: i64,
) -> Result<bool, Error> {
    let until = iso_of_unix(unix_secs(now).unwrap_or_default() + lease_secs);
    sqlx::query(
        "UPDATE core_job_runs SET lease_until = ? WHERE id = ? AND holder = ? AND status = 'running'",
    )
    .bind(until)
    .bind(run)
    .bind(holder)
    .execute(pool)
    .await
    .map(|r| r.rows_affected() == 1)
}

/// Ends a claimed run's attempt with `result`: `ok`, back to `queued` after a backoff, or `dead`
/// when the attempts are used up. Audited (`job.ran`, `job.failed`). `false` when `holder` no
/// longer holds the run, which is left to whoever does.
pub async fn finish(
    pool: &SqlitePool,
    now: &str,
    holder: &str,
    c: &Claimed,
    result: &Result<(), String>,
) -> Result<bool, Error> {
    let error = result
        .as_ref()
        .err()
        .map(|e| e.chars().take(500).collect::<String>());
    let (status, run_at) = match result {
        Ok(()) => ("ok", None),
        Err(_) if c.run.attempt >= c.max_attempts => ("dead", None),
        Err(_) => {
            let wait = (c.backoff_secs << (c.run.attempt - 1).min(12)).min(MAX_BACKOFF);
            let at = iso_of_unix(unix_secs(now).unwrap_or_default() + wait);
            ("queued", Some(at))
        }
    };
    let done = status != "queued";
    let mut tx = begin_write(pool).await?;
    let moved = sqlx::query(
        "UPDATE core_job_runs SET status = ?1, holder = NULL, lease_until = NULL, error = ?2, \
         run_at = coalesce(?3, run_at), finished_at = iif(?4, ?5, NULL), \
         payload = iif(?4, '{}', payload) \
         WHERE id = ?6 AND holder = ?7 AND status = 'running'",
    )
    .bind(status)
    .bind(&error)
    .bind(run_at)
    .bind(done)
    .bind(now)
    .bind(c.run.id)
    .bind(holder)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if moved == 1 && !(status == "ok" && c.run.was_idle()) {
        let shown = if status == "queued" { "retry" } else { status };
        settle(&mut tx, c, shown, error.as_deref()).await?;
    }
    tx.commit().await?;
    Ok(moved == 1)
}
