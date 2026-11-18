//! Project runs (Core 0.9, P5-03): the rows behind `core_project_runs`. A project has at most one
//! live run (`starting`, `running`, `stopping`); the partial unique index is the guard, and
//! `begin` answers a second start with 409 `conflict`. Every start is one audit row and event
//! (`project.run_started`) and every end is one (`project.run_stopped`): the end is a guarded
//! transition (`finish` only moves a live row), so two stops racing write one row. The audit row's
//! origin is the ambient one (`audit::origin`): a person's request, the idle sweep's `schedule`,
//! or `system`.

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Row, SqliteConnection};

use super::projects::{self, Who};
use super::secrets::Error;

/// The states a run counts as live in.
pub const LIVE: [&str; 3] = ["starting", "running", "stopping"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub id: String,
    pub project_id: i64,
    pub spec_version: i64,
    pub runner: String,
    pub state: String,
    pub stop_reason: Option<String>,
    pub error: Option<String>,
    pub started_by: String,
    pub started_at: String,
    pub stopped_at: Option<String>,
    pub last_activity_at: Option<String>,
}

impl Run {
    pub fn is_live(&self) -> bool {
        LIVE.contains(&self.state.as_str())
    }
}

const COLS: &str = "id, project_id, spec_version, runner, state, stop_reason, error, started_by, \
                    started_at, stopped_at, last_activity_at";

fn row(r: &SqliteRow) -> Result<Run, sqlx::Error> {
    Ok(Run {
        id: r.try_get("id")?,
        project_id: r.try_get("project_id")?,
        spec_version: r.try_get("spec_version")?,
        runner: r.try_get("runner")?,
        state: r.try_get("state")?,
        stop_reason: r.try_get("stop_reason")?,
        error: r.try_get("error")?,
        started_by: r.try_get("started_by")?,
        started_at: r.try_get("started_at")?,
        stopped_at: r.try_get("stopped_at")?,
        last_activity_at: r.try_get("last_activity_at")?,
    })
}

fn refused<T>(code: &'static str, message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.into(),
    })
}

/// The project's live run, if any.
pub async fn live(pool: &SqlitePool, project_id: i64) -> Result<Option<Run>, sqlx::Error> {
    let q = format!(
        "SELECT {COLS} FROM core_project_runs WHERE project_id = ? \
         AND state IN ('starting', 'running', 'stopping')"
    );
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(project_id)
        .fetch_optional(pool)
        .await?
        .as_ref()
        .map(row)
        .transpose()
}

/// The project's newest run, live or not.
pub async fn latest(pool: &SqlitePool, project_id: i64) -> Result<Option<Run>, sqlx::Error> {
    let q = format!(
        "SELECT {COLS} FROM core_project_runs WHERE project_id = ? \
         ORDER BY started_at DESC, rowid DESC LIMIT 1"
    );
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(project_id)
        .fetch_optional(pool)
        .await?
        .as_ref()
        .map(row)
        .transpose()
}

pub async fn get(pool: &SqlitePool, id: &str) -> Result<Run, Error> {
    let q = format!("SELECT {COLS} FROM core_project_runs WHERE id = ?");
    match sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(id)
        .fetch_optional(pool)
        .await?
    {
        Some(r) => Ok(row(&r)?),
        None => refused("not_found", "no such run"),
    }
}

/// Every live run, oldest first.
pub async fn live_all(pool: &SqlitePool) -> Result<Vec<Run>, sqlx::Error> {
    let q = format!(
        "SELECT {COLS} FROM core_project_runs \
         WHERE state IN ('starting', 'running', 'stopping') ORDER BY started_at, rowid"
    );
    sqlx::query(sqlx::AssertSqlSafe(q))
        .fetch_all(pool)
        .await?
        .iter()
        .map(row)
        .collect()
}

/// How many live runs each runner holds, for placement.
pub async fn load(
    pool: &SqlitePool,
) -> Result<std::collections::HashMap<String, i64>, sqlx::Error> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT runner, count(*) FROM core_project_runs \
         WHERE state IN ('starting', 'running', 'stopping') GROUP BY runner",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().collect())
}

async fn record(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    project_id: i64,
    details: serde_json::Value,
) -> Result<(), Error> {
    projects::record(conn, actor, action, project_id, details, true).await
}

/// Inserts run `id` as `starting`, audited and emitted as `project.run_started`. 409 `conflict`
/// when the project is archived or already has a live run.
pub async fn begin(
    pool: &SqlitePool,
    id: &str,
    project_id: i64,
    spec_version: i64,
    runner: &str,
    who: Who<'_>,
) -> Result<Run, Error> {
    let mut tx = super::begin_write(pool).await?;
    let project = projects::get(&mut tx, project_id).await?;
    if project.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let inserted = sqlx::query(
        "INSERT INTO core_project_runs (id, project_id, spec_version, runner, state, started_by, \
         started_at) VALUES (?, ?, ?, ?, 'starting', ?, ?)",
    )
    .bind(id)
    .bind(project_id)
    .bind(spec_version)
    .bind(runner)
    .bind(who.by_device)
    .bind(who.now)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        Err(sqlx::Error::Database(d)) if d.is_unique_violation() => {
            return refused("conflict", "the project already has a live run");
        }
        Err(e) => return Err(e.into()),
    }
    let details = json!({"run": id, "spec_version": spec_version, "runner": runner,
                         "by_device": who.by_device});
    record(
        &mut tx,
        who.actor,
        "project.run_started",
        project_id,
        details,
    )
    .await?;
    tx.commit().await?;
    get(pool, id).await
}

/// `starting` to `running`; false when the run is no longer `starting` (it was stopped meanwhile).
pub async fn mark_running(pool: &SqlitePool, id: &str, now: &str) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE core_project_runs SET state = 'running', last_activity_at = ? \
         WHERE id = ? AND state = 'starting'",
    )
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// `starting` or `running` to `stopping`, remembering why. False when it is not either (already
/// stopping, or over).
pub async fn begin_stop(pool: &SqlitePool, id: &str, reason: &str) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE core_project_runs SET state = 'stopping', stop_reason = ? \
         WHERE id = ? AND state IN ('starting', 'running')",
    )
    .bind(reason)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// How a run ended.
pub struct End<'a> {
    /// `stopped` or `failed`.
    pub state: &'a str,
    /// Replaces the stop reason when set (a run that was `stopping` for `user` but whose runner
    /// vanished ends `runner_lost`).
    pub reason: Option<&'a str>,
    /// What went wrong, in words; redacted on the way into the audit row.
    pub error: Option<&'a str>,
}

/// Moves a live run to its end, once: the audit row and event are written only by the call that
/// moved it. Returns whether this call did.
pub async fn finish(
    pool: &SqlitePool,
    id: &str,
    end: End<'_>,
    who: Who<'_>,
) -> Result<bool, Error> {
    let mut tx = super::begin_write(pool).await?;
    let done = sqlx::query(
        "UPDATE core_project_runs SET state = ?, stopped_at = ?, \
         stop_reason = coalesce(?, stop_reason), error = ? \
         WHERE id = ? AND state IN ('starting', 'running', 'stopping')",
    )
    .bind(end.state)
    .bind(who.now)
    .bind(end.reason)
    .bind(end.error)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    if done.rows_affected() != 1 {
        return Ok(false);
    }
    let r = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS} FROM core_project_runs WHERE id = ?"
    )))
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let r = row(&r)?;
    let details = json!({"run": id, "state": end.state, "reason": r.stop_reason,
                         "error": r.error, "runner": r.runner, "by_device": who.by_device});
    record(
        &mut tx,
        who.actor,
        "project.run_stopped",
        r.project_id,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// A viewer or a proxied request was active just now: pushes the idle stop back. Only a running
/// run is touched.
pub async fn touch(pool: &SqlitePool, project_id: i64, now: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE core_project_runs SET last_activity_at = ? \
         WHERE project_id = ? AND state = 'running'",
    )
    .bind(now)
    .bind(project_id)
    .execute(pool)
    .await?;
    Ok(())
}
