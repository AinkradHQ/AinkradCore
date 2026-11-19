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
    /// The run configuration it started from, and the environment it ran in (Core 0.10).
    pub config_id: Option<i64>,
    pub environment: Option<String>,
}

impl Run {
    pub fn is_live(&self) -> bool {
        LIVE.contains(&self.state.as_str())
    }
}

const COLS: &str = "id, project_id, spec_version, runner, state, stop_reason, error, started_by, \
                    started_at, stopped_at, last_activity_at, config_id, environment";

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
        config_id: r.try_get("config_id")?,
        environment: r.try_get("environment")?,
    })
}

fn refused<T>(code: &'static str, message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.into(),
    })
}

/// The project's newest live run, if any (a project may have one live run per configuration).
pub async fn live(pool: &SqlitePool, project_id: i64) -> Result<Option<Run>, sqlx::Error> {
    Ok(live_list(pool, project_id).await?.into_iter().next())
}

/// Every live run of the project, newest first.
pub async fn live_list(pool: &SqlitePool, project_id: i64) -> Result<Vec<Run>, sqlx::Error> {
    let q = format!(
        "SELECT {COLS} FROM core_project_runs WHERE project_id = ? \
         AND state IN ('starting', 'running', 'stopping') ORDER BY started_at DESC, rowid DESC"
    );
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(project_id)
        .fetch_all(pool)
        .await?
        .iter()
        .map(row)
        .collect()
}

/// The live run of one configuration (`None`: the project's setup as saved).
pub async fn live_for(
    pool: &SqlitePool,
    project_id: i64,
    config: Option<i64>,
) -> Result<Option<Run>, sqlx::Error> {
    Ok(live_list(pool, project_id)
        .await?
        .into_iter()
        .find(|r| r.config_id.unwrap_or(0) == config.unwrap_or(0)))
}

/// The project's newest runs, live or not, newest first.
pub async fn recent(
    pool: &SqlitePool,
    project_id: i64,
    limit: i64,
) -> Result<Vec<Run>, sqlx::Error> {
    let q = format!(
        "SELECT {COLS} FROM core_project_runs WHERE project_id = ? \
         ORDER BY started_at DESC, rowid DESC LIMIT ?"
    );
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(project_id)
        .bind(limit)
        .fetch_all(pool)
        .await?
        .iter()
        .map(row)
        .collect()
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
    config: Option<(i64, &str)>,
    who: Who<'_>,
) -> Result<Run, Error> {
    let mut tx = super::begin_write(pool).await?;
    let project = projects::get(&mut tx, project_id).await?;
    if project.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let inserted = sqlx::query(
        "INSERT INTO core_project_runs (id, project_id, spec_version, runner, state, started_by, \
         started_at, config_id, environment) VALUES (?, ?, ?, ?, 'starting', ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(project_id)
    .bind(spec_version)
    .bind(runner)
    .bind(who.by_device)
    .bind(who.now)
    .bind(config.map(|c| c.0))
    .bind(config.map(|c| c.1))
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        Err(sqlx::Error::Database(d)) if d.is_unique_violation() => {
            return refused("conflict", "that run is already live");
        }
        Err(e) => return Err(e.into()),
    }
    let details = json!({"run": id, "spec_version": spec_version, "runner": runner,
                         "by_device": who.by_device, "config": config.map(|c| c.0),
                         "environment": config.map(|c| c.1)});
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
    /// What went wrong, in words; scrubbed by `finish` ([`scrub_error`]) before it is stored.
    pub error: Option<&'a str>,
}

/// The longest error text a run keeps.
pub const ERROR_MAX: usize = 1024;

/// `error` as it may be stored, audited and emitted: secret shapes masked, the names of the
/// project's secrets and any lease id scrubbed, cut to [`ERROR_MAX`] bytes. A runner's reason
/// is text from a container, so none of it is trusted.
pub async fn scrub_error(pool: &SqlitePool, project_id: i64, error: &str) -> String {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT s.name FROM core_secrets s JOIN core_projects p ON p.secret_group = s.group_id \
         WHERE p.id = ?",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    let mut text = ainkrad_proto::redact::Redactor::new().text(error);
    for stored in &names {
        let short = stored.split_once('.').map_or(stored.as_str(), |(_, n)| n);
        for n in [stored.as_str(), short] {
            if n.len() >= 3 {
                text = text.replace(n, "[secret]");
            }
        }
    }
    // Lease ids are found whatever surrounds them (`lease=l_…,`, `"l_…"`): words are runs of
    // letters, digits and `_`.
    let mut scrubbed = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let word = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        if word == 0 {
            let c = rest.chars().next().expect("not empty");
            scrubbed.push(c);
            rest = &rest[c.len_utf8()..];
            continue;
        }
        let (w, tail) = rest.split_at(word);
        scrubbed.push_str(if w.starts_with("l_") && w.len() > 10 {
            "[lease]"
        } else {
            w
        });
        rest = tail;
    }
    let text = scrubbed;
    let mut cut = text.len().min(ERROR_MAX);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text[..cut].to_owned()
}

/// Moves a live run to its end, once: the audit row and event are written only by the call that
/// moved it. Returns whether this call did.
pub async fn finish(
    pool: &SqlitePool,
    id: &str,
    end: End<'_>,
    who: Who<'_>,
) -> Result<bool, Error> {
    let error = match end.error {
        Some(e) => {
            let project: Option<i64> =
                sqlx::query_scalar("SELECT project_id FROM core_project_runs WHERE id = ?")
                    .bind(id)
                    .fetch_optional(pool)
                    .await?;
            Some(scrub_error(pool, project.unwrap_or(0), e).await)
        }
        None => None,
    };
    let mut tx = super::begin_write(pool).await?;
    let done = sqlx::query(
        "UPDATE core_project_runs SET state = ?, stopped_at = ?, \
         stop_reason = coalesce(?, stop_reason), error = ? \
         WHERE id = ? AND state IN ('starting', 'running', 'stopping')",
    )
    .bind(end.state)
    .bind(who.now)
    .bind(end.reason)
    .bind(error)
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

/// Runs that ended as a `crash` since `since`, of a configuration that wants a restart, with no
/// newer run of that configuration: the ones a restart is owed for.
pub async fn crashed_to_restart(pool: &SqlitePool, since: &str) -> Result<Vec<Run>, sqlx::Error> {
    let cols = COLS
        .split(", ")
        .map(|c| format!("r.{c}"))
        .collect::<Vec<_>>()
        .join(", ");
    let q = format!(
        "SELECT {cols} FROM core_project_runs r JOIN core_run_configs c ON c.id = r.config_id \
         WHERE r.state IN ('failed', 'stopped') AND r.stop_reason = 'crash' AND c.restart = 1 \
         AND r.stopped_at >= ? AND NOT EXISTS (SELECT 1 FROM core_project_runs n \
         WHERE n.project_id = r.project_id AND n.config_id = r.config_id AND n.rowid > r.rowid)"
    );
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(since)
        .fetch_all(pool)
        .await?
        .iter()
        .map(row)
        .collect()
}

/// How many runs of the configuration ended as a `crash` since `since`.
pub async fn crashes_since(
    pool: &SqlitePool,
    project_id: i64,
    config: i64,
    since: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM core_project_runs WHERE project_id = ? AND config_id = ? \
         AND stop_reason = 'crash' AND stopped_at >= ?",
    )
    .bind(project_id)
    .bind(config)
    .bind(since)
    .fetch_one(pool)
    .await
}

/// Audits and emits `project.run_gave_up`: the Core stopped restarting `run`'s configuration.
pub async fn gave_up(pool: &SqlitePool, run: &Run, crashes: i64, max: i64) -> Result<(), Error> {
    let mut tx = super::begin_write(pool).await?;
    let details = json!({"run": run.id, "config": run.config_id, "crashes": crashes,
                         "max_retries": max, "environment": run.environment});
    record(
        &mut tx,
        AuditActor::System,
        "project.run_gave_up",
        run.project_id,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
