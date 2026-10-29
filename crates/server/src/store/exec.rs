//! Execution repository: runners and runs here; wake requests, leases and cost events in
//! `queue`; the wake queue's enqueue, dispatch and retry in `wake`; lease renewal and
//! runner-loss recovery in `lease`; the loop breaker in `breaker`; the read-only stuck
//! detector in `stuck`; the scheduler's tick (timers, then reaping) in `schedule`; per-run
//! tokens in `token`; token caps and mid-run usage in `usage`; run transcripts in
//! `transcript`; permission escalations in `escalation`; the progress watchdog in `progress`;
//! the stuck detector's automatic repairs in `repair`; runners' disk reports in `disk`; the
//! admin's controls (pause, stop, message, nudge, wake) in `controls`; registering, draining,
//! removing a runner, its Power Nap preference and its reported state in `runner_admin`.
//!
//! `update_*` / `delete_*` return `false` when no row matched. A run's or wake request's
//! agent and issue are fixed at insert, where same-company rules are enforced by triggers
//! and surface as `Error::Database`. A run's state, runner and transition timestamps move
//! only through `transition_run` (the state machine), so `update_run` cannot touch them,
//! and a runner holding live runs cannot be deleted: every live run keeps its lease. Runs
//! and wakes are created only by the engine (`dispatch_next`, `enqueue_wake`); the raw
//! `create_*` / `delete_*` of runs and wakes and `update_wake_request` exist for tests only
//! (`cfg(test)` or the `test-support` feature).

use std::fmt;

use ainkrad_core::exec::{NewRunner, Run, RunId, Runner, RunnerId, Usage, WakeRequestId};
use ainkrad_core::org::AgentId;
use ainkrad_core::work::IssueId;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::types::Json;
use sqlx::{Error, Row};

use super::org::{affected, text};
use super::{key_hash, random_key};

#[macro_use]
mod queue;
pub use queue::*;

/// Reads the shared token / cost columns.
fn usage(row: &SqliteRow) -> Result<Usage, Error> {
    Ok(Usage {
        input_tokens: row.try_get("input_tokens")?,
        output_tokens: row.try_get("output_tokens")?,
        cache_tokens: row.try_get("cache_tokens")?,
        cost_usd_micros: row.try_get("cost_usd_micros")?,
    })
}

// --- runners ----------------------------------------------------------------

macro_rules! runner_columns {
    () => {
        "id, name, tags, status, last_seen_at, health_reason, wake_requested_at, wake_mode, \
         drained_at, power_nap"
    };
}

fn runner(row: SqliteRow) -> Result<Runner, Error> {
    let Json(tags) = row.try_get::<Json<Vec<String>>, _>("tags")?;
    Ok(Runner {
        id: RunnerId(row.try_get("id")?),
        name: row.try_get("name")?,
        tags,
        status: text(&row, "status")?,
        last_seen_at: row.try_get("last_seen_at")?,
        health_reason: row.try_get("health_reason")?,
        wake_requested_at: row.try_get("wake_requested_at")?,
        wake_mode: row.try_get("wake_mode")?,
        drained_at: row.try_get("drained_at")?,
        power_nap: row.try_get("power_nap")?,
    })
}

/// Registers an `offline` runner; only the SHA-256 of `key` is stored.
pub async fn create_runner(pool: &SqlitePool, r: &NewRunner, key: &str) -> Result<Runner, Error> {
    sqlx::query(concat!(
        "INSERT INTO runners (name, key_hash, tags) VALUES (?, ?, ?) RETURNING ",
        runner_columns!()
    ))
    .bind(&r.name)
    .bind(key_hash(key))
    .bind(Json(&r.tags))
    .fetch_one(pool)
    .await
    .and_then(runner)
}

/// Registers an `offline` runner with a fresh random key (`cit_runner_` + 256 bits): the
/// runner and its key, which is returned here once and never stored.
pub async fn register_runner(pool: &SqlitePool, r: &NewRunner) -> Result<(Runner, String), Error> {
    let key = random_key("cit_runner_")?;
    Ok((create_runner(pool, r, &key).await?, key))
}

pub async fn get_runner(pool: &SqlitePool, id: RunnerId) -> Result<Option<Runner>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        runner_columns!(),
        " FROM runners WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(runner)
    .transpose()
}

/// The runner holding `key`, if any.
pub async fn get_runner_by_key(pool: &SqlitePool, key: &str) -> Result<Option<Runner>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        runner_columns!(),
        " FROM runners WHERE key_hash = ?"
    ))
    .bind(key_hash(key))
    .fetch_optional(pool)
    .await?
    .map(runner)
    .transpose()
}

pub async fn list_runners(pool: &SqlitePool) -> Result<Vec<Runner>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        runner_columns!(),
        " FROM runners ORDER BY id"
    ))
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(runner)
    .collect()
}

/// Updates every field; the key is not changed.
pub async fn update_runner(pool: &SqlitePool, r: &Runner) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE runners SET name = ?, tags = ?, status = ?, last_seen_at = ?, \
         health_reason = ? WHERE id = ?",
    )
    .bind(&r.name)
    .bind(Json(&r.tags))
    .bind(r.status.as_str())
    .bind(&r.last_seen_at)
    .bind(&r.health_reason)
    .bind(r.id.0)
    .execute(pool)
    .await
    .map(affected)
}

/// Why a runner was not deleted.
#[derive(Debug)]
pub enum DeleteRunnerError {
    /// The runner holds these claimed or running runs. They end first, by their runner or
    /// by the reaper once their leases expire.
    LiveRuns(Vec<RunId>),
    Db(Error),
}

impl From<Error> for DeleteRunnerError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for DeleteRunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LiveRuns(runs) => write!(f, "runner holds {} live run(s)", runs.len()),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DeleteRunnerError {}

/// Deletes a runner that holds no claimed or running run; its ended runs stay, with no
/// runner. Refused, not reaped: deleting a runner says nothing about whether it is still
/// working, so its runs end the normal way (lease expiry is the one runner-loss path).
pub async fn delete_runner(pool: &SqlitePool, id: RunnerId) -> Result<bool, DeleteRunnerError> {
    remove_runner(pool, id, None).await
}

/// Revokes the runner named `name` by deleting it, so its key stops working (`delete_runner`'s
/// rules: refused while it holds live runs). `false` when there is no such runner.
pub async fn revoke_runner(pool: &SqlitePool, name: &str) -> Result<bool, DeleteRunnerError> {
    let id: Option<i64> = sqlx::query_scalar("SELECT id FROM runners WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    match id {
        Some(id) => delete_runner(pool, RunnerId(id)).await,
        None => Ok(false),
    }
}

// --- runs -------------------------------------------------------------------

macro_rules! run_columns {
    () => {
        "id, agent_id, issue_id, wake_request_id, runner_id, state, terminal_reason, harness, \
         harness_version, session_id, input_tokens, output_tokens, cache_tokens, \
         cost_usd_micros, queued_at, claimed_at, started_at, ended_at, failure_fingerprint, \
         account_id, model_used, fallback_reason, tier, context_tokens, woken_at, \
         harness_started_at, first_token_at, last_progress_at, diff_files, diff_repos, \
         transcript_pruned_at"
    };
}

mod breaker;
pub use breaker::*;
mod controls;
mod terminate;
pub use terminate::*;
mod runner_admin;
pub use controls::*;
pub use runner_admin::*;
mod messages;
pub use messages::*;
mod reads;
pub use reads::*;
mod runner_wake;
pub use runner_wake::*;
mod disk;
pub use disk::*;
mod route;
pub(crate) use route::start_route_in;
pub use route::{Fallback, SwitchError, fallback_routes, switch_route};
mod escalation;
pub use escalation::*;
mod lease;
pub use lease::*;
mod progress;
pub use progress::*;
mod no_action;
pub use no_action::ENDED_WITHOUT_ACTION;
mod prompt;
pub use prompt::*;
mod repair;
pub use repair::*;
mod schedule;
pub use schedule::*;
mod stages;
pub use stages::*;
mod stuck;
pub use stuck::*;
mod stuck_actions;
pub use stuck_actions::*;
mod tier;
pub(crate) use tier::task_tier_in;
pub use tier::{DEFAULT_RULES, list_tier_rules, resume_session, set_tier_rules};
mod token;
pub use token::*;
mod transcript;
pub use transcript::*;
mod transition;
pub use transition::*;
mod usage;
pub use usage::*;
mod wake;
pub use wake::*;

fn run(row: SqliteRow) -> Result<Run, Error> {
    Ok(Run {
        id: RunId(row.try_get("id")?),
        agent_id: AgentId(row.try_get("agent_id")?),
        issue_id: row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId),
        wake_request_id: row
            .try_get::<Option<i64>, _>("wake_request_id")?
            .map(WakeRequestId),
        runner_id: row.try_get::<Option<i64>, _>("runner_id")?.map(RunnerId),
        state: text(&row, "state")?,
        terminal_reason: row.try_get("terminal_reason")?,
        harness: text(&row, "harness")?,
        harness_version: row.try_get("harness_version")?,
        session_id: row.try_get("session_id")?,
        usage: usage(&row)?,
        queued_at: row.try_get("queued_at")?,
        claimed_at: row.try_get("claimed_at")?,
        started_at: row.try_get("started_at")?,
        ended_at: row.try_get("ended_at")?,
        failure_fingerprint: row.try_get("failure_fingerprint")?,
        account_id: row
            .try_get::<Option<i64>, _>("account_id")?
            .map(ainkrad_core::gov::AccountId),
        model_used: row.try_get("model_used")?,
        fallback_reason: row.try_get("fallback_reason")?,
        tier: row
            .try_get::<Option<String>, _>("tier")?
            .map(|t| t.parse().map_err(|e| Error::Decode(Box::new(e))))
            .transpose()?,
        context_tokens: row.try_get("context_tokens")?,
        woken_at: row.try_get("woken_at")?,
        harness_started_at: row.try_get("harness_started_at")?,
        first_token_at: row.try_get("first_token_at")?,
        last_progress_at: row.try_get("last_progress_at")?,
        diff_files: row.try_get("diff_files")?,
        diff_repos: row.try_get("diff_repos")?,
        transcript_pruned_at: row.try_get("transcript_pruned_at")?,
    })
}

/// Queues a run with zero usage and no price yet. Test-only (and `test-support`): runs are
/// inserted and claimed together by `dispatch_next`; a raw insert leaves a `queued` run
/// nothing will claim, holding back its agent's wakes for the issue.
#[cfg(any(test, feature = "test-support"))]
pub async fn create_run(pool: &SqlitePool, r: &ainkrad_core::exec::NewRun) -> Result<Run, Error> {
    sqlx::query(concat!(
        "INSERT INTO runs (agent_id, issue_id, wake_request_id, harness) \
         VALUES (?, ?, ?, ?) RETURNING ",
        run_columns!()
    ))
    .bind(r.agent_id.0)
    .bind(r.issue_id.map(|i| i.0))
    .bind(r.wake_request_id.map(|w| w.0))
    .bind(r.harness.as_str())
    .fetch_one(pool)
    .await
    .and_then(run)
}

pub async fn get_run(pool: &SqlitePool, id: RunId) -> Result<Option<Run>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        run_columns!(),
        " FROM runs WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(run)
    .transpose()
}

/// The agent's runs, oldest first.
pub async fn list_runs(pool: &SqlitePool, agent_id: AgentId) -> Result<Vec<Run>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        run_columns!(),
        " FROM runs WHERE agent_id = ? ORDER BY id"
    ))
    .bind(agent_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(run)
    .collect()
}

/// Updates the harness version, session and usage only. State, runner, reason,
/// fingerprint and the transition timestamps move through `transition_run`.
pub async fn update_run(pool: &SqlitePool, r: &Run) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE runs SET harness_version = ?, session_id = ?, input_tokens = ?, \
         output_tokens = ?, cache_tokens = ?, cost_usd_micros = ?, priced = ? WHERE id = ?",
    )
    .bind(&r.harness_version)
    .bind(&r.session_id)
    .bind(r.usage.input_tokens)
    .bind(r.usage.output_tokens)
    .bind(r.usage.cache_tokens)
    .bind(r.usage.cost_usd_micros)
    .bind(r.usage.cost_usd_micros.is_some())
    .bind(r.id.0)
    .execute(pool)
    .await
    .map(affected)
}

/// Cascades to its lease and cost events; comments it wrote keep no run. Test-only, like
/// `create_run`: deleting a run erases its record and resets its wake's retry count.
#[cfg(any(test, feature = "test-support"))]
pub async fn delete_run(pool: &SqlitePool, id: RunId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM runs WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}

#[cfg(test)]
mod tests;
