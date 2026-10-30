//! The run engine's repository (S7). A run is one wake of one agent on one issue; its harness is
//! an agent session of the platform (`ainkrad_core_server::agents`), which owns the transcript, the
//! lease and the supervision, so the monolith's runners, leases and transcript copies are gone.
//!
//! - `wake`: the wake queue (enqueue with idempotency and coalescing, the stale-wake drop).
//! - `dispatch`: a due wake becomes a run on an online runner (budget admission, then a session).
//! - `transition`: the run state machine applied to a stored run, with its terminal effects.
//! - `reconcile`: runs follow their sessions (start, end, loss), usage into the ledger, the cap.
//! - `control`: cancel, kill, message and the engine switch.
//! - `token`: a run's short-lived token for its agent's callbacks (S8).
//!
//! Not ported yet (kept in `modules/citadel/server` as the reference): account routing and
//! fallbacks, tier routing, the loop breaker, the stuck detector and its repairs, escalation,
//! the no-action and progress watchdogs.

use ainkrad_core::audit::AuditActor;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row, SqliteConnection};

use crate::domain::exec::RunState;
use crate::domain::org::{AgentId, Harness};
use crate::domain::work::{IssueId, RunId};
use crate::store::org::text;

pub mod control;
pub mod dispatch;
mod prompt;
pub mod reconcile;
pub mod timer;
pub mod token;
pub mod transition;
pub mod wake;

pub use control::*;
pub use dispatch::*;
pub use reconcile::*;
pub use token::*;
pub use transition::*;
pub use wake::*;

/// Token counts and cost of a run so far. `cost_usd_micros` is `None` while unpriced, never 0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    pub cost_usd_micros: Option<i64>,
}

impl Usage {
    pub fn total(&self) -> i64 {
        self.input_tokens + self.output_tokens + self.cache_tokens
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub id: RunId,
    pub agent_id: AgentId,
    pub issue_id: Option<IssueId>,
    pub wake_request_id: Option<i64>,
    /// The platform's agent session (`as_...`) that is this run's harness.
    pub session_id: Option<String>,
    /// The runner (a Core device, `d_...`) the session is on.
    pub runner: Option<String>,
    pub state: RunState,
    /// Set exactly when `state` is terminal.
    pub terminal_reason: Option<String>,
    pub harness: Harness,
    pub model_used: Option<String>,
    pub usage: Usage,
    pub failure_fingerprint: Option<String>,
    pub cancel_requested_at: Option<String>,
    pub queued_at: String,
    pub claimed_at: Option<String>,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
}

macro_rules! run_columns {
    () => {
        "id, agent_id, issue_id, wake_request_id, session_id, runner, state, terminal_reason, \
         harness, model_used, input_tokens, output_tokens, cache_tokens, cost_usd_micros, \
         failure_fingerprint, cancel_requested_at, queued_at, claimed_at, started_at, ended_at"
    };
}
pub(crate) use run_columns;

pub(crate) fn run(row: SqliteRow) -> Result<Run, Error> {
    Ok(Run {
        id: RunId(row.try_get("id")?),
        agent_id: AgentId(row.try_get("agent_id")?),
        issue_id: row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId),
        wake_request_id: row.try_get("wake_request_id")?,
        session_id: row.try_get("session_id")?,
        runner: row.try_get("runner")?,
        state: text(&row, "state")?,
        terminal_reason: row.try_get("terminal_reason")?,
        harness: text(&row, "harness")?,
        model_used: row.try_get("model_used")?,
        usage: Usage {
            input_tokens: row.try_get("input_tokens")?,
            output_tokens: row.try_get("output_tokens")?,
            cache_tokens: row.try_get("cache_tokens")?,
            cost_usd_micros: row.try_get("cost_usd_micros")?,
        },
        failure_fingerprint: row.try_get("failure_fingerprint")?,
        cancel_requested_at: row.try_get("cancel_requested_at")?,
        queued_at: row.try_get("queued_at")?,
        claimed_at: row.try_get("claimed_at")?,
        started_at: row.try_get("started_at")?,
        ended_at: row.try_get("ended_at")?,
    })
}

pub async fn get_run(pool: &SqlitePool, id: RunId) -> Result<Option<Run>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        run_columns!(),
        " FROM citadel_runs WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(run)
    .transpose()
}

/// The run, read inside the caller's transaction.
pub(crate) async fn run_in(conn: &mut SqliteConnection, id: RunId) -> Result<Option<Run>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        run_columns!(),
        " FROM citadel_runs WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(run)
    .transpose()
}

/// Which runs a listing keeps; a `None` field keeps everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct RunFilter {
    pub agent: Option<AgentId>,
    pub issue: Option<IssueId>,
    /// Only queued, claimed and running runs.
    pub live: bool,
}

/// Newest first, below run `before`, at most `limit` (1 to 200).
pub async fn list_runs(
    pool: &SqlitePool,
    f: RunFilter,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<Run>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        run_columns!(),
        " FROM citadel_runs WHERE (?1 IS NULL OR agent_id = ?1) AND (?2 IS NULL OR issue_id = ?2) \
         AND (?3 = 0 OR state IN ('queued', 'claimed', 'running')) AND (?4 IS NULL OR id < ?4) \
         ORDER BY id DESC LIMIT ?5"
    ))
    .bind(f.agent.map(|a| a.0))
    .bind(f.issue.map(|i| i.0))
    .bind(f.live)
    .bind(before)
    .bind(limit.clamp(1, 200))
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(run)
    .collect()
}

/// The company a run belongs to (its agent's).
pub async fn run_company(pool: &SqlitePool, id: RunId) -> Result<Option<i64>, Error> {
    sqlx::query_scalar(
        "SELECT a.company_id FROM citadel_runs r JOIN citadel_agents a ON a.id = r.agent_id \
         WHERE r.id = ?",
    )
    .bind(id.0)
    .fetch_optional(pool)
    .await
}

/// The engine's standing authorisation: `Some(device)` while the operator has it enabled (that
/// device, which stepped up to enable it, is the accountable creator of the engine's sessions).
pub async fn engine_device(pool: &SqlitePool) -> Result<Option<String>, Error> {
    sqlx::query_scalar("SELECT by_device FROM citadel_engine WHERE id = 1 AND enabled = 1")
        .fetch_optional(pool)
        .await
}

/// The audit actor of the engine's own steps.
pub(crate) const SYSTEM: AuditActor = AuditActor::System;
