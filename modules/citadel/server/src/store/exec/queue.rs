//! Wake requests, leases and cost events.

use citadel_core::exec::{
    CostEvent, CostEventId, Lease, NewCostEvent, RunId, RunnerId, WakeRequest, WakeRequestId,
};
use citadel_core::org::AgentId;
use citadel_core::work::IssueId;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row};

use super::usage;
#[cfg(any(test, feature = "test-support"))]
use crate::store::org::affected;
use crate::store::org::text;

// --- wake requests ----------------------------------------------------------

macro_rules! wake_columns {
    () => {
        "id, agent_id, issue_id, source, reason, idempotency_key, coalesced_count, status, \
         not_before, attempt, coalesced_into, dropped_reason"
    };
}

pub(super) fn wake_request(row: SqliteRow) -> Result<WakeRequest, Error> {
    Ok(WakeRequest {
        id: WakeRequestId(row.try_get("id")?),
        agent_id: AgentId(row.try_get("agent_id")?),
        issue_id: row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId),
        source: text(&row, "source")?,
        reason: row.try_get("reason")?,
        idempotency_key: row.try_get("idempotency_key")?,
        coalesced_count: row.try_get("coalesced_count")?,
        status: text(&row, "status")?,
        not_before: row.try_get("not_before")?,
        attempt: row.try_get("attempt")?,
        coalesced_into: row
            .try_get::<Option<i64>, _>("coalesced_into")?
            .map(WakeRequestId),
        dropped_reason: row.try_get("dropped_reason")?,
    })
}

/// Stores a `pending` first attempt. Idempotent per key: a repeat returns the first request
/// unchanged. Test-only (and `test-support`): no coalescing, so it can store a second pending
/// wake for one agent and issue; the engine enqueues with `enqueue_wake`.
#[cfg(any(test, feature = "test-support"))]
pub async fn create_wake_request(
    pool: &SqlitePool,
    w: &citadel_core::exec::NewWakeRequest,
) -> Result<WakeRequest, Error> {
    let inserted = sqlx::query(concat!(
        "INSERT INTO wake_requests (agent_id, issue_id, source, reason, idempotency_key, \
         not_before) VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT (idempotency_key) DO NOTHING RETURNING ",
        wake_columns!()
    ))
    .bind(w.agent_id.0)
    .bind(w.issue_id.map(|i| i.0))
    .bind(w.source.as_str())
    .bind(&w.reason)
    .bind(&w.idempotency_key)
    .bind(&w.not_before)
    .fetch_optional(pool)
    .await?;
    let row = match inserted {
        Some(row) => row,
        None => {
            sqlx::query(concat!(
                "SELECT ",
                wake_columns!(),
                " FROM wake_requests WHERE idempotency_key = ?"
            ))
            .bind(&w.idempotency_key)
            .fetch_one(pool)
            .await?
        }
    };
    wake_request(row)
}

pub async fn get_wake_request(
    pool: &SqlitePool,
    id: WakeRequestId,
) -> Result<Option<WakeRequest>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        wake_columns!(),
        " FROM wake_requests WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(wake_request)
    .transpose()
}

/// The agent's wake requests, oldest first.
pub async fn list_wake_requests(
    pool: &SqlitePool,
    agent_id: AgentId,
) -> Result<Vec<WakeRequest>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        wake_columns!(),
        " FROM wake_requests WHERE agent_id = ? ORDER BY id"
    ))
    .bind(agent_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(wake_request)
    .collect()
}

/// Updates reason, status, coalesced count and target, backoff, attempt and drop reason;
/// agent, issue, source and key are fixed. A `dropped` request without a reason, or a
/// `coalesced` one without a target, is a constraint error. Test-only, like
/// `create_wake_request`: status, attempt and backoff are the wake queue's to move.
#[cfg(any(test, feature = "test-support"))]
pub async fn update_wake_request(pool: &SqlitePool, w: &WakeRequest) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE wake_requests SET reason = ?, coalesced_count = ?, status = ?, \
         not_before = ?, attempt = ?, coalesced_into = ?, dropped_reason = ? WHERE id = ?",
    )
    .bind(&w.reason)
    .bind(w.coalesced_count)
    .bind(w.status.as_str())
    .bind(&w.not_before)
    .bind(w.attempt)
    .bind(w.coalesced_into.map(|c| c.0))
    .bind(&w.dropped_reason)
    .bind(w.id.0)
    .execute(pool)
    .await
    .map(affected)
}

/// Runs it started keep no wake request. Test-only, like `create_wake_request`: a run with
/// no wake counts as attempt 1, so deleting one would reset the retry limit.
#[cfg(any(test, feature = "test-support"))]
pub async fn delete_wake_request(pool: &SqlitePool, id: WakeRequestId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM wake_requests WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}

// --- leases -----------------------------------------------------------------

fn lease(row: SqliteRow) -> Result<Lease, Error> {
    Ok(Lease {
        run_id: RunId(row.try_get("run_id")?),
        runner_id: RunnerId(row.try_get("runner_id")?),
        expires_at: row.try_get("expires_at")?,
        heartbeat_at: row.try_get("heartbeat_at")?,
    })
}

/// Test-only: leases are granted by `dispatch_next`, renewed by `renew_lease` and dropped
/// by run ends; raw writes could leave a live run without one. A second lease on the same
/// run is a constraint error.
#[cfg(test)]
pub(crate) async fn create_lease(pool: &SqlitePool, l: &Lease) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO leases (run_id, runner_id, expires_at, heartbeat_at) VALUES (?, ?, ?, ?)",
    )
    .bind(l.run_id.0)
    .bind(l.runner_id.0)
    .bind(&l.expires_at)
    .bind(&l.heartbeat_at)
    .execute(pool)
    .await
    .map(drop)
}

pub async fn get_lease(pool: &SqlitePool, run_id: RunId) -> Result<Option<Lease>, Error> {
    sqlx::query("SELECT run_id, runner_id, expires_at, heartbeat_at FROM leases WHERE run_id = ?")
        .bind(run_id.0)
        .fetch_optional(pool)
        .await?
        .map(lease)
        .transpose()
}

pub async fn list_leases(pool: &SqlitePool, runner_id: RunnerId) -> Result<Vec<Lease>, Error> {
    sqlx::query(
        "SELECT run_id, runner_id, expires_at, heartbeat_at FROM leases \
         WHERE runner_id = ? ORDER BY run_id",
    )
    .bind(runner_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(lease)
    .collect()
}

/// Test-only, like `create_lease`. Renews the heartbeat and expiry; run and runner are fixed.
#[cfg(test)]
pub(crate) async fn update_lease(pool: &SqlitePool, l: &Lease) -> Result<bool, Error> {
    sqlx::query("UPDATE leases SET expires_at = ?, heartbeat_at = ? WHERE run_id = ?")
        .bind(&l.expires_at)
        .bind(&l.heartbeat_at)
        .bind(l.run_id.0)
        .execute(pool)
        .await
        .map(affected)
}

/// Test-only, like `create_lease`.
#[cfg(test)]
pub(crate) async fn delete_lease(pool: &SqlitePool, run_id: RunId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM leases WHERE run_id = ?")
        .bind(run_id.0)
        .execute(pool)
        .await
        .map(affected)
}

// --- cost events ------------------------------------------------------------

macro_rules! cost_columns {
    () => {
        "id, run_id, agent_id, issue_id, input_tokens, output_tokens, cache_tokens, \
         cost_usd_micros, idempotency_key"
    };
}

pub(super) fn cost_event(row: SqliteRow) -> Result<CostEvent, Error> {
    Ok(CostEvent {
        id: CostEventId(row.try_get("id")?),
        run_id: RunId(row.try_get("run_id")?),
        agent_id: AgentId(row.try_get("agent_id")?),
        issue_id: row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId),
        usage: usage(&row)?,
        idempotency_key: row.try_get("idempotency_key")?,
    })
}

/// Appends to the ledger. Idempotent per key: a repeat returns the first event unchanged.
/// There is no update or delete; the schema rejects edits.
pub async fn record_cost_event(pool: &SqlitePool, c: &NewCostEvent) -> Result<CostEvent, Error> {
    let inserted = sqlx::query(concat!(
        "INSERT INTO cost_events (run_id, agent_id, issue_id, input_tokens, output_tokens, \
         cache_tokens, cost_usd_micros, priced, idempotency_key) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (idempotency_key) DO NOTHING RETURNING ",
        cost_columns!()
    ))
    .bind(c.run_id.0)
    .bind(c.agent_id.0)
    .bind(c.issue_id.map(|i| i.0))
    .bind(c.usage.input_tokens)
    .bind(c.usage.output_tokens)
    .bind(c.usage.cache_tokens)
    .bind(c.usage.cost_usd_micros)
    .bind(c.usage.cost_usd_micros.is_some())
    .bind(&c.idempotency_key)
    .fetch_optional(pool)
    .await?;
    let row = match inserted {
        Some(row) => row,
        None => {
            sqlx::query(concat!(
                "SELECT ",
                cost_columns!(),
                " FROM cost_events WHERE idempotency_key = ?"
            ))
            .bind(&c.idempotency_key)
            .fetch_one(pool)
            .await?
        }
    };
    cost_event(row)
}

pub async fn get_cost_event(
    pool: &SqlitePool,
    id: CostEventId,
) -> Result<Option<CostEvent>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        cost_columns!(),
        " FROM cost_events WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(cost_event)
    .transpose()
}

/// The run's cost events, oldest first.
pub async fn list_cost_events(pool: &SqlitePool, run_id: RunId) -> Result<Vec<CostEvent>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        cost_columns!(),
        " FROM cost_events WHERE run_id = ? ORDER BY id"
    ))
    .bind(run_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(cost_event)
    .collect()
}
