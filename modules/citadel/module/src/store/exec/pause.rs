//! Pausing and resuming an agent. A paused agent is never dispatched. Pausing stops its live runs
//! through the admin's cancel path (the runner takes the stop first); resuming wakes it on each
//! open issue still waiting on it and drops the wakes that piled up on issues that moved on.
//! Resuming is the only way out of a pause, including the loop breaker's: nothing un-pauses an
//! agent by itself.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::api::App;
use serde_json::json;
use sqlx::SqliteConnection;

use super::*;
use crate::domain::work::WakeSource;
use crate::store::audit::{self, Event};

/// Why a paused agent's runs ended.
pub const PAUSED: &str = "agent paused";

/// Pauses the agent as `actor`; `false` when it was not active. Its live runs are then stopped
/// (`by` is the device that asked).
pub async fn pause_agent<H: Host>(
    app: &App,
    host: &H,
    agent: AgentId,
    (actor, by): (AuditActor, &str),
    now: &str,
) -> Result<bool, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(&app.pool).await?;
    let company: Option<i64> = sqlx::query_scalar(
        "UPDATE citadel_agents SET status = 'paused', paused_at = ?1 \
         WHERE id = ?2 AND status = 'active' RETURNING company_id",
    )
    .bind(now)
    .bind(agent.0)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(company) = company else {
        return Ok(false);
    };
    let live: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM citadel_runs WHERE agent_id = ? \
         AND state IN ('queued', 'claimed', 'running') ORDER BY id",
    )
    .bind(agent.0)
    .fetch_all(&mut *tx)
    .await?;
    audit::append(
        &mut tx,
        Event::new(actor, "agent.paused")
            .entity("agent", agent.0)
            .company(company)
            .details(json!({"runs": live, "at": now})),
    )
    .await?;
    tx.commit().await?;
    for id in live {
        if let Err(e) =
            super::control::stop_run_because(app, host, RunId(id), false, by, PAUSED, now).await
        {
            tracing::warn!(run = id, error = ?e, "stopping a paused agent's run is left to reconcile");
        }
    }
    Ok(true)
}

/// Resumes the agent inside the caller's transaction, waking it on each open issue waiting on
/// it: `false` when it was not paused.
async fn resume_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    actor: AuditActor,
    now: &str,
) -> Result<bool, Error> {
    let company: Option<i64> = sqlx::query_scalar(
        "UPDATE citadel_agents SET status = 'active', paused_at = NULL \
         WHERE id = ? AND status = 'paused' RETURNING company_id",
    )
    .bind(agent.0)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(company) = company else {
        return Ok(false);
    };
    let issues: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM citadel_issues WHERE next_agent_id = ? \
         AND state NOT IN ('done', 'cancelled') ORDER BY id",
    )
    .bind(agent.0)
    .fetch_all(&mut *conn)
    .await?;
    // Wakes that piled up while paused on issues that moved on (closed, or handed to someone
    // else) would replay stale work: dropped, and named in the audit.
    let mut dropped: Vec<i64> = sqlx::query_scalar(
        "UPDATE citadel_wake_requests SET status = 'dropped', \
         dropped_reason = 'resume: the issue no longer waits on this agent' \
         WHERE agent_id = ?1 AND status = 'pending' AND issue_id IS NOT NULL \
         AND issue_id NOT IN (SELECT value FROM json_each(?2)) RETURNING id",
    )
    .bind(agent.0)
    .bind(json!(issues).to_string())
    .fetch_all(&mut *conn)
    .await?;
    dropped.sort_unstable();
    for &issue in &issues {
        let wake = NewWakeRequest {
            agent_id: agent,
            issue_id: Some(IssueId(issue)),
            source: WakeSource::Manual,
            reason: "resumed by the admin".to_owned(),
            idempotency_key: format!("resume:agent:{}:issue:{issue}:{now}", agent.0),
            not_before: None,
        };
        enqueue_in(conn, &wake, 1).await?;
    }
    audit::append(
        conn,
        Event::new(actor, "agent.resumed")
            .entity("agent", agent.0)
            .company(company)
            .details(json!({"issues": issues, "dropped_wakes": dropped, "at": now})),
    )
    .await?;
    Ok(true)
}

/// Resumes a paused agent (by the admin; the loop breaker's pause too): `false` when it was not
/// paused.
pub async fn resume_agent(
    pool: &sqlx::SqlitePool,
    agent: AgentId,
    actor: AuditActor,
    now: &str,
) -> Result<bool, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let resumed = resume_in(&mut tx, agent, actor, now).await?;
    tx.commit().await?;
    Ok(resumed)
}
