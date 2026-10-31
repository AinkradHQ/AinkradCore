//! Terminating an agent: the admin lets it go for good. In one `BEGIN IMMEDIATE` transaction the
//! agent is `terminated`, its pending wakes are dropped and every open issue that waited on it or
//! was owned by it is handed to a human (the owner is cleared); `agent.terminated` lists all of
//! it. A terminated agent is never dispatched, and a wake asked for it afterwards is stored
//! `dropped` (`enqueue_in`).
//!
//! Its live runs are stopped after the commit, through the same path as the admin's cancel
//! (`stop_run`): the runner takes the stop first and the run ends `cancelled: agent terminated`.
//! A run whose runner does not answer is left to `reconcile` (it asks again) and ends the same way;
//! until then no new wake can start for the agent.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::api::App;
use serde_json::json;
use sqlx::SqliteConnection;

use super::*;
use crate::domain::work::{NextActor, UserId, WakeSource};
use crate::store::audit::{self, Event};
use crate::store::work::reassign_in;

/// Why a terminated agent's runs ended.
pub const TERMINATED: &str = "agent terminated";

/// Terminates the agent, handing its open issues to `to`, for `reason`, as `actor`; `false` when
/// it was already terminated or does not exist. Its live runs are then stopped (`by` is the device
/// that asked).
pub async fn terminate_agent<H: Host>(
    app: &App,
    host: &H,
    agent: AgentId,
    reason: &str,
    to: UserId,
    (actor, by): (AuditActor, &str),
    now: &str,
) -> Result<bool, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(&app.pool).await?;
    let live = terminate_in(&mut tx, agent, reason.trim(), to, actor, now).await?;
    tx.commit().await?;
    let Some(live) = live else { return Ok(false) };
    for id in live {
        match stop_run_for(app, host, id, by, now).await {
            Ok(()) => {}
            // Over already, or the runner is away: reconcile ends it the same way.
            Err(e) => tracing::warn!(
                run = id,
                error = ?e,
                "stopping a terminated agent's run is left to reconcile"
            ),
        }
    }
    Ok(true)
}

/// Stops one live run; its terminal reason says why.
async fn stop_run_for<H: Host>(
    app: &App,
    host: &H,
    id: i64,
    by: &str,
    now: &str,
) -> Result<(), ControlError> {
    super::control::stop_run_because(app, host, RunId(id), false, by, TERMINATED, now)
        .await
        .map(drop)
}

/// The live runs to stop, when the agent was terminated now.
async fn terminate_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    reason: &str,
    to: UserId,
    actor: AuditActor,
    now: &str,
) -> Result<Option<Vec<i64>>, Error> {
    let company: Option<i64> = sqlx::query_scalar(
        "UPDATE citadel_agents SET status = 'terminated', paused_at = NULL \
         WHERE id = ? AND status <> 'terminated' RETURNING company_id",
    )
    .bind(agent.0)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(company) = company else {
        return Ok(None);
    };
    let live: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM citadel_runs WHERE agent_id = ? \
         AND state IN ('queued', 'claimed', 'running') ORDER BY id",
    )
    .bind(agent.0)
    .fetch_all(&mut *conn)
    .await?;
    // Its tokens die with the decision, not when the runner finally answers the stop.
    for &id in &live {
        super::token::revoke_in(conn, RunId(id), now).await?;
    }
    let wakes: Vec<i64> = sqlx::query_scalar(
        "UPDATE citadel_wake_requests SET status = 'dropped', dropped_reason = ? \
         WHERE agent_id = ? AND status = 'pending' RETURNING id",
    )
    .bind(TERMINATED)
    .bind(agent.0)
    .fetch_all(&mut *conn)
    .await?;
    let issues: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM citadel_issues WHERE state NOT IN ('done', 'cancelled') \
         AND (next_agent_id = ?1 OR owner_agent_id = ?1) ORDER BY id",
    )
    .bind(agent.0)
    .fetch_all(&mut *conn)
    .await?;
    for &id in &issues {
        let waiting: bool =
            sqlx::query_scalar("SELECT next_agent_id IS ? FROM citadel_issues WHERE id = ?")
                .bind(agent.0)
                .bind(id)
                .fetch_one(&mut *conn)
                .await?;
        if waiting {
            let next = NextActor::Human(to);
            // A refusal (a full column cannot happen for a human hand-off) leaves the issue to
            // the stuck detector rather than undoing the termination.
            if let Err(crate::store::work::IssueTransitionError::Db(e)) =
                reassign_in(conn, IssueId(id), next, actor, WakeSource::Manual).await
            {
                return Err(e);
            }
        }
        sqlx::query(
            "UPDATE citadel_issues SET owner_agent_id = NULL WHERE id = ? AND owner_agent_id = ?",
        )
        .bind(id)
        .bind(agent.0)
        .execute(&mut *conn)
        .await?;
    }
    audit::append(
        conn,
        Event::new(actor, "agent.terminated")
            .entity("agent", agent.0)
            .company(company)
            .details(
                json!({"reason": reason.chars().take(120).collect::<String>(), "runs": live, "dropped_wakes": wakes,
                "issues": issues, "handed_to": to.0, "at": now}),
            ),
    )
    .await?;
    Ok(Some(live))
}
