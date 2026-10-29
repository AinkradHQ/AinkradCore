//! Terminating an agent (API minor 17): the admin lets it go for good, in one `BEGIN IMMEDIATE`
//! transaction. Its live runs are cancelled (`cancelled: agent terminated`, its runner told to
//! stop), its pending wakes dropped, and every open issue that waited on it or was owned by it is
//! handed to a human (the owner is cleared); the agent is `terminated` and `agent.terminated`
//! lists all of it. A terminated agent is never dispatched, and a wake asked for it afterwards is
//! stored `dropped` (`enqueue_in`).

use citadel_core::audit::AuditActor;
use citadel_core::exec::{RunEvent, WakeSource};
use citadel_core::work::{NextActor, UserId};
use serde_json::json;
use sqlx::SqliteConnection;

use super::controls::{control_in, record};
use super::*;
use crate::store::work::reassign_in;

/// Why a terminated agent's runs ended.
pub const TERMINATED: &str = "agent terminated";

/// Terminates the agent (the module's rules), handing its open issues to `to`, for `reason`:
/// `false` when it was already terminated or does not exist.
pub async fn terminate_agent(
    pool: &SqlitePool,
    agent: AgentId,
    reason: &str,
    to: UserId,
    actor: AuditActor,
    now: &str,
) -> Result<bool, TransitionError> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let done = terminate_in(&mut tx, agent, reason.trim(), to, actor, now).await?;
    tx.commit().await?;
    if done {
        signal_wakes();
    }
    Ok(done)
}

async fn terminate_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    reason: &str,
    to: UserId,
    actor: AuditActor,
    now: &str,
) -> Result<bool, TransitionError> {
    let company: Option<i64> = sqlx::query_scalar(
        "UPDATE agents SET status = 'terminated', paused_at = NULL \
         WHERE id = ? AND status <> 'terminated' RETURNING company_id",
    )
    .bind(agent.0)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(company) = company else {
        return Ok(false);
    };
    let live: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM runs WHERE agent_id = ? AND state IN ('queued', 'claimed', 'running') \
         ORDER BY id",
    )
    .bind(agent.0)
    .fetch_all(&mut *conn)
    .await?;
    for &id in &live {
        let Some(current) = run_in(conn, RunId(id)).await? else {
            continue;
        };
        let cancel = RunEvent::Cancel {
            reason: TERMINATED.to_owned(),
        };
        transition_in(conn, &current, actor, &cancel, now).await?;
        if current.runner_id.is_some() {
            control_in(conn, current.id, "stop", TERMINATED, None, now).await?;
        }
    }
    let wakes: Vec<i64> = sqlx::query_scalar(
        "UPDATE wake_requests SET status = 'dropped', dropped_reason = ? \
         WHERE agent_id = ? AND status = 'pending' RETURNING id",
    )
    .bind(TERMINATED)
    .bind(agent.0)
    .fetch_all(&mut *conn)
    .await?;
    let issues: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM issues WHERE state NOT IN ('done', 'cancelled') \
         AND (next_agent_id = ?1 OR owner_agent_id = ?1) ORDER BY id",
    )
    .bind(agent.0)
    .fetch_all(&mut *conn)
    .await?;
    for &id in &issues {
        let waiting: bool =
            sqlx::query_scalar("SELECT next_agent_id IS ? FROM issues WHERE id = ?")
                .bind(agent.0)
                .bind(id)
                .fetch_one(&mut *conn)
                .await?;
        if waiting {
            let next = NextActor::Human(to);
            reassign_in(conn, IssueId(id), next, actor, WakeSource::Manual).await?;
        }
        sqlx::query("UPDATE issues SET owner_agent_id = NULL WHERE id = ? AND owner_agent_id = ?")
            .bind(id)
            .bind(agent.0)
            .execute(&mut *conn)
            .await?;
    }
    let details = json!({"reason": reason, "runs": live, "dropped_wakes": wakes,
                         "issues": issues, "handed_to": to.0, "at": now});
    let entity = ("agent", agent.0);
    record(
        conn,
        actor,
        "agent.terminated",
        entity,
        company,
        None,
        details,
    )
    .await?;
    Ok(true)
}
