//! The scheduler's tick (E2.9): agent heartbeat timers, then lease reaping (E2.6), approval
//! expiry, the stuck detector's repairs (E15.8), and transcript pruning.
//!
//! Agents are event-driven by default; one that opts in to a timer is woken once per
//! interval, and only when it has something to act on. Paperclip woke idle agents on every
//! heartbeat and burned tokens doing nothing (#3401, #4027), so an idle timer is skipped,
//! not fired.

use ainkrad_core::exec::{NewWakeRequest, WakeRequest, WakeSource};
use ainkrad_core::gov::ApprovalId;
use sqlx::SqliteConnection;

use super::*;

/// What one `tick` did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    /// The `timer` wakes stored this tick, one per due agent with actionable work.
    pub woken: Vec<WakeRequest>,
    /// Due timer agents skipped for having nothing to do; they are checked again next tick.
    pub idle: Vec<AgentId>,
    /// Runs whose leases expired, from `reap_expired_leases`.
    pub reaped: Vec<Reaped>,
    /// Approvals that expired, from `gov::expire_approvals`.
    pub expired: Vec<ApprovalId>,
    /// Repairs of stuck issues, wakes and runs, from `repair_stuck` (E15.8).
    pub repaired: Vec<Repaired>,
    /// Runs whose transcripts were pruned (`transcript.retention_secs`).
    pub pruned: Vec<RunId>,
}

/// Opts the agent in to a timer every `interval_secs` (must be positive), or out with
/// `None`; either way the next due tick may fire at once. `false` when there is no agent.
pub async fn set_agent_timer(
    pool: &SqlitePool,
    agent: AgentId,
    interval_secs: Option<i64>,
) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE agents SET timer_interval_secs = ?, timer_last_fired_at = NULL WHERE id = ?",
    )
    .bind(interval_secs)
    .bind(agent.0)
    .execute(pool)
    .await
    .map(affected)
}

/// One scheduler pass at `now` (ISO-8601).
///
/// Timers: time is cut into slots of each agent's interval since the Unix epoch, and an
/// active opted-in agent is due once per slot. A due agent with actionable work (an open,
/// unblocked issue it is next actor on, or a pending wake) gets a `timer` wake with no issue,
/// keyed `timer:agent:<id>:slot:<n>`, and its `timer_last_fired_at` becomes `now`; one with
/// none is reported idle and left due. All in one `BEGIN IMMEDIATE` transaction, so ticks
/// never double-fire a slot. Then expired leases are reaped, overdue approvals expired and
/// whatever is stuck repaired (`repair_stuck`).
pub async fn tick(pool: &SqlitePool, now: &str) -> Result<TickReport, LeaseError> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let (woken, idle) = fire_timers_in(&mut tx, now).await?;
    tx.commit().await?;
    let reaped = reap_expired_leases(pool, now).await?;
    let expired = crate::store::gov::expire_approvals(pool, now).await?;
    let repaired = repair_stuck(pool, now).await?;
    let pruned = prune_transcripts(pool, now).await?;
    Ok(TickReport {
        woken,
        idle,
        reaped,
        expired,
        repaired,
        pruned,
    })
}

async fn fire_timers_in(
    conn: &mut SqliteConnection,
    now: &str,
) -> Result<(Vec<WakeRequest>, Vec<AgentId>), Error> {
    let due: Vec<(i64, i64, i64, bool)> = sqlx::query_as(
        "SELECT a.id, a.timer_interval_secs, unixepoch(?1) / a.timer_interval_secs, \
         EXISTS (SELECT 1 FROM issues i WHERE i.next_agent_id = a.id \
             AND i.state NOT IN ('done', 'cancelled', 'blocked')) \
         OR EXISTS (SELECT 1 FROM wake_requests w WHERE w.agent_id = a.id \
             AND w.status = 'pending') \
         FROM agents a WHERE a.status = 'active' AND a.timer_interval_secs IS NOT NULL \
         AND (a.timer_last_fired_at IS NULL OR unixepoch(a.timer_last_fired_at) \
             / a.timer_interval_secs < unixepoch(?1) / a.timer_interval_secs) \
         ORDER BY a.id",
    )
    .bind(now)
    .fetch_all(&mut *conn)
    .await?;
    let (mut woken, mut idle) = (vec![], vec![]);
    for (agent, interval, slot, actionable) in due {
        if !actionable {
            idle.push(AgentId(agent));
            continue;
        }
        let wake = NewWakeRequest {
            agent_id: AgentId(agent),
            issue_id: None,
            source: WakeSource::Timer,
            reason: format!("timer, every {interval}s"),
            idempotency_key: format!("timer:agent:{agent}:slot:{slot}"),
            not_before: None,
        };
        woken.push(enqueue_in(conn, &wake, 1).await?);
        sqlx::query("UPDATE agents SET timer_last_fired_at = ? WHERE id = ?")
            .bind(now)
            .bind(agent)
            .execute(&mut *conn)
            .await?;
    }
    Ok((woken, idle))
}
