//! Agent heartbeat timers (E2.9), run by the platform scheduler's `timers` job.
//!
//! Agents are event-driven by default; one that opts in to a timer is woken once per interval,
//! and only when it has something to act on. An idle timer is skipped, not fired: waking idle
//! agents on every heartbeat burned tokens doing nothing.

use super::wake::{NewWakeRequest, WakeRequest, enqueue_in};
use super::*;
use crate::domain::work::WakeSource;

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimerReport {
    /// The `timer` wakes stored, one per due agent with actionable work.
    pub woken: Vec<WakeRequest>,
    /// Due agents skipped for having nothing to do; they are checked again next pass.
    pub idle: Vec<AgentId>,
}

/// Opts the agent in to a timer every `interval_secs` (positive), or out with `None`; either way
/// the next pass may fire at once. `false` when there is no agent.
pub async fn set_agent_timer(
    pool: &SqlitePool,
    agent: AgentId,
    interval_secs: Option<i64>,
) -> Result<bool, Error> {
    sqlx::query("UPDATE citadel_agents SET timer_interval_secs = ?, timer_last_fired_at = NULL WHERE id = ?")
        .bind(interval_secs)
        .bind(agent.0)
        .execute(pool)
        .await
        .map(|r| r.rows_affected() > 0)
}

/// Time is cut into slots of each agent's interval since the Unix epoch, and an active opted-in
/// agent is due once per slot: one with actionable work (an open, unblocked issue it is next
/// actor on, or a pending wake) gets a `timer` wake keyed `timer:agent:<id>:slot:<n>` and its
/// `timer_last_fired_at` becomes `now`. One write transaction, so passes never double-fire a slot.
pub async fn fire_timers(pool: &SqlitePool, now: &str) -> Result<TimerReport, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let batch = crate::settings::value_in(&mut tx, "wake.timer_batch").await?;
    let due: Vec<(i64, i64, i64, bool)> = sqlx::query_as(
        "SELECT a.id, a.timer_interval_secs, unixepoch(?1) / a.timer_interval_secs, \
         EXISTS (SELECT 1 FROM citadel_issues i WHERE i.next_agent_id = a.id \
             AND i.state NOT IN ('done', 'cancelled', 'blocked')) \
         OR EXISTS (SELECT 1 FROM citadel_wake_requests w WHERE w.agent_id = a.id \
             AND w.status = 'pending') \
         FROM citadel_agents a WHERE a.status = 'active' AND a.timer_interval_secs IS NOT NULL \
         AND (a.timer_last_fired_at IS NULL OR unixepoch(a.timer_last_fired_at) \
             / a.timer_interval_secs < unixepoch(?1) / a.timer_interval_secs) \
         ORDER BY a.id LIMIT ?2",
    )
    .bind(now)
    .bind(batch)
    .fetch_all(&mut *tx)
    .await?;
    let mut report = TimerReport::default();
    for (agent, interval, slot, actionable) in due {
        if !actionable {
            report.idle.push(AgentId(agent));
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
        report.woken.push(enqueue_in(&mut tx, &wake, 1).await?);
        sqlx::query("UPDATE citadel_agents SET timer_last_fired_at = ? WHERE id = ?")
            .bind(now)
            .bind(agent)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(report)
}
