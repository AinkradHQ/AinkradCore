//! The stuck detector (E2.8): reads what the rules in `citadel_core::exec::stuck` need, in
//! one transaction so every rule sees the same snapshot. Read-only: it reports, with each
//! issue's last repair; the scheduler's repair pass (`repair`, E15.8) acts on the same report.
//!
//! How long counts as stuck is the `run.stuck_after_secs` setting (E15.17): an issue's for its
//! project, a wake's or a queued run's for its issue's project (else its agent's company).

use std::collections::HashMap;

use citadel_core::exec::{IssueFacts, LastRepair, StuckIssue, issue_stuck, run_stuck, wake_stuck};
use citadel_core::org::CompanyId;
use citadel_core::settings::{Key, Scope};
use citadel_core::work::{NextActor, ProjectId, UserId};
use sqlx::SqliteConnection;

use super::*;
use crate::store::settings::value_in;

/// Where a wake's or run's threshold is read: its issue's project, else its agent's company.
fn scope(row: &SqliteRow) -> Result<Scope, Error> {
    Ok(match row.try_get::<Option<i64>, _>("project_id")? {
        Some(p) => Scope::Project(ProjectId(p)),
        None => Scope::Company(CompanyId(row.try_get("company_id")?)),
    })
}

/// `run.stuck_after_secs` at `at`, read once per scope per report.
async fn after_in(
    conn: &mut SqliteConnection,
    seen: &mut HashMap<Scope, i64>,
    at: Scope,
) -> Result<i64, Error> {
    if let Some(v) = seen.get(&at) {
        return Ok(*v);
    }
    let v = value_in(conn, Key::StuckAfterSecs, at).await?;
    seen.insert(at, v);
    Ok(v)
}

/// Seconds from `$1` (now) back to the column expression, as an integer.
macro_rules! secs_since {
    ($at:literal) => {
        concat!(
            "CAST((julianday(?1) - julianday(",
            $at,
            ")) * 86400 AS INTEGER)"
        )
    };
}

/// Every stuck open issue, then every pending wake no online runner can serve, then every
/// `queued` run with no lease, then every online runner whose disk is full (E15.9), as of `now`
/// (ISO-8601), in id order, each issue's with its last repair. See `issue_stuck`, `wake_stuck` and `run_stuck` for the rules.
pub async fn stuck_report(pool: &SqlitePool, now: &str) -> Result<Vec<StuckIssue>, Error> {
    let mut tx = pool.begin().await?;
    check_time(&mut tx, now).await?;
    let mut stuck = stuck_in(&mut tx, now).await?;
    for s in &mut stuck {
        let Some(issue) = s.issue_id else { continue };
        let last: Option<(String, String)> = sqlx::query_as(
            "SELECT json_extract(details, '$.action'), json_extract(details, '$.at') \
             FROM audit_events WHERE entity_kind = 'issue' AND entity_id = ? \
             AND action LIKE 'repair.%' ORDER BY seq DESC LIMIT 1",
        )
        .bind(issue.0)
        .fetch_optional(&mut *tx)
        .await?;
        s.last_repair = last.map(|(action, at)| LastRepair { action, at });
    }
    tx.commit().await?;
    Ok(stuck)
}

/// Every open issue's facts as of `now`, with its project, in id order; an issue waiting on its
/// requirement's plan (`plan_held!`, E15.10), or on an agent the admin paused (decision #34), is
/// not stuck: it waits by design.
pub(super) async fn issue_facts_in(
    conn: &mut SqliteConnection,
    now: &str,
) -> Result<Vec<(IssueFacts, ProjectId)>, Error> {
    let rows = sqlx::query(concat!(
        "SELECT i.id, i.project_id, i.state, i.next_agent_id, i.next_user_id, i.next_at, \
         a.status AS agent_status, \
         EXISTS (SELECT 1 FROM audit_events e WHERE e.action = 'agent.paused_by_breaker' \
             AND e.entity_kind = 'agent' AND e.entity_id = a.id) AS by_breaker, \
         (SELECT count(*) FROM blocker_links l WHERE l.blocked_id = i.id) AS blockers, \
         (SELECT count(*) FROM blocker_links l JOIN issues b ON b.id = l.blocker_id \
             WHERE l.blocked_id = i.id AND b.state NOT IN ('done', 'cancelled')) \
             AS open_blockers, \
         EXISTS (SELECT 1 FROM wake_requests w WHERE w.status = 'pending' \
             AND w.issue_id = i.id AND w.agent_id = i.next_agent_id) AS pending_wake, \
         EXISTS (SELECT 1 FROM runs r WHERE r.issue_id = i.id \
             AND r.state IN ('queued', 'claimed', 'running')) AS live_run, \
         (i.state = 'todo' AND i.parent_id IS NULL AND EXISTS (SELECT 1 FROM wip_limits w \
             JOIN projects p ON p.id = w.project_id AND p.mode = 'kanban' \
             WHERE w.project_id = i.project_id AND w.state = 'in_progress' \
             AND w.max_issues <= (SELECT count(*) FROM issues o WHERE o.parent_id IS NULL \
                 AND o.project_id = i.project_id AND o.state = 'in_progress'))) AS wip_held, ",
        secs_since!(
            "max(i.created_at, \
             coalesce((SELECT max(at) FROM audit_events \
                 WHERE entity_kind = 'issue' AND entity_id = i.id), i.created_at), \
             coalesce((SELECT max(ended_at) FROM runs WHERE issue_id = i.id), i.created_at))"
        ),
        " AS idle_secs, \
         CASE WHEN i.checkout_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM runs r \
             WHERE r.id = i.checkout_run_id AND r.state IN ('queued', 'claimed', 'running')) \
             THEN i.checkout_run_id END AS dead_checkout \
         FROM issues i LEFT JOIN agents a ON a.id = i.next_agent_id \
         WHERE i.state NOT IN ('done', 'cancelled') \
         AND NOT (a.status = 'paused' AND a.paused_at IS NOT NULL) AND NOT ",
        plan_held!("i.next_agent_id", "i.id"),
        " ORDER BY i.id"
    ))
    .bind(now)
    .fetch_all(&mut *conn)
    .await?;
    let mut all = vec![];
    for row in rows {
        let agent = row.try_get::<Option<i64>, _>("next_agent_id")?.map(AgentId);
        let user = row.try_get::<Option<i64>, _>("next_user_id")?.map(UserId);
        let at: Option<String> = row.try_get("next_at")?;
        let next_actor = match (agent, user, at) {
            (Some(a), _, _) => Some(NextActor::Agent(a)),
            (_, Some(u), _) => Some(NextActor::Human(u)),
            (_, _, at) => at.map(NextActor::Timer),
        };
        let agent_status: Option<String> = row.try_get("agent_status")?;
        let facts = IssueFacts {
            id: IssueId(row.try_get("id")?),
            state: text(&row, "state")?,
            next_actor,
            agent_status: match agent_status {
                Some(_) => Some(text(&row, "agent_status")?),
                None => None,
            },
            paused_by_breaker: row.try_get("by_breaker")?,
            blockers: row.try_get("blockers")?,
            open_blockers: row.try_get("open_blockers")?,
            pending_wake: row.try_get("pending_wake")?,
            live_run: row.try_get("live_run")?,
            wip_held: row.try_get("wip_held")?,
            idle_secs: row.try_get("idle_secs")?,
            dead_checkout: row.try_get::<Option<i64>, _>("dead_checkout")?.map(RunId),
        };
        all.push((facts, ProjectId(row.try_get("project_id")?)));
    }
    Ok(all)
}

/// `stuck_report` inside the caller's transaction, without the last repairs.
pub(super) async fn stuck_in(
    tx: &mut SqliteConnection,
    now: &str,
) -> Result<Vec<StuckIssue>, Error> {
    let (mut stuck, mut seen) = (vec![], HashMap::new());
    for (facts, project) in issue_facts_in(tx, now).await? {
        let at = Scope::Project(project);
        stuck.extend(issue_stuck(&facts, after_in(tx, &mut seen, at).await?));
    }

    // An agent's wake is served by a runner holding every one of its tags (`dispatch_next`), the
    // one it is pinned to when it is.
    let wakes = sqlx::query(concat!(
        "SELECT w.id, w.agent_id, w.issue_id, a.runner_tags, a.company_id, \
         (SELECT project_id FROM issues WHERE id = w.issue_id) AS project_id, ",
        secs_since!("max(w.created_at, coalesce(w.not_before, w.created_at))"),
        " AS waiting_secs, \
         EXISTS (SELECT 1 FROM runners r \
             WHERE (w.runner_id IS NULL OR r.id = w.runner_id) \
             AND NOT EXISTS (SELECT 1 FROM json_each(a.runner_tags) t \
                 WHERE t.value NOT IN (SELECT value FROM json_each(r.tags)))) AS runner_known \
         FROM wake_requests w JOIN agents a ON a.id = w.agent_id \
         WHERE w.status = 'pending' AND a.status = 'active' \
         AND NOT EXISTS (SELECT 1 FROM runners r \
             WHERE (r.status = 'online' OR r.wake_requested_at IS NOT NULL) \
             AND (w.runner_id IS NULL OR r.id = w.runner_id) \
             AND NOT EXISTS (SELECT 1 FROM json_each(a.runner_tags) t \
                 WHERE t.value NOT IN (SELECT value FROM json_each(r.tags)))) \
         ORDER BY w.id"
    ))
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    for row in wakes {
        let Json(tags) = row.try_get::<Json<Vec<String>>, _>("runner_tags")?;
        let at = scope(&row)?;
        stuck.extend(wake_stuck(
            WakeRequestId(row.try_get("id")?),
            AgentId(row.try_get("agent_id")?),
            row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId),
            &tags,
            row.try_get("runner_known")?,
            row.try_get("waiting_secs")?,
            after_in(tx, &mut seen, at).await?,
        ));
    }

    // Defence in depth: dispatch claims what it queues, so a queued run is never leased.
    let queued = sqlx::query(concat!(
        "SELECT r.id, r.agent_id, r.issue_id, a.company_id, \
         (SELECT project_id FROM issues WHERE id = r.issue_id) AS project_id, ",
        secs_since!("r.queued_at"),
        " AS queued_secs FROM runs r JOIN agents a ON a.id = r.agent_id \
         WHERE r.state = 'queued' \
         AND NOT EXISTS (SELECT 1 FROM leases l WHERE l.run_id = r.id) ORDER BY r.id"
    ))
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    for row in queued {
        let at = scope(&row)?;
        stuck.extend(run_stuck(
            RunId(row.try_get("id")?),
            AgentId(row.try_get("agent_id")?),
            row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId),
            row.try_get("queued_secs")?,
            after_in(tx, &mut seen, at).await?,
        ));
    }
    stuck.extend(full_disks_in(tx).await?);
    Ok(stuck)
}
