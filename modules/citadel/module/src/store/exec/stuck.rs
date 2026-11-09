//! The stuck detector (E2.8): reads what the rules in `domain::exec::stuck` need, in one
//! transaction so every rule sees the same snapshot. Read-only: it reports, with each issue's
//! last repair; the repair pass (`repair`, E15.8) acts on the same report.
//!
//! How long counts as stuck is the `run.stuck_after_secs` setting. A wake is stuck when no runner
//! that is online offers any harness of its agent's chain (the monolith's runner tags are not
//! ported: a Core runner is a device and carries none). A `queued` run with no session is stuck
//! too (dispatch claims what it queues, so one left queued came from outside the engine).

use std::collections::HashSet;

use ainkrad_core_server::api::App;
use sqlx::SqliteConnection;

use super::*;
use crate::domain::exec::stuck::{
    IssueFacts, LastRepair, StuckIssue, issue_stuck, run_stuck, wake_stuck,
};
use crate::domain::org::Tier;
use crate::domain::work::{NextActor, ProjectId, UserId};
use crate::store::work::requirements::plan_held;

/// Which harnesses a runner can take now, and whether any runner is known at all (it may only be
/// offline: a wake then waits for it rather than escalating to a person).
#[derive(Debug, Clone, Default)]
pub struct Serving {
    pub harnesses: HashSet<String>,
    pub known: bool,
}

/// What the platform offers right now.
pub async fn serving<H: Host>(app: &App, host: &H) -> Serving {
    let mut s = Serving {
        known: app.hub.runners().values().any(|r| {
            r.drivers
                .iter()
                .any(|d| d.name == ainkrad_proto::v2::AGENT_DRIVER)
        }),
        ..Serving::default()
    };
    for h in ["claude", "codex", "opencode", "agy"] {
        if !host.runners(app, h).await.is_empty() {
            s.harnesses.insert(h.to_owned());
        }
    }
    s
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
/// `queued` run with no session, as of `now` (ISO-8601), in id order, each issue's with its last
/// repair. See `issue_stuck`, `wake_stuck` and `run_stuck` for the rules.
pub async fn stuck_report<H: Host>(
    app: &App,
    host: &H,
    now: &str,
) -> Result<Vec<StuckIssue>, Error> {
    let serving = serving(app, host).await;
    let mut tx = app.pool.begin().await?;
    let mut stuck = stuck_in(&mut tx, now, &serving).await?;
    for s in &mut stuck {
        let Some(issue) = s.issue_id else { continue };
        let last: Option<(String, String)> = sqlx::query_as(
            "SELECT json_extract(details, '$.action'), json_extract(details, '$.at') \
             FROM audit_events WHERE entity_kind = 'issue' AND entity_id = ? \
             AND action LIKE 'citadel.repair.%' ORDER BY seq DESC LIMIT 1",
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
/// requirement's plan (`plan_held!`), or on an agent the admin paused, is not stuck: it waits by
/// design.
pub(super) async fn issue_facts_in(
    conn: &mut SqliteConnection,
    now: &str,
) -> Result<Vec<(IssueFacts, ProjectId)>, Error> {
    let rows = sqlx::query(concat!(
        "SELECT i.id, i.project_id, i.state, i.next_agent_id, i.next_user_id, i.next_at, \
         a.status AS agent_status, \
         EXISTS (SELECT 1 FROM audit_events e WHERE e.action = 'citadel.agent.paused_by_breaker' \
             AND e.entity_kind = 'agent' AND e.entity_id = a.id) AS by_breaker, \
         (SELECT count(*) FROM citadel_blocker_links l WHERE l.blocked_id = i.id) AS blockers, \
         (SELECT count(*) FROM citadel_blocker_links l JOIN citadel_issues b \
             ON b.id = l.blocker_id WHERE l.blocked_id = i.id \
             AND b.state NOT IN ('done', 'cancelled')) AS open_blockers, \
         EXISTS (SELECT 1 FROM citadel_wake_requests w WHERE w.status = 'pending' \
             AND w.issue_id = i.id AND w.agent_id = i.next_agent_id) AS pending_wake, \
         EXISTS (SELECT 1 FROM citadel_runs r WHERE r.issue_id = i.id \
             AND r.state IN ('queued', 'claimed', 'running')) AS live_run, \
         (i.state = 'todo' AND i.parent_id IS NULL AND EXISTS (SELECT 1 FROM citadel_wip_limits w \
             JOIN citadel_projects p ON p.id = w.project_id AND p.mode = 'kanban' \
             WHERE w.project_id = i.project_id AND w.state = 'in_progress' \
             AND w.max_issues <= (SELECT count(*) FROM citadel_issues o WHERE o.parent_id IS NULL \
                 AND o.project_id = i.project_id AND o.state = 'in_progress'))) AS wip_held, ",
        secs_since!(
            "max(i.created_at, \
             coalesce((SELECT max(at) FROM audit_events \
                 WHERE entity_kind = 'issue' AND entity_id = i.id), i.created_at), \
             coalesce((SELECT max(ended_at) FROM citadel_runs WHERE issue_id = i.id), \
                 i.created_at))"
        ),
        " AS idle_secs, \
         CASE WHEN i.checkout_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM citadel_runs r \
             WHERE r.id = i.checkout_run_id AND r.state IN ('queued', 'claimed', 'running')) \
             THEN i.checkout_run_id END AS dead_checkout \
         FROM citadel_issues i LEFT JOIN citadel_agents a ON a.id = i.next_agent_id \
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
    serving: &Serving,
) -> Result<Vec<StuckIssue>, Error> {
    let mut stuck = vec![];
    let after = crate::settings::value_in(tx, "run.stuck_after_secs").await?;
    for (facts, _) in issue_facts_in(tx, now).await? {
        stuck.extend(issue_stuck(&facts, after));
    }

    let wakes = sqlx::query(concat!(
        "SELECT w.id, w.agent_id, w.issue_id, ",
        secs_since!("max(w.created_at, coalesce(w.not_before, w.created_at))"),
        " AS waiting_secs FROM citadel_wake_requests w \
         JOIN citadel_agents a ON a.id = w.agent_id \
         WHERE w.status = 'pending' AND a.status = 'active' ORDER BY w.id"
    ))
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    for row in wakes {
        let agent = AgentId(row.try_get("agent_id")?);
        let chain = super::route::chain_in(tx, agent, Tier::Standard).await?;
        if chain
            .iter()
            .any(|r| serving.harnesses.contains(r.harness.as_str()))
        {
            continue;
        }
        let harness = chain.first().map_or("", |r| r.harness.as_str());
        stuck.extend(wake_stuck(
            row.try_get("id")?,
            agent,
            row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId),
            harness,
            // No runner online at all is an outage (told, not acted on); escalating is for a
            // runner that is online but offers nothing for this agent.
            serving.known || serving.harnesses.is_empty(),
            row.try_get("waiting_secs")?,
            after,
        ));
    }

    // Defence in depth: dispatch claims what it queues, so a queued run is never idle here.
    let queued = sqlx::query(concat!(
        "SELECT r.id, r.agent_id, r.issue_id, ",
        secs_since!("r.queued_at"),
        " AS queued_secs FROM citadel_runs r \
         WHERE r.state = 'queued' AND r.session_id IS NULL ORDER BY r.id"
    ))
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    for row in queued {
        stuck.extend(run_stuck(
            RunId(row.try_get("id")?),
            AgentId(row.try_get("agent_id")?),
            row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId),
            row.try_get("queued_secs")?,
            after,
        ));
    }
    Ok(stuck)
}
