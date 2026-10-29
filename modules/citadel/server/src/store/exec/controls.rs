//! The admin's controls of agents and runs (decision #34, runner protocol 1.19), each through the
//! engine, audited as its actor, in one `BEGIN IMMEDIATE` transaction:
//!
//! - **Pause** an agent (`pause_agent`, or a company's every agent): it gets no new run (dispatch
//!   serves active agents only) and its wakes wait; its running run finishes the tool call in
//!   flight and ends `cancelled: paused by admin` (a `pause` control); a run not started yet is
//!   cancelled at once. Its issues wait on it by design, so the stuck detector leaves them alone
//!   (`agents.paused_at`). **Resume** makes it active and wakes it on every open issue waiting on
//!   it, its paused work included; its pending wakes on issues that no longer wait on it are
//!   dropped (`agent.resumed` lists them).
//! - **Stop** a run (`stop_run`): the hard stop. The run ends `cancelled: stopped by admin` now
//!   (the state machine; its lease, token and checkout go with it), and its runner is told at
//!   once (a `stop` control, sent as `Cancel`), else at its next heartbeat.
//! - **Message** a run (`message_run`): a live run's runner gives it to the harness as its next
//!   turn and says so in the transcript (`user_message`, which marks it delivered). One the run
//!   ends before taking becomes a comment on its issue that wakes the run's agent
//!   (`undelivered_in`, from the terminal transition); a message to a run that is not live is
//!   that comment at once.
//! - **Nudge** an issue (`nudge_issue`): its next actor, an agent, is woken again.
//!
//! The runner's connection takes its runs' unsent controls (`take_controls`) each poll.
// ponytail: a control is sent once; one lost to a dropped connection is not resent (a pause is
// then not applied, a message becomes a comment when the run ends, a stop still lands at the
// next heartbeat). Resend unsent-and-undelivered on `Hello` if that ever matters.

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::exec::{NewWakeRequest, RunEvent, RunState, WakeRequest, WakeSource};
use citadel_core::org::CompanyId;
use citadel_core::work::NextActor;
use serde_json::{Value, json};
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit;
use crate::store::work::{append_issue_event, issue_in};

/// Why a paused run ended; the runner says the same.
pub const PAUSED: &str = "paused by admin";
/// Why a stopped run ended.
pub const STOPPED: &str = "stopped by admin";

/// A control for a run's runner: (id, run, kind, body).
pub type RunControl = (i64, i64, String, String);

/// Appends `action` by `actor` about `(kind, id)` in `company`.
pub(super) async fn record(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    (kind, id): (&str, i64),
    company: i64,
    run: Option<RunId>,
    details: Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: kind.to_owned(),
            id,
        }),
        company_id: Some(CompanyId(company)),
        run_id: run,
        details: details.to_string(),
    };
    audit::append(&mut *conn, &event).await.map(drop)
}

/// Inserts a control, once per `key`: its id, and whether it is new.
pub(super) async fn control_in(
    conn: &mut SqliteConnection,
    run: RunId,
    kind: &str,
    body: &str,
    key: Option<&str>,
    now: &str,
) -> Result<(i64, bool), Error> {
    let inserted: Option<i64> = sqlx::query_scalar(
        "INSERT INTO run_controls (run_id, kind, body, idempotency_key, created_at) \
         VALUES (?, ?, ?, ?, ?) ON CONFLICT (run_id, idempotency_key) DO NOTHING RETURNING id",
    )
    .bind(run.0)
    .bind(kind)
    .bind(body)
    .bind(key)
    .bind(now)
    .fetch_optional(&mut *conn)
    .await?;
    match inserted {
        Some(id) => Ok((id, true)),
        None => sqlx::query_scalar(
            "SELECT id FROM run_controls WHERE run_id = ? AND idempotency_key = ?",
        )
        .bind(run.0)
        .bind(key)
        .fetch_one(&mut *conn)
        .await
        .map(|id| (id, false)),
    }
}

/// Pauses the agent inside the caller's transaction: `false` when it was not active.
async fn pause_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    actor: AuditActor,
    now: &str,
) -> Result<bool, TransitionError> {
    let company: Option<i64> = sqlx::query_scalar(
        "UPDATE agents SET status = 'paused', paused_at = ?1 WHERE id = ?2 AND status = 'active' \
         RETURNING company_id",
    )
    .bind(now)
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
        match current.state {
            // Its tool call finishes first; the runner then ends it `Cancelled`.
            RunState::Running => drop(control_in(conn, current.id, "pause", "", None, now).await?),
            _ => {
                let cancel = RunEvent::Cancel {
                    reason: PAUSED.to_owned(),
                };
                transition_in(conn, &current, actor, &cancel, now).await?;
            }
        }
    }
    let details = json!({"runs": live, "at": now});
    record(
        conn,
        actor,
        "agent.paused",
        ("agent", agent.0),
        company,
        None,
        details,
    )
    .await?;
    Ok(true)
}

/// Pauses the agent (the module's rules): `false` when it was not active.
pub async fn pause_agent(
    pool: &SqlitePool,
    agent: AgentId,
    actor: AuditActor,
    now: &str,
) -> Result<bool, TransitionError> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let paused = pause_in(&mut tx, agent, actor, now).await?;
    tx.commit().await?;
    if paused {
        signal_wakes();
    }
    Ok(paused)
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
        "UPDATE agents SET status = 'active', paused_at = NULL WHERE id = ? AND status = 'paused' \
         RETURNING company_id",
    )
    .bind(agent.0)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(company) = company else {
        return Ok(false);
    };
    let issues: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM issues WHERE next_agent_id = ? AND state NOT IN ('done', 'cancelled') \
         ORDER BY id",
    )
    .bind(agent.0)
    .fetch_all(&mut *conn)
    .await?;
    // Wakes that piled up while paused on issues that moved on (closed, or handed to someone
    // else) would replay stale work: dropped, and named in the audit.
    let mut dropped: Vec<i64> = sqlx::query_scalar(
        "UPDATE wake_requests SET status = 'dropped', \
         dropped_reason = 'resume: the issue no longer waits on this agent' \
         WHERE agent_id = ?1 AND status = 'pending' AND issue_id IS NOT NULL \
         AND issue_id NOT IN (SELECT value FROM json_each(?2)) RETURNING id",
    )
    .bind(agent.0)
    .bind(Json(&issues))
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
    let details = json!({"issues": issues, "dropped_wakes": dropped, "at": now});
    record(
        conn,
        actor,
        "agent.resumed",
        ("agent", agent.0),
        company,
        None,
        details,
    )
    .await?;
    Ok(true)
}

/// Resumes a paused agent (by the admin or the loop breaker): `false` when it was not paused.
pub async fn resume_agent(
    pool: &SqlitePool,
    agent: AgentId,
    actor: AuditActor,
    now: &str,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let resumed = resume_in(&mut tx, agent, actor, now).await?;
    tx.commit().await?;
    if resumed {
        signal_wakes();
    }
    Ok(resumed)
}

/// Wakes the active agent now, as `actor` (`agent.woken`): on each open issue waiting on it, else
/// once with no issue (it looks at its inbox). The wakes made (folded into pending ones where
/// there are); `None` when it is not active.
pub async fn wake_agent(
    pool: &SqlitePool,
    agent: AgentId,
    actor: AuditActor,
    now: &str,
) -> Result<Option<Vec<WakeRequest>>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let company: Option<i64> =
        sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ? AND status = 'active'")
            .bind(agent.0)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(company) = company else {
        return Ok(None);
    };
    let issues: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM issues WHERE next_agent_id = ? AND state NOT IN ('done', 'cancelled') \
         ORDER BY id",
    )
    .bind(agent.0)
    .fetch_all(&mut *tx)
    .await?;
    let targets: Vec<Option<IssueId>> = match issues.is_empty() {
        true => vec![None],
        false => issues.into_iter().map(|i| Some(IssueId(i))).collect(),
    };
    let mut wakes = vec![];
    for issue in targets {
        let wake = NewWakeRequest {
            agent_id: agent,
            issue_id: issue,
            source: WakeSource::Manual,
            reason: "woken by the admin".to_owned(),
            idempotency_key: format!(
                "wake:agent:{}:issue:{}:{now}",
                agent.0,
                issue.map_or(0, |i| i.0)
            ),
            not_before: None,
        };
        wakes.push(enqueue_in(&mut tx, &wake, 1).await?);
    }
    let ids: Vec<i64> = wakes.iter().map(|w| w.id.0).collect();
    let details = json!({"wakes": ids, "at": now});
    let entity = ("agent", agent.0);
    record(
        &mut tx,
        actor,
        "agent.woken",
        entity,
        company,
        None,
        details,
    )
    .await?;
    tx.commit().await?;
    signal_wakes();
    Ok(Some(wakes))
}

/// Pauses (`true`) or resumes every agent of the company that can be: the ones it changed.
pub async fn pause_company(
    pool: &SqlitePool,
    company: CompanyId,
    pause: bool,
    actor: AuditActor,
    now: &str,
) -> Result<Vec<AgentId>, TransitionError> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let from = if pause { "active" } else { "paused" };
    let agents: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM agents WHERE company_id = ? AND status = ? ORDER BY id")
            .bind(company.0)
            .bind(from)
            .fetch_all(&mut *tx)
            .await?;
    let mut changed = vec![];
    for agent in agents.into_iter().map(AgentId) {
        let done = match pause {
            true => pause_in(&mut tx, agent, actor, now).await?,
            false => resume_in(&mut tx, agent, actor, now).await?,
        };
        if done {
            changed.push(agent);
        }
    }
    tx.commit().await?;
    signal_wakes();
    Ok(changed)
}

/// Stops the run now: it ends `cancelled: stopped by admin` through the state machine, and its
/// runner is told at once.
pub async fn stop_run(
    pool: &SqlitePool,
    run: RunId,
    actor: AuditActor,
    now: &str,
) -> Result<Run, TransitionError> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let current = run_in(&mut tx, run)
        .await?
        .ok_or(TransitionError::NotFound)?;
    let cancel = RunEvent::Cancel {
        reason: STOPPED.to_owned(),
    };
    let (stopped, _) = transition_in(&mut tx, &current, actor, &cancel, now).await?;
    if current.runner_id.is_some() {
        control_in(&mut tx, run, "stop", STOPPED, None, now).await?;
    }
    tx.commit().await?;
    signal_wakes();
    Ok(stopped)
}

/// The unsent controls of `runner`'s runs, of `kinds`, marked sent at `now`, oldest first.
pub async fn take_controls(
    pool: &SqlitePool,
    runner: RunnerId,
    kinds: &[&str],
    now: &str,
) -> Result<Vec<RunControl>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let taken: Vec<RunControl> = sqlx::query_as(
        "UPDATE run_controls SET sent_at = ?1 WHERE sent_at IS NULL \
         AND kind IN (SELECT value FROM json_each(?3)) \
         AND run_id IN (SELECT id FROM runs WHERE runner_id = ?2) \
         RETURNING id, run_id, kind, body",
    )
    .bind(now)
    .bind(runner.0)
    .bind(Json(kinds))
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut taken = taken;
    taken.sort_by_key(|c| c.0);
    Ok(taken)
}

/// Wakes the issue's next actor again, as `actor`: the wake (folded into a pending one when
/// there is one). `None` when there is no such open issue; `Err(InvalidArgument)` when it waits
/// on no agent.
pub async fn nudge_issue(
    pool: &SqlitePool,
    issue: IssueId,
    actor: AuditActor,
    now: &str,
) -> Result<Option<WakeRequest>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let Some(i) = issue_in(&mut tx, issue).await? else {
        return Ok(None);
    };
    if i.state.is_terminal() {
        return Ok(None);
    }
    let Some(NextActor::Agent(agent)) = i.next_actor.clone() else {
        let why = "the issue waits on no agent; reassign it to one";
        return Err(Error::InvalidArgument(why.to_owned()));
    };
    let wake = NewWakeRequest {
        agent_id: agent,
        issue_id: Some(issue),
        source: WakeSource::Manual,
        reason: "nudged by the admin".to_owned(),
        idempotency_key: format!("nudge:issue:{}:{now}", issue.0),
        not_before: None,
    };
    let w = enqueue_in(&mut tx, &wake, 1).await?;
    let details = json!({"agent": agent.0, "wake": w.id.0, "status": w.status.as_str()});
    append_issue_event(
        &mut tx,
        &i,
        actor,
        "issue.nudged",
        None,
        details.to_string(),
    )
    .await?;
    tx.commit().await?;
    signal_wakes();
    Ok(Some(w))
}
