//! Stuck auto-repair (E15.8, pains #3 and #4: stuck agents, and hand-offs nobody checks).
//!
//! Each scheduler tick repairs what the stuck detector reports, by the rule's `RepairAction`
//! (`citadel_core::exec::repair_for`): wake the next actor again, hand the issue to its lead or
//! up the chain, unblock it, release a dead checkout, requeue a lost run, or drop a wake nothing
//! can serve. An open issue untouched for `issue.idle_escalate_secs` (0: never) with no live run
//! is escalated too, as rule `issue_idle`: up the chain from the agent it waits on, or to the
//! admin from any other person.
//!
//! Every repair is audited as `repair.<rule>` with its rule, action, whether it changed
//! anything and when. An issue gets `repair.budget` repairs within `repair.window_secs`; a
//! repair that changed nothing counts too. Past the budget the issue goes to the admin (user 1)
//! once, audited as `repair.exhausted` with the repair history; a human next actor is never
//! stuck, so nothing repairs it again. Repairs never loop: each touches its issue (the stuck
//! clock restarts) and each is bounded by the budget. One repair per issue per pass, all in one
//! `BEGIN IMMEDIATE` transaction; one refused repair (a full kanban column) is recorded as
//! unchanged and the pass goes on.

use std::collections::HashSet;

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::exec::{
    IssueFacts, NewWakeRequest, RepairAction, RunEvent, WakeSource, WakeStatus,
};
use citadel_core::org::CompanyId;
use citadel_core::settings::{Key, Scope};
use citadel_core::work::{IssueTransition, NextActor};
use serde_json::{Value, json};
use sqlx::{Acquire, SqliteConnection};

use super::*;
use crate::store::audit;
use crate::store::org::{escalation_target_in, product_owner_in};
use crate::store::settings::value_in;
use crate::store::work::{IssueTransitionError, reassign_in, release_held_in, transition_issue_in};

/// One repair a tick applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repaired {
    /// The stuck rule (`StuckKind`), `issue_idle`, or `exhausted` for a hand-off to the admin.
    pub rule: String,
    pub issue_id: Option<IssueId>,
    /// The `RepairAction`, or `escalate_to_admin`.
    pub action: String,
    /// It moved something; one that did not still counts against the issue's budget.
    pub changed: bool,
}

/// What to repair.
struct Item {
    rule: &'static str,
    issue: Option<IssueId>,
    agent: Option<AgentId>,
    wake: Option<WakeRequestId>,
    run: Option<RunId>,
    action: RepairAction,
}

/// A repair that could not be applied: refused (recorded as unchanged), or a storage error.
enum Failed {
    Refused(String),
    Db(Error),
}

impl From<Error> for Failed {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl From<IssueTransitionError> for Failed {
    fn from(e: IssueTransitionError) -> Self {
        match e {
            IssueTransitionError::Db(e) => Self::Db(e),
            e => Self::Refused(e.to_string()),
        }
    }
}

impl From<TransitionError> for Failed {
    fn from(e: TransitionError) -> Self {
        match e {
            TransitionError::Db(e) => Self::Db(e),
            e => Self::Refused(e.to_string()),
        }
    }
}

/// Repairs everything stuck at `now`, then escalates idle issues; what it did, in order.
pub async fn repair_stuck(pool: &SqlitePool, now: &str) -> Result<Vec<Repaired>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let (mut done, mut touched) = (vec![], HashSet::new());
    for s in stuck_in(&mut tx, now).await? {
        // A full disk is the admin's: told once, when it fills (`runner.disk_full`).
        if s.repair == RepairAction::Notify || s.issue_id.is_some_and(|i| !touched.insert(i)) {
            continue;
        }
        let item = Item {
            rule: s.kind.as_str(),
            issue: s.issue_id,
            agent: s.agent_id,
            wake: s.wake_id,
            run: s.run_id,
            action: s.repair,
        };
        done.extend(repair_in(&mut tx, &item, now).await?);
    }
    for (f, project) in issue_facts_in(&mut tx, now).await? {
        if f.live_run {
            continue;
        }
        park_wake_in(&mut tx, &f).await?;
        if touched.contains(&f.id) {
            continue;
        }
        let limit = value_in(&mut tx, Key::IdleEscalateSecs, Scope::Project(project)).await?;
        if limit == 0 || f.idle_secs < limit {
            continue;
        }
        let agent = match f.next_actor {
            Some(NextActor::Agent(a)) => Some(a),
            Some(NextActor::Human(u)) if u != ESCALATION_USER => None,
            _ => continue,
        };
        let item = Item {
            rule: "issue_idle",
            issue: Some(f.id),
            agent,
            wake: None,
            run: None,
            action: RepairAction::Escalate,
        };
        done.extend(repair_in(&mut tx, &item, now).await?);
    }
    tx.commit().await?;
    if done.iter().any(|r| r.changed) {
        signal_wakes();
    }
    Ok(done)
}

/// How long an open issue may sit parked on a person, with no live run, before its product owner
/// is woken to look at it (R7a).
pub const PARKED_WAKE_SECS: i64 = 15 * 60;

/// Wakes the product owner of an issue whose next actor is a person and that has been idle for
/// more than `PARKED_WAKE_SECS`. Keyed by the issue's last change, so one park wakes once however
/// many passes see it, and a later park wakes again. Not a repair: it spends no budget.
async fn park_wake_in(conn: &mut SqliteConnection, f: &IssueFacts) -> Result<(), Error> {
    if !matches!(f.next_actor, Some(NextActor::Human(_))) || f.idle_secs <= PARKED_WAKE_SECS {
        return Ok(());
    }
    let Some(po) = product_owner_in(conn, f.id).await? else {
        return Ok(());
    };
    let since: String =
        sqlx::query_scalar("SELECT coalesce(updated_at, created_at) FROM issues WHERE id = ?")
            .bind(f.id.0)
            .fetch_one(&mut *conn)
            .await?;
    let wake = NewWakeRequest {
        agent_id: po,
        issue_id: Some(f.id),
        source: WakeSource::Escalation,
        reason: format!(
            "{} parked on a person for {} min",
            f.state.as_str(),
            f.idle_secs / 60
        ),
        idempotency_key: format!("parked:issue:{}:{since}", f.id.0),
        not_before: None,
    };
    enqueue_in(conn, &wake, 1).await?;
    Ok(())
}

/// One repair inside the pass: within the issue's budget, else its one hand-off to the admin.
async fn repair_in(
    conn: &mut SqliteConnection,
    it: &Item,
    now: &str,
) -> Result<Option<Repaired>, Error> {
    let mut action = it.action.as_str();
    let (mut rule, mut history) = (it.rule, Value::Null);
    if let Some(issue) = it.issue {
        let project: i64 = sqlx::query_scalar("SELECT project_id FROM issues WHERE id = ?")
            .bind(issue.0)
            .fetch_one(&mut *conn)
            .await?;
        let at = Scope::Project(citadel_core::work::ProjectId(project));
        let budget = value_in(conn, Key::RepairBudget, at).await?;
        let window = value_in(conn, Key::RepairWindowSecs, at).await?;
        let past: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT action, coalesce(json_extract(details, '$.action'), ''), \
             json_extract(details, '$.at') FROM audit_events \
             WHERE entity_kind = 'issue' AND entity_id = ?1 AND action LIKE 'repair.%' \
             AND julianday(json_extract(details, '$.at')) > julianday(?2, ?3) ORDER BY seq",
        )
        .bind(issue.0)
        .bind(now)
        .bind(format!("-{window} seconds"))
        .fetch_all(&mut *conn)
        .await?;
        if past.iter().any(|(a, _, _)| a == "repair.exhausted") {
            return Ok(None);
        }
        if past.len() as i64 >= budget {
            (rule, action) = ("exhausted", "escalate_to_admin");
            let past: Vec<Value> = past
                .iter()
                .map(|(a, act, at)| json!({"rule": &a[7..], "action": act, "at": at}))
                .collect();
            history = Value::Array(past);
        }
    }
    let mut sp = conn.begin().await?;
    let applied = match rule {
        "exhausted" => to_admin(&mut sp, it).await,
        _ => apply(&mut sp, it, now).await,
    };
    let (changed, error) = match applied {
        Ok(changed) => {
            sp.commit().await?;
            (changed, None)
        }
        Err(Failed::Refused(why)) => {
            sp.rollback().await?;
            (false, Some(why))
        }
        Err(Failed::Db(e)) => return Err(e),
    };
    let details = json!({"rule": rule, "action": action, "changed": changed, "error": error,
        "agent": it.agent.map(|a| a.0), "wake": it.wake.map(|w| w.0),
        "run": it.run.map(|r| r.0), "history": history, "at": now});
    record(conn, it, &format!("repair.{rule}"), details).await?;
    Ok(Some(Repaired {
        rule: rule.to_owned(),
        issue_id: it.issue,
        action: action.to_owned(),
        changed,
    }))
}

/// Applies the item's action: `true` when it moved something.
async fn apply(conn: &mut SqliteConnection, it: &Item, now: &str) -> Result<bool, Failed> {
    use RepairAction as R;
    let why = format!("repair: {}", it.rule);
    let wake_again = |agent: AgentId, key: String| NewWakeRequest {
        agent_id: agent,
        issue_id: it.issue,
        source: WakeSource::Timer,
        reason: why.clone(),
        idempotency_key: key,
        not_before: None,
    };
    match (it.action, it.issue) {
        (R::Rewake, Some(issue)) => {
            let Some(agent) = it.agent else {
                return Ok(false);
            };
            let key = format!("repair:issue:{}:{}:{now}", issue.0, it.rule);
            let w = enqueue_in(conn, &wake_again(agent, key), 1).await?;
            Ok(w.status == WakeStatus::Pending)
        }
        (R::ReassignToLead, Some(issue)) if it.rule == "no_next_actor" => {
            // The engine moves no issue without a next actor; this repairs that row itself.
            let to = escalation_target_in(conn, issue, AgentId(0)).await?;
            let (agent, user) = match &to {
                NextActor::Agent(a) => (Some(a.0), None),
                NextActor::Human(u) => (None, Some(u.0)),
                NextActor::Timer(_) => return Ok(false),
            };
            let set = sqlx::query(
                "UPDATE issues SET next_agent_id = ?, next_user_id = ? WHERE id = ? \
                 AND next_agent_id IS NULL AND next_user_id IS NULL AND next_at IS NULL",
            )
            .bind(agent)
            .bind(user)
            .bind(issue.0)
            .execute(&mut *conn)
            .await
            .map(affected)?;
            if let (true, NextActor::Agent(a)) = (set, to) {
                let key = format!("repair:issue:{}:{}:{now}", issue.0, it.rule);
                enqueue_in(conn, &wake_again(a, key), 1).await?;
            }
            Ok(set)
        }
        (R::ReassignToLead | R::Escalate, Some(issue)) => {
            if let Some(wake) = it.wake {
                drop_wake(
                    conn,
                    wake,
                    "no online runner can serve it; its issue escalated",
                )
                .await?;
                // Only the issue's own next actor's wake moves the issue.
                let next: Option<i64> =
                    sqlx::query_scalar("SELECT next_agent_id FROM issues WHERE id = ?")
                        .bind(issue.0)
                        .fetch_one(&mut *conn)
                        .await?;
                if next != it.agent.map(|a| a.0) {
                    return Ok(true);
                }
            }
            let to = match (it.action, it.agent) {
                (R::Escalate, Some(from)) => escalation_target_in(conn, issue, from).await?,
                (R::Escalate, None) => NextActor::Human(ESCALATION_USER),
                // An id no agent has: the chain starts at its bottom, the team lead.
                _ => escalation_target_in(conn, issue, AgentId(0)).await?,
            };
            let by = AuditActor::System;
            let moved = reassign_in(conn, issue, to, by, WakeSource::Escalation).await?;
            Ok(moved.is_some())
        }
        (R::Unblock, Some(issue)) => {
            let unblock = IssueTransition::Unblock;
            transition_issue_in(conn, issue, &unblock, AuditActor::System).await?;
            Ok(true)
        }
        (R::ReleaseCheckout, _) => {
            let Some(run) = it.run else { return Ok(false) };
            release_held_in(conn, run, AuditActor::System).await?;
            Ok(true)
        }
        (R::Requeue, _) => {
            let Some(current) = (match it.run {
                Some(run) => run_in(conn, run).await?,
                None => None,
            }) else {
                return Ok(false);
            };
            let cancel = RunEvent::Cancel {
                reason: format!("{why}: queued with no lease, requeued"),
            };
            transition_in(conn, &current, AuditActor::System, &cancel, now).await?;
            let key = format!("repair:run:{}", current.id.0);
            enqueue_in(conn, &wake_again(current.agent_id, key), 1).await?;
            Ok(true)
        }
        (R::DropWake, _) => {
            let Some(wake) = it.wake else {
                return Ok(false);
            };
            Ok(drop_wake(conn, wake, "no online runner can serve it").await?)
        }
        _ => Ok(false),
    }
}

/// The issue to the admin, past its repair budget.
async fn to_admin(conn: &mut SqliteConnection, it: &Item) -> Result<bool, Failed> {
    let Some(issue) = it.issue else {
        return Ok(false);
    };
    let admin = NextActor::Human(ESCALATION_USER);
    let by = AuditActor::System;
    let moved = reassign_in(conn, issue, admin, by, WakeSource::Escalation).await?;
    Ok(moved.is_some())
}

/// Drops a pending wake with `why` (never silently); `false` when it was no longer pending.
async fn drop_wake(
    conn: &mut SqliteConnection,
    wake: WakeRequestId,
    why: &str,
) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE wake_requests SET status = 'dropped', dropped_reason = ? \
         WHERE id = ? AND status = 'pending'",
    )
    .bind(format!("repair: {why}"))
    .bind(wake.0)
    .execute(&mut *conn)
    .await
    .map(affected)
}

/// Audits a repair by the system about its issue, else its run or wake.
async fn record(
    conn: &mut SqliteConnection,
    it: &Item,
    action: &str,
    details: Value,
) -> Result<(), Error> {
    let (kind, id) = match (it.issue, it.run, it.wake) {
        (Some(i), _, _) => ("issue", i.0),
        (None, Some(r), _) => ("run", r.0),
        (None, None, Some(w)) => ("wake_request", w.0),
        (None, None, None) => return Ok(()),
    };
    let company: Option<i64> = sqlx::query_scalar(
        "SELECT coalesce((SELECT p.company_id FROM issues i JOIN projects p \
             ON p.id = i.project_id WHERE i.id = ?1), \
         (SELECT company_id FROM agents WHERE id = ?2))",
    )
    .bind(it.issue.map(|i| i.0))
    .bind(it.agent.map(|a| a.0))
    .fetch_one(&mut *conn)
    .await?;
    let event = NewAuditEvent {
        actor: AuditActor::System,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: kind.to_owned(),
            id,
        }),
        company_id: company.map(CompanyId),
        run_id: it.run,
        details: details.to_string(),
    };
    audit::append(&mut *conn, &event).await.map(drop)
}
