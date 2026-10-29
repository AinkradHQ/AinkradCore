//! The approvals service (E7.1): one path for every kind (sprint commit, PR merge, budget
//! overrun, hire, permission escalation). A `pr_merge` of the done flow (E9.3) marks the PR for
//! merging, or sends its issue back to the author (`forge::merge_decided_in`).
//!
//! - Opening: `open_approval_in` (or `open_approval`) stamps the deadline: `now` plus the
//!   kind's `approval.deadline.<kind>` setting (E15.17) for its project or company (0 waits for
//!   as long as it takes), or the caller's own (a runner's approval timeout, so the server expires an
//!   escalation exactly when the runner gives up on it).
//! - Deciding: `decide_approval` records approve / reject with an optional reply, audited, with
//!   what the decision does (a sprint starts, an agent is hired, a requirement's plan is approved
//!   or sent back, E15.10), and tells the requester.
//! - Expiring: `expire_approvals` (every scheduler tick) closes those past their deadline, and
//!   escalations whose run ended, audited, and tells the requester too.
//!
//! Telling the requester (`notify_in`): a decider's reply becomes their comment on the subject
//! issue, and the requesting agent gets one `approval` wake (key `approval:<id>:<status>`, so
//! never twice) whose reason carries the verdict and the reply. Two exceptions: a permission
//! escalation's requester is the run still waiting on it, which the runner answers directly (a
//! queued wake would only start a redundant follow-up run); a hire a human asked for names
//! the new agent itself as requester, so nobody is woken; and the done flow's `pr_merge` (E9.3)
//! wakes nobody either: its issue is merged, or goes back to (and wakes) its developer. An
//! approved `workflow_push` (#103) wakes nobody: a human pushes the branch, and its PR opens
//! once it is on the forge (`forge::workflow_decided_in`); a rejected one wakes the agent to
//! drop the workflow change.

use std::fmt;

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::exec::{NewWakeRequest, WakeSource};
use ainkrad_core::gov::{Approval, ApprovalId, ApprovalKind, ApprovalStatus, NewApproval};
use ainkrad_core::org::{AgentId, CompanyId};
use ainkrad_core::settings::Key;
use ainkrad_core::work::{IssueId, SprintId, UserId};
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row, SqliteConnection};

use super::id_column;
use crate::store::exec::enqueue_in;
use crate::store::forge::{merge_decided_in, workflow_decided_in};
use crate::store::org::{hire_decided_in, text};
use crate::store::settings::{run_scope_in, value_in};
use crate::store::work::{SprintError, approval_comment_in, plan_decided_in, sprint_decided_in};

macro_rules! approval_columns {
    () => {
        "id, company_id, kind, issue_id, sprint_id, agent_id, requested_by_agent_id, status, \
         decided_by_user_id, reply, payload, expires_at, created_at, decided_at"
    };
}

mod allow;
pub use allow::{allow_for_issue, allow_rule, issue_allow_rules};
#[cfg(any(test, feature = "test-support"))]
mod raw;
#[cfg(any(test, feature = "test-support"))]
pub use raw::*;

pub(crate) fn approval(row: SqliteRow) -> Result<Approval, Error> {
    Ok(Approval {
        id: ApprovalId(row.try_get("id")?),
        company_id: CompanyId(row.try_get("company_id")?),
        kind: text(&row, "kind")?,
        issue_id: id_column(&row, "issue_id")?.map(IssueId),
        sprint_id: id_column(&row, "sprint_id")?.map(SprintId),
        agent_id: id_column(&row, "agent_id")?.map(AgentId),
        requested_by: AgentId(row.try_get("requested_by_agent_id")?),
        status: text(&row, "status")?,
        decided_by: id_column(&row, "decided_by_user_id")?.map(UserId),
        reply: row.try_get("reply")?,
        payload: row.try_get("payload")?,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
        decided_at: row.try_get("decided_at")?,
    })
}

/// The longest deadline anyone may set, a year: past that, `NULL` (no deadline) says it better.
pub const MAX_DEADLINE_SECS: u64 = 365 * 24 * 3600;

/// Opens a `pending` approval at `now`, inside the caller's transaction, and appends
/// `approval.pending` by the agent that asked (the app's inbox and pushes follow it, E10). It
/// expires `deadline` seconds after `now` when given (clamped to 1..=`MAX_DEADLINE_SECS`),
/// else after its kind's deadline setting for its issue's project (else the requester's
/// company), else (0) never. `payload` must be valid JSON.
pub(crate) async fn open_approval_in(
    conn: &mut SqliteConnection,
    a: &NewApproval,
    deadline: Option<u64>,
    now: &str,
) -> Result<Approval, Error> {
    let valid: bool = sqlx::query_scalar("SELECT julianday(?) IS NOT NULL")
        .bind(now)
        .fetch_one(&mut *conn)
        .await?;
    if !valid {
        return Err(Error::InvalidArgument(format!("bad timestamp `{now}`")));
    }
    let deadline = match deadline {
        Some(d) => Some(d.clamp(1, MAX_DEADLINE_SECS) as i64),
        None => {
            let at = run_scope_in(conn, a.issue_id, a.requested_by).await?;
            let secs = value_in(conn, Key::approval_deadline(a.kind), at).await?;
            (secs > 0).then_some(secs)
        }
    };
    let opened = sqlx::query(concat!(
        "INSERT INTO approvals (company_id, kind, issue_id, sprint_id, agent_id, \
         requested_by_agent_id, payload, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, \
         strftime('%Y-%m-%dT%H:%M:%fZ', ?8, '+' || ?9 || ' seconds')) RETURNING ",
        approval_columns!()
    ))
    .bind(a.company_id.0)
    .bind(a.kind.as_str())
    .bind(a.issue_id.map(|i| i.0))
    .bind(a.sprint_id.map(|s| s.0))
    .bind(a.agent_id.map(|g| g.0))
    .bind(a.requested_by.0)
    .bind(&a.payload)
    .bind(now)
    .bind(deadline)
    .fetch_one(&mut *conn)
    .await
    .and_then(approval)?;
    let by = AuditActor::Agent(opened.requested_by);
    let details = json!({"kind": opened.kind.as_str()});
    append_approval_event(conn, &opened, by, details).await?;
    Ok(opened)
}

/// `open_approval_in` in its own `BEGIN IMMEDIATE` transaction, with its kind's deadline.
pub async fn open_approval(
    pool: &SqlitePool,
    a: &NewApproval,
    now: &str,
) -> Result<Approval, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let opened = open_approval_in(&mut tx, a, None, now).await?;
    tx.commit().await?;
    Ok(opened)
}

pub async fn get_approval(pool: &SqlitePool, id: ApprovalId) -> Result<Option<Approval>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        approval_columns!(),
        " FROM approvals WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(approval)
    .transpose()
}

/// The company's approvals, oldest first.
pub async fn list_approvals(
    pool: &SqlitePool,
    company_id: CompanyId,
) -> Result<Vec<Approval>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        approval_columns!(),
        " FROM approvals WHERE company_id = ? ORDER BY id"
    ))
    .bind(company_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(approval)
    .collect()
}

/// The approval, read inside the caller's transaction.
pub(crate) async fn approval_in(
    conn: &mut SqliteConnection,
    id: ApprovalId,
) -> Result<Approval, Error> {
    sqlx::query(concat!(
        "SELECT ",
        approval_columns!(),
        " FROM approvals WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_one(&mut *conn)
    .await
    .and_then(approval)
}

/// Why a decision was not recorded.
#[derive(Debug)]
pub enum DecideError {
    NotFound,
    /// It was decided (or expired) already.
    NotPending(ApprovalStatus),
    /// Its deadline passed before the decision: it is now expired.
    Expired,
    /// Approving a sprint commit starts the sprint, and it cannot start now.
    Sprint(SprintError),
    /// A budget overrun is approved with a raise of more than 0 tokens
    /// (`approve_budget_raise`); nothing else takes one.
    Raise,
    /// Only a permission escalation on an issue is allowed for its issue (`allow_for_issue`).
    Allow(String),
    Db(Error),
}

impl From<Error> for DecideError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for DecideError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such approval"),
            Self::NotPending(s) => write!(f, "the approval is {} already", s.as_str()),
            Self::Expired => f.write_str("the approval expired before the decision"),
            Self::Sprint(e) => write!(f, "the sprint cannot start: {e}"),
            Self::Raise => f.write_str(
                "a budget overrun is approved with a raise in tokens (more than 0); \
                 no other approval takes one",
            ),
            Self::Allow(why) => f.write_str(why),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DecideError {}

/// What a decision does besides approving or rejecting.
#[derive(Clone, Copy)]
enum Extra<'a> {
    None,
    /// A `budget_overrun`'s raise, in tokens.
    Raise(i64),
    /// "Allow for this issue": the allowlist entry, or `None` for the escalated call's own.
    Allow(Option<&'a str>),
}

/// Records `by`'s decision on the pending approval at `now`, with `reply`, and appends
/// `approval.approved` / `approval.rejected`, in one `BEGIN IMMEDIATE` transaction with what
/// the decision does: a `sprint_commit` starts its sprint or returns it to the product owner
/// (`work::sprint_decided_in`); a `hire_agent` activates or terminates its agent
/// (`org::hire_decided_in`); then the requester is told (`notify_in`). One past its deadline
/// is expired instead (`DecideError::Expired`). A `budget_overrun` is approved with
/// `approve_budget_raise`.
pub async fn decide_approval(
    pool: &SqlitePool,
    id: ApprovalId,
    approve: bool,
    by: UserId,
    reply: Option<&str>,
    now: &str,
) -> Result<Approval, DecideError> {
    decide(pool, id, approve, by, reply, Extra::None, now).await
}

/// Approves the pending `budget_overrun` as `decide_approval` does, raising its budget's
/// period by `raise` tokens (`budgets::raise_in`); anything else is `DecideError::Raise`.
pub async fn approve_budget_raise(
    pool: &SqlitePool,
    id: ApprovalId,
    raise: i64,
    by: UserId,
    reply: Option<&str>,
    now: &str,
) -> Result<Approval, DecideError> {
    decide(pool, id, true, by, reply, Extra::Raise(raise), now).await
}

async fn decide(
    pool: &SqlitePool,
    id: ApprovalId,
    approve: bool,
    by: UserId,
    reply: Option<&str>,
    extra: Extra<'_>,
    now: &str,
) -> Result<Approval, DecideError> {
    let raise = match extra {
        Extra::Raise(raise) => Some(raise),
        _ => None,
    };
    if expire_approvals(pool, now).await?.contains(&id) {
        return Err(DecideError::Expired);
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let current = match approval_in(&mut tx, id).await {
        Ok(a) => a,
        Err(Error::RowNotFound) => return Err(DecideError::NotFound),
        Err(e) => return Err(e.into()),
    };
    if current.status != ApprovalStatus::Pending {
        return Err(DecideError::NotPending(current.status));
    }
    let allow = match extra {
        Extra::Allow(rule) => Some(allow::target(&current, rule)?),
        _ => None,
    };
    let overrun = current.kind == ApprovalKind::BudgetOverrun && approve;
    if overrun != raise.is_some_and(|r| r > 0) || (!overrun && raise.is_some()) {
        return Err(DecideError::Raise);
    }
    let status = match approve {
        true => ApprovalStatus::Approved,
        false => ApprovalStatus::Rejected,
    };
    let reply = reply.map(str::trim).filter(|r| !r.is_empty());
    sqlx::query(
        "UPDATE approvals SET status = ?, decided_by_user_id = ?, reply = ?, decided_at = ? \
         WHERE id = ?",
    )
    .bind(status.as_str())
    .bind(by.0)
    .bind(reply)
    .bind(now)
    .bind(id.0)
    .execute(&mut *tx)
    .await?;
    let decided = approval_in(&mut tx, id).await?;
    let mut details = json!({"kind": decided.kind.as_str(), "reply": reply});
    if let Some(raise) = raise {
        details["raise"] = raise.into();
    }
    append_approval_event(&mut tx, &decided, AuditActor::User(by), details).await?;
    match decided.kind {
        ApprovalKind::SprintCommit => sprint_decided_in(&mut tx, &decided, by)
            .await
            .map_err(DecideError::Sprint)?,
        ApprovalKind::HireAgent => hire_decided_in(&mut tx, &decided, AuditActor::User(by)).await?,
        ApprovalKind::PrMerge => merge_decided_in(&mut tx, &decided, by).await?,
        ApprovalKind::PlanApproval => {
            plan_decided_in(&mut tx, &decided, AuditActor::User(by), now).await?;
        }
        ApprovalKind::WorkflowPush => workflow_decided_in(&mut tx, &decided).await?,
        ApprovalKind::BudgetOverrun => {
            if let Some(raise) = raise {
                super::raise_in(&mut tx, &decided, raise, by).await?;
            }
        }
        _ => {}
    }
    if let Some((issue, rule)) = allow {
        allow::allow_in(&mut tx, &decided, issue, &rule, by, now).await?;
    }
    notify_in(&mut tx, &decided, Some(by)).await?;
    tx.commit().await?;
    Ok(decided)
}

/// Expires, at `now`, every pending approval past its deadline, and every pending permission
/// escalation whose run has ended (the runner has denied it by then), with the reason as the
/// reply; appends `approval.expired` by the system for each, terminates the agent of an
/// expired hire, and tells each requester. Returns their ids.
pub async fn expire_approvals(pool: &SqlitePool, now: &str) -> Result<Vec<ApprovalId>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let ids: Vec<i64> = sqlx::query_scalar(
        "UPDATE approvals SET status = 'expired', decided_at = ?1, reply = CASE \
             WHEN julianday(expires_at) <= julianday(?1) \
                 THEN 'expired: no decision by ' || expires_at \
             ELSE 'expired: run ' || json_extract(payload, '$.run') || ' ended' END \
         WHERE status = 'pending' AND (julianday(expires_at) <= julianday(?1) \
             OR (kind = 'permission_escalation' AND EXISTS (SELECT 1 FROM runs r \
                 WHERE r.id = json_extract(approvals.payload, '$.run') \
                 AND r.state NOT IN ('queued', 'claimed', 'running')))) \
         RETURNING id",
    )
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    for &id in &ids {
        let a = approval_in(&mut tx, ApprovalId(id)).await?;
        let details = json!({"kind": a.kind.as_str(), "reason": a.reply});
        append_approval_event(&mut tx, &a, AuditActor::System, details).await?;
        if a.kind == ApprovalKind::HireAgent {
            hire_decided_in(&mut tx, &a, AuditActor::System).await?;
        }
        if a.kind == ApprovalKind::PlanApproval {
            plan_decided_in(&mut tx, &a, AuditActor::System, now).await?;
        }
        notify_in(&mut tx, &a, None).await?;
    }
    tx.commit().await?;
    Ok(ids.into_iter().map(ApprovalId).collect())
}

/// What the approval is about, for its requester: "Sprint 3 commit", "Hire of QA 2", …
async fn subject_in(conn: &mut SqliteConnection, a: &Approval) -> Result<String, Error> {
    let payload: serde_json::Value = serde_json::from_str(&a.payload).unwrap_or_default();
    let field = |k: &str| payload[k].as_str().unwrap_or("?").to_owned();
    Ok(match a.kind {
        ApprovalKind::SprintCommit => {
            let name: Option<String> = sqlx::query_scalar("SELECT name FROM sprints WHERE id = ?")
                .bind(a.sprint_id.map(|s| s.0))
                .fetch_optional(&mut *conn)
                .await?;
            format!("Sprint {} commit", name.unwrap_or_else(|| "?".to_owned()))
        }
        ApprovalKind::PrMerge => "PR merge".to_owned(),
        ApprovalKind::BudgetOverrun => "Budget overrun".to_owned(),
        ApprovalKind::HireAgent => format!("Hire of {}", field("name")),
        ApprovalKind::PermissionEscalation => format!("Permission for {}", field("tool")),
        ApprovalKind::PlanApproval => format!("Plan of {}", field("key")),
        ApprovalKind::WorkflowPush => format!("Workflow push of {}", field("branch")),
    })
}

/// Tells the requester of the decided (or expired) approval; see the module docs. `by` is the
/// decider, `None` on expiry (no comment then: nobody wrote one).
async fn notify_in(
    conn: &mut SqliteConnection,
    a: &Approval,
    by: Option<UserId>,
) -> Result<(), Error> {
    let subject = subject_in(conn, a).await?;
    let reply = a.reply.as_deref().map(str::trim).filter(|r| !r.is_empty());
    let headline = match (a.status, reply) {
        // Its reply already reads "expired: …".
        (ApprovalStatus::Expired, Some(r)) => format!("{subject} {r}"),
        (status, Some(r)) => format!("{subject} {}: {r}", status.as_str()),
        (status, None) => format!("{subject} {}", status.as_str()),
    };
    if let (Some(by), Some(_)) = (by, reply) {
        approval_comment_in(conn, a, by, &headline).await?;
    }
    let self_hire = a.kind == ApprovalKind::HireAgent && a.agent_id == Some(a.requested_by);
    // The done flow's merge (E9.3) moves its issue itself: merged, or back to its developer.
    let flow_merge = a.kind == ApprovalKind::PrMerge
        && serde_json::from_str::<serde_json::Value>(&a.payload)
            .is_ok_and(|p| p.get("pr").is_some());
    // An approved workflow push waits on a human, not on the agent (`workflow_decided_in`).
    let human_push = a.kind == ApprovalKind::WorkflowPush && a.status == ApprovalStatus::Approved;
    if a.kind == ApprovalKind::PermissionEscalation || self_hire || flow_merge || human_push {
        return Ok(());
    }
    let wake = NewWakeRequest {
        agent_id: a.requested_by,
        issue_id: a.issue_id,
        source: WakeSource::Approval,
        reason: format!("approval {}: {headline}", a.id.0),
        idempotency_key: format!("approval:{}:{}", a.id.0, a.status.as_str()),
        not_before: None,
    };
    enqueue_in(conn, &wake, 1).await.map(drop)
}

/// Appends `approval.<status>` about `a`.
async fn append_approval_event(
    conn: &mut SqliteConnection,
    a: &Approval,
    actor: AuditActor,
    details: serde_json::Value,
) -> Result<(), Error> {
    let action = format!("approval.{}", a.status.as_str());
    append_approval_event_as(conn, a, actor, &action, details).await
}

/// Appends `action` by `actor` about the approval.
async fn append_approval_event_as(
    conn: &mut SqliteConnection,
    a: &Approval,
    actor: AuditActor,
    action: &str,
    details: serde_json::Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "approval".to_owned(),
            id: a.id.0,
        }),
        company_id: Some(a.company_id),
        run_id: None,
        details: details.to_string(),
    };
    crate::store::audit::append(&mut *conn, &event)
        .await
        .map(drop)
}
