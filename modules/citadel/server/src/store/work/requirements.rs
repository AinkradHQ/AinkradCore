//! Requirements (E15.10, pain #10): what the admin asked for, from intake to done.
//!
//! - Every intake request becomes a requirement (`create_requirement_in`, called by
//!   `submit_intake`), numbered per company (R-1, R-2, …), owned by the company's CEO.
//! - Routing it (`route_intake`) ties each new project to it, so every epic and issue made there
//!   carries its id (`create_issue_in`: an issue inherits its parent's, else its epic's, else
//!   its project's); the owner becomes the first route's product owner (`hand_off_in`, decision
//!   #45).
//! - Plan-first (`plan`): no dev work until the full plan exists and is approved.
//! - The tree (`tree`): epics → tasks with live numbers, burndown, ETA and spend.

use std::fmt;

use citadel_core::audit::AuditActor;
use citadel_core::org::{AgentId, CompanyId};
use citadel_core::work::{
    Actor, Criterion, Issue, IssueId, PriorityLevel, RequirementId, RequirementState, UserId,
};
use serde_json::json;
use sqlx::SqliteConnection;

use super::*;
use crate::store::org::append_org_event;

mod apply;
mod plan;
mod tree;
pub use apply::*;
pub use plan::*;
pub use tree::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub id: RequirementId,
    pub company_id: CompanyId,
    /// Per company, from 1: `R-12`.
    pub number: i64,
    pub title: String,
    pub body: String,
    pub requested_by: UserId,
    /// The intake request; its comment thread is the requirement's thread.
    pub intake_issue_id: Option<IssueId>,
    /// Who answers the admin about it: the CEO, then the product owner it was handed to.
    pub owner_agent_id: Option<AgentId>,
    /// The issue the owner is woken on.
    pub owner_issue_id: Option<IssueId>,
    pub state: RequirementState,
    /// The approved plan's version; 0 before the first approval.
    pub plan_version: i64,
    pub created_at: String,
    /// The project it was filed for, a hint to the CEO (API minor 18).
    pub project_id: Option<ProjectId>,
    pub priority_level: PriorityLevel,
    pub criteria: Vec<Criterion>,
    /// When the admin paused it: no wake for its issues is dispatched until it is resumed.
    pub paused_at: Option<String>,
}

impl Requirement {
    /// `R-12`.
    pub fn key(&self) -> String {
        format!("R-{}", self.number)
    }
}

macro_rules! requirement_columns {
    () => {
        "id, company_id, number, title, body, requested_by_user_id, intake_issue_id, \
         owner_agent_id, owner_issue_id, state, plan_version, created_at, project_id, \
         priority_level, criteria, paused_at"
    };
}

pub(crate) fn requirement(row: SqliteRow) -> Result<Requirement, Error> {
    let id = |c: &str| -> Result<Option<i64>, Error> { row.try_get(c) };
    Ok(Requirement {
        id: RequirementId(row.try_get("id")?),
        company_id: CompanyId(row.try_get("company_id")?),
        number: row.try_get("number")?,
        title: row.try_get("title")?,
        body: row.try_get("body")?,
        requested_by: UserId(row.try_get("requested_by_user_id")?),
        intake_issue_id: id("intake_issue_id")?.map(IssueId),
        owner_agent_id: id("owner_agent_id")?.map(AgentId),
        owner_issue_id: id("owner_issue_id")?.map(IssueId),
        state: text(&row, "state")?,
        plan_version: row.try_get("plan_version")?,
        created_at: row.try_get("created_at")?,
        project_id: id("project_id")?.map(ProjectId),
        priority_level: text(&row, "priority_level")?,
        criteria: super::issues::criteria(&row.try_get::<String, _>("criteria")?)?,
        paused_at: row.try_get("paused_at")?,
    })
}

/// Why a requirement change was refused.
#[derive(Debug)]
pub enum RequirementError {
    NotFound,
    /// Only a planner of its projects (product owner, team lead), or the CEO or CTO, plans it.
    NotPlanner,
    /// Not in a state that allows it.
    State(RequirementState),
    /// The plan is not complete: every problem, in words.
    Incomplete(Vec<String>),
    /// A run works on one of its issues: stop it first.
    Busy,
    /// This many of its issues are still open: finish or cancel them first.
    Open(usize),
    Db(Error),
}

impl From<Error> for RequirementError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for RequirementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such requirement"),
            Self::NotPlanner => f.write_str(
                "only a product owner or team lead of its projects, or the CEO or CTO, plans a \
                 requirement",
            ),
            Self::State(s) => write!(f, "the requirement is {}", s.as_str()),
            Self::Incomplete(p) => write!(f, "the plan is not complete: {}", p.join("; ")),
            Self::Busy => f.write_str("a run works on one of its issues; stop the run first"),
            Self::Open(n) => write!(f, "{n} of its issues are still open"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RequirementError {}

/// Files the intake issue `intake` as the company's next requirement, owned by `owner` (its
/// CEO) and woken on the intake issue, which joins it; appends `requirement.created` by
/// `actor`. Inside `submit_intake`'s transaction.
pub(crate) async fn create_requirement_in(
    conn: &mut SqliteConnection,
    company: CompanyId,
    intake: &Issue,
    owner: Option<AgentId>,
    actor: AuditActor,
) -> Result<Requirement, Error> {
    let requester = match actor {
        AuditActor::User(u) => u,
        _ => super::INTAKE_FALLBACK_USER,
    };
    let r = sqlx::query(concat!(
        "INSERT INTO requirements (company_id, number, title, body, requested_by_user_id, \
         intake_issue_id, owner_agent_id, owner_issue_id) VALUES (?1, \
         (SELECT coalesce(max(number), 0) + 1 FROM requirements WHERE company_id = ?1), \
         ?2, ?3, ?4, ?5, ?6, ?5) RETURNING ",
        requirement_columns!()
    ))
    .bind(company.0)
    .bind(&intake.title)
    .bind(&intake.body)
    .bind(requester.0)
    .bind(intake.id.0)
    .bind(owner.map(|a| a.0))
    .fetch_one(&mut *conn)
    .await
    .and_then(requirement)?;
    sqlx::query("UPDATE issues SET requirement_id = ? WHERE id = ?")
        .bind(r.id.0)
        .bind(intake.id.0)
        .execute(&mut *conn)
        .await?;
    let details = json!({"key": r.key(), "title": r.title, "intake": intake.id.0,
                         "owner": owner.map(|a| a.0)});
    let entity = ("requirement", r.id.0);
    append_org_event(conn, company, actor, "requirement.created", entity, details).await?;
    Ok(r)
}

/// Hands the intake's requirement to `po`, woken on `kickoff` (decision #45: the product owner
/// owns the thread from here; the CEO can still post), and appends `requirement.handed_off` by
/// `actor`; nothing when the intake has no requirement.
pub(crate) async fn hand_off_in(
    conn: &mut SqliteConnection,
    intake: IssueId,
    po: AgentId,
    kickoff: IssueId,
    actor: AuditActor,
) -> Result<(), Error> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "UPDATE requirements SET owner_agent_id = ?, owner_issue_id = ? \
         WHERE id = (SELECT requirement_id FROM issues WHERE id = ?) RETURNING id, company_id",
    )
    .bind(po.0)
    .bind(kickoff.0)
    .bind(intake.0)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((id, company)) = row else {
        return Ok(());
    };
    let details = json!({"owner": po.0, "issue": kickoff.0});
    let entity = ("requirement", id);
    append_org_event(
        conn,
        CompanyId(company),
        actor,
        "requirement.handed_off",
        entity,
        details,
    )
    .await
}

pub async fn get_requirement(
    pool: &SqlitePool,
    id: RequirementId,
) -> Result<Option<Requirement>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        requirement_columns!(),
        " FROM requirements WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(requirement)
    .transpose()
}

pub(crate) async fn requirement_in(
    conn: &mut SqliteConnection,
    id: RequirementId,
) -> Result<Option<Requirement>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        requirement_columns!(),
        " FROM requirements WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(requirement)
    .transpose()
}

/// Requirements, newest first: the company's, or every company's.
pub async fn list_requirements(
    pool: &SqlitePool,
    company: Option<CompanyId>,
) -> Result<Vec<Requirement>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        requirement_columns!(),
        " FROM requirements WHERE ?1 IS NULL OR company_id = ?1 ORDER BY id DESC"
    ))
    .bind(company.map(|c| c.0))
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(requirement)
    .collect()
}

/// Renames the requirement to `title` as `actor` (`requirement.renamed`, with the old title); a
/// cancelled one keeps its name.
pub async fn rename_requirement(
    pool: &SqlitePool,
    id: RequirementId,
    title: &str,
    actor: AuditActor,
) -> Result<Requirement, RequirementError> {
    let title = title.trim();
    if title.is_empty() || title.contains('\n') {
        let why = "a requirement's title is one line, not empty".to_owned();
        return Err(Error::InvalidArgument(why).into());
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let r = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    if r.state == RequirementState::Cancelled {
        return Err(RequirementError::State(r.state));
    }
    if r.title != title {
        sqlx::query("UPDATE requirements SET title = ? WHERE id = ?")
            .bind(title)
            .bind(id.0)
            .execute(&mut *tx)
            .await?;
        let details = json!({"from": r.title, "to": title});
        event_in(&mut tx, &r, actor, "requirement.renamed", details).await?;
    }
    let renamed = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    tx.commit().await?;
    Ok(renamed)
}

/// Cancels the requirement as `actor`, with an optional `reason`: each of its open issues is
/// cancelled through the issue rules (unblocking what waited on it), then the requirement
/// (`requirement.cancelled`, naming them), in one transaction. Refused when it is done or
/// cancelled already, or while a run works on one of its issues.
pub async fn cancel_requirement(
    pool: &SqlitePool,
    id: RequirementId,
    reason: Option<&str>,
    actor: AuditActor,
) -> Result<Requirement, RequirementError> {
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    let mut tx = crate::store::begin_write(pool).await?;
    let r = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    if matches!(
        r.state,
        RequirementState::Done | RequirementState::Cancelled
    ) {
        return Err(RequirementError::State(r.state));
    }
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM runs u JOIN issues i ON i.id = u.issue_id \
         WHERE i.requirement_id = ? AND u.state IN ('queued', 'claimed', 'running'))",
    )
    .bind(id.0)
    .fetch_one(&mut *tx)
    .await?;
    if busy {
        return Err(RequirementError::Busy);
    }
    let open: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM issues WHERE requirement_id = ? AND state NOT IN ('done', 'cancelled') \
         ORDER BY id",
    )
    .bind(id.0)
    .fetch_all(&mut *tx)
    .await?;
    for &issue in &open {
        let cancel = &citadel_core::work::IssueTransition::Cancel;
        // An issue an earlier one's cancel closed already is skipped by the rules' own check.
        match super::transition_issue_in(&mut tx, IssueId(issue), cancel, actor).await {
            Ok(_) | Err(super::IssueTransitionError::Illegal(_)) => {}
            Err(super::IssueTransitionError::Db(e)) => return Err(e.into()),
            Err(e) => return Err(Error::InvalidArgument(e.to_string()).into()),
        }
    }
    sqlx::query("UPDATE requirements SET state = 'cancelled' WHERE id = ?")
        .bind(id.0)
        .execute(&mut *tx)
        .await?;
    let details = json!({"reason": reason, "from": r.state.as_str(), "issues": open});
    event_in(&mut tx, &r, actor, "requirement.cancelled", details).await?;
    let cancelled = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    tx.commit().await?;
    crate::store::exec::signal_wakes();
    Ok(cancelled)
}

/// Pauses the requirement as `actor` (`requirement.paused`): no wake for its issues is dispatched
/// until it is resumed; runs already working go on. Already paused changes and audits nothing.
/// Refused once it is done or cancelled.
pub async fn pause_requirement(
    pool: &SqlitePool,
    id: RequirementId,
    actor: AuditActor,
) -> Result<Requirement, RequirementError> {
    hold(pool, id, actor, true).await
}

/// Resumes a paused requirement as `actor` (`requirement.resumed`) and lets its held wakes go.
/// Not paused changes and audits nothing.
pub async fn resume_requirement(
    pool: &SqlitePool,
    id: RequirementId,
    actor: AuditActor,
) -> Result<Requirement, RequirementError> {
    let r = hold(pool, id, actor, false).await?;
    crate::store::exec::signal_wakes();
    Ok(r)
}

async fn hold(
    pool: &SqlitePool,
    id: RequirementId,
    actor: AuditActor,
    pause: bool,
) -> Result<Requirement, RequirementError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let r = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    if matches!(
        r.state,
        RequirementState::Done | RequirementState::Cancelled
    ) {
        return Err(RequirementError::State(r.state));
    }
    if r.paused_at.is_some() == pause {
        return Ok(r);
    }
    sqlx::query(
        "UPDATE requirements SET paused_at = CASE WHEN ? THEN \
         strftime('%Y-%m-%dT%H:%M:%fZ', 'now') END WHERE id = ?",
    )
    .bind(pause)
    .bind(id.0)
    .execute(&mut *tx)
    .await?;
    let action = if pause {
        "requirement.paused"
    } else {
        "requirement.resumed"
    };
    event_in(
        &mut tx,
        &r,
        actor,
        action,
        json!({"state": r.state.as_str()}),
    )
    .await?;
    let held = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    tx.commit().await?;
    Ok(held)
}

/// Marks the requirement done as `actor` (`requirement.done`): it must be `in_progress` with none
/// of its issues open (`RequirementError::Open`); a pause ends with it.
pub async fn finish_requirement(
    pool: &SqlitePool,
    id: RequirementId,
    actor: AuditActor,
) -> Result<Requirement, RequirementError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let r = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    if r.state != RequirementState::InProgress {
        return Err(RequirementError::State(r.state));
    }
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issues WHERE requirement_id = ? AND state NOT IN ('done', 'cancelled')",
    )
    .bind(id.0)
    .fetch_one(&mut *tx)
    .await?;
    if open > 0 {
        return Err(RequirementError::Open(open as usize));
    }
    sqlx::query("UPDATE requirements SET state = 'done', paused_at = NULL WHERE id = ?")
        .bind(id.0)
        .execute(&mut *tx)
        .await?;
    event_in(
        &mut tx,
        &r,
        actor,
        "requirement.done",
        json!({"from": r.state.as_str()}),
    )
    .await?;
    let done = requirement_in(&mut tx, id)
        .await?
        .ok_or(RequirementError::NotFound)?;
    tx.commit().await?;
    Ok(done)
}

/// Why `agent`'s work on `issue` waits on the issue's requirement's plan (plan-first,
/// `plan_held!`), in words; `None` when it does not.
pub async fn plan_hold(
    pool: &SqlitePool,
    issue: IssueId,
    agent: AgentId,
) -> Result<Option<String>, Error> {
    let held: Option<(i64, String, Option<String>)> = sqlx::query_as(concat!(
        "SELECT q.number, q.state, q.paused_at FROM issues i JOIN requirements q ON q.id = i.requirement_id \
         WHERE i.id = ?2 AND ",
        plan_held!("?1", "?2")
    ))
    .bind(agent.0)
    .bind(issue.0)
    .fetch_optional(pool)
    .await?;
    Ok(held.map(|(n, state, paused)| match state.as_str() {
        _ if paused.is_some() => format!("requirement R-{n} is paused: no work on its issues"),
        "cancelled" => format!("requirement R-{n} is cancelled: no work on its issues"),
        state => format!(
            "requirement R-{n}'s plan is not approved yet ({state}): no dev work starts until \
             its full plan (every epic with tasks, every task estimated and assigned) is \
             approved"
        ),
    }))
}
