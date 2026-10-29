//! Issue checkout (E2.3): a live run claims an issue so no other run works on it at the
//! same time.
//!
//! The claim is one conditional `UPDATE` inside a `BEGIN IMMEDIATE` transaction: it only
//! matches an issue that is checkable and unheld, so of any number of racing runs exactly
//! one wins and every other gets `CheckoutError::Conflict`. A holder whose run has ended
//! (crashed before releasing) no longer holds the issue; the next checkout replaces it.

use ainkrad_core::audit::{AuditActor, AuditEntity, AuditEvent, NewAuditEvent};
use ainkrad_core::exec::RunState;
use ainkrad_core::org::CompanyId;
use ainkrad_core::work::IssueState;
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit;

/// Why a checkout was refused.
#[derive(Debug)]
pub enum CheckoutError {
    /// Another live run holds the issue. **Do not retry:** the holder is working on it, and
    /// retrying is how two agents end up on one issue. End the run instead.
    Conflict {
        held_by: RunId,
    },
    IssueNotFound,
    RunNotFound,
    /// Only a queued, claimed or running run may hold an issue.
    RunNotLive(RunState),
    /// Blocked and terminal issues cannot be checked out.
    NotCheckable(IssueState),
    /// Checking it out would start it, and the kanban `in_progress` column is full (E5.3).
    WipLimit {
        limit: u32,
    },
    Db(Error),
}

impl From<Error> for CheckoutError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for CheckoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { held_by } => write!(f, "issue is checked out by run {}", held_by.0),
            Self::IssueNotFound => f.write_str("issue not found"),
            Self::RunNotFound => f.write_str("run not found"),
            Self::RunNotLive(s) => write!(f, "a {} run cannot check out an issue", s.as_str()),
            Self::NotCheckable(s) => write!(f, "a {} issue cannot be checked out", s.as_str()),
            Self::WipLimit { limit } => {
                write!(f, "the in_progress column is at its WIP limit of {limit}")
            }
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for CheckoutError {}

/// Whether an issue in `state` may be checked out.
fn checkable(state: IssueState) -> bool {
    !matches!(
        state,
        IssueState::Blocked | IssueState::Done | IssueState::Cancelled
    )
}

/// The issue, read inside the caller's transaction.
pub(crate) async fn issue_in(
    conn: &mut SqliteConnection,
    id: IssueId,
) -> Result<Option<Issue>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        issue_columns!(),
        " FROM issues WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(issue)
    .transpose()
}

/// Checks `issue` out for the live run `run` at `now` (ISO-8601) and appends
/// `issue.checked_out` by the run's agent, in one transaction.
///
/// A `backlog` or `todo` issue moves to `in_progress`. Outside review, the run's agent
/// becomes owner and next actor; an `in_review` issue keeps its owner, state and reviewer,
/// so a reviewer's run can hold it while it reviews. Checking out again with the holding
/// run changes and audits nothing.
pub async fn checkout_issue(
    pool: &SqlitePool,
    issue_id: IssueId,
    run_id: RunId,
    now: &str,
) -> Result<Issue, CheckoutError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let valid: bool = sqlx::query_scalar("SELECT julianday(?) IS NOT NULL")
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
    if !valid {
        return Err(Error::InvalidArgument(format!("bad timestamp `{now}`")).into());
    }
    let r = sqlx::query("SELECT state, agent_id FROM runs WHERE id = ?")
        .bind(run_id.0)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(CheckoutError::RunNotFound)?;
    let run_state: RunState = text(&r, "state")?;
    if run_state.is_terminal() {
        return Err(CheckoutError::RunNotLive(run_state));
    }
    let agent: i64 = r.try_get("agent_id")?;
    let before = issue_in(&mut tx, issue_id)
        .await?
        .ok_or(CheckoutError::IssueNotFound)?;
    let starts = matches!(before.state, IssueState::Backlog | IssueState::Todo);
    if starts && before.parent_id.is_none() {
        let full = super::kanban::wip_full(&mut tx, before.project_id, IssueState::InProgress);
        if let Some(limit) = full.await? {
            return Err(CheckoutError::WipLimit { limit });
        }
    }

    let claimed = sqlx::query(concat!(
        "UPDATE issues SET checkout_run_id = ?1, checked_out_at = ?2, \
         state = CASE WHEN state IN ('backlog', 'todo') THEN 'in_progress' ELSE state END, \
         owner_agent_id = CASE WHEN state = 'in_review' THEN owner_agent_id ELSE ?3 END, \
         owner_user_id = CASE WHEN state = 'in_review' THEN owner_user_id END, \
         next_agent_id = CASE WHEN state = 'in_review' THEN next_agent_id ELSE ?3 END, \
         next_user_id = CASE WHEN state = 'in_review' THEN next_user_id END, \
         next_at = CASE WHEN state = 'in_review' THEN next_at END \
         WHERE id = ?4 AND state IN ('backlog', 'todo', 'in_progress', 'in_review') \
         AND (checkout_run_id IS NULL OR NOT EXISTS (SELECT 1 FROM runs h \
             WHERE h.id = issues.checkout_run_id \
             AND h.state IN ('queued', 'claimed', 'running'))) \
         RETURNING ",
        issue_columns!()
    ))
    .bind(run_id.0)
    .bind(now)
    .bind(agent)
    .bind(issue_id.0)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = claimed else {
        // Missed: the issue is not checkable, or a live run holds it.
        return match before.checkout_run_id {
            _ if !checkable(before.state) => Err(CheckoutError::NotCheckable(before.state)),
            Some(held_by) if held_by == run_id => Ok(before),
            Some(held_by) => Err(CheckoutError::Conflict { held_by }),
            None => Err(CheckoutError::NotCheckable(before.state)),
        };
    };
    let after = issue(row)?;
    let details: String = sqlx::query_scalar("SELECT json_object('from', ?, 'replaced', ?)")
        .bind(before.state.as_str())
        .bind(before.checkout_run_id.map(|r| r.0))
        .fetch_one(&mut *tx)
        .await?;
    append_issue_event(
        &mut tx,
        &after,
        AuditActor::Agent(AgentId(agent)),
        "issue.checked_out",
        Some(run_id),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(after)
}

/// Releases `issue` if `run` holds it, appending `issue.released` by `actor`; `false` when
/// the run did not hold it. State, owner and next actor are left as they are: moving the
/// issue on is a transition (E2.4). A run's terminal transition releases what it holds by
/// itself (E2.6).
pub async fn release_issue(
    pool: &SqlitePool,
    issue_id: IssueId,
    run_id: RunId,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let released = release_in(&mut tx, issue_id, run_id, actor).await?;
    tx.commit().await?;
    Ok(released)
}

/// Releases every issue `run` holds, inside the caller's transaction; the run is ending.
pub(crate) async fn release_held_in(
    conn: &mut SqliteConnection,
    run_id: RunId,
    actor: AuditActor,
) -> Result<(), Error> {
    let held: Vec<i64> = sqlx::query_scalar("SELECT id FROM issues WHERE checkout_run_id = ?")
        .bind(run_id.0)
        .fetch_all(&mut *conn)
        .await?;
    for id in held {
        release_in(conn, IssueId(id), run_id, actor).await?;
    }
    Ok(())
}

/// `release_issue` inside the caller's transaction.
async fn release_in(
    conn: &mut SqliteConnection,
    issue_id: IssueId,
    run_id: RunId,
    actor: AuditActor,
) -> Result<bool, Error> {
    let released = sqlx::query(concat!(
        "UPDATE issues SET checkout_run_id = NULL, checked_out_at = NULL \
         WHERE id = ? AND checkout_run_id = ? RETURNING ",
        issue_columns!()
    ))
    .bind(issue_id.0)
    .bind(run_id.0)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = released else {
        return Ok(false);
    };
    let after = issue(row)?;
    append_issue_event(
        conn,
        &after,
        actor,
        "issue.released",
        Some(run_id),
        "{}".to_owned(),
    )
    .await?;
    Ok(true)
}

/// Appends an event about `issue`, attributed to its project's company.
pub(crate) async fn append_issue_event(
    conn: &mut SqliteConnection,
    issue: &Issue,
    actor: AuditActor,
    action: &str,
    run_id: Option<RunId>,
    details: String,
) -> Result<AuditEvent, Error> {
    let company_id: i64 = sqlx::query_scalar("SELECT company_id FROM projects WHERE id = ?")
        .bind(issue.project_id.0)
        .fetch_one(&mut *conn)
        .await?;
    audit::append(
        &mut *conn,
        &NewAuditEvent {
            actor,
            action: action.to_owned(),
            entity: Some(AuditEntity {
                kind: "issue".to_owned(),
                id: issue.id.0,
            }),
            company_id: Some(CompanyId(company_id)),
            run_id,
            details,
        },
    )
    .await
}
