//! Issue transitions (E2.4): the next-actor rules applied to a stored issue, with its
//! audit event and the wake for an agent next actor, all in one transaction.
//! Removing a blocker link and deleting an issue go through here too, so neither can
//! leave a `blocked` issue with no open blocker.

use crate::domain::work::{IllegalIssueTransition, IssueState, IssueTransition, WakeSource, apply};
use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::SqliteConnection;

use super::checkout::{append_issue_event, issue_in};
use super::kanban::{wake_freed_in, wip_full};
use super::*;
use crate::store::exec::{NewWakeRequest, enqueue_in};

/// Why an issue transition was not applied.
#[derive(Debug)]
pub enum IssueTransitionError {
    NotFound,
    Illegal(IllegalIssueTransition),
    /// Another transition changed the issue first; re-read before trying again.
    Conflict,
    /// The kanban column it would enter holds its limit of issues already (E5.3).
    WipLimit {
        state: IssueState,
        limit: u32,
    },
    Db(Error),
}

impl From<Error> for IssueTransitionError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for IssueTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("issue not found"),
            Self::Illegal(e) => e.fmt(f),
            Self::Conflict => f.write_str("issue changed concurrently"),
            Self::WipLimit { state, limit } => write!(
                f,
                "the {} column is at its WIP limit of {limit}; finish something first",
                state.as_str()
            ),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for IssueTransitionError {}

/// Applies `transition` to the issue and appends `issue.<state>` by `actor`; when the
/// step names an agent to wake, its wake is enqueued in the same `BEGIN IMMEDIATE`
/// transaction, so a state change and its wake commit or roll back together. The wake's
/// idempotency key is `issue:<id>:audit:<seq>`, unique per change.
///
/// The open-blocker count the rules need is read in the same transaction. A timer next
/// actor must be a valid timestamp. The owner and the checkout are left as they are.
///
/// Closing an issue (`done` or `cancelled`) unblocks, in the same transaction and by the
/// same actor, every `blocked` dependant it leaves with no open blocker: each goes back to
/// `todo` with its next actor, who is woken if an agent (E2.5). Reopening a closed blocker
/// does not re-block its dependants.
pub async fn transition_issue(
    pool: &SqlitePool,
    id: IssueId,
    transition: &IssueTransition,
    actor: AuditActor,
) -> Result<Issue, IssueTransitionError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let updated = transition_issue_in(&mut tx, id, transition, actor).await?;
    tx.commit().await?;
    Ok(updated)
}

/// `transition_issue` inside the caller's `BEGIN IMMEDIATE` transaction.
pub(crate) async fn transition_issue_in(
    conn: &mut SqliteConnection,
    id: IssueId,
    transition: &IssueTransition,
    actor: AuditActor,
) -> Result<Issue, IssueTransitionError> {
    let current = issue_in(conn, id)
        .await?
        .ok_or(IssueTransitionError::NotFound)?;
    let source = match transition {
        IssueTransition::Unblock => WakeSource::BlockerClosed,
        _ => WakeSource::Assignment,
    };
    let updated = transition_in(conn, &current, transition, actor, source).await?;
    if updated.state.is_terminal() && !current.state.is_terminal() {
        unblock_dependants(conn, id, actor).await?;
    }
    Ok(updated)
}

/// Unblocks each `blocked` dependant of `closed` that has no open blocker left.
async fn unblock_dependants(
    conn: &mut SqliteConnection,
    closed: IssueId,
    actor: AuditActor,
) -> Result<(), IssueTransitionError> {
    let parked: Vec<i64> = sqlx::query_scalar(
        "SELECT l.blocked_id FROM citadel_blocker_links l JOIN citadel_issues d ON d.id = l.blocked_id \
         WHERE l.blocker_id = ? AND d.state = 'blocked' ORDER BY l.blocked_id",
    )
    .bind(closed.0)
    .fetch_all(&mut *conn)
    .await?;
    unblock_free(conn, parked, actor).await
}

/// Unblocks each of `parked` that is still there, still `blocked` and has no open blocker.
async fn unblock_free(
    conn: &mut SqliteConnection,
    parked: Vec<i64>,
    actor: AuditActor,
) -> Result<(), IssueTransitionError> {
    for id in parked.into_iter().map(IssueId) {
        let Some(dependant) = issue_in(conn, id).await? else {
            continue;
        };
        if dependant.state != IssueState::Blocked || open_blockers(conn, id).await? > 0 {
            continue;
        }
        let unblock = IssueTransition::Unblock;
        transition_in(conn, &dependant, &unblock, actor, WakeSource::BlockerClosed).await?;
    }
    Ok(())
}

/// Links `link.blocker` before `link.blocked` as `actor` (the admin's link): both issues
/// of one company, no cycle; an existing link is kept. A new link is audited on the blocked
/// issue as `issue.blocker_linked`. With `block`, the issue is then blocked, in the same
/// `BEGIN IMMEDIATE` transaction; closing the blocker unblocks it as any other (E2.5). The
/// blocked issue after. A self-link, another company's blocker or a cycle is
/// `Db(InvalidArgument)`.
pub async fn link_blocker(
    pool: &SqlitePool,
    link: BlockerLink,
    block: bool,
    actor: AuditActor,
) -> Result<Issue, IssueTransitionError> {
    let refuse = |why: &str| IssueTransitionError::Db(Error::InvalidArgument(why.to_owned()));
    if link.blocker == link.blocked {
        return Err(refuse("an issue cannot block itself"));
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let blocked = issue_in(&mut tx, link.blocked)
        .await?
        .ok_or(IssueTransitionError::NotFound)?;
    let blocker = issue_in(&mut tx, link.blocker)
        .await?
        .ok_or(IssueTransitionError::NotFound)?;
    let companies: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT company_id) FROM citadel_projects WHERE id IN (?, ?)",
    )
    .bind(blocked.project_id.0)
    .bind(blocker.project_id.0)
    .fetch_one(&mut *tx)
    .await?;
    if companies != 1 {
        return Err(refuse("the blocker is in another company"));
    }
    let linked: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM citadel_blocker_links WHERE blocker_id = ? AND blocked_id = ?)",
    )
    .bind(link.blocker.0)
    .bind(link.blocked.0)
    .fetch_one(&mut *tx)
    .await?;
    if !linked {
        super::add_blocker_in(&mut tx, link)
            .await
            .map_err(|e| match e {
                BlockerError::Cycle => refuse("that link would make a blocker cycle"),
                BlockerError::Db(e) => e.into(),
            })?;
        let details = json!({"blocker": link.blocker.0}).to_string();
        append_issue_event(
            &mut tx,
            &blocked,
            actor,
            "issue.blocker_linked",
            None,
            details,
        )
        .await?;
    }
    let after = match block {
        true => {
            transition_in(
                &mut tx,
                &blocked,
                &IssueTransition::Block,
                actor,
                WakeSource::Assignment,
            )
            .await?
        }
        false => blocked,
    };
    tx.commit().await?;
    Ok(after)
}

/// Removes the link, audited on the blocked issue as `issue.blocker_unlinked`; if that leaves
/// `blocked` parked with no open blocker, it is unblocked by `actor` and its next actor woken,
/// in the same `BEGIN IMMEDIATE` transaction (E2.5).
pub async fn remove_blocker(
    pool: &SqlitePool,
    link: BlockerLink,
    actor: AuditActor,
) -> Result<bool, IssueTransitionError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let removed =
        sqlx::query("DELETE FROM citadel_blocker_links WHERE blocker_id = ? AND blocked_id = ?")
            .bind(link.blocker.0)
            .bind(link.blocked.0)
            .execute(&mut *tx)
            .await
            .map(affected)?;
    if removed && let Some(blocked) = issue_in(&mut tx, link.blocked).await? {
        let details = json!({"blocker": link.blocker.0}).to_string();
        append_issue_event(
            &mut tx,
            &blocked,
            actor,
            "issue.blocker_unlinked",
            None,
            details,
        )
        .await?;
    }
    unblock_free(&mut tx, vec![link.blocked.0], actor).await?;
    tx.commit().await?;
    Ok(removed)
}

/// Cascades to subtasks, labels, blocker links and comments. Numbers are never reused.
/// Deleting a started top-level issue frees its kanban column (E5.3). Every `blocked` issue the deleted issue or its subtasks blocked, left with no open
/// blocker, is unblocked by `actor` and woken in the same `BEGIN IMMEDIATE` transaction.
pub async fn delete_issue(
    pool: &SqlitePool,
    id: IssueId,
    actor: AuditActor,
) -> Result<bool, IssueTransitionError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let gone = issue_in(&mut tx, id).await?;
    let parked: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT l.blocked_id FROM citadel_blocker_links l \
         JOIN citadel_issues d ON d.id = l.blocked_id \
         WHERE d.state = 'blocked' AND (l.blocker_id = ?1 \
             OR l.blocker_id IN (SELECT id FROM citadel_issues WHERE parent_id = ?1)) \
         ORDER BY l.blocked_id",
    )
    .bind(id.0)
    .fetch_all(&mut *tx)
    .await?;
    let deleted = sqlx::query("DELETE FROM citadel_issues WHERE id = ?")
        .bind(id.0)
        .execute(&mut *tx)
        .await
        .map(affected)?;
    unblock_free(&mut tx, parked, actor).await?;
    // A started top-level issue leaving a full kanban column wakes the next `todo` issue's agent.
    if let Some(i) = gone.filter(|i| i.parent_id.is_none() && i.state == IssueState::InProgress) {
        let key = format!("wip:issue:{}:deleted", i.id.0);
        wake_freed_in(&mut tx, i.project_id, key).await?;
    }
    tx.commit().await?;
    Ok(deleted)
}

/// Hands the issue to `next` (a `Reassign` by `actor`) inside the caller's `BEGIN
/// IMMEDIATE` transaction, waking an agent with `source`; `None` when the issue is gone or
/// closed and so has no next actor to change.
#[allow(dead_code)] // `terminate_agent` (the admin's controls) is not ported yet
pub(crate) async fn reassign_in(
    conn: &mut SqliteConnection,
    id: IssueId,
    next: NextActor,
    actor: AuditActor,
    source: WakeSource,
) -> Result<Option<Issue>, IssueTransitionError> {
    let Some(current) = issue_in(conn, id).await? else {
        return Ok(None);
    };
    if current.state.is_terminal() {
        return Ok(None);
    }
    let reassign = IssueTransition::Reassign { next };
    transition_in(conn, &current, &reassign, actor, source)
        .await
        .map(Some)
}

/// How many of the issue's blockers are not done or cancelled.
async fn open_blockers(conn: &mut SqliteConnection, id: IssueId) -> Result<i64, Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM citadel_blocker_links l JOIN citadel_issues b ON b.id = l.blocker_id \
         WHERE l.blocked_id = ? AND b.state NOT IN ('done', 'cancelled')",
    )
    .bind(id.0)
    .fetch_one(&mut *conn)
    .await
}

/// `transition_issue` inside the caller's `BEGIN IMMEDIATE` transaction, from the
/// `current` row it read; an agent it wakes is woken with `source`.
async fn transition_in(
    conn: &mut SqliteConnection,
    current: &Issue,
    transition: &IssueTransition,
    actor: AuditActor,
    source: WakeSource,
) -> Result<Issue, IssueTransitionError> {
    let open = open_blockers(conn, current.id).await? as usize;
    let step = apply(current.state, current.next_actor.as_ref(), transition, open)
        .map_err(IssueTransitionError::Illegal)?;
    // A full kanban column takes no more top-level issues, except one unblocked (E5.3).
    let entering = step.state != current.state && !step.state.is_terminal();
    if entering
        && current.parent_id.is_none()
        && *transition != IssueTransition::Unblock
        && let Some(limit) = wip_full(conn, current.project_id, step.state).await?
    {
        let state = step.state;
        return Err(IssueTransitionError::WipLimit { state, limit });
    }
    let (next_agent, next_user, next_at) = next_actor_columns(&step.next_actor);
    if let Some(at) = next_at {
        let valid: bool = sqlx::query_scalar("SELECT julianday(?) IS NOT NULL")
            .bind(at)
            .fetch_one(&mut *conn)
            .await?;
        if !valid {
            return Err(Error::InvalidArgument(format!("bad timestamp `{at}`")).into());
        }
    }

    let Some(row) = sqlx::query(concat!(
        "UPDATE citadel_issues SET state = ?, next_agent_id = ?, next_user_id = ?, next_at = ? \
         WHERE id = ? AND state = ? RETURNING ",
        issue_columns!()
    ))
    .bind(step.state.as_str())
    .bind(next_agent)
    .bind(next_user)
    .bind(next_at)
    .bind(current.id.0)
    .bind(current.state.as_str())
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Err(IssueTransitionError::Conflict);
    };
    let updated = issue(row)?;

    let details: String = sqlx::query_scalar(
        "SELECT json_object('from', ?, 'transition', ?, 'next_agent', ?, 'next_user', ?, \
         'next_at', ?)",
    )
    .bind(current.state.as_str())
    .bind(transition.name())
    .bind(next_agent)
    .bind(next_user)
    .bind(next_at)
    .fetch_one(&mut *conn)
    .await?;
    let action = format!("issue.{}", step.state.as_str());
    let seq = append_issue_event(conn, &updated, actor, &action, None, details).await?;
    // A leaving `in_progress` top-level issue frees a kanban slot: the next `todo` issue's agent is
    // woken. An agent next actor is woken in the same transaction, so the change and its wake
    // commit or roll back together.
    if current.parent_id.is_none()
        && current.state == IssueState::InProgress
        && step.state != IssueState::InProgress
    {
        let key = format!("wip:issue:{}:audit:{seq}", current.id.0);
        wake_freed_in(conn, current.project_id, key).await?;
    }
    if let Some(agent_id) = step.wake {
        let wake = NewWakeRequest {
            agent_id,
            issue_id: Some(current.id),
            source,
            reason: format!("issue {} {}", current.id.0, transition.name()),
            idempotency_key: format!("issue:{}:audit:{seq}", current.id.0),
            not_before: None,
        };
        enqueue_in(conn, &wake, 1).await?;
    }
    Ok(updated)
}
