//! Run transitions: the state machine applied to a stored run, with its audit event. A
//! run that ends drops its lease and releases its issue checkout in the same transaction
//! (E2.6), and a run that ends badly consults the loop breaker and the retry limits there
//! too (E2.7), so no caller can leave a lease, a checkout or a due escalation behind.

use std::fmt;

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::exec::{IllegalTransition, RunEvent, RunState, apply, failure_fingerprint};
use ainkrad_core::org::CompanyId;
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit;
use crate::store::work::{IssueTransitionError, release_held_in};

/// Why a transition was not applied.
#[derive(Debug)]
pub enum TransitionError {
    NotFound,
    Illegal(IllegalTransition),
    /// Another transition changed the run first; re-read before trying again.
    Conflict,
    /// Escalating the ended run's issue was refused; nothing was applied.
    Escalation(IssueTransitionError),
    /// `Start` goes through `start_run`, which also issues the run's token (E4.1).
    StartNeedsToken,
    Db(Error),
}

impl From<Error> for TransitionError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl From<IssueTransitionError> for TransitionError {
    fn from(e: IssueTransitionError) -> Self {
        Self::Escalation(e)
    }
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("run not found"),
            Self::Illegal(e) => e.fmt(f),
            Self::Conflict => f.write_str("run changed concurrently"),
            Self::Escalation(e) => e.fmt(f),
            Self::StartNeedsToken => f.write_str("start a run with `start_run` to issue its token"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for TransitionError {}

/// Applies `event` to the run and appends `run.<state>` by `actor`, in one transaction.
///
/// Optimistic: the state is read first and the update only matches a run still in that
/// state, so of two racing transitions one wins and the other gets `Conflict` (or
/// `Illegal`, if it read the winner's state). The write is the transaction's first
/// statement, so it never works from a stale snapshot. A heartbeat changes nothing and
/// writes nothing. Claim sets the runner and start the session; each stamps its
/// `claimed_at` / `started_at` / `ended_at`. A run ending failed, timed out or lost gets its
/// `failure_fingerprint` (E2.7), from the fail event's own fingerprint or else the reason.
/// A terminal transition deletes the run's lease, revokes its token (E4.1) and releases
/// every issue it holds (`issue.released` by `actor`); a failed, timed-out or lost run then
/// goes through `stop_in` at `now`: the loop breaker, and the escalation of a token-capped
/// run or a last attempt. A succeeded run that did not act on the issue waiting on it is
/// marked, and its agent nudged or the issue escalated (`no_action`). Retrying is still the caller's call (`schedule_retry`). `Start` is
/// refused with `StartNeedsToken`: only `start_run` starts a run, so every running run has a
/// token.
pub async fn transition_run(
    pool: &SqlitePool,
    id: RunId,
    actor: AuditActor,
    event: &RunEvent,
    now: &str,
) -> Result<Run, TransitionError> {
    if matches!(event, RunEvent::Start { .. }) {
        return Err(TransitionError::StartNeedsToken);
    }
    let current = get_run(pool, id).await?.ok_or(TransitionError::NotFound)?;
    let t = apply(current.state, event).map_err(TransitionError::Illegal)?;
    if t.state == current.state {
        return Ok(current);
    }
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let (updated, _) = transition_in(&mut tx, &current, actor, event, now).await?;
    tx.commit().await?;
    if updated.state.is_terminal() {
        // Its agent's follow-up wakes on the issue may go now (E15.6).
        signal_wakes();
    }
    Ok(updated)
}

/// `transition_run` inside the caller's transaction, from the `current` row it read; also
/// returns what `stop_in` did when the run ended badly.
pub(super) async fn transition_in(
    conn: &mut SqliteConnection,
    current: &Run,
    actor: AuditActor,
    event: &RunEvent,
    now: &str,
) -> Result<(Run, Option<Stop>), TransitionError> {
    let id = current.id;
    let t = apply(current.state, event).map_err(TransitionError::Illegal)?;
    if t.state == current.state {
        return Ok((current.clone(), None));
    }
    let (runner, session, given) = match event {
        RunEvent::Claim { runner } => (Some(runner.0), None, None),
        RunEvent::Start { session } => (None, session.as_deref(), None),
        RunEvent::Fail { fingerprint, .. } => (None, None, fingerprint.as_deref()),
        _ => (None, None, None),
    };
    let reason = t.reason.map(|r| r.to_string());
    let fingerprint = match (t.state, &reason) {
        (RunState::Failed | RunState::TimedOut | RunState::RunnerLost, Some(why)) => {
            Some(failure_fingerprint(t.state, given.unwrap_or(why)))
        }
        _ => None,
    };

    let Some(row) = sqlx::query(concat!(
        "UPDATE runs SET state = ?1, terminal_reason = ?2, \
         runner_id = coalesce(?3, runner_id), session_id = coalesce(?4, session_id), \
         failure_fingerprint = coalesce(?5, failure_fingerprint), \
         claimed_at = CASE WHEN ?1 = 'claimed' THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             ELSE claimed_at END, \
         started_at = CASE WHEN ?1 = 'running' THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             ELSE started_at END, \
         ended_at = CASE WHEN ?2 IS NOT NULL THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             ELSE ended_at END \
         WHERE id = ?6 AND state = ?7 RETURNING ",
        run_columns!()
    ))
    .bind(t.state.as_str())
    .bind(&reason)
    .bind(runner)
    .bind(session)
    .bind(&fingerprint)
    .bind(id.0)
    .bind(current.state.as_str())
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Err(TransitionError::Conflict);
    };
    let mut updated = run(row)?;

    let (company_id, details): (i64, String) = sqlx::query_as(
        "SELECT company_id, json_object('from', ?, 'event', ?, 'reason', ?) \
         FROM agents WHERE id = ?",
    )
    .bind(current.state.as_str())
    .bind(event.name())
    .bind(&reason)
    .bind(updated.agent_id.0)
    .fetch_one(&mut *conn)
    .await?;
    audit::append(
        &mut *conn,
        &NewAuditEvent {
            actor,
            action: format!("run.{}", t.state.as_str()),
            entity: Some(AuditEntity {
                kind: "run".to_owned(),
                id: id.0,
            }),
            company_id: Some(CompanyId(company_id)),
            run_id: Some(id),
            details,
        },
    )
    .await?;
    if t.state.is_terminal() {
        sqlx::query("DELETE FROM leases WHERE run_id = ?")
            .bind(id.0)
            .execute(&mut *conn)
            .await?;
        revoke_in(conn, id, now).await?;
        release_held_in(conn, id, actor).await?;
        // The admin's messages it never took go to its issue (1.19).
        undelivered_in(conn, &updated).await?;
        // A success that left its issue waiting on it untouched is no progress.
        if t.state == RunState::Succeeded
            && let Some(why) = super::no_action::no_action_in(conn, &updated, now).await?
        {
            updated.terminal_reason = Some(why);
        }
    }
    let stop = match fingerprint {
        Some(_) => stop_in(conn, &updated, now).await?,
        None => None,
    };
    Ok((updated, stop))
}

/// The run, read inside the caller's transaction.
pub(super) async fn run_in(conn: &mut SqliteConnection, id: RunId) -> Result<Option<Run>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        run_columns!(),
        " FROM runs WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(run)
    .transpose()
}
