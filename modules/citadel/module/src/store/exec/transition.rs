//! Run transitions: the state machine applied to a stored run, with its audit row. A run that
//! ends revokes its token, releases every issue it holds and, when it ended badly, queues its
//! retry, all in the same transaction, so no caller can leave a token, a checkout or a due retry
//! behind.

use std::fmt;

use ainkrad_core::audit::AuditActor;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, SqliteConnection};

use super::*;
use crate::domain::exec::breaker::failure_fingerprint;
use crate::domain::exec::{IllegalTransition, RunEvent, apply};
use crate::store::audit::{self, Event};
use crate::store::work::release_held_in;

/// Why a transition was not applied.
#[derive(Debug)]
pub enum TransitionError {
    NotFound,
    Illegal(IllegalTransition),
    /// Another transition changed the run first; re-read before trying again.
    Conflict,
    Db(Error),
}

impl From<Error> for TransitionError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("run not found"),
            Self::Illegal(e) => e.fmt(f),
            Self::Conflict => f.write_str("run changed concurrently"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for TransitionError {}

/// Applies `event` to the run and appends `run.<state>` by `actor`, in one transaction. A
/// heartbeat-like event that changes nothing writes nothing.
pub async fn transition_run(
    pool: &SqlitePool,
    id: RunId,
    actor: AuditActor,
    event: &RunEvent,
    now: &str,
) -> Result<Run, TransitionError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let current = run_in(&mut tx, id)
        .await?
        .ok_or(TransitionError::NotFound)?;
    let updated = transition_in(&mut tx, &current, actor, event, now).await?;
    tx.commit().await?;
    Ok(updated)
}

/// `transition_run` inside the caller's transaction, from the `current` row it read.
///
/// Optimistic: the update only matches a run still in the state read, so of two racing
/// transitions one wins and the other is `Conflict`.
pub(crate) async fn transition_in(
    conn: &mut SqliteConnection,
    current: &Run,
    actor: AuditActor,
    event: &RunEvent,
    now: &str,
) -> Result<Run, TransitionError> {
    let t = apply(current.state, event).map_err(TransitionError::Illegal)?;
    if t.state == current.state {
        return Ok(current.clone());
    }
    let runner = match event {
        RunEvent::Claim { runner } => Some(runner.as_str()),
        _ => None,
    };
    let reason = t.reason.map(|r| r.to_string());
    let given = match event {
        RunEvent::Fail { fingerprint, .. } => fingerprint.as_deref(),
        _ => None,
    };
    let fp = match (t.state, &reason) {
        (RunState::Failed | RunState::TimedOut | RunState::RunnerLost, Some(why)) => {
            Some(failure_fingerprint(t.state, given.unwrap_or(why)))
        }
        _ => None,
    };
    let Some(row) = sqlx::query(concat!(
        "UPDATE citadel_runs SET state = ?1, terminal_reason = ?2, \
         runner = coalesce(?3, runner), failure_fingerprint = coalesce(?4, failure_fingerprint), \
         claimed_at = CASE WHEN ?1 = 'claimed' THEN ?5 ELSE claimed_at END, \
         started_at = CASE WHEN ?1 = 'running' THEN ?5 ELSE started_at END, \
         ended_at = CASE WHEN ?2 IS NOT NULL THEN ?5 ELSE ended_at END \
         WHERE id = ?6 AND state = ?7 RETURNING ",
        run_columns!()
    ))
    .bind(t.state.as_str())
    .bind(&reason)
    .bind(runner)
    .bind(&fp)
    .bind(now)
    .bind(current.id.0)
    .bind(current.state.as_str())
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Err(TransitionError::Conflict);
    };
    let mut updated = run(row)?;
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM citadel_agents WHERE id = ?")
        .bind(updated.agent_id.0)
        .fetch_one(&mut *conn)
        .await?;
    audit::append(
        conn,
        Event::new(actor, &format!("run.{}", t.state.as_str()))
            .entity("run", current.id.0)
            .company(company)
            .run(current.id.0)
            .details(
                serde_json::json!({"from": current.state.as_str(), "event": event.name(),
                                        "reason": reason}),
            ),
    )
    .await?;
    if t.state.is_terminal() {
        revoke_in(conn, current.id, now).await?;
        release_held_in(conn, current.id, actor).await?;
        // A success that left its issue waiting on it untouched is no progress.
        if t.state == RunState::Succeeded
            && let Some(why) = super::no_action::no_action_in(conn, &updated, now).await?
        {
            updated.terminal_reason = Some(why);
        }
        // A run that ended badly consults the loop breaker (and the escalation of a run that may
        // not be retried) before anything queues its retry: a trip never waits on a caller.
        let stopped = match fp {
            Some(_) => super::breaker::stop_in(conn, &updated, now)
                .await?
                .is_some(),
            None => false,
        };
        if !stopped {
            super::wake::schedule_retry_in(conn, &updated, now).await?;
        }
    }
    Ok(updated)
}
