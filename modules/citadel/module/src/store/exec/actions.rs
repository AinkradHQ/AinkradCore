//! The "why stuck" list's engine actions: release a checkout its run no longer holds, and retry
//! an ended run. Each runs in one `BEGIN IMMEDIATE` transaction and is audited as its actor.
//!
//! - **Release** (`release_dead_checkout`): an issue checked out by a run that has ended (the
//!   stuck rule `checkout_dead`) is released, as the repair pass does; a live holder is refused
//!   (stop the run instead).
//! - **Retry** (`retry_run`): an ended run's agent is woken again on its issue. It is a wake like
//!   any other: the dispatcher admits it against the budgets and picks the runner. (The
//!   monolith's pin to a runner chosen by the admin, and its tag check, are not ported: a Core
//!   runner is a device and carries no tags.)

use ainkrad_core::audit::AuditActor;
use serde_json::json;

use super::*;
use crate::domain::work::{Issue, WakeSource};
use crate::store::audit::{self, Event};
use crate::store::work::{issue_in, release_held_in};

/// Why a stuck-list action was refused.
#[derive(Debug)]
pub enum StuckActionError {
    NotFound(String),
    /// The action does not apply in the current state.
    Conflict(String),
    Db(Error),
}

impl From<Error> for StuckActionError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

const LIVE: [&str; 3] = ["queued", "claimed", "running"];

/// Releases the issue's checkout, held by a run that has ended, as `actor` (`issue.released`).
pub async fn release_dead_checkout(
    pool: &SqlitePool,
    issue: IssueId,
    actor: AuditActor,
) -> Result<Issue, StuckActionError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let i = issue_in(&mut tx, issue)
        .await?
        .ok_or_else(|| StuckActionError::NotFound(format!("no issue {}", issue.0)))?;
    let Some(run) = i.checkout_run_id else {
        let why = format!("issue {} is not checked out", issue.0);
        return Err(StuckActionError::Conflict(why));
    };
    let state: Option<String> = sqlx::query_scalar("SELECT state FROM citadel_runs WHERE id = ?")
        .bind(run.0)
        .fetch_optional(&mut *tx)
        .await?;
    if let Some(state) = state.filter(|s| LIVE.contains(&s.as_str())) {
        let why = format!("run {} holding it is {state}; stop the run instead", run.0);
        return Err(StuckActionError::Conflict(why));
    }
    release_held_in(&mut tx, run, actor).await?;
    let released = issue_in(&mut tx, issue).await?.expect("read above");
    tx.commit().await?;
    Ok(released)
}

/// Wakes the ended `run`'s agent on its issue again, as `actor` (`run.retried`): the pending wake
/// that will start the retry. A wake already pending for the agent and issue takes it in.
pub async fn retry_run(
    pool: &SqlitePool,
    run: RunId,
    actor: AuditActor,
    now: &str,
) -> Result<WakeRequest, StuckActionError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let r = run_in(&mut tx, run)
        .await?
        .ok_or_else(|| StuckActionError::NotFound(format!("no run {}", run.0)))?;
    if !r.state.is_terminal() {
        let why = format!("run {} is still {}; stop it first", run.0, r.state.as_str());
        return Err(StuckActionError::Conflict(why));
    }
    if let Some(issue) = r.issue_id {
        let i = issue_in(&mut tx, issue).await?;
        if i.is_none_or(|i| i.state.is_terminal()) {
            let why = format!("issue {} is closed", issue.0);
            return Err(StuckActionError::Conflict(why));
        }
    }
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM citadel_agents WHERE id = ?")
        .bind(r.agent_id.0)
        .fetch_one(&mut *tx)
        .await?;
    let wake = NewWakeRequest {
        agent_id: r.agent_id,
        issue_id: r.issue_id,
        source: WakeSource::Retry,
        reason: format!("retry of run {} by the admin", run.0),
        idempotency_key: format!("retry:run:{}:manual:{now}", run.0),
        not_before: None,
    };
    let w = enqueue_in(&mut tx, &wake, 1).await?;
    audit::append(
        &mut tx,
        Event::new(actor, "run.retried")
            .entity("run", run.0)
            .company(company)
            .run(run.0)
            .details(json!({"wake": w.id, "at": now})),
    )
    .await?;
    tx.commit().await?;
    Ok(w)
}
