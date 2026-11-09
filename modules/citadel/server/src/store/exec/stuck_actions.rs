//! The "why stuck" list's engine actions (the Mac plugin): release a checkout its run no longer
//! holds, and retry a run on a runner the admin picks. Each runs in one `BEGIN IMMEDIATE`
//! transaction and is audited as its actor.
//!
//! - **Release** (`release_dead_checkout`): an issue checked out by a run that has ended (the
//!   stuck rule `checkout_dead`) is released, as the scheduler's repair does; a live holder is
//!   refused (stop the run instead).
//! - **Retry on a runner** (`retry_run_on`): an ended run's agent is woken again on its issue,
//!   the wake pinned to the runner (`wake_requests.runner_id`): `dispatch_next` gives it to that
//!   runner only, and it is stuck while that runner cannot take it. A runner without every one of
//!   the agent's tags is refused. A wake already pending for the agent and issue takes the pin.
// ponytail: the pin is on the wake, so a failed pinned run's backoff retry may go to any runner;
// and the runner's harnesses are not checked here (it reports them only on connect), so a runner
// without the agent's harness leaves the wake pending until the stuck detector reports it.

use std::collections::BTreeMap;

use citadel_core::audit::AuditActor;
use citadel_core::exec::{NewWakeRequest, WakeRequest, WakeSource, WakeStatus};
use citadel_core::work::Issue;
use serde_json::json;

use super::controls::record;
use super::*;
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
    let mut tx = crate::store::begin_write(pool).await?;
    let i = issue_in(&mut tx, issue)
        .await?
        .ok_or_else(|| StuckActionError::NotFound(format!("no issue {}", issue.0)))?;
    let Some(run) = i.checkout_run_id else {
        let why = format!("issue {} is not checked out", issue.0);
        return Err(StuckActionError::Conflict(why));
    };
    let state: Option<String> = sqlx::query_scalar("SELECT state FROM runs WHERE id = ?")
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

/// Wakes the ended `run`'s agent on its issue again, pinned to `runner`, as `actor`
/// (`run.retried`): the pending wake that will start the retry.
pub async fn retry_run_on(
    pool: &SqlitePool,
    run: RunId,
    runner: RunnerId,
    actor: AuditActor,
    now: &str,
) -> Result<WakeRequest, StuckActionError> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let r = run_in(&mut tx, run)
        .await?
        .ok_or_else(|| StuckActionError::NotFound(format!("no run {}", run.0)))?;
    if !r.state.is_terminal() {
        let why = format!("run {} is still {}; stop it first", run.0, r.state.as_str());
        return Err(StuckActionError::Conflict(why));
    }
    type RunnerRow = (
        Json<Vec<String>>,
        Option<Json<BTreeMap<String, String>>>,
        Option<String>,
    );
    let found: Option<RunnerRow> =
        sqlx::query_as("SELECT tags, harnesses, drained_at FROM runners WHERE id = ?")
            .bind(runner.0)
            .fetch_optional(&mut *tx)
            .await?;
    let (Json(tags), harnesses, drained) =
        found.ok_or_else(|| StuckActionError::NotFound(format!("no runner {}", runner.0)))?;
    if drained.is_some() {
        let why = format!("runner {} is drained; it takes no new run", runner.0);
        return Err(StuckActionError::Conflict(why));
    }
    let (Json(wanted), company, harness): (Json<Vec<String>>, i64, String) =
        sqlx::query_as("SELECT runner_tags, company_id, harness FROM agents WHERE id = ?")
            .bind(r.agent_id.0)
            .fetch_one(&mut *tx)
            .await?;
    // Unknown until the runner's first 1.20 hello; then it must have the agent's harness.
    if harnesses.is_some_and(|Json(h)| !h.contains_key(&harness)) {
        let why = format!("runner {} has no {harness} harness", runner.0);
        return Err(StuckActionError::Conflict(why));
    }
    let missing: Vec<&str> = wanted
        .iter()
        .filter(|t| !tags.contains(t))
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        let why = format!(
            "runner {} lacks the agent's tags: {}",
            runner.0,
            missing.join(", ")
        );
        return Err(StuckActionError::Conflict(why));
    }
    if let Some(issue) = r.issue_id {
        let i = issue_in(&mut tx, issue).await?;
        if i.is_none_or(|i| i.state.is_terminal()) {
            let why = format!("issue {} is closed", issue.0);
            return Err(StuckActionError::Conflict(why));
        }
    }
    let wake = NewWakeRequest {
        agent_id: r.agent_id,
        issue_id: r.issue_id,
        source: WakeSource::Retry,
        reason: format!("retry of run {} on runner {}", run.0, runner.0),
        idempotency_key: format!("retry:run:{}:runner:{}:{now}", run.0, runner.0),
        not_before: None,
    };
    let w = enqueue_in(&mut tx, &wake, 1).await?;
    let pending = match w.status {
        WakeStatus::Coalesced => w.coalesced_into.unwrap_or(w.id),
        _ => w.id,
    };
    sqlx::query("UPDATE wake_requests SET runner_id = ? WHERE id = ? AND status = 'pending'")
        .bind(runner.0)
        .bind(pending.0)
        .execute(&mut *tx)
        .await?;
    let details = json!({"runner": runner.0, "wake": pending.0, "at": now});
    let entity = ("run", run.0);
    record(
        &mut tx,
        actor,
        "run.retried",
        entity,
        company,
        Some(run),
        details,
    )
    .await?;
    let pinned = sqlx::query(concat!(
        "SELECT ",
        wake_columns!(),
        " FROM wake_requests WHERE id = ?"
    ))
    .bind(pending.0)
    .fetch_one(&mut *tx)
    .await
    .and_then(wake_request)?;
    tx.commit().await?;
    signal_wakes();
    Ok(pinned)
}
