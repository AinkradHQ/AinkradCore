//! The wake queue (E2.2): enqueue with idempotency and coalescing, dispatch to a runner by
//! tags, retry with backoff.
//!
//! Every operation runs in one `BEGIN IMMEDIATE` transaction, so SQLite serialises them:
//! a read-then-write never acts on a stale read, and of any number of dispatchers exactly
//! one takes a given wake. `now` is passed in as ISO-8601 text and compared through
//! `julianday`, so the caller's clock drives backoff and tests are deterministic.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::exec::{
    NewWakeRequest, RunEvent, RunState, TerminalReason, WakeRequest, WakeSource, retry_backoff_secs,
};
use ainkrad_core::org::{AgentId, CompanyId, Harness};
use ainkrad_core::settings::Key;
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit;
use crate::store::gov::{admit_in, use_account_in};
use crate::store::settings::{run_scope_in, value_in};
use crate::store::work::IssueTransitionError;

/// Stores a wake and returns the request stored under its key. Idempotent per key: a repeat
/// returns that request unchanged.
///
/// Coalescing: when a `pending` wake already waits for the same agent and issue, the new
/// one is stored `coalesced`, pointing at it, and the survivor's `coalesced_count` goes up;
/// its `not_before` moves to the earlier of the two. A wake that arrives while a run for
/// that agent and issue is live is never folded into the run: it stays `pending` and
/// `dispatch_next` holds it until the run ends, so it fires as a follow-up and is not lost.
pub async fn enqueue_wake(pool: &SqlitePool, w: &NewWakeRequest) -> Result<WakeRequest, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let stored = enqueue_in(&mut tx, w, 1).await?;
    tx.commit().await?;
    Ok(stored)
}

/// `enqueue_wake` inside the caller's `BEGIN IMMEDIATE` transaction, as attempt `attempt`.
pub(crate) async fn enqueue_in(
    conn: &mut SqliteConnection,
    w: &NewWakeRequest,
    attempt: i64,
) -> Result<WakeRequest, Error> {
    let existing = sqlx::query(concat!(
        "SELECT ",
        wake_columns!(),
        " FROM wake_requests WHERE idempotency_key = ?"
    ))
    .bind(&w.idempotency_key)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(row) = existing {
        return wake_request(row);
    }
    // A terminated agent is woken for nothing: the wake is kept, `dropped`, as a record.
    let gone: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM agents WHERE id = ? AND status = 'terminated')",
    )
    .bind(w.agent_id.0)
    .fetch_one(&mut *conn)
    .await?;
    let survivor: Option<i64> = if gone {
        None
    } else {
        sqlx::query_scalar(
            "UPDATE wake_requests SET coalesced_count = coalesced_count + 1, \
         attempt = max(attempt, ?4), \
         not_before = CASE WHEN ?3 IS NULL OR not_before IS NULL THEN NULL \
             WHEN julianday(?3) < julianday(not_before) THEN ?3 ELSE not_before END \
         WHERE id = (SELECT id FROM wake_requests WHERE status = 'pending' \
             AND agent_id = ?1 AND issue_id IS ?2 ORDER BY id LIMIT 1) \
         RETURNING id",
        )
        .bind(w.agent_id.0)
        .bind(w.issue_id.map(|i| i.0))
        .bind(&w.not_before)
        .bind(attempt)
        .fetch_optional(&mut *conn)
        .await?
    };
    let stored = sqlx::query(concat!(
        "INSERT INTO wake_requests (agent_id, issue_id, source, reason, idempotency_key, \
         not_before, attempt, status, coalesced_into, dropped_reason) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING ",
        wake_columns!()
    ))
    .bind(w.agent_id.0)
    .bind(w.issue_id.map(|i| i.0))
    .bind(w.source.as_str())
    .bind(&w.reason)
    .bind(&w.idempotency_key)
    .bind(&w.not_before)
    .bind(attempt)
    .bind(match (gone, survivor.is_some()) {
        (true, _) => "dropped",
        (_, true) => "coalesced",
        _ => "pending",
    })
    .bind(survivor)
    .bind(gone.then_some("agent terminated"))
    .fetch_one(&mut *conn)
    .await
    .and_then(wake_request)?;
    signal_wakes();
    Ok(stored)
}

/// How many due wakes one dispatch looks at past budget-blocked ones.
// ponytail: a backlog of more blocked wakes than this starves the ones behind it until
// approvals clear; a per-agent skip list is the upgrade if that ever bites.
const ADMISSION_CANDIDATES: i64 = 16;

/// How long a wake waits for the runner that last ran its issue (B3) before any eligible runner
/// may take it: QA then reuses the engineer's built worktree, but never waits on a busy or gone
/// runner. A preferred runner that is offline, unhealthy, drained or lacks the agent's tags is
/// ignored at once.
// ponytail: busy-ness is not known server-side (runners pull when they have a slot), so a busy
// preferred runner costs one grace; a per-runner slot count is the upgrade.
const STICKY_GRACE_SECS: i64 = 45;

/// Takes the oldest due `pending` wake this runner may serve (a bumped issue's first; one pinned
/// to another runner never) and starts its run, claimed by
/// the runner, in one transaction; `None` when there is nothing to do.
///
/// A wake is served when it is due (`not_before` at or before `now`), its agent is
/// `active`, every one of the agent's runner tags, and of its issue's project's (R18), is in `runner_tags`, the agent's harness
/// is one of `harnesses` (those the runner has at a supported version, E3.6), and no run for
/// that issue is live (any agent's; for an issue-less wake, none of that agent's), its issue's project has fewer live runs than its `max_parallel_runs` (R18; unset = no cap), and its issue's requirement does not hold it back (plan-first,
/// `plan_held!`, E15.10: it waits, pending, until the plan is approved). A wake whose run a
/// hard-stop budget would block is skipped
/// and stays pending (`gov::admit_in`, E7.2), and the budget's `budget_overrun` approval is
/// opened once per period; the next due wake is tried (up to `ADMISSION_CANDIDATES`). The wake
/// becomes `dispatched`; `wake.dispatched` and `run.claimed` are audited. The runner gets the
/// run's lease, expiring `lease.ttl_secs` after `now` (E2.6).
///
/// Accounts and fallbacks (E15.1, E15.3, `route::start_route_in`): the run starts on the first
/// entry of its agent's (harness, model) chain this runner offers with an account the company
/// may use (or no pool for that harness), named in `wake.dispatched`; the entries passed over
/// are its `fallback_reason`. A wake with no such entry is skipped and stays pending.
///
/// Tiers (E15.5, `tier::task_tier_in`): the task's tier (by its project's routing rules, else
/// its points) is recorded on the run, and the agent's model for it heads the chain.
///
/// Stale wakes (`drop_stale_in`) are dropped first, so a wake whose issue moved on to another
/// actor never starts a run.
pub async fn dispatch_next(
    pool: &SqlitePool,
    runner_id: RunnerId,
    runner_tags: &[String],
    harnesses: &[Harness],
    now: &str,
) -> Result<Option<Run>, TransitionError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let valid: bool = sqlx::query_scalar("SELECT julianday(?) IS NOT NULL")
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
    if !valid {
        return Err(Error::InvalidArgument(format!("bad timestamp `{now}`")).into());
    }
    drop_stale_in(&mut tx, now).await?;
    let candidates = sqlx::query(concat!(
        "SELECT w.id, w.agent_id, w.issue_id, a.harness, a.company_id, \
         iif(julianday(w.not_before) > julianday(w.created_at), w.not_before, w.created_at) \
             AS woken_at \
         FROM wake_requests w JOIN agents a ON a.id = w.agent_id \
         LEFT JOIN runners sticky ON sticky.id = (SELECT r.runner_id FROM runs r \
             WHERE r.issue_id = w.issue_id AND r.runner_id IS NOT NULL ORDER BY r.id DESC LIMIT 1) \
             AND w.runner_id IS NULL AND sticky.status = 'online' AND sticky.drained_at IS NULL \
             AND NOT EXISTS (SELECT 1 FROM json_each(a.runner_tags) t \
                 WHERE t.value NOT IN (SELECT value FROM json_each(sticky.tags))) \
         WHERE w.status = 'pending' AND a.status = 'active' \
         AND (w.not_before IS NULL OR julianday(w.not_before) <= julianday(?1)) \
         AND NOT EXISTS (SELECT 1 FROM json_each(a.runner_tags) t \
             WHERE t.value NOT IN (SELECT value FROM json_each(?2))) \
         AND NOT EXISTS (SELECT 1 FROM issues ti JOIN projects tp ON tp.id = ti.project_id, \
                 json_each(tp.runner_tags) t \
             WHERE ti.id = w.issue_id AND t.value NOT IN (SELECT value FROM json_each(?2))) \
         AND a.harness IN (SELECT value FROM json_each(?3)) \
         AND (w.runner_id IS NULL OR w.runner_id = ?5) \
         AND (?5 = sticky.id OR sticky.id IS NULL \
             OR julianday(?1) - julianday(iif(julianday(w.not_before) > julianday(w.created_at), \
                 w.not_before, w.created_at)) >= ?6 / 86400.0) \
         AND NOT EXISTS (SELECT 1 FROM issues wi JOIN projects wp ON wp.id = wi.project_id \
             WHERE wi.id = w.issue_id AND wp.max_parallel_runs IS NOT NULL \
             AND wp.max_parallel_runs <= (SELECT count(*) FROM runs pr \
                 JOIN issues pi ON pi.id = pr.issue_id \
                 WHERE pi.project_id = wi.project_id \
                 AND pr.state IN ('queued', 'claimed', 'running'))) \
         AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.state IN ('queued', 'claimed', 'running') \
             AND CASE WHEN w.issue_id IS NULL THEN r.agent_id = w.agent_id AND r.issue_id IS NULL \
                 ELSE r.issue_id = w.issue_id END) \
         AND NOT ",
        plan_held!("w.agent_id", "w.issue_id"),
        " ORDER BY coalesce((SELECT priority FROM issues WHERE id = w.issue_id), 0) DESC, w.id \
         LIMIT ?4"
    ))
    .bind(now)
    .bind(Json(runner_tags))
    .bind(Json(
        harnesses.iter().map(|h| h.as_str()).collect::<Vec<_>>(),
    ))
    .bind(ADMISSION_CANDIDATES)
    .bind(runner_id.0)
    .bind(STICKY_GRACE_SECS)
    .fetch_all(&mut *tx)
    .await?;
    let mut admitted = None;
    for row in candidates {
        let agent = AgentId(row.try_get("agent_id")?);
        let company = CompanyId(row.try_get("company_id")?);
        let issue = row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId);
        let tier = task_tier_in(&mut tx, issue).await?;
        let Some(start) = start_route_in(&mut tx, agent, (tier, issue), harnesses, now).await?
        else {
            continue;
        };
        if admit_in(&mut tx, agent, company, issue, now).await? {
            admitted = Some((row, start, tier));
            break;
        }
    }
    let Some((row, start, tier)) = admitted else {
        // Keeps the overrun approvals admission opened.
        tx.commit().await?;
        return Ok(None);
    };
    let wake_id: i64 = row.try_get("id")?;
    let company_id: i64 = row.try_get("company_id")?;

    sqlx::query("UPDATE wake_requests SET status = 'dispatched' WHERE id = ?")
        .bind(wake_id)
        .execute(&mut *tx)
        .await?;
    let queued = sqlx::query(concat!(
        "INSERT INTO runs (agent_id, issue_id, wake_request_id, harness, model_used, \
         fallback_reason, tier, woken_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING ",
        run_columns!()
    ))
    .bind(row.try_get::<i64, _>("agent_id")?)
    .bind(row.try_get::<Option<i64>, _>("issue_id")?)
    .bind(wake_id)
    .bind(start.harness.as_str())
    .bind(&start.model)
    .bind((!start.skipped.is_empty()).then(|| start.skipped.join("; ")))
    .bind(tier.as_str())
    .bind(row.try_get::<String, _>("woken_at")?)
    .fetch_one(&mut *tx)
    .await
    .and_then(run)?;
    let account = start.account;
    if let Some(account) = account {
        use_account_in(&mut tx, queued.id.0, account, now).await?;
    }
    audit::append(
        &mut *tx,
        &NewAuditEvent {
            actor: AuditActor::Runner(runner_id),
            action: "wake.dispatched".to_owned(),
            entity: Some(AuditEntity {
                kind: "wake_request".to_owned(),
                id: wake_id,
            }),
            company_id: Some(CompanyId(company_id)),
            run_id: Some(queued.id),
            details: serde_json::json!({"account": account.map(|a| a.0), "tier": tier.as_str(),
                                        "model": start.model})
            .to_string(),
        },
    )
    .await?;
    let claim = RunEvent::Claim { runner: runner_id };
    let by = AuditActor::Runner(runner_id);
    let (claimed, _) = transition_in(&mut tx, &queued, by, &claim, now).await?;
    grant_lease_in(&mut tx, claimed.id, runner_id, now).await?;
    tx.commit().await?;
    Ok(Some(claimed))
}

const STALE: &str = "superseded: issue has a live run or another next actor";

/// Drops every due `pending` wake on a non-terminal issue that no longer
/// waits on the wake's agent, auditing each as `wake.dropped`: running it would put that agent
/// back on work already handed to someone else (a QA follow-up firing after QA sent the issue
/// back to its developer). On any other non-terminal state a wake is dropped only when another
/// agent is the next actor and it is not the owner (a person or nobody next leaves it). The issue waits on its agent next actor, and while `in_progress`
/// also on its agent owner, who works it (as a person's comment targets it, `chat_agent`). A
/// human's own wake is kept, or one a human's folded into: the admin's (`manual`), a decided
/// approval, a person's comment (`comment:<id>`) or answer (`answer:<id>`), or the lead's repo request
/// (`repo-request:<seq>`: the lead decides on an issue that waits on its developer), and the
/// product owner's wakes, which are not its agent's: the one for an issue parked on a person
/// (`parked:`) and the one for a merged PR (`pr:…:merged:…`), both R7a.
async fn drop_stale_in(conn: &mut SqliteConnection, now: &str) -> Result<(), Error> {
    let dropped: Vec<(i64, i64, i64, i64)> = sqlx::query_as(
        "UPDATE wake_requests SET status = 'dropped', \
         dropped_reason = ?2 \
         WHERE status = 'pending' AND issue_id IS NOT NULL \
         AND (not_before IS NULL OR julianday(not_before) <= julianday(?1)) \
         AND NOT EXISTS (SELECT 1 FROM wake_requests h \
             WHERE (h.id = wake_requests.id OR h.coalesced_into = wake_requests.id) \
             AND (h.source IN ('manual', 'approval') OR (h.source = 'comment' \
                 AND (h.idempotency_key LIKE 'comment:%' OR h.idempotency_key LIKE 'answer:%' \
                     OR h.idempotency_key LIKE 'repo-request:%' \
                     OR h.idempotency_key LIKE 'pr:%:merged:%')) \
                 OR (h.source = 'escalation' AND h.idempotency_key LIKE 'parked:%'))) \
         AND EXISTS (SELECT 1 FROM issues i WHERE i.id = wake_requests.issue_id \
             AND CASE WHEN i.state IN ('in_progress', 'in_review') \
                 THEN i.next_agent_id IS NOT wake_requests.agent_id \
                     AND (i.state = 'in_review' OR i.owner_agent_id IS NOT wake_requests.agent_id) \
                 ELSE i.state NOT IN ('done', 'cancelled') \
                     AND i.next_agent_id <> wake_requests.agent_id \
                     AND i.owner_agent_id IS NOT wake_requests.agent_id END) \
         RETURNING id, agent_id, issue_id, \
             (SELECT company_id FROM agents a WHERE a.id = wake_requests.agent_id)",
    )
    .bind(now)
    .bind(STALE)
    .fetch_all(&mut *conn)
    .await?;
    for (wake, agent, issue, company) in dropped {
        audit::append(
            &mut *conn,
            &NewAuditEvent {
                actor: AuditActor::System,
                action: "wake.dropped".to_owned(),
                entity: Some(AuditEntity {
                    kind: "wake_request".to_owned(),
                    id: wake,
                }),
                company_id: Some(CompanyId(company)),
                run_id: None,
                details: serde_json::json!({"agent": agent, "issue": issue,
                    "reason": STALE})
                .to_string(),
            },
        )
        .await?;
    }
    Ok(())
}

/// What `schedule_retry` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retry {
    /// The retry wake stored for the run (`coalesced` if a pending wake already waited).
    Scheduled(WakeRequest),
    /// The run was the wake's last attempt: no retry; its end already escalated the issue.
    Exhausted { attempt: i64 },
    /// The loop breaker tripped (E2.7): no retry, and the issue is already escalated.
    Tripped(Trip),
    /// Only a failed, timed-out or lost run is retried.
    NotRetryable(RunState),
    /// The run was stopped at its token cap: retrying would spend the same tokens again, so
    /// it is never retried; its end already escalated the issue.
    TokenCap,
    /// The run was stopped for making no progress (E15.7): a retry would likely stall again,
    /// so it is never retried; its end already escalated the issue.
    Stalled,
}

/// Why a retry was not scheduled.
#[derive(Debug)]
pub enum RetryError {
    /// The loop breaker's escalation of the issue was refused.
    Escalation(IssueTransitionError),
    Db(Error),
}

impl From<Error> for RetryError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl From<IssueTransitionError> for RetryError {
    fn from(e: IssueTransitionError) -> Self {
        Self::Escalation(e)
    }
}

impl fmt::Display for RetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Escalation(e) => e.fmt(f),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RetryError {}

/// Queues a `retry` wake for a run that ended badly: attempt + 1, not before `now` plus the
/// backoff for the failed attempt. Idempotent per run. The loop breaker is consulted first
/// (`trip_in`): a trip is `Tripped`, with no retry; the run's end already tripped it, so the
/// trip is not repeated and `escalated_to` is `None`. A run that was its wake's last attempt
/// (`wake.max_attempts`) is `Exhausted`; a run with no wake counts as attempt 1. The backoff
/// is capped at `wake.retry_backoff_max_secs`; both settings are read for the run's project.
/// A missing run is `Error::RowNotFound`.
pub async fn schedule_retry(
    pool: &SqlitePool,
    failed: RunId,
    now: &str,
) -> Result<Retry, RetryError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let retry = schedule_retry_in(&mut tx, failed, now).await?;
    tx.commit().await?;
    Ok(retry)
}

/// `schedule_retry` inside the caller's `BEGIN IMMEDIATE` transaction.
pub(super) async fn schedule_retry_in(
    conn: &mut SqliteConnection,
    failed: RunId,
    now: &str,
) -> Result<Retry, RetryError> {
    let r = run_in(conn, failed).await?.ok_or(Error::RowNotFound)?;
    if !matches!(
        r.state,
        RunState::Failed | RunState::TimedOut | RunState::RunnerLost
    ) {
        return Ok(Retry::NotRetryable(r.state));
    }
    let valid: bool = sqlx::query_scalar("SELECT julianday(?) IS NOT NULL")
        .bind(now)
        .fetch_one(&mut *conn)
        .await?;
    if !valid {
        return Err(Error::InvalidArgument(format!("bad timestamp `{now}`")).into());
    }
    if let Some(trip) = trip_in(conn, &r, now).await? {
        return Ok(Retry::Tripped(trip));
    }
    if token_capped(&r) {
        return Ok(Retry::TokenCap);
    }
    if stalled(&r) {
        return Ok(Retry::Stalled);
    }
    let attempt = attempt_in(conn, &r).await?;
    let at = run_scope_in(conn, r.issue_id, r.agent_id).await?;
    if attempt >= value_in(conn, Key::WakeMaxAttempts, at).await? {
        return Ok(Retry::Exhausted { attempt });
    }
    let max = value_in(conn, Key::RetryBackoffMaxSecs, at).await?;
    let not_before: Option<String> =
        sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?, ?)")
            .bind(now)
            .bind(format!("+{} seconds", retry_backoff_secs(attempt, max)))
            .fetch_one(&mut *conn)
            .await?;
    let not_before =
        not_before.ok_or_else(|| Error::InvalidArgument(format!("bad timestamp `{now}`")))?;
    let wake = NewWakeRequest {
        agent_id: r.agent_id,
        issue_id: r.issue_id,
        source: WakeSource::Retry,
        reason: format!(
            "retry {} after run {}: {}",
            attempt + 1,
            r.id.0,
            r.terminal_reason.as_deref().unwrap_or_default()
        ),
        idempotency_key: format!("retry:run:{}", r.id.0),
        not_before: Some(not_before),
    };
    let stored = enqueue_in(conn, &wake, attempt + 1).await?;
    Ok(Retry::Scheduled(stored))
}

/// The run was stopped at its token cap.
pub(super) fn token_capped(r: &Run) -> bool {
    r.terminal_reason.as_deref() == Some(TerminalReason::TokenCap.to_string().as_str())
}

/// Which attempt of its wake the run was; a run with no wake counts as attempt 1.
pub(super) async fn attempt_in(conn: &mut SqliteConnection, r: &Run) -> Result<i64, Error> {
    sqlx::query_scalar("SELECT coalesce((SELECT attempt FROM wake_requests WHERE id = ?), 1)")
        .bind(r.wake_request_id.map(|w| w.0))
        .fetch_one(&mut *conn)
        .await
}
