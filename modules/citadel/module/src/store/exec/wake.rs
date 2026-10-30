//! The wake queue (E2.2): enqueue with idempotency and coalescing, the drop of stale wakes, and
//! the retry of a run that ended badly. Every write runs in one `BEGIN IMMEDIATE` transaction, so
//! SQLite serialises them. `now` is passed in as ISO-8601 text and compared through `julianday`,
//! so the caller's clock drives backoff and tests are deterministic.

use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, Row, SqliteConnection};

use super::*;
use crate::domain::exec::{WakeStatus, retry_backoff_secs};
use crate::domain::work::WakeSource;
use crate::store::audit::{self, Event};

/// A wake before it is stored. Posting twice with the same key yields the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWakeRequest {
    pub agent_id: AgentId,
    pub issue_id: Option<IssueId>,
    pub source: WakeSource,
    pub reason: String,
    /// 1 to 128 bytes.
    pub idempotency_key: String,
    /// Not dispatched before this timestamp (retry backoff).
    pub not_before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeRequest {
    pub id: i64,
    pub agent_id: AgentId,
    pub issue_id: Option<IssueId>,
    pub source: WakeSource,
    pub reason: String,
    pub idempotency_key: String,
    /// How many later wakes were folded into this one.
    pub coalesced_count: i64,
    pub status: WakeStatus,
    pub not_before: Option<String>,
    /// 1 on the first try.
    pub attempt: i64,
    pub coalesced_into: Option<i64>,
    /// Set exactly when `status` is `Dropped` (no silent drops).
    pub dropped_reason: Option<String>,
}

macro_rules! wake_columns {
    () => {
        "id, agent_id, issue_id, source, reason, idempotency_key, coalesced_count, status, \
         not_before, attempt, coalesced_into, dropped_reason"
    };
}

fn wake_request(row: sqlx::sqlite::SqliteRow) -> Result<WakeRequest, Error> {
    Ok(WakeRequest {
        id: row.try_get("id")?,
        agent_id: AgentId(row.try_get("agent_id")?),
        issue_id: row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId),
        source: text(&row, "source")?,
        reason: row.try_get("reason")?,
        idempotency_key: row.try_get("idempotency_key")?,
        coalesced_count: row.try_get("coalesced_count")?,
        status: text(&row, "status")?,
        not_before: row.try_get("not_before")?,
        attempt: row.try_get("attempt")?,
        coalesced_into: row.try_get("coalesced_into")?,
        dropped_reason: row.try_get("dropped_reason")?,
    })
}

pub async fn get_wake_request(pool: &SqlitePool, id: i64) -> Result<Option<WakeRequest>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        wake_columns!(),
        " FROM citadel_wake_requests WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?
    .map(wake_request)
    .transpose()
}

/// The agent's wake requests, oldest first.
pub async fn list_wake_requests(
    pool: &SqlitePool,
    agent_id: AgentId,
) -> Result<Vec<WakeRequest>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        wake_columns!(),
        " FROM citadel_wake_requests WHERE agent_id = ? ORDER BY id"
    ))
    .bind(agent_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(wake_request)
    .collect()
}

/// Stores a wake and returns the request stored under its key. Idempotent per key.
///
/// Coalescing: when a `pending` wake already waits for the same agent and issue, the new one is
/// stored `coalesced`, pointing at it, and the survivor's `coalesced_count` goes up; its
/// `not_before` moves to the earlier of the two. A wake that arrives while a run for that agent
/// and issue is live is never folded into the run: it stays `pending` and dispatch holds it
/// until the run ends, so it fires as a follow-up and is not lost.
pub async fn enqueue_wake(pool: &SqlitePool, w: &NewWakeRequest) -> Result<WakeRequest, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
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
    if w.idempotency_key.is_empty() || w.idempotency_key.len() > 128 {
        return Err(Error::InvalidArgument(
            "a wake key is 1 to 128 bytes".to_owned(),
        ));
    }
    let existing = sqlx::query(concat!(
        "SELECT ",
        wake_columns!(),
        " FROM citadel_wake_requests WHERE idempotency_key = ?"
    ))
    .bind(&w.idempotency_key)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(row) = existing {
        return wake_request(row);
    }
    // A wake never carries another company's issue into an agent's session (its title, body and
    // repo): the issue's project and the agent belong to one company.
    if let Some(issue) = w.issue_id {
        let same: Option<bool> = sqlx::query_scalar(
            "SELECT p.company_id = a.company_id FROM citadel_issues i \
             JOIN citadel_projects p ON p.id = i.project_id, citadel_agents a \
             WHERE i.id = ? AND a.id = ?",
        )
        .bind(issue.0)
        .bind(w.agent_id.0)
        .fetch_optional(&mut *conn)
        .await?;
        match same {
            Some(true) => {}
            Some(false) => {
                return Err(Error::InvalidArgument(
                    "the issue belongs to another company than the agent".to_owned(),
                ));
            }
            None => return Err(Error::InvalidArgument("no such issue or agent".to_owned())),
        }
    }
    // A terminated agent is woken for nothing: the wake is kept, `dropped`, as a record.
    let gone: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM citadel_agents WHERE id = ? AND status = 'terminated')",
    )
    .bind(w.agent_id.0)
    .fetch_one(&mut *conn)
    .await?;
    let survivor: Option<i64> = if gone {
        None
    } else {
        sqlx::query_scalar(
            "UPDATE citadel_wake_requests SET coalesced_count = coalesced_count + 1, \
             attempt = max(attempt, ?4), \
             not_before = CASE WHEN ?3 IS NULL OR not_before IS NULL THEN NULL \
                 WHEN julianday(?3) < julianday(not_before) THEN ?3 ELSE not_before END \
             WHERE id = (SELECT id FROM citadel_wake_requests WHERE status = 'pending' \
                 AND agent_id = ?1 AND issue_id IS ?2 ORDER BY id LIMIT 1) RETURNING id",
        )
        .bind(w.agent_id.0)
        .bind(w.issue_id.map(|i| i.0))
        .bind(&w.not_before)
        .bind(attempt)
        .fetch_optional(&mut *conn)
        .await?
    };
    let status = match (gone, survivor.is_some()) {
        (true, _) => "dropped",
        (_, true) => "coalesced",
        _ => "pending",
    };
    sqlx::query(concat!(
        "INSERT INTO citadel_wake_requests (agent_id, issue_id, source, reason, idempotency_key, \
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
    .bind(status)
    .bind(survivor)
    .bind(gone.then_some("agent terminated"))
    .fetch_one(&mut *conn)
    .await
    .and_then(wake_request)
}

const STALE: &str = "superseded: issue has a live run or another next actor";

/// Drops every due `pending` wake on a non-terminal issue that no longer waits on the wake's
/// agent, auditing each as `wake.dropped`: running it would put that agent back on work already
/// handed to someone else. A human's own wake is kept, or one a human's folded into: the admin's
/// (`manual`), a decided approval, a person's comment or answer, or the lead's repo request.
pub(crate) async fn drop_stale_in(conn: &mut SqliteConnection, now: &str) -> Result<(), Error> {
    let dropped: Vec<(i64, i64, i64, i64)> = sqlx::query_as(
        "UPDATE citadel_wake_requests SET status = 'dropped', dropped_reason = ?2 \
         WHERE status = 'pending' AND issue_id IS NOT NULL \
         AND (not_before IS NULL OR julianday(not_before) <= julianday(?1)) \
         AND NOT EXISTS (SELECT 1 FROM citadel_wake_requests h \
             WHERE (h.id = citadel_wake_requests.id OR h.coalesced_into = citadel_wake_requests.id) \
             AND (h.source IN ('manual', 'approval') OR (h.source = 'comment' \
                 AND (h.idempotency_key LIKE 'comment:%' OR h.idempotency_key LIKE 'answer:%' \
                     OR h.idempotency_key LIKE 'repo-request:%' \
                     OR h.idempotency_key LIKE 'pr:%:merged:%')) \
                 OR (h.source = 'escalation' AND h.idempotency_key LIKE 'parked:%'))) \
         AND EXISTS (SELECT 1 FROM citadel_issues i WHERE i.id = citadel_wake_requests.issue_id \
             AND CASE WHEN i.state IN ('in_progress', 'in_review') \
                 THEN i.next_agent_id IS NOT citadel_wake_requests.agent_id \
                     AND (i.state = 'in_review' \
                          OR i.owner_agent_id IS NOT citadel_wake_requests.agent_id) \
                 ELSE i.state NOT IN ('done', 'cancelled') \
                     AND i.next_agent_id IS NOT citadel_wake_requests.agent_id \
                     AND i.owner_agent_id IS NOT citadel_wake_requests.agent_id END) \
         RETURNING id, agent_id, issue_id, \
             (SELECT company_id FROM citadel_agents a WHERE a.id = citadel_wake_requests.agent_id)",
    )
    .bind(now)
    .bind(STALE)
    .fetch_all(&mut *conn)
    .await?;
    for (wake, agent, issue, company) in dropped {
        audit::append(
            conn,
            Event::new(super::SYSTEM, "wake.dropped")
                .entity("wake_request", wake)
                .company(company)
                .details(json!({"agent": agent, "issue": issue, "reason": STALE})),
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
    /// The run was the wake's last attempt: no retry.
    Exhausted { attempt: i64 },
    /// Only a failed, timed-out or lost run is retried.
    NotRetryable(RunState),
    /// The run was stopped at its token cap: retrying would spend the same tokens again.
    TokenCap,
    /// The run was cancelled by hand: never retried (it is not a failure).
    Cancelled,
}

/// Queues a `retry` wake for a run that ended badly: attempt + 1, not before `now` plus the
/// backoff for the failed attempt. Idempotent per run. A run with no wake counts as attempt 1.
pub(crate) async fn schedule_retry_in(
    conn: &mut SqliteConnection,
    failed: &Run,
    now: &str,
) -> Result<Retry, Error> {
    if !matches!(
        failed.state,
        RunState::Failed | RunState::TimedOut | RunState::RunnerLost
    ) {
        return Ok(Retry::NotRetryable(failed.state));
    }
    if failed.terminal_reason.as_deref() == Some("token_cap") {
        return Ok(Retry::TokenCap);
    }
    let attempt: i64 = sqlx::query_scalar(
        "SELECT coalesce((SELECT attempt FROM citadel_wake_requests WHERE id = ?), 1)",
    )
    .bind(failed.wake_request_id)
    .fetch_one(&mut *conn)
    .await?;
    let max_attempts = crate::settings::value_in(&mut *conn, "wake.max_attempts").await?;
    if attempt >= max_attempts {
        return Ok(Retry::Exhausted { attempt });
    }
    let max = crate::settings::value_in(&mut *conn, "wake.retry_backoff_max_secs").await?;
    let not_before: Option<String> =
        sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?, ?)")
            .bind(now)
            .bind(format!("+{} seconds", retry_backoff_secs(attempt, max)))
            .fetch_one(&mut *conn)
            .await?;
    let wake = NewWakeRequest {
        agent_id: failed.agent_id,
        issue_id: failed.issue_id,
        source: WakeSource::Retry,
        reason: format!(
            "retry {} after run {}: {}",
            attempt + 1,
            failed.id.0,
            failed.terminal_reason.as_deref().unwrap_or_default()
        ),
        idempotency_key: format!("retry:run:{}", failed.id.0),
        not_before,
    };
    Ok(Retry::Scheduled(
        enqueue_in(conn, &wake, attempt + 1).await?,
    ))
}
