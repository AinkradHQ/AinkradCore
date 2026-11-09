//! The loop breaker (E2.7, decision #15): the same failure `breaker.loop_threshold` times in
//! a row on one agent and issue stops retrying and escalates the issue; an agent tripping
//! `breaker.agent_trips` breakers within `breaker.agent_window_secs` is paused. The thresholds
//! are settings (E15.17): the run's project's, and the agent's company's.
//!
//! Every failed, timed-out or lost run consults it in its own terminal transition
//! (`stop_in`), so a trip never waits on a caller asking for a retry; `schedule_retry`
//! consults it again before anything else, so it cannot retry past a trip either.

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::exec::{NewWakeRequest, WakeSource};
use citadel_core::org::CompanyId;
use citadel_core::settings::{Key, Scope};
use citadel_core::work::NextActor;
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit;
use crate::store::org::escalation_target_in;
use crate::store::settings::{run_scope_in, value_in};
use crate::store::work::{IssueTransitionError, reassign_in};

/// What a tripped breaker did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trip {
    pub fingerprint: String,
    /// The runs that ended with it in a row, newest first; at least the threshold.
    pub runs: Vec<RunId>,
    /// Who the issue went to, up the escalation chain (E6.3). `None` when there was
    /// no open issue, or when this run had already tripped (the first call escalated).
    pub escalated_to: Option<NextActor>,
    /// This trip was the agent's `breaker.agent_trips`th within the window: it is paused.
    pub agent_paused: bool,
}

/// What a badly ended run's own terminal transition did about it, instead of leaving it to
/// a retry the caller may never ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The loop breaker tripped and escalated the issue.
    Tripped(Trip),
    /// No retry is left (the run hit its token cap, stalled, or was its wake's last attempt), so the
    /// issue went up the escalation chain: to whom, or `None` when there was no open issue.
    Escalated(Option<NextActor>),
}

/// Runs inside the terminal transition of every failed, timed-out or lost run `r`, at
/// `now`: trips the breaker (`trip_in`), else escalates a run that may not be retried.
/// `None` leaves the retry to the caller. Each run ends once, so this never repeats.
pub(super) async fn stop_in(
    conn: &mut SqliteConnection,
    r: &Run,
    now: &str,
) -> Result<Option<Stop>, IssueTransitionError> {
    if let Some(trip) = trip_in(conn, r, now).await? {
        return Ok(Some(Stop::Tripped(trip)));
    }
    let at = run_scope_in(conn, r.issue_id, r.agent_id).await?;
    if token_capped(r)
        || stalled(r)
        || attempt_in(conn, r).await? >= value_in(conn, Key::WakeMaxAttempts, at).await?
    {
        return Ok(Some(Stop::Escalated(escalate_in(conn, r).await?)));
    }
    Ok(None)
}

/// Trips the breaker for the ended run `r` if the runs ending in it repeat one fingerprint
/// `breaker.loop_threshold` times; `None` otherwise. Runs of one agent and issue never
/// overlap (dispatch holds a wake while a run is live), so id order is end order. A
/// success, a cancel or a different failure ends the streak.
///
/// On a trip, in the caller's `BEGIN IMMEDIATE` transaction: the agent's pending wakes on
/// the issue are dropped, the issue goes up the escalation chain with an `escalation` wake, and
/// `loop_breaker.tripped` is audited with the fingerprint, count and runs. Repeating it for
/// the same run changes nothing.
pub(super) async fn trip_in(
    conn: &mut SqliteConnection,
    r: &Run,
    now: &str,
) -> Result<Option<Trip>, IssueTransitionError> {
    let Some(fingerprint) = r.failure_fingerprint.clone() else {
        return Ok(None);
    };
    let runs: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM runs WHERE agent_id = ?1 AND issue_id IS ?2 AND id <= ?3 \
         AND state NOT IN ('queued', 'claimed', 'running') \
         AND id > coalesce((SELECT max(id) FROM runs WHERE agent_id = ?1 AND issue_id IS ?2 \
             AND id <= ?3 AND state NOT IN ('queued', 'claimed', 'running') \
             AND failure_fingerprint IS NOT ?4), 0) \
         ORDER BY id DESC",
    )
    .bind(r.agent_id.0)
    .bind(r.issue_id.map(|i| i.0))
    .bind(r.id.0)
    .bind(&fingerprint)
    .fetch_all(&mut *conn)
    .await?;
    let at = run_scope_in(conn, r.issue_id, r.agent_id).await?;
    if (runs.len() as i64) < value_in(conn, Key::LoopBreakerThreshold, at).await? {
        return Ok(None);
    }
    let mut trip = Trip {
        fingerprint,
        runs: runs.iter().copied().map(RunId).collect(),
        escalated_to: None,
        agent_paused: false,
    };
    let tripped: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM audit_events \
         WHERE action = 'loop_breaker.tripped' AND run_id = ?)",
    )
    .bind(r.id.0)
    .fetch_one(&mut *conn)
    .await?;
    if tripped {
        return Ok(Some(trip));
    }

    sqlx::query(
        "UPDATE wake_requests SET status = 'dropped', dropped_reason = ? \
         WHERE agent_id = ? AND issue_id IS ? AND status = 'pending'",
    )
    .bind(format!("loop breaker: {}", trip.fingerprint))
    .bind(r.agent_id.0)
    .bind(r.issue_id.map(|i| i.0))
    .execute(&mut *conn)
    .await?;
    trip.escalated_to = escalate_in(conn, r).await?;
    let ids: Vec<String> = runs.iter().map(i64::to_string).collect();
    let (company, details): (i64, String) = sqlx::query_as(
        "SELECT company_id, json_object('agent', id, 'issue', ?, 'fingerprint', ?, \
         'count', ?, 'runs', json(?), 'escalated_to', ?, 'at', ?) FROM agents WHERE id = ?",
    )
    .bind(r.issue_id.map(|i| i.0))
    .bind(&trip.fingerprint)
    .bind(runs.len() as i64)
    .bind(format!("[{}]", ids.join(",")))
    .bind(trip.escalated_to.as_ref().map(actor_text))
    .bind(now)
    .bind(r.agent_id.0)
    .fetch_one(&mut *conn)
    .await?;
    append(
        conn,
        "loop_breaker.tripped",
        ("run", r.id.0),
        company,
        r.id,
        details,
    )
    .await?;
    trip.agent_paused = pause_if_looping(conn, r, company, now).await?;
    Ok(Some(trip))
}

/// Pauses the agent when this trip makes `breaker.agent_trips` within the window ending at
/// `now`, audits `agent.paused_by_breaker` and wakes who the run's issue escalates to
/// (`escalation`, no issue). When that is the admin (or the run had no issue) it learns
/// through the audit event alone: there is no human wake yet. `false` when it stays active, or was not active.
async fn pause_if_looping(
    conn: &mut SqliteConnection,
    r: &Run,
    company: i64,
    now: &str,
) -> Result<bool, IssueTransitionError> {
    let at = Scope::Company(CompanyId(company));
    let window = value_in(conn, Key::AgentBreakerWindowSecs, at).await?;
    let trips: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'loop_breaker.tripped' \
         AND company_id = ?1 AND json_extract(details, '$.agent') = ?2 \
         AND julianday(json_extract(details, '$.at')) > julianday(?3, ?4) \
         AND julianday(json_extract(details, '$.at')) <= julianday(?3)",
    )
    .bind(company)
    .bind(r.agent_id.0)
    .bind(now)
    .bind(format!("-{window} seconds"))
    .fetch_one(&mut *conn)
    .await?;
    if trips < value_in(conn, Key::AgentBreakerTrips, at).await? {
        return Ok(false);
    }
    let paused =
        sqlx::query("UPDATE agents SET status = 'paused' WHERE id = ? AND status = 'active'")
            .bind(r.agent_id.0)
            .execute(&mut *conn)
            .await
            .map(affected)?;
    if !paused {
        return Ok(false);
    }
    let details: String =
        sqlx::query_scalar("SELECT json_object('trips', ?, 'window_secs', ?, 'run', ?, 'at', ?)")
            .bind(trips)
            .bind(window)
            .bind(r.id.0)
            .bind(now)
            .fetch_one(&mut *conn)
            .await?;
    let agent = ("agent", r.agent_id.0);
    append(
        conn,
        "agent.paused_by_breaker",
        agent,
        company,
        r.id,
        details,
    )
    .await?;
    let lead = match r.issue_id {
        Some(issue) => escalation_target_in(conn, issue, r.agent_id).await?,
        None => NextActor::Human(ESCALATION_USER),
    };
    if let NextActor::Agent(lead) = lead {
        let wake = NewWakeRequest {
            agent_id: lead,
            issue_id: None,
            source: WakeSource::Escalation,
            reason: format!("agent {} paused by the loop breaker", r.agent_id.0),
            idempotency_key: format!("breaker:agent:{}:run:{}", r.agent_id.0, r.id.0),
            not_before: None,
        };
        enqueue_in(conn, &wake, 1).await?;
    }
    Ok(true)
}

/// Appends `action` by the system about `entity`.
async fn append(
    conn: &mut SqliteConnection,
    action: &str,
    (kind, id): (&str, i64),
    company: i64,
    run: RunId,
    details: String,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor: AuditActor::System,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: kind.to_owned(),
            id,
        }),
        company_id: Some(CompanyId(company)),
        run_id: Some(run),
        details,
    };
    audit::append(&mut *conn, &event).await.map(drop)
}

/// Hands the run's open issue up the escalation chain from the run's agent
/// (`org::escalation_target_in`: team lead, product owner, then the admin; the CEO only for
/// a cross-department issue), with an `escalation` wake; `None` when there is no open issue
/// to hand over.
pub(super) async fn escalate_in(
    conn: &mut SqliteConnection,
    r: &Run,
) -> Result<Option<NextActor>, IssueTransitionError> {
    let Some(issue_id) = r.issue_id else {
        return Ok(None);
    };
    let to = escalation_target_in(conn, issue_id, r.agent_id).await?;
    let next = to.clone();
    let reassigned = reassign_in(
        conn,
        issue_id,
        next,
        AuditActor::System,
        WakeSource::Escalation,
    );
    Ok(reassigned.await?.map(|_| to))
}

pub(super) fn actor_text(n: &NextActor) -> String {
    match n {
        NextActor::Agent(a) => format!("agent:{}", a.0),
        NextActor::Human(u) => format!("user:{}", u.0),
        NextActor::Timer(at) => format!("timer:{at}"),
    }
}
