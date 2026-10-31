//! The loop breaker (E2.7, decision #15): the same failure `breaker.loop_threshold` times in a
//! row on one agent and issue stops retrying and escalates the issue; an agent tripping
//! `breaker.agent_trips` breakers within `breaker.agent_window_secs` is paused.
//!
//! Every failed, timed-out or lost run consults it in its own terminal transition (`stop_in`),
//! so a trip never waits on a caller asking for a retry.
//!
//! What a trip may do is bounded on purpose: it drops the agent's pending wakes on the issue,
//! hands the issue one rung up the escalation chain (a wake, not a start: the dispatcher still
//! admits it against the lead's budgets) and pauses the looping agent. It never kills a run,
//! merges, raises a budget or widens anyone's access. An agent is un-paused by the admin only.

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::SqliteConnection;

use super::*;
use crate::domain::work::{NextActor, WakeSource};
use crate::store::audit::{self, Event};
use crate::store::org::{ESCALATION_USER, escalation_target_in};
use crate::store::work::{IssueTransitionError, reassign_in};

/// What a tripped breaker did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trip {
    pub fingerprint: String,
    /// The runs that ended with it in a row, newest first; at least the threshold.
    pub runs: Vec<RunId>,
    /// Who the issue went to, up the escalation chain. `None` when there was no open issue, or
    /// when this run had already tripped (the first call escalated).
    pub escalated_to: Option<NextActor>,
    /// This trip was the agent's `breaker.agent_trips`th within the window: it is paused.
    pub agent_paused: bool,
}

/// What a badly ended run's own terminal transition did about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The loop breaker tripped and escalated the issue.
    Tripped(Trip),
    /// No retry is left (token cap, stalled, or its wake's last attempt): the issue went up the
    /// escalation chain; to whom, or `None` when there was no open issue.
    Escalated(Option<NextActor>),
}

/// Runs inside the terminal transition of every failed, timed-out or lost run `r`, at `now`:
/// trips the breaker, else escalates a run that may not be retried. `None` leaves the retry to
/// the caller. Each run ends once, so this never repeats.
pub(super) async fn stop_in(
    conn: &mut SqliteConnection,
    r: &Run,
    now: &str,
) -> Result<Option<Stop>, sqlx::Error> {
    if let Some(trip) = trip_in(conn, r, now).await? {
        return Ok(Some(Stop::Tripped(trip)));
    }
    let max = crate::settings::value_in(conn, "wake.max_attempts").await?;
    if token_capped(r) || stalled(r) || super::wake::attempt_in(conn, r).await? >= max {
        return Ok(Some(Stop::Escalated(escalate_in(conn, r).await?)));
    }
    Ok(None)
}

pub(super) fn token_capped(r: &Run) -> bool {
    r.terminal_reason.as_deref() == Some("token_cap")
}

pub(super) fn stalled(r: &Run) -> bool {
    r.terminal_reason.as_deref() == Some("stalled")
}

/// Trips the breaker for the ended run `r` if the runs ending in it repeat one fingerprint
/// `breaker.loop_threshold` times; `None` otherwise. Runs of one agent and issue never overlap
/// (dispatch holds a wake while a run is live), so id order is end order. A success, a cancel or
/// a different failure ends the streak. Repeating it for the same run changes nothing.
pub(super) async fn trip_in(
    conn: &mut SqliteConnection,
    r: &Run,
    now: &str,
) -> Result<Option<Trip>, sqlx::Error> {
    let Some(fingerprint) = r.failure_fingerprint.clone() else {
        return Ok(None);
    };
    let runs: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM citadel_runs WHERE agent_id = ?1 AND issue_id IS ?2 AND id <= ?3 \
         AND state NOT IN ('queued', 'claimed', 'running') \
         AND id > coalesce((SELECT max(id) FROM citadel_runs WHERE agent_id = ?1 \
             AND issue_id IS ?2 AND id <= ?3 AND state NOT IN ('queued', 'claimed', 'running') \
             AND failure_fingerprint IS NOT ?4), 0) \
         ORDER BY id DESC",
    )
    .bind(r.agent_id.0)
    .bind(r.issue_id.map(|i| i.0))
    .bind(r.id.0)
    .bind(&fingerprint)
    .fetch_all(&mut *conn)
    .await?;
    if (runs.len() as i64) < crate::settings::value_in(conn, "breaker.loop_threshold").await? {
        return Ok(None);
    }
    let mut trip = Trip {
        fingerprint,
        runs: runs.iter().copied().map(RunId).collect(),
        escalated_to: None,
        agent_paused: false,
    };
    let tripped: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM audit_events WHERE action = 'citadel.loop_breaker.tripped' \
         AND entity_kind = 'run' AND entity_id = ?)",
    )
    .bind(r.id.0)
    .fetch_one(&mut *conn)
    .await?;
    if tripped {
        return Ok(Some(trip));
    }
    sqlx::query(
        "UPDATE citadel_wake_requests SET status = 'dropped', dropped_reason = ? \
         WHERE agent_id = ? AND issue_id IS ? AND status = 'pending'",
    )
    .bind(format!("loop breaker: {}", trip.fingerprint))
    .bind(r.agent_id.0)
    .bind(r.issue_id.map(|i| i.0))
    .execute(&mut *conn)
    .await?;
    trip.escalated_to = escalate_in(conn, r).await?;
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM citadel_agents WHERE id = ?")
        .bind(r.agent_id.0)
        .fetch_one(&mut *conn)
        .await?;
    audit::append(
        conn,
        Event::new(AuditActor::System, "loop_breaker.tripped")
            .entity("run", r.id.0)
            .company(company)
            .run(r.id.0)
            .details(
                json!({"agent": r.agent_id.0, "issue": r.issue_id.map(|i| i.0),
                "fingerprint": trip.fingerprint, "count": runs.len(), "runs": runs,
                "escalated_to": trip.escalated_to.as_ref().map(actor_text), "at": now}),
            ),
    )
    .await?;
    trip.agent_paused = pause_if_looping(conn, r, company, now).await?;
    Ok(Some(trip))
}

/// Pauses the agent when this trip makes `breaker.agent_trips` within the window ending at
/// `now`, audits `agent.paused_by_breaker` and wakes who the run's issue escalates to. When that
/// is the admin it learns through the audit event alone. `false` when it stays active.
async fn pause_if_looping(
    conn: &mut SqliteConnection,
    r: &Run,
    company: i64,
    now: &str,
) -> Result<bool, sqlx::Error> {
    let window = crate::settings::value_in(conn, "breaker.agent_window_secs").await?;
    let trips: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'citadel.loop_breaker.tripped' \
         AND json_extract(details, '$.company_id') = ?1 AND json_extract(details, '$.agent') = ?2 \
         AND julianday(json_extract(details, '$.at')) > julianday(?3, ?4) \
         AND julianday(json_extract(details, '$.at')) <= julianday(?3)",
    )
    .bind(company)
    .bind(r.agent_id.0)
    .bind(now)
    .bind(format!("-{window} seconds"))
    .fetch_one(&mut *conn)
    .await?;
    if trips < crate::settings::value_in(conn, "breaker.agent_trips").await? {
        return Ok(false);
    }
    let paused = sqlx::query(
        "UPDATE citadel_agents SET status = 'paused' WHERE id = ? AND status = 'active'",
    )
    .bind(r.agent_id.0)
    .execute(&mut *conn)
    .await?
    .rows_affected()
        > 0;
    if !paused {
        return Ok(false);
    }
    audit::append(
        conn,
        Event::new(AuditActor::System, "agent.paused_by_breaker")
            .entity("agent", r.agent_id.0)
            .company(company)
            .run(r.id.0)
            .details(json!({"trips": trips, "window_secs": window, "run": r.id.0, "at": now})),
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

/// Hands the run's open issue up the escalation chain from the run's agent, with an `escalation`
/// wake; `None` when there is no open issue to hand over (or the move was refused, e.g. a full
/// column: the run still ends, and the stuck detector finds the issue).
pub(super) async fn escalate_in(
    conn: &mut SqliteConnection,
    r: &Run,
) -> Result<Option<NextActor>, sqlx::Error> {
    let Some(issue_id) = r.issue_id else {
        return Ok(None);
    };
    let to = escalation_target_in(conn, issue_id, r.agent_id).await?;
    match reassign_in(
        conn,
        issue_id,
        to.clone(),
        AuditActor::System,
        WakeSource::Escalation,
    )
    .await
    {
        Ok(moved) => Ok(moved.map(|_| to)),
        Err(IssueTransitionError::Db(e)) => Err(e),
        Err(_) => Ok(None),
    }
}

pub(crate) fn actor_text(n: &NextActor) -> String {
    match n {
        NextActor::Agent(a) => format!("agent:{}", a.0),
        NextActor::Human(u) => format!("user:{}", u.0),
        NextActor::Timer(at) => format!("timer:{at}"),
    }
}
