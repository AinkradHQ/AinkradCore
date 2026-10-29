//! Leases and runner loss (E2.6, brainstorm §6).
//!
//! `dispatch_next` gives each claimed run a lease held by its runner until `lease.ttl_secs`
//! (a setting, E15.17: the runner's, else the server's) after the claim. The runner renews it
//! while it works. Once `expires_at` has passed the lease is lapsed, but the run stays live
//! for `lease.grace_secs` (the same scope): a runner back inside that grace re-claims its run
//! with a renewal, which clears the lapse and is audited as `lease.expired` with
//! `recovered: true`. Once the grace is over the runner is lost for good: a late renewal is
//! refused, so the outcome does not depend on when the reaper runs. `reap_expired_leases`
//! ends each such run `runner_lost`, which, as every terminal transition does, drops its
//! lease, releases its issue and trips the loop breaker or escalates when no retry is left;
//! otherwise the reaper retries it.
//!
//! Every operation is one `BEGIN IMMEDIATE` transaction per run, so a reaper and a renewal,
//! or two reapers, never both act on one lease.

use std::fmt;

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::exec::{Lease, RunEvent, WakeRequest};
use citadel_core::org::CompanyId;
use citadel_core::settings::{Key, Scope};
use citadel_core::work::{NextActor, UserId};
use ainkrad_proto::runner::HostLoad;
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit;
use crate::store::settings::value_in;
use crate::store::work::IssueTransitionError;

/// Who an escalation goes to past the top of its issue's chain (E6.3): the admin user (#4).
pub const ESCALATION_USER: UserId = UserId(1);

/// Why a lease was not renewed or a lost run not recovered.
#[derive(Debug)]
pub enum LeaseError {
    /// The run has no lease: it is not claimed or running, or it was already reaped.
    NoLease,
    /// Another runner holds the run's lease.
    WrongRunner {
        held_by: RunnerId,
    },
    /// The lease lapsed past its grace before this renewal; the run is lost and will be reaped.
    Expired,
    /// Ending the lost run was refused.
    Run(TransitionError),
    /// Escalating the lost run's issue was refused.
    Issue(IssueTransitionError),
    Db(Error),
}

impl From<Error> for LeaseError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl From<TransitionError> for LeaseError {
    fn from(e: TransitionError) -> Self {
        Self::Run(e)
    }
}

impl From<IssueTransitionError> for LeaseError {
    fn from(e: IssueTransitionError) -> Self {
        Self::Issue(e)
    }
}

impl From<RetryError> for LeaseError {
    fn from(e: RetryError) -> Self {
        match e {
            RetryError::Escalation(e) => Self::Issue(e),
            RetryError::Db(e) => Self::Db(e),
        }
    }
}

impl fmt::Display for LeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoLease => f.write_str("run has no lease"),
            Self::WrongRunner { held_by } => write!(f, "lease is held by runner {}", held_by.0),
            Self::Expired => f.write_str("lease expired"),
            Self::Run(e) => e.fmt(f),
            Self::Issue(e) => e.fmt(f),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for LeaseError {}

/// What happened after a run's runner was lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// The retry wake stored for the run (E2.2).
    Retry(WakeRequest),
    /// Retries are exhausted; the issue's next actor is now the agent's lead, or the admin
    /// user when it has none.
    Escalated { to: NextActor },
    /// The loop breaker tripped (E2.7) and escalated; no retry.
    Tripped(Trip),
    /// Retries are exhausted and there is nothing to escalate: the run had no issue, or it
    /// is gone or closed.
    GaveUp,
}

/// One run `reap_expired_leases` ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaped {
    pub run_id: RunId,
    pub runner_id: RunnerId,
    pub issue_id: Option<IssueId>,
    pub recovery: Recovery,
}

pub(super) async fn check_time(conn: &mut SqliteConnection, now: &str) -> Result<(), Error> {
    let valid: bool = sqlx::query_scalar("SELECT julianday(?) IS NOT NULL")
        .bind(now)
        .fetch_one(&mut *conn)
        .await?;
    if !valid {
        return Err(Error::InvalidArgument(format!("bad timestamp `{now}`")));
    }
    Ok(())
}

/// Gives `runner` the lease on the just-claimed `run`, inside `dispatch_next`'s transaction.
pub(super) async fn grant_lease_in(
    conn: &mut SqliteConnection,
    run: RunId,
    runner: RunnerId,
    now: &str,
) -> Result<(), Error> {
    let ttl = value_in(conn, Key::LeaseTtlSecs, Scope::Runner(runner)).await?;
    sqlx::query(
        "INSERT INTO leases (run_id, runner_id, expires_at, heartbeat_at) VALUES \
         (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', ?3, ?4), strftime('%Y-%m-%dT%H:%M:%fZ', ?3))",
    )
    .bind(run.0)
    .bind(runner.0)
    .bind(now)
    .bind(format!("+{ttl} seconds"))
    .execute(&mut *conn)
    .await
    .map(drop)
}

/// The most a loaded host's lease is stretched by (AIN-55): `lease.ttl_secs` times this at
/// the outside, so a host that is truly dead is still reaped in a few minutes.
pub const MAX_LOAD_STRETCH: f64 = 4.0;

/// How much to stretch a runner's lease for its load (AIN-55): its load average per CPU,
/// kept within `1 ..= MAX_LOAD_STRETCH`; `1` when it sent no load or a load that is not a
/// number.
pub fn load_stretch(load: Option<HostLoad>) -> f64 {
    match load {
        Some(HostLoad { avg1, cores }) if avg1.is_finite() && cores > 0 => {
            (avg1 / f64::from(cores)).clamp(1.0, MAX_LOAD_STRETCH)
        }
        _ => 1.0,
    }
}

/// Renews `runner`'s lease on the live `run` at `now`: it then expires `lease.ttl_secs`
/// later, and the runner's `last_seen_at` becomes `now`. Only the holder renews, and only
/// within the lease's grace. A renewal that clears a lapse (the runner came back, E15.19)
/// is audited as a recovered `lease.expired`; a plain renewal is not.
pub async fn renew_lease(
    pool: &SqlitePool,
    run: RunId,
    runner: RunnerId,
    now: &str,
) -> Result<Lease, LeaseError> {
    renew_lease_loaded(pool, run, runner, now, None).await
}

/// `renew_lease` for a heartbeat that reports the host's `load` (AIN-55): the lease lasts
/// `lease.ttl_secs` times `load_stretch(load)`, so a loaded host that could not beat on time
/// keeps its run.
pub async fn renew_lease_loaded(
    pool: &SqlitePool,
    run: RunId,
    runner: RunnerId,
    now: &str,
    load: Option<HostLoad>,
) -> Result<Lease, LeaseError> {
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let held: Option<(i64, bool)> = sqlx::query_as(
        "SELECT l.runner_id, julianday(l.expires_at) <= julianday(?) FROM leases l \
         JOIN runs r ON r.id = l.run_id \
         WHERE l.run_id = ? AND r.state IN ('claimed', 'running')",
    )
    .bind(now)
    .bind(run.0)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((holder, lapsed)) = held else {
        return Err(LeaseError::NoLease);
    };
    if holder != runner.0 {
        return Err(LeaseError::WrongRunner {
            held_by: RunnerId(holder),
        });
    }
    let grace = value_in(&mut tx, Key::LeaseGraceSecs, Scope::Runner(runner)).await?;
    if lease_lost_in(&mut tx, run, grace, now).await? {
        return Err(LeaseError::Expired);
    }
    let ttl = value_in(&mut tx, Key::LeaseTtlSecs, Scope::Runner(runner)).await?;
    let ttl = (ttl as f64 * load_stretch(load)).round() as i64;
    let lease = sqlx::query_as(
        "UPDATE leases SET heartbeat_at = strftime('%Y-%m-%dT%H:%M:%fZ', ?1), \
         expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', ?1, ?2) WHERE run_id = ?3 \
         RETURNING expires_at, heartbeat_at",
    )
    .bind(now)
    .bind(format!("+{ttl} seconds"))
    .bind(run.0)
    .fetch_one(&mut *tx)
    .await
    .map(|(expires_at, heartbeat_at)| Lease {
        run_id: run,
        runner_id: runner,
        expires_at,
        heartbeat_at,
    })?;
    sqlx::query("UPDATE runners SET last_seen_at = ? WHERE id = ?")
        .bind(now)
        .bind(runner.0)
        .execute(&mut *tx)
        .await?;
    if lapsed {
        audit_recovery(&mut tx, run, runner, &lease.expires_at, now).await?;
    }
    tx.commit().await?;
    Ok(lease)
}

/// Whether `run`'s lease ran out `grace` seconds before `now`, so the run is lost: past its
/// grace, a lease is no longer renewed and the reaper takes it.
async fn lease_lost_in(
    conn: &mut SqliteConnection,
    run: RunId,
    grace: i64,
    now: &str,
) -> Result<bool, Error> {
    sqlx::query_scalar(
        "SELECT julianday(expires_at, ?) <= julianday(?) FROM leases WHERE run_id = ?",
    )
    .bind(format!("+{grace} seconds"))
    .bind(now)
    .bind(run.0)
    .fetch_one(&mut *conn)
    .await
}

/// Records that `runner` came back inside the grace and re-claimed `run`, whose lease had
/// lapsed at `expired_at`: a `lease.expired` event with `recovered: true`.
async fn audit_recovery(
    conn: &mut SqliteConnection,
    run: RunId,
    runner: RunnerId,
    renewed_until: &str,
    now: &str,
) -> Result<(), Error> {
    let (company_id, details): (i64, String) = sqlx::query_as(
        "SELECT a.company_id, json_object('runner', ?, 'renewed_until', ?, 'recovered', \
         json('true'), 'at', ?) FROM runs r JOIN agents a ON a.id = r.agent_id WHERE r.id = ?",
    )
    .bind(runner.0)
    .bind(renewed_until)
    .bind(now)
    .bind(run.0)
    .fetch_one(&mut *conn)
    .await?;
    audit::append(
        &mut *conn,
        &NewAuditEvent {
            actor: AuditActor::Runner(runner),
            action: "lease.expired".to_owned(),
            entity: Some(AuditEntity {
                kind: "run".to_owned(),
                id: run.0,
            }),
            company_id: Some(CompanyId(company_id)),
            run_id: Some(run),
            details,
        },
    )
    .await
    .map(drop)
}

/// Ends every run whose lease lapsed past its grace by `now`, one transaction per run, and
/// returns what it did; each run is reported once, by whichever reaper got it first, so
/// reaping again or concurrently is safe.
///
/// For each run, by the system: `run.runner_lost` (lease dropped, issue released, and the
/// run end's loop breaker and escalation, E2.7), then a retry wake (E2.2) unless the run
/// end stopped it. An escalated issue goes up its escalation chain (team lead, product
/// owner, `ESCALATION_USER`; E6.3), waking an agent with an `escalation` wake. A
/// `lease.expired` event records the runner, expiry and recovery.
pub async fn reap_expired_leases(pool: &SqlitePool, now: &str) -> Result<Vec<Reaped>, LeaseError> {
    let expired: Vec<i64> = {
        let mut conn = pool.acquire().await?;
        check_time(&mut conn, now).await?;
        sqlx::query_scalar(
            "SELECT run_id FROM leases WHERE julianday(expires_at) <= julianday(?) \
             ORDER BY run_id",
        )
        .bind(now)
        .fetch_all(&mut *conn)
        .await?
    };
    let mut reaped = vec![];
    for run_id in expired.into_iter().map(RunId) {
        let mut tx = crate::store::begin_write(pool).await?;
        if let Some(r) = reap_in(&mut tx, run_id, now).await? {
            reaped.push(r);
        }
        tx.commit().await?;
    }
    Ok(reaped)
}

/// Reaps `run_id` if its lease is still there and lost past its grace; `None` if another
/// reaper (or a run end) got to it first, or the runner is still inside its grace.
async fn reap_in(
    conn: &mut SqliteConnection,
    run_id: RunId,
    now: &str,
) -> Result<Option<Reaped>, LeaseError> {
    let lease: Option<(i64, String)> = sqlx::query_as(
        "SELECT runner_id, expires_at FROM leases \
         WHERE run_id = ? AND julianday(expires_at) <= julianday(?)",
    )
    .bind(run_id.0)
    .bind(now)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((runner, expires_at)) = lease else {
        return Ok(None);
    };
    let grace = value_in(conn, Key::LeaseGraceSecs, Scope::Runner(RunnerId(runner))).await?;
    if !lease_lost_in(conn, run_id, grace, now).await? {
        return Ok(None);
    }
    let current = run_in(conn, run_id).await?.ok_or(Error::RowNotFound)?;
    let lost = RunEvent::RunnerLost;
    let (lost, stop) = transition_in(conn, &current, AuditActor::System, &lost, now).await?;

    let recovery = match stop {
        Some(Stop::Tripped(trip)) => Recovery::Tripped(trip),
        Some(Stop::Escalated(Some(to))) => Recovery::Escalated { to },
        Some(Stop::Escalated(None)) => Recovery::GaveUp,
        None => match schedule_retry_in(conn, run_id, now).await? {
            Retry::Scheduled(wake) => Recovery::Retry(wake),
            // The run end found a retry left, so nothing else is reachable here.
            _ => Recovery::GaveUp,
        },
    };
    let (kind, wake, to) = match &recovery {
        Recovery::Retry(w) => ("retry", Some(w.id.0), None),
        Recovery::Escalated { to } => ("escalated", None, Some(actor_text(to))),
        Recovery::Tripped(t) => ("tripped", None, t.escalated_to.as_ref().map(actor_text)),
        Recovery::GaveUp => ("gave_up", None, None),
    };
    let (company_id, details): (i64, String) = sqlx::query_as(
        "SELECT company_id, json_object('runner', ?, 'expires_at', ?, 'recovery', ?, \
         'wake', ?, 'escalated_to', ?) FROM agents WHERE id = ?",
    )
    .bind(runner)
    .bind(&expires_at)
    .bind(kind)
    .bind(wake)
    .bind(to)
    .bind(lost.agent_id.0)
    .fetch_one(&mut *conn)
    .await?;
    audit::append(
        &mut *conn,
        &NewAuditEvent {
            actor: AuditActor::System,
            action: "lease.expired".to_owned(),
            entity: Some(AuditEntity {
                kind: "run".to_owned(),
                id: run_id.0,
            }),
            company_id: Some(CompanyId(company_id)),
            run_id: Some(run_id),
            details,
        },
    )
    .await?;
    Ok(Some(Reaped {
        run_id,
        runner_id: RunnerId(runner),
        issue_id: lost.issue_id,
        recovery,
    }))
}
