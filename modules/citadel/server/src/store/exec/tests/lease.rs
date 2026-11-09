//! Leases and runner loss: a runner that stops renewing loses its run, which is retried or
//! escalated; every run end drops its lease and checkout.

use citadel_core::audit::AuditActor;
use citadel_core::exec::RunEvent;
use citadel_core::settings::{Key, Scope};
use citadel_core::work::IssueTransition;
use ainkrad_proto::runner::HostLoad;

use super::flow::wakes_for;
use super::settings::set;
use super::wake::{dispatch, runner};
use super::*;
use crate::store::work::{checkout_issue, get_issue, transition_issue};

const NOW: &str = "2026-10-21T10:00:00.000Z";
/// `NOW` + `LEASE_TTL_SECS`.
const EXPIRY: &str = "2026-10-21T10:01:30.000Z";
/// `EXPIRY` + `LEASE_GRACE_SECS`: past it the lapsed lease's run is lost.
const LOST: &str = "2026-10-21T10:06:30.000Z";

/// `dev`'s issue `i`, assigned to it; the assignment wake is the one dispatched.
pub(super) async fn assigned(pool: &SqlitePool, name: &str) -> (AgentId, IssueId) {
    let (dev, i) = fixture(pool, name).await;
    let to_dev = IssueTransition::Reassign {
        next: NextActor::Agent(dev),
    };
    transition_issue(pool, i, &to_dev, AuditActor::System)
        .await
        .unwrap();
    (dev, i)
}

/// Dispatches to `mac` at `at`, starts the run and checks its issue out.
pub(super) async fn working(pool: &SqlitePool, mac: RunnerId, at: &str) -> Run {
    let run = dispatch(pool, mac, at).await.unwrap();
    start_run(pool, run.id, AuditActor::Runner(mac), None, at)
        .await
        .unwrap();
    checkout_issue(pool, run.issue_id.unwrap(), run.id, at)
        .await
        .unwrap();
    run
}

async fn count(pool: &SqlitePool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

/// No live run without a lease, no issue held by an ended run, no open issue without a
/// next actor.
async fn assert_invariants(pool: &SqlitePool) {
    let unleased = "SELECT count(*) FROM runs r WHERE r.state IN ('claimed', 'running') \
                    AND NOT EXISTS (SELECT 1 FROM leases l WHERE l.run_id = r.id)";
    let held_by_ended = "SELECT count(*) FROM issues i JOIN runs r ON r.id = i.checkout_run_id \
                         WHERE r.state NOT IN ('queued', 'claimed', 'running')";
    let stranded = "SELECT count(*) FROM issues WHERE state NOT IN ('done', 'cancelled') \
                    AND next_agent_id IS NULL AND next_user_id IS NULL AND next_at IS NULL";
    for sql in [unleased, held_by_ended, stranded] {
        assert_eq!(count(pool, sql).await, 0, "{sql}");
    }
}

#[tokio::test]
async fn a_lost_runner_ends_the_run_releases_the_issue_and_schedules_a_retry() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = assigned(pool, "A").await;
    let mac = runner(pool, "mac").await;
    let run = working(pool, mac, NOW).await;
    let lease = get_lease(pool, run.id).await.unwrap().unwrap();
    assert_eq!(
        (
            lease.runner_id,
            lease.expires_at.as_str(),
            lease.heartbeat_at.as_str()
        ),
        (mac, EXPIRY, NOW)
    );

    // The runner stops renewing. Not lost until the lease runs out.
    let early = reap_expired_leases(pool, "2026-10-21T10:01:29.999Z").await;
    assert!(early.unwrap().is_empty());
    assert_eq!(
        get_run(pool, run.id).await.unwrap().unwrap().state,
        RunState::Running
    );

    // Lapsed but inside the grace: still live, not reaped.
    assert!(reap_expired_leases(pool, EXPIRY).await.unwrap().is_empty());
    assert_eq!(
        get_run(pool, run.id).await.unwrap().unwrap().state,
        RunState::Running
    );

    let reaped = reap_expired_leases(pool, LOST).await.unwrap();
    assert_eq!(reaped.len(), 1);
    let Recovery::Retry(retry) = &reaped[0].recovery else {
        panic!("{reaped:?}");
    };
    assert_eq!(
        (reaped[0].run_id, reaped[0].runner_id, reaped[0].issue_id),
        (run.id, mac, Some(i))
    );
    assert_eq!(
        (retry.source, retry.attempt, retry.not_before.as_deref()),
        (WakeSource::Retry, 2, Some("2026-10-21T10:07:00.000Z"))
    );
    let lost = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!(
        (lost.state, lost.terminal_reason.as_deref()),
        (RunState::RunnerLost, Some("runner_lost"))
    );
    assert_eq!(get_lease(pool, run.id).await.unwrap(), None);
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(issue.checkout_run_id, None);
    assert_eq!(issue.next_actor, Some(NextActor::Agent(dev)));
    assert_invariants(pool).await;
    let audited = count(
        pool,
        "SELECT count(*) FROM audit_events WHERE action IN \
         ('run.runner_lost', 'issue.released', 'lease.expired')",
    )
    .await;
    assert_eq!(audited, 3);

    // Reaping again does nothing; the lost runner cannot come back.
    assert!(reap_expired_leases(pool, LOST).await.unwrap().is_empty());
    assert!(matches!(
        renew_lease(pool, run.id, mac, LOST).await,
        Err(LeaseError::NoLease)
    ));
    // The retry runs once due, with a fresh lease.
    let again = dispatch(pool, mac, "2026-10-21T10:07:00.000Z")
        .await
        .unwrap();
    assert_eq!(again.wake_request_id, Some(retry.id));
    assert!(get_lease(pool, again.id).await.unwrap().is_some());
}

#[tokio::test]
async fn only_the_holder_renews_and_renewal_outlives_the_first_ttl() {
    let db = db().await;
    let pool = &db.pool;
    assigned(pool, "A").await;
    let (mac, pc) = (runner(pool, "mac").await, runner(pool, "pc").await);
    let run = working(pool, mac, NOW).await;

    assert!(matches!(
        renew_lease(pool, run.id, pc, NOW).await,
        Err(LeaseError::WrongRunner { held_by }) if held_by == mac
    ));
    assert!(matches!(
        renew_lease(pool, run.id, mac, "soon").await,
        Err(LeaseError::Db(Error::InvalidArgument(_)))
    ));
    let at = "2026-10-21T10:01:00.000Z";
    let renewed = renew_lease(pool, run.id, mac, at).await.unwrap();
    assert_eq!(
        (renewed.heartbeat_at.as_str(), renewed.expires_at.as_str()),
        (at, "2026-10-21T10:02:30.000Z")
    );
    assert_eq!(get_lease(pool, run.id).await.unwrap(), Some(renewed));
    let seen = get_runner(pool, mac).await.unwrap().unwrap().last_seen_at;
    assert_eq!(seen.as_deref(), Some(at));

    // Past the first expiry: still alive.
    assert!(reap_expired_leases(pool, EXPIRY).await.unwrap().is_empty());
    assert_eq!(
        get_run(pool, run.id).await.unwrap().unwrap().state,
        RunState::Running
    );
    // Once the grace runs out too, a late renewal is refused and the reaper takes it.
    let late = "2026-10-21T10:07:30.000Z";
    assert!(matches!(
        renew_lease(pool, run.id, mac, late).await,
        Err(LeaseError::Expired)
    ));
    assert_eq!(reap_expired_leases(pool, late).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_runner_back_inside_the_grace_reclaims_its_lapsed_run() {
    let db = db().await;
    let pool = &db.pool;
    let (_, i) = assigned(pool, "A").await;
    let mac = runner(pool, "mac").await;
    let run = working(pool, mac, NOW).await;

    // A two-minute network drop: the lease lapses at EXPIRY and the runner is back at 10:03.
    let back = "2026-10-21T10:03:00.000Z";
    assert!(reap_expired_leases(pool, back).await.unwrap().is_empty());
    let renewed = renew_lease(pool, run.id, mac, back).await.unwrap();
    assert_eq!(renewed.expires_at, "2026-10-21T10:04:30.000Z");
    assert_eq!(
        get_run(pool, run.id).await.unwrap().unwrap().state,
        RunState::Running
    );
    assert_eq!(
        get_issue(pool, i).await.unwrap().unwrap().checkout_run_id,
        Some(run.id)
    );
    assert_invariants(pool).await;

    // Recovered: a `lease.expired` with `recovered`, and no `runner_lost`.
    let recovered = "SELECT count(*) FROM audit_events WHERE action = 'lease.expired' \
                     AND json_extract(details, '$.recovered') = 1";
    assert_eq!(count(pool, recovered).await, 1);
    let lost = "SELECT count(*) FROM audit_events WHERE action = 'run.runner_lost'";
    assert_eq!(count(pool, lost).await, 0);

    // The re-claimed lease is a normal one: it lapses and is reaped only past its grace.
    assert!(
        reap_expired_leases(pool, "2026-10-21T10:04:30.000Z")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        reap_expired_leases(pool, "2026-10-21T10:09:30.000Z")
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn the_grace_is_the_runners_setting_and_zero_loses_the_run_at_expiry() {
    let db = db().await;
    let pool = &db.pool;
    assigned(pool, "A").await;
    let mac = runner(pool, "mac").await;
    set(pool, Key::LeaseGraceSecs, Scope::Runner(mac), 0).await;
    let run = working(pool, mac, NOW).await;

    assert!(matches!(
        renew_lease(pool, run.id, mac, EXPIRY).await,
        Err(LeaseError::Expired)
    ));
    assert_eq!(reap_expired_leases(pool, EXPIRY).await.unwrap().len(), 1);
}

/// Runs every attempt on the agent's issue, ten minutes apart (each retry is due by then),
/// and loses each runner, except that with `fail_second` the second run fails itself and is
/// retried, so the breaker sees two different failures. Returns the last recovery.
async fn lose_every_attempt(pool: &SqlitePool, mac: RunnerId, fail_second: bool) -> Recovery {
    let mut last = None;
    for (start, lost) in [("10:00", "10:06"), ("10:10", "10:16"), ("10:20", "10:26")] {
        let run = working(pool, mac, &format!("2026-10-21T{start}:00.000Z")).await;
        let at = format!("2026-10-21T{lost}:30.000Z");
        if fail_second && start == "10:10" {
            let fail = RunEvent::Fail {
                reason: "tests red".to_owned(),
                fingerprint: None,
            };
            transition_run(pool, run.id, AuditActor::Runner(mac), &fail, &at)
                .await
                .unwrap();
            let retry = schedule_retry(pool, run.id, &at).await.unwrap();
            assert!(matches!(retry, Retry::Scheduled(_)), "{retry:?}");
            continue;
        }
        let mut reaped = reap_expired_leases(pool, &at).await.unwrap();
        assert_eq!(reaped.len(), 1, "{start}");
        last = reaped.pop().map(|r| r.recovery);
    }
    assert_invariants(pool).await;
    last.unwrap()
}

#[tokio::test]
async fn three_lost_runners_trip_the_breaker_and_escalate_to_the_lead() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = assigned(pool, "A").await;
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(dev.0)
        .fetch_one(pool)
        .await
        .unwrap();
    let lead = agent(pool, CompanyId(company)).await;
    lead_team(pool, dev, lead).await;
    let mac = runner(pool, "mac").await;
    let to = NextActor::Agent(lead);
    let Recovery::Tripped(trip) = lose_every_attempt(pool, mac, false).await else {
        panic!("not tripped");
    };
    assert_eq!(trip.fingerprint, "runner_lost:runner_lost");
    assert_eq!(
        (trip.runs.len(), trip.escalated_to.as_ref()),
        (3, Some(&to))
    );
    let recorded = "SELECT count(*) FROM audit_events WHERE action = 'lease.expired' \
                    AND json_extract(details, '$.recovery') = 'tripped'";
    assert_eq!(count(pool, recorded).await, 1);
    // Escalated once, by the run's end: the assignment to dev, then the one to the lead.
    let reassigns = "SELECT count(*) FROM audit_events \
                     WHERE json_extract(details, '$.transition') = 'reassign'";
    assert_eq!(count(pool, reassigns).await, 2);
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(issue.next_actor, Some(to));
    let woken = wakes_for(pool, i).await.pop().unwrap();
    assert_eq!(
        (woken.agent_id, woken.status, woken.source),
        (lead, WakeStatus::Pending, WakeSource::Escalation)
    );
}

#[tokio::test]
async fn exhausted_mixed_failures_without_a_lead_escalate_to_the_admin() {
    let db = db().await;
    let pool = &db.pool;
    let (_, i) = assigned(pool, "A").await;
    let mac = runner(pool, "mac").await;
    let admin = NextActor::Human(UserId(1));
    assert_eq!(
        lose_every_attempt(pool, mac, true).await,
        Recovery::Escalated { to: admin.clone() }
    );
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(issue.next_actor, Some(admin));
    // Nothing is left to dispatch: the admin is a human.
    assert_eq!(dispatch(pool, mac, "2026-10-21T12:00:00.000Z").await, None);
}

#[tokio::test]
async fn concurrent_reapers_handle_each_run_once() {
    for round in 0..5 {
        let db = db().await;
        let pool = &db.pool;
        let mut runs = vec![];
        for n in 0..4 {
            assigned(pool, &format!("C{n}")).await;
            let mac = runner(pool, &format!("mac-{round}-{n}")).await;
            runs.push(working(pool, mac, NOW).await.id);
        }
        let reapers: Vec<_> = (0..4)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move { reap_expired_leases(&pool, LOST).await })
            })
            .collect();
        let mut handled = vec![];
        for r in reapers {
            handled.extend(r.await.unwrap().unwrap().into_iter().map(|r| r.run_id));
        }
        handled.sort_by_key(|r| r.0);
        assert_eq!(handled, runs);
        let expired = "SELECT count(*) FROM audit_events WHERE action = 'lease.expired'";
        assert_eq!(count(pool, expired).await, 4);
        let retries = "SELECT count(*) FROM wake_requests WHERE source = 'retry'";
        assert_eq!(count(pool, retries).await, 4);
        assert_invariants(pool).await;
    }
}

#[tokio::test]
async fn every_terminal_transition_drops_the_lease_and_releases_the_checkout() {
    let db = db().await;
    let pool = &db.pool;
    let ends = [
        RunEvent::Succeed,
        RunEvent::Fail {
            reason: "tests red".to_owned(),
            fingerprint: None,
        },
        RunEvent::Cancel {
            reason: "stop".to_owned(),
        },
        RunEvent::Timeout,
        RunEvent::RunnerLost,
        RunEvent::TokenCap,
    ];
    for (n, end) in ends.iter().enumerate() {
        let (_, i) = assigned(pool, &format!("C{n}")).await;
        let mac = runner(pool, &format!("mac-{n}")).await;
        let run = working(pool, mac, NOW).await;
        let ended = transition_run(pool, run.id, AuditActor::Runner(mac), end, NOW)
            .await
            .unwrap();
        assert!(ended.state.is_terminal(), "{end:?}");
        assert_eq!(get_lease(pool, run.id).await.unwrap(), None, "{end:?}");
        let issue = get_issue(pool, i).await.unwrap().unwrap();
        assert_eq!(issue.checkout_run_id, None, "{end:?}");
        assert_invariants(pool).await;
    }
    let released = "SELECT count(*) FROM audit_events WHERE action = 'issue.released'";
    assert_eq!(count(pool, released).await, ends.len() as i64);
}

#[tokio::test]
async fn a_runner_holding_live_runs_cannot_be_deleted() {
    let db = db().await;
    let pool = &db.pool;
    assigned(pool, "A").await;
    let mac = runner(pool, "mac").await;
    let run = working(pool, mac, NOW).await;

    assert!(matches!(
        delete_runner(pool, mac).await,
        Err(DeleteRunnerError::LiveRuns(runs)) if runs == vec![run.id]
    ));
    assert!(get_runner(pool, mac).await.unwrap().is_some());
    assert!(get_lease(pool, run.id).await.unwrap().is_some());
    assert_invariants(pool).await;

    // Once the reaper ends the run, the runner goes; the ended run stays, runnerless.
    assert_eq!(reap_expired_leases(pool, LOST).await.unwrap().len(), 1);
    assert!(delete_runner(pool, mac).await.unwrap());
    let ended = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!((ended.state, ended.runner_id), (RunState::RunnerLost, None));
    assert_invariants(pool).await;
}

/// How far a host's load stretches its lease (AIN-55): per CPU, kept between 1 and the cap, and
/// 1 for a load it did not send or cannot be.
#[test]
fn load_stretches_the_lease_within_its_bounds() {
    let load = |avg1, cores| Some(HostLoad { avg1, cores });
    assert_eq!(load_stretch(None), 1.0);
    assert_eq!(load_stretch(load(2.0, 4)), 1.0);
    assert_eq!(load_stretch(load(6.0, 4)), 1.5);
    assert_eq!(load_stretch(load(44.0, 4)), MAX_LOAD_STRETCH);
    assert_eq!(load_stretch(load(f64::NAN, 4)), 1.0);
    assert_eq!(load_stretch(load(6.0, 0)), 1.0);
}

/// A loaded host's heartbeat stretches its lease (AIN-55): 44 on 4 cores is capped at 4, so
/// the lease runs 4 × 90 s from the renewal, and the reaper leaves its run alone past the
/// plain expiry. A later plain renewal goes back to the plain TTL.
#[tokio::test]
async fn a_loaded_runners_lease_is_stretched_by_its_load() {
    let db = db().await;
    let pool = &db.pool;
    assigned(pool, "A").await;
    let mac = runner(pool, "mac").await;
    let run = working(pool, mac, NOW).await;

    let load = Some(HostLoad {
        avg1: 44.0,
        cores: 4,
    });
    let renewed = renew_lease_loaded(pool, run.id, mac, NOW, load)
        .await
        .unwrap();
    assert_eq!(renewed.expires_at, "2026-10-21T10:06:00.000Z");
    assert!(reap_expired_leases(pool, EXPIRY).await.unwrap().is_empty());

    let plain = renew_lease(pool, run.id, mac, "2026-10-21T10:02:00.000Z")
        .await
        .unwrap();
    assert_eq!(plain.expires_at, "2026-10-21T10:03:30.000Z");
}
