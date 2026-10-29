//! Scenario 7: a repeating failure trips the loop breaker. Scenario 8: a runner is deleted
//! while holding runs.

use ainkrad_core::exec::{
    LEASE_GRACE_SECS, LEASE_TTL_SECS, LOOP_BREAKER_THRESHOLD, MAX_RETRY_BACKOFF_SECS, RunEvent,
    RunState, WakeSource, WakeStatus, retry_backoff_secs,
};
use ainkrad_core::org::Harness;
use ainkrad_core::work::NextActor;
use ainkrad_core_server::store::exec::{
    DeleteRunnerError, Recovery, Retry, delete_runner, dispatch_next, get_run, get_runner,
    list_wake_requests, schedule_retry, tick,
};
use ainkrad_core_server::store::work::{checkout_issue, get_issue};

use super::harness::*;

/// The same failure on every attempt: the third trips the breaker, which drops the agent's
/// wakes on the issue and hands it to the lead; the agent never runs on it again.
#[tokio::test]
async fn a_repeating_failure_trips_the_breaker_and_stops() {
    let db = Db::new().await;
    let pool = &db.pool;
    let mut clock = Clock::new();
    let (c, p) = company(pool, "A").await;
    // The lead needs a tag only `lead_box` has, so `mac` only ever serves `dev`.
    let lead = agent(pool, c, "Lead", &["lead"], None).await;
    let dev = agent(pool, c, "Dev", &[], Some(lead)).await;
    let i = issue(pool, p).await;
    let mac = runner(pool, "mac", &[]).await;
    let lead_box = runner(pool, "lead-box", &["lead"]).await;
    assign(pool, i, dev).await;

    for attempt in 1..=LOOP_BREAKER_THRESHOLD as i64 {
        let now = clock.now();
        let run = dispatch_next(pool, mac, &[], &Harness::ALL, &now)
            .await
            .unwrap()
            .unwrap();
        step(pool, &run, RunEvent::Start { session: None }, &now).await;
        let failed = step(pool, &run, fail("E0308@build"), &now).await;
        assert_eq!(failed.state, RunState::Failed);
        assert_invariants(pool, &now, NONE).await;
        match schedule_retry(pool, run.id, &now).await.unwrap() {
            Retry::Scheduled(w) if attempt < LOOP_BREAKER_THRESHOLD as i64 => {
                assert_eq!(w.attempt, attempt + 1);
                clock.advance(retry_backoff_secs(attempt, MAX_RETRY_BACKOFF_SECS));
            }
            Retry::Tripped(trip) if attempt == LOOP_BREAKER_THRESHOLD as i64 => {
                assert_eq!(trip.runs.len(), LOOP_BREAKER_THRESHOLD);
                assert_eq!(trip.escalated_to, None, "the run's own end escalated");
            }
            other => panic!("attempt {attempt}: {other:?}"),
        }
        assert_invariants(pool, &clock.now(), NONE).await;
    }

    let escalated = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(escalated.next_actor, Some(NextActor::Agent(lead)));
    let dev_pending = list_wake_requests(pool, dev).await.unwrap();
    assert!(dev_pending.iter().all(|w| w.status != WakeStatus::Pending));
    let lead_wakes = list_wake_requests(pool, lead).await.unwrap();
    assert!(
        lead_wakes
            .iter()
            .any(|w| w.source == WakeSource::Escalation && w.status == WakeStatus::Pending)
    );

    // An hour of ticks and dispatches: the agent never runs on it again.
    for _ in 0..12 {
        let now = clock.advance(300);
        tick(pool, &now).await.unwrap();
        assert_eq!(
            dispatch_next(pool, mac, &[], &Harness::ALL, &now)
                .await
                .unwrap(),
            None
        );
        assert_invariants(pool, &now, NONE).await;
    }
    let dev_runs = "SELECT count(*) FROM runs WHERE agent_id = ";
    assert_eq!(count(pool, &format!("{dev_runs}{}", dev.0)).await, 3);
    // The lead picks it up.
    let now = clock.now();
    let lead_run = dispatch_next(pool, lead_box, &["lead".to_owned()], &Harness::ALL, &now).await;
    assert_eq!(lead_run.unwrap().unwrap().agent_id, lead);
    assert_invariants(pool, &now, NONE).await;
}

/// Deleting a runner that holds runs is refused and changes nothing; once its leases
/// expire the reaper ends them, after which the delete goes through and another runner
/// picks up the retries.
#[tokio::test]
async fn a_runner_deleted_while_holding_runs_is_refused_then_reaped() {
    let db = Db::new().await;
    let pool = &db.pool;
    let mut clock = Clock::new();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let (i, j) = (issue(pool, p).await, issue(pool, p).await);
    let mac = runner(pool, "mac", &[]).await;
    let mut held = vec![];
    for x in [i, j] {
        assign(pool, x, dev).await;
        let now = clock.now();
        let run = dispatch_next(pool, mac, &[], &Harness::ALL, &now)
            .await
            .unwrap()
            .unwrap();
        step(pool, &run, RunEvent::Start { session: None }, &now).await;
        checkout_issue(pool, x, run.id, &now).await.unwrap();
        held.push(run.id);
    }

    let refused = delete_runner(pool, mac).await;
    let Err(DeleteRunnerError::LiveRuns(runs)) = refused else {
        panic!("{refused:?}");
    };
    assert_eq!(runs, held);
    assert!(get_runner(pool, mac).await.unwrap().is_some());
    assert_invariants(pool, &clock.now(), NONE).await;

    let now = clock.advance(LEASE_TTL_SECS + LEASE_GRACE_SECS);
    let reaped = tick(pool, &now).await.unwrap().reaped;
    assert_eq!(reaped.iter().map(|r| r.run_id).collect::<Vec<_>>(), held);
    assert!(
        reaped
            .iter()
            .all(|r| matches!(r.recovery, Recovery::Retry(_)))
    );
    assert_invariants(pool, &now, NONE).await;

    assert!(delete_runner(pool, mac).await.unwrap());
    for id in &held {
        let run = get_run(pool, *id).await.unwrap().unwrap();
        assert_eq!((run.state, run.runner_id), (RunState::RunnerLost, None));
    }
    assert_invariants(pool, &now, NONE).await;

    let pc = runner(pool, "pc", &[]).await;
    let now = clock.advance(retry_backoff_secs(1, MAX_RETRY_BACKOFF_SECS));
    for _ in 0..2 {
        let run = dispatch_next(pool, pc, &[], &Harness::ALL, &now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(run.runner_id, Some(pc));
    }
    assert_invariants(pool, &now, NONE).await;
}
