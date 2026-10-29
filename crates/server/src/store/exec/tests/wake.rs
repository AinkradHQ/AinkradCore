//! The wake queue: idempotency, coalescing, follow-ups, dispatch by tags, retries.

use std::collections::HashSet;

use ainkrad_core::audit::{AuditActor, AuditFilter};
use ainkrad_core::exec::{MAX_WAKE_ATTEMPTS, RunEvent};
use ainkrad_core::org::Agent;

use super::*;
use crate::store::audit;
use crate::store::org::{get_agent, update_agent};

const NOW: &str = "2026-10-21T10:00:00.000Z";

pub(super) fn wake(agent_id: AgentId, issue_id: Option<IssueId>, key: &str) -> NewWakeRequest {
    NewWakeRequest {
        agent_id,
        issue_id,
        source: WakeSource::Comment,
        reason: format!("wake {key}"),
        idempotency_key: key.to_owned(),
        not_before: None,
    }
}

pub(super) async fn runner(pool: &SqlitePool, name: &str) -> RunnerId {
    let r = NewRunner {
        name: name.to_owned(),
        tags: vec![],
    };
    create_runner(pool, &r, name).await.unwrap().id
}

pub(super) async fn dispatch(pool: &SqlitePool, r: RunnerId, now: &str) -> Option<Run> {
    dispatch_next(pool, r, &[], &Harness::ALL, now)
        .await
        .unwrap()
}

/// Starts the run and ends it with `end`.
pub(super) async fn finish(pool: &SqlitePool, run: &Run, end: RunEvent) {
    let by = AuditActor::Runner(run.runner_id.unwrap());
    start_run(pool, run.id, by, None, NOW).await.unwrap();
    transition_run(pool, run.id, by, &end, NOW).await.unwrap();
}

fn fail() -> RunEvent {
    RunEvent::Fail {
        reason: "tests red".to_owned(),
        fingerprint: None,
    }
}

async fn set_agent(pool: &SqlitePool, id: AgentId, f: impl FnOnce(&mut Agent)) {
    let mut a = get_agent(pool, id).await.unwrap().unwrap();
    f(&mut a);
    assert!(update_agent(pool, &a).await.unwrap());
}

#[tokio::test]
async fn duplicate_key_stores_one_request() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let first = enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    let again = enqueue_wake(
        pool,
        &NewWakeRequest {
            reason: "different".to_owned(),
            ..wake(dev, Some(i), "k")
        },
    )
    .await
    .unwrap();
    assert_eq!(again, first);
    assert_eq!(first.coalesced_count, 0);
    assert_eq!(list_wake_requests(pool, dev).await.unwrap(), vec![first]);
}

#[tokio::test]
async fn a_burst_coalesces_into_one_pending_wake() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    for n in 0..50 {
        enqueue_wake(pool, &wake(dev, Some(i), &format!("burst-{n}")))
            .await
            .unwrap();
    }
    // A repeat of a coalesced key is idempotent too: the count does not move.
    let repeat = enqueue_wake(pool, &wake(dev, Some(i), "burst-7"))
        .await
        .unwrap();
    let all = list_wake_requests(pool, dev).await.unwrap();
    let pending: Vec<_> = all
        .iter()
        .filter(|w| w.status == WakeStatus::Pending)
        .collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].coalesced_count, 49);
    let survivor = pending[0].id;
    assert_eq!(
        (repeat.status, repeat.coalesced_into),
        (WakeStatus::Coalesced, Some(survivor))
    );
    assert!(
        all.iter()
            .filter(|w| w.id != survivor)
            .all(|w| w.status == WakeStatus::Coalesced && w.coalesced_into == Some(survivor))
    );
    // An agent-level wake (no issue) is its own queue.
    let agent_level = enqueue_wake(pool, &wake(dev, None, "timer")).await.unwrap();
    assert_eq!(agent_level.status, WakeStatus::Pending);
}

#[tokio::test]
async fn coalescing_moves_the_survivor_earlier_never_later() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let later = NewWakeRequest {
        not_before: Some("2026-10-21T10:05:00.000Z".to_owned()),
        ..wake(dev, Some(i), "a")
    };
    let first = enqueue_wake(pool, &later).await.unwrap();
    let sooner = NewWakeRequest {
        not_before: Some("2026-10-21T10:01:00.000Z".to_owned()),
        ..wake(dev, Some(i), "b")
    };
    enqueue_wake(pool, &sooner).await.unwrap();
    let w = get_wake_request(pool, first.id).await.unwrap().unwrap();
    assert_eq!(w.not_before.as_deref(), Some("2026-10-21T10:01:00.000Z"));
    let latest = NewWakeRequest {
        not_before: Some("2026-10-21T11:00:00.000Z".to_owned()),
        ..wake(dev, Some(i), "c")
    };
    enqueue_wake(pool, &latest).await.unwrap();
    let w = get_wake_request(pool, first.id).await.unwrap().unwrap();
    assert_eq!(w.not_before.as_deref(), Some("2026-10-21T10:01:00.000Z"));
    enqueue_wake(pool, &wake(dev, Some(i), "now"))
        .await
        .unwrap();
    let w = get_wake_request(pool, first.id).await.unwrap().unwrap();
    assert_eq!((w.not_before, w.coalesced_count), (None, 3));
}

#[tokio::test]
async fn a_wake_during_a_live_run_fires_after_the_run_ends() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    let w1 = enqueue_wake(pool, &wake(dev, Some(i), "w1")).await.unwrap();
    let run1 = dispatch(pool, mac, NOW).await.unwrap();
    assert_eq!(
        (run1.state, run1.runner_id, run1.wake_request_id),
        (RunState::Claimed, Some(mac), Some(w1.id))
    );
    assert_eq!(
        get_wake_request(pool, w1.id).await.unwrap().unwrap().status,
        WakeStatus::Dispatched
    );

    // Not folded into the running wake: a new pending follow-up, held while the run lives.
    let w2 = enqueue_wake(pool, &wake(dev, Some(i), "w2")).await.unwrap();
    assert_eq!((w2.status, w2.coalesced_into), (WakeStatus::Pending, None));
    let w3 = enqueue_wake(pool, &wake(dev, Some(i), "w3")).await.unwrap();
    assert_eq!(w3.coalesced_into, Some(w2.id));
    assert_eq!(dispatch(pool, mac, NOW).await, None);

    finish(pool, &run1, RunEvent::Succeed).await;
    let run2 = dispatch(pool, mac, NOW).await.unwrap();
    assert_eq!(run2.wake_request_id, Some(w2.id));
    assert_eq!(dispatch(pool, mac, NOW).await, None);

    let filter = AuditFilter {
        run_id: Some(run2.id),
        ..AuditFilter::default()
    };
    let actions: Vec<_> = audit::list(pool, &filter, None, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|e| (e.action, e.actor))
        .collect();
    assert_eq!(
        actions,
        vec![
            ("wake.dispatched".to_owned(), AuditActor::Runner(mac)),
            ("run.claimed".to_owned(), AuditActor::Runner(mac)),
        ]
    );
}

#[tokio::test]
async fn dispatch_matches_runner_tags() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    set_agent(pool, dev, |a| a.runner_tags = vec!["macos".to_owned()]).await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    let linux = runner(pool, "linux").await;
    let mac = runner(pool, "mac").await;
    let tags = |t: &[&str]| t.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    for t in [tags(&[]), tags(&["linux"]), tags(&["linux", "docker"])] {
        assert_eq!(
            dispatch_next(pool, linux, &t, &Harness::ALL, NOW)
                .await
                .unwrap(),
            None
        );
    }
    let run = dispatch_next(pool, mac, &tags(&["xcode", "macos"]), &Harness::ALL, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.runner_id, Some(mac));
}

/// Only a runner offering the agent's harness (at a supported version, E3.6) gets its wake.
#[tokio::test]
async fn dispatch_matches_the_agents_harness() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    set_agent(pool, dev, |a| a.harness = Harness::Codex).await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    let r = runner(pool, "box").await;
    for offered in [&[][..], &[Harness::Claude, Harness::Agy]] {
        assert_eq!(
            dispatch_next(pool, r, &[], offered, NOW).await.unwrap(),
            None
        );
    }
    let run = dispatch_next(pool, r, &[], &[Harness::Codex], NOW).await;
    assert_eq!(run.unwrap().unwrap().harness, Harness::Codex);
}

#[tokio::test]
async fn a_paused_agent_is_not_dispatched() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    set_agent(pool, dev, |a| a.status = AgentStatus::Paused).await;
    assert_eq!(dispatch(pool, mac, NOW).await, None);
    set_agent(pool, dev, |a| a.status = AgentStatus::Active).await;
    assert!(dispatch(pool, mac, NOW).await.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_dispatchers_take_each_wake_exactly_once() {
    let db = db().await;
    let pool = &db.pool;
    let mut wakes = HashSet::new();
    for n in 0..20 {
        let (dev, i) = fixture(pool, &format!("C{n}")).await;
        let w = enqueue_wake(pool, &wake(dev, Some(i), &format!("w{n}")))
            .await
            .unwrap();
        wakes.insert(w.id);
    }
    let mut tasks = Vec::new();
    for n in 0..8 {
        let id = runner(pool, &format!("r{n}")).await;
        let pool = pool.clone();
        tasks.push(tokio::spawn(async move {
            let mut runs = Vec::new();
            while let Some(run) = dispatch_next(&pool, id, &[], &Harness::ALL, NOW)
                .await
                .unwrap()
            {
                assert_eq!(run.runner_id, Some(id));
                runs.push(run);
            }
            runs
        }));
    }
    let mut runs = Vec::new();
    for t in tasks {
        runs.extend(t.await.unwrap());
    }
    assert_eq!(runs.len(), 20);
    let taken: HashSet<_> = runs.iter().map(|r| r.wake_request_id.unwrap()).collect();
    assert_eq!(taken, wakes);
    let dispatched: i64 =
        sqlx::query_scalar("SELECT count(*) FROM wake_requests WHERE status = 'dispatched'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(dispatched, 20);
}

#[tokio::test]
async fn retries_back_off_then_exhaust() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();

    let run1 = dispatch(pool, mac, NOW).await.unwrap();
    finish(pool, &run1, fail()).await;
    let Retry::Scheduled(w2) = schedule_retry(pool, run1.id, NOW).await.unwrap() else {
        panic!("not scheduled");
    };
    assert_eq!(
        (w2.source, w2.status, w2.attempt),
        (WakeSource::Retry, WakeStatus::Pending, 2)
    );
    assert_eq!(w2.not_before.as_deref(), Some("2026-10-21T10:00:30.000Z"));
    // Idempotent per run.
    assert_eq!(
        schedule_retry(pool, run1.id, NOW).await.unwrap(),
        Retry::Scheduled(w2.clone())
    );
    // Not due before the backoff ends.
    assert_eq!(dispatch(pool, mac, "2026-10-21T10:00:29.999Z").await, None);
    let run2 = dispatch(pool, mac, "2026-10-21T10:00:30.000Z")
        .await
        .unwrap();
    assert_eq!(run2.wake_request_id, Some(w2.id));

    finish(pool, &run2, RunEvent::Timeout).await;
    let t2 = "2026-10-21T10:01:00.000Z";
    let Retry::Scheduled(w3) = schedule_retry(pool, run2.id, t2).await.unwrap() else {
        panic!("not scheduled");
    };
    assert_eq!(w3.attempt, 3);
    assert_eq!(w3.not_before.as_deref(), Some("2026-10-21T10:02:00.000Z"));

    let run3 = dispatch(pool, mac, "2026-10-21T10:02:00.000Z")
        .await
        .unwrap();
    finish(pool, &run3, fail()).await;
    assert_eq!(
        schedule_retry(pool, run3.id, NOW).await.unwrap(),
        Retry::Exhausted {
            attempt: MAX_WAKE_ATTEMPTS
        }
    );
    assert_eq!(dispatch(pool, mac, "2026-10-21T12:00:00.000Z").await, None);
}

#[tokio::test]
async fn a_token_capped_run_is_never_retried() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    let run = dispatch(pool, mac, NOW).await.unwrap();
    finish(pool, &run, RunEvent::TokenCap).await;
    assert_eq!(
        schedule_retry(pool, run.id, NOW).await.unwrap(),
        Retry::TokenCap
    );
    assert_eq!(dispatch(pool, mac, "2026-10-21T12:00:00.000Z").await, None);
}

#[tokio::test]
async fn a_retry_coalesced_into_a_waiting_wake_keeps_its_attempt() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    enqueue_wake(pool, &wake(dev, Some(i), "k1")).await.unwrap();
    let run = dispatch(pool, mac, NOW).await.unwrap();
    // A fresh wake arrives while the run is live: it waits, at attempt 1.
    let waiting = enqueue_wake(pool, &wake(dev, Some(i), "k2")).await.unwrap();
    assert_eq!(waiting.attempt, 1);
    finish(pool, &run, fail()).await;
    let Retry::Scheduled(r) = schedule_retry(pool, run.id, NOW).await.unwrap() else {
        panic!("not scheduled");
    };
    assert_eq!(r.coalesced_into, Some(waiting.id));
    // The survivor carries the retry's attempt, so the loop breaker still counts.
    let survivor = get_wake_request(pool, waiting.id).await.unwrap().unwrap();
    assert_eq!(survivor.attempt, 2);
}

#[tokio::test]
async fn only_failed_runs_retry_and_bad_input_is_rejected() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    let run = dispatch(pool, mac, NOW).await.unwrap();
    assert_eq!(
        schedule_retry(pool, run.id, NOW).await.unwrap(),
        Retry::NotRetryable(RunState::Claimed)
    );
    finish(pool, &run, RunEvent::Succeed).await;
    assert_eq!(
        schedule_retry(pool, run.id, NOW).await.unwrap(),
        Retry::NotRetryable(RunState::Succeeded)
    );
    assert!(matches!(
        schedule_retry(pool, RunId(999), NOW).await,
        Err(RetryError::Db(Error::RowNotFound))
    ));
    // A run with no wake counts as attempt 1; a bad clock is refused, not "due now".
    let lone = create_run(pool, &new_run(dev, None)).await.unwrap();
    transition_run(
        pool,
        lone.id,
        AuditActor::System,
        &RunEvent::Claim { runner: mac },
        NOW,
    )
    .await
    .unwrap();
    finish(
        pool,
        &get_run(pool, lone.id).await.unwrap().unwrap(),
        fail(),
    )
    .await;
    assert!(matches!(
        schedule_retry(pool, lone.id, "yesterday").await,
        Err(RetryError::Db(Error::InvalidArgument(_)))
    ));
    let Retry::Scheduled(w) = schedule_retry(pool, lone.id, NOW).await.unwrap() else {
        panic!("not scheduled");
    };
    assert_eq!((w.attempt, w.issue_id), (2, None));
    assert!(matches!(
        dispatch_next(pool, mac, &[], &Harness::ALL, "soon").await,
        Err(TransitionError::Db(Error::InvalidArgument(_)))
    ));
}

#[tokio::test]
async fn dropping_or_coalescing_needs_its_detail() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mut w = enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    w.status = WakeStatus::Dropped;
    for reason in [None, Some(" ".to_owned())] {
        w.dropped_reason = reason;
        let e = update_wake_request(pool, &w).await.unwrap_err();
        assert!(is_constraint(&e), "{e}");
    }
    w.dropped_reason = Some("issue closed".to_owned());
    assert!(update_wake_request(pool, &w).await.unwrap());
    assert_eq!(get_wake_request(pool, w.id).await.unwrap(), Some(w.clone()));

    w.status = WakeStatus::Coalesced;
    w.dropped_reason = None;
    let e = update_wake_request(pool, &w).await.unwrap_err();
    assert!(is_constraint(&e), "{e}");
    // A pending wake carries neither.
    w.status = WakeStatus::Pending;
    w.dropped_reason = Some("stale".to_owned());
    let e = update_wake_request(pool, &w).await.unwrap_err();
    assert!(is_constraint(&e), "{e}");
}
