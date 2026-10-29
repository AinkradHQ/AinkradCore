//! Fault-injection suite (E2.10, brainstorm §6 #4 "no silent dead runs").
//!
//! Each scenario injects one fault through the public store API on a real database file,
//! with a fake clock, and after every step checks `assert_invariants`: every run ends in a
//! known state with a reason, and no wake is lost. The Paperclip failures it proves
//! impossible here: a cancel before dispatch leaving the task unrecoverable (#13640), a
//! skipped handoff wake being terminal (#13532), a long thread that can never be woken
//! (#13959/#13662), duplicate runs from a watchdog's re-wakes (#14600; the stuck detector's
//! repairs wake only through the wake queue, and no wake path can start a second live run), a
//! restart mid-run, and duplicate wake storms.
//!
//! Scenarios 1–5 are here; the wake storm (6) is in `storm`, the loop breaker (7) and the
//! deleted runner (8) in `recovery`, the seeded interleaving (9) in `chaos`, the stuck
//! auto-repair under chaos (10) in `repair`, the admin's controls (11) in `controls`.

mod fault_injection {
    pub mod chaos;
    pub mod controls;
    pub mod harness;
    pub mod recovery;
    pub mod repair;
    pub mod storm;
}

use citadel_core::audit::AuditActor;
use citadel_core::exec::{
    LEASE_GRACE_SECS, LEASE_TTL_SECS, MAX_RETRY_BACKOFF_SECS, NewRun, NewWakeRequest, RunEvent,
    RunState, STUCK_AFTER_SECS, StuckKind, WakeSource, WakeStatus, retry_backoff_secs,
};
use citadel_core::org::{AgentId, Harness};
use citadel_core::work::{Actor, BlockerLink, IssueId, IssueTransition, NewComment, NextActor};
use citadel_server::store::exec::{
    LeaseError, Recovery, Retry, create_run, dispatch_next, enqueue_wake, get_lease, get_run,
    get_wake_request, list_wake_requests, reap_expired_leases, renew_lease, schedule_retry,
    stuck_report, tick, transition_run, update_wake_request,
};
use citadel_server::store::work::{
    add_blocker, checkout_issue, create_comment, get_issue, list_comments, transition_issue,
};
use fault_injection::harness::*;

pub fn wake(agent: AgentId, issue: Option<IssueId>, key: &str) -> NewWakeRequest {
    NewWakeRequest {
        agent_id: agent,
        issue_id: issue,
        source: WakeSource::Comment,
        reason: format!("wake {key}"),
        idempotency_key: key.to_owned(),
        not_before: None,
    }
}

/// 1. Cancel before dispatch (#13640): a cancelled pending wake, a cancelled queued run and a
/// run cancelled between claim and start each end with a reason, and the issue still wakes.
#[tokio::test]
async fn cancel_before_dispatch_leaves_the_issue_recoverable() {
    let db = Db::new().await;
    let pool = &db.pool;
    let mut clock = Clock::new();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let i = issue(pool, p).await;
    let mac = runner(pool, "mac", &[]).await;

    // (a) The pending wake is cancelled: dropped, with why.
    assign(pool, i, dev).await;
    let mut w = list_wake_requests(pool, dev).await.unwrap().pop().unwrap();
    assert_eq!(w.status, WakeStatus::Pending);
    w.status = WakeStatus::Dropped;
    w.dropped_reason = Some("cancelled by the admin before dispatch".to_owned());
    assert!(update_wake_request(pool, &w).await.unwrap());
    assert_eq!(
        dispatch_next(pool, mac, &[], &Harness::ALL, &clock.now())
            .await
            .unwrap(),
        None
    );
    assert_invariants(pool, &clock.now(), NONE).await;
    // Nothing wakes it now; once idle that is reported, with a reason, never silent.
    let later = clock.advance(STUCK_AFTER_SECS + 60);
    let stuck = stuck_report(pool, &later).await.unwrap();
    let found: Vec<_> = stuck.iter().map(|s| (s.kind, s.issue_id)).collect();
    assert_eq!(found, vec![(StuckKind::TodoIdle, Some(i))]);
    assert_invariants(pool, &later, &[StuckKind::TodoIdle]).await;

    // (b) A run queued but never dispatched is cancelled; the issue still dispatches.
    let queued = NewRun {
        agent_id: dev,
        issue_id: Some(i),
        wake_request_id: None,
        harness: Harness::Claude,
    };
    let queued = create_run(pool, &queued).await.unwrap();
    enqueue_wake(pool, &wake(dev, Some(i), "nudge"))
        .await
        .unwrap();
    // While it is queued it holds the issue's wakes back (the one state the invariants
    // reject, reachable only through the raw `create_run`).
    assert_eq!(
        dispatch_next(pool, mac, &[], &Harness::ALL, &clock.now())
            .await
            .unwrap(),
        None
    );
    let cancel = RunEvent::Cancel {
        reason: "cancelled before dispatch".to_owned(),
    };
    let ended = transition_run(pool, queued.id, AuditActor::System, &cancel, &clock.now())
        .await
        .unwrap();
    assert_eq!(ended.state, RunState::Cancelled);
    assert_eq!(
        ended.terminal_reason.as_deref(),
        Some("cancelled before dispatch")
    );
    let run = dispatch_next(pool, mac, &[], &Harness::ALL, &clock.now())
        .await
        .unwrap()
        .unwrap();
    assert_invariants(pool, &clock.now(), NONE).await;

    // (c) Cancelled after the claim, before the harness started; a wake that came in
    // meanwhile is held, not lost (#13532), and fires next.
    enqueue_wake(pool, &wake(dev, Some(i), "handoff"))
        .await
        .unwrap();
    let ended = step(pool, &run, cancel.clone(), &clock.now()).await;
    assert_eq!(ended.state, RunState::Cancelled);
    assert_eq!(get_lease(pool, run.id).await.unwrap(), None);
    let retry = schedule_retry(pool, run.id, &clock.now()).await.unwrap();
    assert_eq!(retry, Retry::NotRetryable(RunState::Cancelled));
    assert_invariants(pool, &clock.now(), NONE).await;
    let next = dispatch_next(pool, mac, &[], &Harness::ALL, &clock.now())
        .await
        .unwrap()
        .unwrap();
    let handoff = get_wake_request(pool, next.wake_request_id.unwrap())
        .await
        .unwrap();
    assert_eq!(handoff.unwrap().idempotency_key, "handoff");
    assert_invariants(pool, &clock.now(), NONE).await;
}

/// 2. Kill the runner mid-run: it stops renewing, the lease runs out, the run ends
/// `runner_lost`, the issue is released and a retry wake fires after its backoff.
#[tokio::test]
async fn a_killed_runner_is_reaped_and_its_run_retried() {
    let db = Db::new().await;
    let pool = &db.pool;
    let mut clock = Clock::new();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let i = issue(pool, p).await;
    let mac = runner(pool, "mac", &[]).await;
    assign(pool, i, dev).await;

    let run = dispatch_next(pool, mac, &[], &Harness::ALL, &clock.now())
        .await
        .unwrap()
        .unwrap();
    step(pool, &run, RunEvent::Start { session: None }, &clock.now()).await;
    checkout_issue(pool, i, run.id, &clock.now()).await.unwrap();
    for _ in 0..3 {
        let now = clock.advance(30);
        renew_lease(pool, run.id, mac, &now).await.unwrap();
        assert_invariants(pool, &now, NONE).await;
    }
    // Killed: no renewal from here. Lapsed, but one second before the grace ends nothing is
    // reaped.
    let now = clock.advance(LEASE_TTL_SECS + LEASE_GRACE_SECS - 1);
    assert_eq!(tick(pool, &now).await.unwrap().reaped, vec![]);
    assert_invariants(pool, &now, NONE).await;

    // Two reapers race at the end of the grace: exactly one ends the run.
    let now = clock.advance(1);
    let (a, b) = tokio::join!(tick(pool, &now), reap_expired_leases(pool, &now));
    let mut reaped = a.unwrap().reaped;
    reaped.extend(b.unwrap());
    assert_eq!(reaped.len(), 1, "{reaped:?}");
    let Recovery::Retry(retry) = &reaped[0].recovery else {
        panic!("{reaped:?}");
    };
    assert_eq!(retry.attempt, 2);
    let lost = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!(lost.state, RunState::RunnerLost);
    assert_eq!(lost.terminal_reason.as_deref(), Some("runner_lost"));
    let held = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(held.checkout_run_id, None);
    assert_eq!(held.next_actor, Some(NextActor::Agent(dev)));
    // The runner coming back late cannot resurrect it.
    let late = renew_lease(pool, run.id, mac, &now).await;
    assert!(matches!(late, Err(LeaseError::NoLease)), "{late:?}");
    assert_eq!(tick(pool, &now).await.unwrap().reaped, vec![]);
    assert_invariants(pool, &now, NONE).await;

    // The retry waits out its backoff, then dispatches as attempt 2.
    let now = clock.advance(retry_backoff_secs(1, MAX_RETRY_BACKOFF_SECS) - 1);
    assert_eq!(
        dispatch_next(pool, mac, &[], &Harness::ALL, &now)
            .await
            .unwrap(),
        None
    );
    let now = clock.advance(1);
    let again = dispatch_next(pool, mac, &[], &Harness::ALL, &now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.wake_request_id, Some(retry.id));
    assert_invariants(pool, &now, NONE).await;
}

/// 3. Server restart mid-run: an uncommitted dispatch vanishes and its wake is still
/// pending; a committed run keeps its lease across the restart, and a runner that died with
/// the server is reaped by the first ticks after it.
#[tokio::test]
async fn a_restart_mid_run_resumes_from_a_known_state() {
    let mut db = Db::new().await;
    let mut clock = Clock::new();
    let (c, p) = company(&db.pool, "A").await;
    let dev = agent(&db.pool, c, "Dev", &[], None).await;
    let (i, j) = (issue(&db.pool, p).await, issue(&db.pool, p).await);
    let mac = runner(&db.pool, "mac", &[]).await;
    assign(&db.pool, i, dev).await;
    let run = dispatch_next(&db.pool, mac, &[], &Harness::ALL, &clock.now())
        .await
        .unwrap()
        .unwrap();
    step(
        &db.pool,
        &run,
        RunEvent::Start { session: None },
        &clock.now(),
    )
    .await;
    checkout_issue(&db.pool, i, run.id, &clock.now())
        .await
        .unwrap();
    enqueue_wake(&db.pool, &wake(dev, Some(i), "follow-up"))
        .await
        .unwrap();

    // The server dies halfway through dispatching `j`'s wake: the wake is marked and its
    // run inserted, but the transaction never commits.
    assign(&db.pool, j, dev).await;
    let wj = list_wake_requests(&db.pool, dev)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let mut conn = db.pool.acquire().await.unwrap().detach();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut conn)
        .await
        .unwrap();
    sqlx::query("UPDATE wake_requests SET status = 'dispatched' WHERE id = ?")
        .bind(wj.id.0)
        .execute(&mut conn)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO runs (agent_id, issue_id, wake_request_id, harness) \
         VALUES (?, ?, ?, 'claude')",
    )
    .bind(dev.0)
    .bind(j.0)
    .bind(wj.id.0)
    .execute(&mut conn)
    .await
    .unwrap();
    use sqlx::Connection;
    conn.close().await.unwrap();
    db.restart().await;
    let pool = &db.pool;
    let now = clock.advance(10);
    let wj = get_wake_request(pool, wj.id).await.unwrap().unwrap();
    assert_eq!(wj.status, WakeStatus::Pending);
    assert_eq!(tick(pool, &now).await.unwrap().reaped, vec![]);
    assert_invariants(pool, &now, NONE).await;

    // The run survived with its lease; its runner, still alive, renews and finishes.
    renew_lease(pool, run.id, mac, &now).await.unwrap();
    let jr = dispatch_next(pool, mac, &[], &Harness::ALL, &now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((jr.issue_id, jr.wake_request_id), (Some(j), Some(wj.id)));
    step(pool, &jr, RunEvent::Start { session: None }, &now).await;
    step(pool, &jr, RunEvent::Succeed, &now).await;
    assert_invariants(pool, &now, NONE).await;

    // A second restart, and this time the runner died with the server.
    db.restart().await;
    let pool = &db.pool;
    let now = clock.advance(LEASE_TTL_SECS + LEASE_GRACE_SECS);
    let reaped = tick(pool, &now).await.unwrap().reaped;
    assert_eq!(reaped.len(), 1);
    assert_eq!(reaped[0].run_id, run.id);
    // The retry folded into the waiting follow-up, which is due now.
    let Recovery::Retry(retry) = &reaped[0].recovery else {
        panic!("{reaped:?}");
    };
    assert_eq!(retry.status, WakeStatus::Coalesced);
    assert_invariants(pool, &now, NONE).await;
    let next = dispatch_next(pool, mac, &[], &Harness::ALL, &now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.wake_request_id, retry.coalesced_into);
    assert_invariants(pool, &now, NONE).await;
}

/// 4. A 10,000-comment thread (#13959/#13662): the context is never put on a command line.
/// Wakes and runs carry ids and a one-line reason, so the issue still wakes and dispatches
/// however long its thread is.
#[tokio::test]
async fn a_ten_thousand_comment_thread_still_wakes_and_dispatches() {
    const COMMENTS: usize = 10_000;
    let db = Db::new().await;
    let pool = &db.pool;
    let clock = Clock::new();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let i = issue(pool, p).await;
    let mac = runner(pool, "mac", &[]).await;

    // ~10 MiB of thread: ten times macOS's ARG_MAX, eighty times Linux's per-argument cap.
    let line = "x".repeat(1024);
    for n in 0..COMMENTS {
        let c = NewComment {
            issue_id: i,
            author: Actor::Human(citadel_core::work::UserId(1)),
            body: format!("{n}: {line}"),
            run_id: None,
            idempotency_key: None,
        };
        create_comment(pool, &c).await.unwrap();
    }
    assert_eq!(list_comments(pool, i).await.unwrap().len(), COMMENTS);

    // Assigning wakes it; a comment arriving meanwhile coalesces.
    assign(pool, i, dev).await;
    let comment = NewWakeRequest {
        source: WakeSource::Comment,
        ..wake(dev, Some(i), "comment:10000")
    };
    let folded = enqueue_wake(pool, &comment).await.unwrap();
    assert_eq!(folded.status, WakeStatus::Coalesced);
    let run = dispatch_next(pool, mac, &[], &Harness::ALL, &clock.now())
        .await
        .unwrap()
        .unwrap();
    let woke = get_wake_request(pool, run.wake_request_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(woke.reason.len() < 100, "{}", woke.reason);
    step(pool, &run, RunEvent::Start { session: None }, &clock.now()).await;
    checkout_issue(pool, i, run.id, &clock.now()).await.unwrap();
    assert_eq!(list_comments(pool, i).await.unwrap().len(), COMMENTS);
    step(pool, &run, RunEvent::Succeed, &clock.now()).await;
    assert_invariants(pool, &clock.now(), NONE).await;
}

/// 5. A blocker closes while its dependants are parked: one whose run already ended is
/// woken and dispatched at once; one whose run is still live gets its wake held until that
/// run ends, then dispatched (#13532: a held handoff is never terminal).
#[tokio::test]
async fn closing_a_blocker_wakes_parked_dependants() {
    let db = Db::new().await;
    let pool = &db.pool;
    let clock = Clock::new();
    let now = clock.now();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let ops = agent(pool, c, "Ops", &[], None).await;
    let blocker = issue(pool, p).await;
    let (d1, d2) = (issue(pool, p).await, issue(pool, p).await);
    let mac = runner(pool, "mac", &[]).await;
    for d in [d1, d2] {
        let link = BlockerLink {
            blocker,
            blocked: d,
        };
        add_blocker(pool, link).await.unwrap();
    }

    // Each dependant is picked up, then parks itself on the blocker.
    let mut runs = vec![];
    for (d, a) in [(d1, dev), (d2, ops)] {
        assign(pool, d, a).await;
        let run = dispatch_next(pool, mac, &[], &Harness::ALL, &now)
            .await
            .unwrap()
            .unwrap();
        step(pool, &run, RunEvent::Start { session: None }, &now).await;
        checkout_issue(pool, d, run.id, &now).await.unwrap();
        transition_issue(pool, d, &IssueTransition::Block, AuditActor::Agent(a))
            .await
            .unwrap();
        runs.push(run);
    }
    // `d1`'s run ends parked; `d2`'s is still working when the blocker closes.
    step(pool, &runs[0], RunEvent::Succeed, &now).await;
    assert_invariants(pool, &now, NONE).await;

    let admin = AuditActor::User(citadel_core::work::UserId(1));
    transition_issue(pool, blocker, &IssueTransition::Cancel, admin)
        .await
        .unwrap();
    for (d, a) in [(d1, dev), (d2, ops)] {
        let woken = get_issue(pool, d).await.unwrap().unwrap();
        assert_eq!(woken.next_actor, Some(NextActor::Agent(a)));
    }
    assert_invariants(pool, &now, NONE).await;
    let first = dispatch_next(pool, mac, &[], &Harness::ALL, &now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.issue_id, Some(d1));
    let w = get_wake_request(pool, first.wake_request_id.unwrap())
        .await
        .unwrap();
    assert_eq!(w.unwrap().source, WakeSource::BlockerClosed);
    assert_eq!(
        dispatch_next(pool, mac, &[], &Harness::ALL, &now)
            .await
            .unwrap(),
        None
    );
    assert_invariants(pool, &now, NONE).await;

    step(pool, &runs[1], RunEvent::Succeed, &now).await;
    let second = dispatch_next(pool, mac, &[], &Harness::ALL, &now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.issue_id, Some(d2));
    let w = get_wake_request(pool, second.wake_request_id.unwrap())
        .await
        .unwrap();
    assert_eq!(w.unwrap().source, WakeSource::BlockerClosed);
    assert_invariants(pool, &now, NONE).await;
}
