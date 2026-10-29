//! Scenario 11: the admin's controls (decision #34) mid-flight. Pausing an agent with a live
//! run, stopping a run, messaging one that then ends, nudging, and pausing a whole company all
//! go through the engine, and every invariant holds after each step: no run without its lease
//! or a reason, no lost wake (a paused agent's wait for its resume), no issue without a next
//! actor; the stuck detector and its repairs leave a paused agent's issue alone.

use citadel_core::audit::AuditActor;
use citadel_core::exec::{RunEvent, RunState, WakeStatus};
use citadel_core::org::Harness;
use citadel_core::work::{NextActor, UserId};
use citadel_server::store::exec::{
    PAUSED, dispatch_next, list_wake_requests, message_run, nudge_issue, pause_agent,
    pause_company, resume_agent, stop_run, tick,
};
use citadel_server::store::work::get_issue;

use super::harness::*;

const ADMIN: AuditActor = AuditActor::User(UserId(1));

#[tokio::test]
async fn the_admins_controls_keep_every_invariant() {
    let db = Db::new().await;
    let pool = &db.pool;
    let mut clock = Clock::new();
    let (c, p) = company(pool, "A").await;
    let lead = agent(pool, c, "Lead", &["lead"], None).await;
    let dev = agent(pool, c, "Dev", &[], Some(lead)).await;
    let (i, j) = (issue(pool, p).await, issue(pool, p).await);
    let mac = runner(pool, "mac", &[]).await;
    assign(pool, i, dev).await;
    let now = clock.now();
    let run = dispatch_next(pool, mac, &[], &Harness::ALL, &now)
        .await
        .unwrap()
        .unwrap();
    let run = step(pool, &run, RunEvent::Start { session: None }, &now).await;
    assert_invariants(pool, &now, NONE).await;

    // Pause: the run goes on to its tool call's end, then its runner ends it.
    assert!(pause_agent(pool, dev, ADMIN, &now).await.unwrap());
    assert_invariants(pool, &now, NONE).await;
    let paused = RunEvent::Cancel {
        reason: PAUSED.to_owned(),
    };
    let ended = step(pool, &run, paused, &clock.advance(5)).await;
    assert_eq!(ended.state, RunState::Cancelled);
    assert_invariants(pool, &clock.now(), NONE).await;
    // A day of ticks: no run for the paused agent, no repair moves its issue.
    assign(pool, j, dev).await;
    for _ in 0..24 {
        let now = clock.advance(3600);
        tick(pool, &now).await.unwrap();
        let none = dispatch_next(pool, mac, &[], &Harness::ALL, &now).await;
        assert_eq!(none.unwrap(), None);
        assert_invariants(pool, &now, NONE).await;
    }
    for issue in [i, j] {
        let waiting = get_issue(pool, issue).await.unwrap().unwrap().next_actor;
        assert_eq!(
            waiting,
            Some(NextActor::Agent(dev)),
            "parked, not escalated"
        );
    }

    // Resume: woken on both issues; one run at a time.
    let now = clock.advance(60);
    assert!(resume_agent(pool, dev, ADMIN, &now).await.unwrap());
    assert_invariants(pool, &now, NONE).await;
    let second = dispatch_next(pool, mac, &[], &Harness::ALL, &now)
        .await
        .unwrap()
        .unwrap();
    let second = step(pool, &second, RunEvent::Start { session: None }, &now).await;
    assert_invariants(pool, &now, NONE).await;

    // A message it never takes becomes a comment when the run is stopped; nothing dangles.
    let by = UserId(1);
    message_run(pool, second.id, by, "check the lease math", None, &now)
        .await
        .unwrap();
    let stopped = stop_run(pool, second.id, ADMIN, &clock.advance(5))
        .await
        .unwrap();
    assert_eq!(stopped.terminal_reason.as_deref(), Some("stopped by admin"));
    assert_invariants(pool, &clock.now(), NONE).await;
    let comment = "SELECT count(*) FROM comments WHERE body = 'check the lease math'";
    assert_eq!(count(pool, comment).await, 1);

    // Nudge: one pending wake per agent and issue, however often.
    for _ in 0..3 {
        let now = clock.advance(1);
        let issue = second.issue_id.unwrap();
        let w = nudge_issue(pool, issue, ADMIN, &now)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            w.status,
            WakeStatus::Pending | WakeStatus::Coalesced
        ));
        assert_invariants(pool, &now, NONE).await;
    }

    // The whole company, twice over.
    let now = clock.advance(1);
    let all = pause_company(pool, c, true, ADMIN, &now).await.unwrap();
    assert_eq!(all, [lead, dev]);
    assert_invariants(pool, &now, NONE).await;
    let back = pause_company(pool, c, false, ADMIN, &now).await.unwrap();
    assert_eq!(back, [lead, dev]);
    assert_invariants(pool, &now, NONE).await;
    let pending = list_wake_requests(pool, dev).await.unwrap();
    assert!(pending.iter().any(|w| w.status == WakeStatus::Pending));
}
