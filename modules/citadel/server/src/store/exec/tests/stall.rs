//! A stalled run (E15.7): it ends `failed: stalled`, its issue escalates at once and it is
//! never retried; stalls count for the loop breaker like any repeated failure.

use citadel_core::audit::AuditActor;
use citadel_core::exec::{LOOP_BREAKER_THRESHOLD, RunEvent};
use citadel_core::work::IssueTransition;

use super::breaker::led;
use super::wake::{dispatch, runner, wake};
use super::*;
use crate::store::work::{get_issue, transition_issue};

const NOW: &str = "2026-10-21T10:00:00.000Z";

/// A fresh wake for `dev` on `i`, then a run that stalls.
async fn stall(pool: &SqlitePool, mac: RunnerId, dev: AgentId, i: IssueId, key: &str) -> Run {
    enqueue_wake(pool, &wake(dev, Some(i), key)).await.unwrap();
    let run = dispatch(pool, mac, NOW).await.unwrap();
    let by = AuditActor::Runner(mac);
    start_run(pool, run.id, by, None, NOW).await.unwrap();
    transition_run(pool, run.id, by, &RunEvent::Stall, NOW)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_stalled_run_escalates_at_once_and_is_never_retried() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    let mac = runner(pool, "mac").await;
    let run = stall(pool, mac, dev, i, "k").await;
    assert_eq!(run.state, RunState::Failed);
    assert_eq!(run.terminal_reason.as_deref(), Some("stalled"));
    assert_eq!(run.failure_fingerprint.as_deref(), Some("failed:stalled"));
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(
        issue.next_actor,
        Some(NextActor::Agent(lead)),
        "up the chain"
    );
    let retry = schedule_retry(pool, run.id, NOW).await.unwrap();
    assert_eq!(retry, Retry::Stalled);
}

#[tokio::test]
async fn stalls_in_a_row_trip_the_loop_breaker() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    led(pool, dev).await;
    let mac = runner(pool, "mac").await;
    for n in 0..LOOP_BREAKER_THRESHOLD {
        // Handed back to the developer each time, as a lead would.
        let back = IssueTransition::Reassign {
            next: NextActor::Agent(dev),
        };
        transition_issue(pool, i, &back, AuditActor::System)
            .await
            .unwrap();
        stall(pool, mac, dev, i, &format!("k{n}")).await;
    }
    let trips: Vec<String> = sqlx::query_scalar(
        "SELECT json_extract(details, '$.fingerprint') FROM audit_events \
         WHERE action = 'loop_breaker.tripped'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(trips, vec!["failed:stalled".to_owned()]);
}
