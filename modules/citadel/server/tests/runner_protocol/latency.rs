//! Push dispatch (E15.6): a wake reaches a waiting runner as it is enqueued, not on the next
//! poll. The fallback poll here is a minute, so only the push can be this fast.

use std::time::{Duration, Instant};

use super::support::*;
use crate::harness::{agent, assign, company, count, issue, runner};

#[tokio::test]
async fn a_wake_reaches_a_waiting_runner_at_once() {
    let stack = Stack::with_dispatch_poll(Duration::from_secs(60)).await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    runner(pool, "box", &[]).await;
    let (executor, mut tokens, release) = held();
    stack.runner("box", &[], executor);
    let hello = "SELECT count(*) FROM runners WHERE last_seen_at IS NOT NULL";
    until(pool, "the runner's hello", hello).await;
    // Its `Ready` found nothing; the connection now waits.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(count(pool, "SELECT count(*) FROM runs").await, 0);

    let i = issue(pool, p).await;
    let enqueued = Instant::now();
    assign(pool, i, dev).await;
    let claimed = "SELECT count(*) FROM runs WHERE claimed_at IS NOT NULL";
    while count(pool, claimed).await == 0 {
        assert!(
            enqueued.elapsed() < Duration::from_secs(30),
            "never dispatched"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let dispatch = enqueued.elapsed();
    let (run, _) = tokens.recv().await.unwrap();
    eprintln!("push dispatch: claimed {dispatch:?} after the wake was enqueued (run {run})");
    // The poll is a minute: anything well under it was the push. A tighter bound only measures
    // how loaded the machine is.
    assert!(
        dispatch < Duration::from_secs(10),
        "dispatched {dispatch:?} after enqueue"
    );
    release.notify_one();
    until(
        pool,
        "the run to end",
        "SELECT count(*) FROM runs WHERE state = 'succeeded'",
    )
    .await;
}
