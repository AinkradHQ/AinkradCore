//! B3: a wake prefers the runner that last ran its issue, but never waits on it for long.

use super::wake::{dispatch, finish, runner, wake};
use super::*;
use citadel_core::exec::RunEvent;

const NOW: &str = "2026-10-21T10:00:00.000Z";
// Wakes are stamped with the real clock, so "past the grace" must be far ahead of it.
const LATER: &str = "2099-01-01T00:00:00.000Z";

async fn online(pool: &SqlitePool, r: RunnerId) {
    sqlx::query("UPDATE runners SET status = 'online' WHERE id = ?")
        .bind(r.0)
        .execute(pool)
        .await
        .unwrap();
}

async fn drain(pool: &SqlitePool, r: RunnerId) {
    sqlx::query("UPDATE runners SET drained_at = '2026-10-21T09:00:00Z' WHERE id = ?")
        .bind(r.0)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn wake_waits_a_grace_for_the_last_runner_then_any_runner_takes_it() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let (a, b) = (runner(pool, "a").await, runner(pool, "b").await);
    enqueue_wake(pool, &wake(dev, Some(i), "k1")).await.unwrap();
    let first = dispatch(pool, a, NOW).await.unwrap();
    finish(pool, &first, RunEvent::Succeed).await;
    while let Some(r) = dispatch(pool, a, NOW).await {
        finish(pool, &r, RunEvent::Succeed).await;
    }
    for r in [a, b] {
        online(pool, r).await;
    }
    enqueue_wake(pool, &wake(dev, Some(i), "k2")).await.unwrap();
    // B is eligible but A is online and preferred: B waits.
    assert!(dispatch(pool, b, NOW).await.is_none());
    // Past the grace B takes it.
    let run = dispatch(pool, b, LATER).await.unwrap();
    assert_eq!(run.runner_id, Some(b));
    finish(pool, &run, RunEvent::Succeed).await;

    // The last runner is now B but drained: A is not made to wait on it.
    enqueue_wake(pool, &wake(dev, Some(i), "k3")).await.unwrap();
    drain(pool, b).await;
    let run = dispatch(pool, a, NOW).await.unwrap();
    assert_eq!(run.runner_id, Some(a));
    finish(pool, &run, RunEvent::Succeed).await;

    // The preferred runner takes it at once.
    enqueue_wake(pool, &wake(dev, Some(i), "k4")).await.unwrap();
    assert!(dispatch(pool, a, NOW).await.is_some());
}

#[tokio::test]
async fn offline_preferred_runner_never_holds_the_wake() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let (a, b) = (runner(pool, "a").await, runner(pool, "b").await);
    enqueue_wake(pool, &wake(dev, Some(i), "k1")).await.unwrap();
    let first = dispatch(pool, a, NOW).await.unwrap();
    finish(pool, &first, RunEvent::Succeed).await;
    while let Some(r) = dispatch(pool, a, NOW).await {
        finish(pool, &r, RunEvent::Succeed).await;
    }
    // A stays offline (its default); B is online and takes the wake at once.
    online(pool, b).await;
    enqueue_wake(pool, &wake(dev, Some(i), "k2")).await.unwrap();
    let run = dispatch(pool, b, NOW).await.unwrap();
    assert_eq!(run.runner_id, Some(b));
}
