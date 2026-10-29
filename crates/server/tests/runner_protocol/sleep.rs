//! Mac sleep (E3.11): the runner's machine sleeps past the lease TTL. The server reaps the
//! run (`runner_lost`) and requeues it; the runner notices the wall-clock jump on waking,
//! reconnects at once, is told to drop the lost run, and takes the retry.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use ainkrad_core::exec::{LEASE_GRACE_SECS, RunId, RunState};
use ainkrad_core_server::store::exec::{get_run, tick};
use ainkrad_harness::claude;
use ainkrad_runner::Config;

use super::support::*;
use crate::harness::{agent, assign, company, issue, runner};

#[tokio::test]
async fn a_run_lost_while_asleep_is_dropped_on_wake_and_its_retry_taken() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &["macos"], None).await;
    assign(pool, issue(pool, p).await, dev).await;
    runner(pool, "mac", &[]).await;
    let (executor, mut tokens, release) = held();
    let slept = Arc::new(AtomicU64::new(0));
    let wall = slept.clone();
    let clock =
        Arc::new(move || SystemTime::now() + Duration::from_secs(wall.load(Ordering::SeqCst)));
    let config = Config {
        log: None,
        url: stack.url(),
        key: "mac".to_owned(),
        tags: vec!["macos".to_owned()],
        harnesses: BTreeMap::from([("claude".to_owned(), claude::VERSION.to_owned())]),
    };
    tokio::spawn(ainkrad_runner::run_with_clock(config, executor, clock));
    let (lost, _) = tokens.recv().await.unwrap();
    // Its one chunk is in before it sleeps: a later chunk would be refused with a `Cancel`,
    // which is another way to learn the run is lost.
    until(pool, "the run's chunk", "SELECT count(*) FROM run_events").await;

    // Asleep: no heartbeat for longer than the TTL and its grace, though the socket looks open.
    // The reaper ends the run and queues its retry, due after the backoff.
    let late = stack.advance(91 + LEASE_GRACE_SECS);
    assert_eq!(tick(pool, &late).await.unwrap().reaped.len(), 1);
    stack.advance(31);
    let r = get_run(pool, RunId(lost)).await.unwrap().unwrap();
    assert_eq!(r.state, RunState::RunnerLost);

    // Awake: the wall clock jumped an hour. Long before a heartbeat would have noticed,
    // the runner reconnects, drops the lost run and takes the retry.
    slept.store(3600, Ordering::SeqCst);
    let retry = tokio::time::timeout(Duration::from_secs(5), tokens.recv());
    let (retry, _) = retry.await.expect("no retry after waking").unwrap();
    assert_ne!(retry, lost);
    release.notify_one();
    let done = format!("SELECT count(*) FROM runs WHERE id = {retry} AND state = 'succeeded'");
    until(pool, "the retry to finish", &done).await;
    let r = get_run(pool, RunId(lost)).await.unwrap().unwrap();
    assert_eq!(r.state, RunState::RunnerLost, "the lost run stays lost");
}
