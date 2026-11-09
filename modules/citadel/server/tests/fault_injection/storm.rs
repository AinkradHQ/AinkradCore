//! Scenario 6: a duplicate wake storm (#14600): 1,200 enqueues (1,000 keys, 200 repeats) over 24
//! agent-and-issue pairs, raced by 4 enqueuers against 8 dispatchers.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use citadel_core::exec::RunEvent;
use citadel_core::org::Harness;
use citadel_core::work::IssueId;
use citadel_server::store::exec::{dispatch_next, enqueue_wake};

use super::harness::*;
use crate::wake;

const KEYS: usize = 1000;
const REPEATS: usize = 200;
const ENQUEUERS: usize = 4;
const DISPATCHERS: usize = 8;

/// An agent and issue, by id.
type Pair = (i64, Option<i64>);

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_duplicate_wake_storm_runs_one_at_a_time_and_loses_nothing() {
    let db = Db::new().await;
    let pool = db.pool.clone();
    let clock = Clock::new();
    let now = clock.now();
    let (c, p) = company(&pool, "A").await;
    let mut agents = vec![];
    for n in 0..4 {
        agents.push(agent(&pool, c, &format!("Dev{n}"), &[], None).await);
    }
    let mut issues: Vec<Option<IssueId>> = vec![None];
    for _ in 0..5 {
        issues.push(Some(issue(&pool, p).await));
    }

    // Enqueuer `e` sends keys e, e + 4, … and then repeats a slice of them.
    let mut enqueuers = vec![];
    for e in 0..ENQUEUERS {
        let (pool, agents, issues) = (pool.clone(), agents.clone(), issues.clone());
        enqueuers.push(tokio::spawn(async move {
            let mut seen = vec![];
            let mine: Vec<usize> = (e..KEYS).step_by(ENQUEUERS).collect();
            let again = mine.iter().take(REPEATS / ENQUEUERS).copied();
            for k in mine.iter().copied().chain(again) {
                let (a, i) = (agents[k % agents.len()], issues[k / 4 % issues.len()]);
                let w = enqueue_wake(&pool, &wake(a, i, &format!("storm:{k}")))
                    .await
                    .unwrap();
                seen.push((w.idempotency_key, w.id));
            }
            seen
        }));
    }

    let done = Arc::new(AtomicBool::new(false));
    let live: Arc<Mutex<HashSet<Pair>>> = Arc::default();
    let mut dispatchers = vec![];
    for d in 0..DISPATCHERS {
        let mac = runner(&pool, &format!("mac{d}"), &[]).await;
        let (pool, now, done, live) = (pool.clone(), now.clone(), done.clone(), live.clone());
        dispatchers.push(tokio::spawn(async move {
            let mut ran = 0;
            loop {
                let Some(run) = dispatch_next(&pool, mac, &[], &Harness::ALL, &now)
                    .await
                    .unwrap()
                else {
                    let pending = "SELECT count(*) FROM wake_requests WHERE status = 'pending'";
                    if done.load(Ordering::SeqCst) && count(&pool, pending).await == 0 {
                        return ran;
                    }
                    tokio::task::yield_now().await;
                    continue;
                };
                let pair = (run.agent_id.0, run.issue_id.map(|i| i.0));
                assert!(
                    live.lock().unwrap().insert(pair),
                    "two live runs on {pair:?}"
                );
                step(&pool, &run, RunEvent::Start { session: None }, &now).await;
                // Leave the set while the run is still live, so no other dispatcher can
                // have taken the pair yet.
                live.lock().unwrap().remove(&pair);
                step(&pool, &run, RunEvent::Succeed, &now).await;
                ran += 1;
            }
        }));
    }

    let mut keys: HashMap<String, i64> = HashMap::new();
    for e in enqueuers {
        for (key, id) in e.await.unwrap() {
            assert_eq!(*keys.entry(key).or_insert(id.0), id.0, "one key, two wakes");
        }
    }
    assert_eq!(keys.len(), KEYS);
    done.store(true, Ordering::SeqCst);
    let mut ran = 0;
    for d in dispatchers {
        ran += d.await.unwrap();
    }

    // Every wake stored once, and each one either ran or rode along with one that did.
    let stored = count(&pool, "SELECT count(*) FROM wake_requests").await;
    assert_eq!(stored, KEYS as i64);
    let dispatched = "SELECT count(*) FROM wake_requests WHERE status = 'dispatched'";
    assert_eq!(count(&pool, dispatched).await, ran);
    let runs = "SELECT count(*) FROM runs WHERE state = 'succeeded'";
    assert_eq!(count(&pool, runs).await, ran);
    let folded = "SELECT count(*) FROM wake_requests WHERE status = 'coalesced'";
    let folded = count(&pool, folded).await;
    let counted = "SELECT coalesce(sum(coalesced_count), 0) FROM wake_requests";
    assert_eq!(folded, count(&pool, counted).await);
    assert_eq!(ran + folded, KEYS as i64);
    let audited = "SELECT count(*) FROM audit_events WHERE action = 'wake.dispatched'";
    assert_eq!(count(&pool, audited).await, ran);
    assert_invariants(&pool, &now, NONE).await;
}
