//! S8, the allocator under real concurrency (I4): picks, failovers and wakes race on small caps, on
//! worker threads, while a sampler counts every account's live sessions again and again. At no sampled
//! instant is an account over its cap, and when the dust settles no hold outlived its session, no run
//! has two live attempts, and no account holds a session twice in a run.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::json;

use super::allocator::{pick_owned, w};
use super::failover::{budget, limited, mv_owned};
use super::health::at;
use crate::store::accounts as acc;
use crate::store::agents as store;
use crate::store::alloc;

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn neg_concurrent_picks_failovers_and_wakes_never_put_an_account_over_its_cap() {
    let w = w().await;
    let pool = w.fx.app.pool.clone();
    let mut caps = Vec::new();
    let mut ids = Vec::new();
    for (label, cap) in [("a", 2), ("b", 1), ("c", 2), ("d", 1)] {
        let a = w.acct(label).await;
        acc::set_cap(&pool, a.id, cap, &w.fx.dev.id, BY, super::NOW)
            .await
            .unwrap();
        caps.push((a.id, cap));
        ids.push(a.id);
    }
    let chain = vec![w.keys("p1", &ids[..2]).await, w.keys("p2", &ids[2..]).await];
    budget(&w, chain[0].pool).await;
    let done = Arc::new(AtomicBool::new(false));
    let sampler = {
        let (pool, done, caps) = (pool.clone(), Arc::clone(&done), caps.clone());
        tokio::spawn(async move {
            let mut samples = 0;
            while !done.load(Ordering::Relaxed) {
                for (a, cap) in &caps {
                    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_agent_sessions WHERE account_id = ? AND state IN ('starting', 'running', 'interrupted')")
                        .bind(a)
                        .fetch_one(&pool)
                        .await
                        .unwrap();
                    assert!(n <= *cap, "account {a} had {n} live on a cap of {cap}");
                }
                samples += 1;
                tokio::task::yield_now().await;
            }
            samples
        })
    };
    let mut tasks = Vec::new();
    for i in 0..36 {
        let s = w.session(&chain, &[]).await;
        let (pool, runner, chain) = (pool.clone(), w.vm.id.clone(), chain.clone());
        tasks.push(tokio::spawn(async move {
            let args = (1, vec![], vec![], 0, true);
            let got = pick_owned(pool.clone(), runner, s.id.clone(), chain, at(0), args).await;
            if !matches!(got, alloc::Outcome::Picked(_)) || i % 3 == 0 {
                return;
            }
            alloc::mark_start_sent(&pool, &s.id).await.unwrap();
            sqlx::query("UPDATE core_agent_sessions SET harness_session = 'h' WHERE id = ?")
                .bind(&s.id)
                .execute(&pool)
                .await
                .unwrap();
            store::set_state(&pool, &s.id, "running", "t", false, &at(1))
                .await
                .unwrap();
            if i % 3 == 1 {
                store::end(&pool, &s.id, "ended", &limited(), &at(2))
                    .await
                    .unwrap();
                mv_owned(pool, s.id, "rate_limited", at(3), true).await;
            } else {
                store::end(&pool, &s.id, "ended", &json!({"kind": "succeeded"}), &at(2))
                    .await
                    .unwrap();
                store::wake(&pool, &s.id, None, &at(3)).await.unwrap();
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    done.store(true, Ordering::Relaxed);
    let samples = sampler.await.unwrap();
    assert!(samples > 0);
    let count = |sql: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(sql)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    for (a, cap) in &caps {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_agent_sessions WHERE account_id = ? AND state IN ('starting', 'running', 'interrupted')")
            .bind(a)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(n <= *cap, "account {a} ends with {n} of {cap}");
    }
    assert_eq!(count("SELECT count(*) FROM core_budget_holds h LEFT JOIN core_agent_sessions s ON s.id = h.session WHERE s.id IS NULL OR s.state IN ('ended', 'lost')").await, 0, "a hold outlived its session");
    assert_eq!(count("SELECT count(*) FROM (SELECT 1 FROM core_agent_sessions WHERE state NOT IN ('ended', 'lost') GROUP BY coalesce(run_id, id) HAVING count(*) > 1)").await, 0, "two live attempts");
    assert_eq!(count("SELECT count(*) FROM (SELECT 1 FROM core_agent_sessions WHERE account_id IS NOT NULL GROUP BY coalesce(run_id, id), account_id HAVING count(*) > 1)").await, 0, "an account twice in a run");
    assert!(
        count("SELECT count(*) FROM core_agent_sessions WHERE failover_of IS NOT NULL").await > 0,
        "no move ran"
    );
}
