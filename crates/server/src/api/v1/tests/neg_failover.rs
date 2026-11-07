//! S8, failover and allocator negatives (design §8, §9, §10, §12): no successor before the old
//! attempt ended (I2), a cancel racing the inside of a move, the hop cap walked for real, the storm
//! guard across runners, the decision function fuzzed (a Core end never moves a run, a forged
//! fingerprint moves it only along the closed class set), a stale stop after a wake, a foreign or
//! deleted pool in a snapshot (I5), soft against hard budgets, a pinned session, and a chain a
//! successor keeps alive. Assertions read rows, never the S7 event names.

use serde_json::json;

use super::allocator::{took, w};
use super::failover::{HOLDS, budget, limited, mv, over, to};
use super::health::at;
use super::*;
use crate::store::agents as store;
use crate::store::alloc::{self, Entry, Outcome};
use crate::store::budgets::{self, NewBudget};
use crate::store::chains::{self as ch, EntrySpec};
use crate::store::failover::{self as fo, Ctx, Decision, Moved};
use crate::store::{begin_write, gateway as gw, pools as pl};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

async fn live_count(w: &super::allocator::W) -> i64 {
    w.count("SELECT count(*) FROM core_agent_sessions WHERE state NOT IN ('ended', 'lost') AND ? IS NOT NULL", "x").await
}

#[tokio::test]
async fn neg_no_successor_starts_before_the_old_attempt_ended() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    for state in ["starting", "running", "interrupted"] {
        let s = w.session(&chain, &[]).await;
        took(w.pick(&s.id, &chain, &at(0)).await);
        alloc::mark_start_sent(pool, &s.id).await.unwrap();
        if state != "starting" {
            store::set_state(pool, &s.id, state, "t", false, &at(1))
                .await
                .unwrap();
        }
        // Even with the class already written and every account free, a live attempt moves nothing.
        sqlx::query("UPDATE core_agent_sessions SET failover_class = 'quota' WHERE id = ?")
            .bind(&s.id)
            .execute(pool)
            .await
            .unwrap();
        assert_eq!(
            mv(&w, &s.id, "quota", &at(2), true).await,
            Moved::Skipped,
            "{state}"
        );
        let (done, kids): (i64, i64) = sqlx::query_as("SELECT failover_done, (SELECT count(*) FROM core_agent_sessions WHERE failover_of = ?1) FROM core_agent_sessions WHERE id = ?1")
            .bind(&s.id)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!((done, kids), (0, 0), "{state}: the claim stayed open");
        store::end(pool, &s.id, "ended", &limited(), &at(3))
            .await
            .unwrap();
        to(mv(&w, &s.id, "quota", &at(4), true).await);
        // Free the account again for the next state.
        let kid: String =
            sqlx::query_scalar("SELECT id FROM core_agent_sessions WHERE failover_of = ?")
                .bind(&s.id)
                .fetch_one(pool)
                .await
                .unwrap();
        assert!(alloc::end_unstarted(pool, &kid, &at(5)).await.unwrap());
    }
    assert_eq!(live_count(&w).await, 0);
}

fn ctx<'a>(
    now: &'a str,
    min: &'a (dyn Fn(&Entry) -> u64 + Sync),
    serves: &'a (dyn Fn(&Entry) -> Option<String> + Sync),
) -> Ctx<'a> {
    Ctx {
        now,
        min_turn: min,
        serves,
        wait_max_secs: alloc::WAIT_MAX_SECS,
    }
}

#[tokio::test]
async fn neg_a_cancel_that_arrives_inside_a_move_leaves_no_live_successor_and_no_hold() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    budget(&w, chain[0].pool).await;
    let min = |_: &Entry| 0u64;
    let serves = |_: &Entry| -> Option<String> { None };
    for commit in [true, false] {
        let (old, _) = over(&w, &chain, limited(), 0).await;
        // The move has claimed and inserted and is not committed; the cancel queues behind it.
        let now = at(10);
        let mut tx = begin_write(pool).await.unwrap();
        let moved = fo::move_in(&mut tx, &old.id, "rate_limited", &ctx(&now, &min, &serves))
            .await
            .unwrap();
        let (new, _) = to(moved);
        let (cp, cid) = (pool.clone(), old.id.clone());
        let cancel = tokio::spawn(async move { fo::cancel_run(&cp, &cid).await });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            !cancel.is_finished(),
            "the cancel ran inside the move's write"
        );
        if commit {
            tx.commit().await.unwrap();
        } else {
            drop(tx);
        }
        let newest = cancel.await.unwrap().unwrap().newest;
        if commit {
            assert_eq!(newest, new, "the cancel found the successor");
            assert!(alloc::end_unstarted(pool, &newest, &at(11)).await.unwrap());
        } else {
            assert_eq!(newest, old.id);
            assert_eq!(
                mv(&w, &old.id, "rate_limited", &at(12), true).await,
                Moved::Skipped
            );
        }
        assert_eq!(live_count(&w).await, 0, "commit {commit}");
        assert_eq!(
            w.count(
                "SELECT count(*) FROM core_budget_holds WHERE ? IS NOT NULL",
                "x"
            )
            .await,
            0
        );
        assert_eq!(
            w.count(
                "SELECT count(*) FROM core_agent_sessions WHERE failover_of = ?",
                &old.id
            )
            .await,
            i64::from(commit)
        );
    }
}

#[tokio::test]
async fn neg_a_run_walks_exactly_the_hop_cap_and_ends_with_no_hold() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let mut ids = Vec::new();
    for i in 0..=fo::MAX_HOPS + 1 {
        ids.push(w.acct(&format!("a{i}")).await.id);
    }
    let chain = [w.keys("main", &ids).await];
    budget(&w, chain[0].pool).await;
    let (first, _) = over(&w, &chain, limited(), 0).await;
    let mut cur = first.id;
    for hop in 1..=fo::MAX_HOPS {
        let t = hop * 10;
        let (new, _) = to(mv(&w, &cur, "rate_limited", &at(t), true).await);
        alloc::mark_start_sent(pool, &new).await.unwrap();
        store::set_state(pool, &new, "running", "t", false, &at(t))
            .await
            .unwrap();
        store::end(pool, &new, "ended", &limited(), &at(t + 1))
            .await
            .unwrap();
        cur = new;
    }
    let capped = mv(&w, &cur, "rate_limited", &at(500), true).await;
    assert!(
        matches!(&capped, Moved::Ended { why, .. } if why.starts_with("hop cap")),
        "{capped:?}"
    );
    let attempts = w
        .count(
            "SELECT count(*) FROM core_agent_sessions WHERE ? IS NOT NULL",
            "x",
        )
        .await;
    assert_eq!(attempts, fo::MAX_HOPS + 1);
    let accounts = w
        .count(
            "SELECT count(DISTINCT account_id) FROM core_agent_sessions WHERE ? IS NOT NULL",
            "x",
        )
        .await;
    assert_eq!(accounts, fo::MAX_HOPS + 1, "no account twice");
    assert_eq!(
        w.count(
            "SELECT count(*) FROM core_budget_holds WHERE ? IS NOT NULL",
            "x"
        )
        .await,
        0
    );
}

/// The design (§10) says the failover budget is per user. The code counts a user's moves per runner,
/// so a user with two runners gets the bucket twice.
#[tokio::test]
#[ignore = "BUG: the storm guard counts per (user, runner); design §10 says per user"]
async fn neg_one_users_storm_is_counted_across_all_their_runners() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let ids: Vec<i64> = [w.acct("a").await, w.acct("b").await]
        .iter()
        .map(|a| a.id)
        .collect();
    let chain = [w.keys("main", &ids).await];
    let r2 = super::secrets::runner(&w.fx, "second-runner").await.id;
    for i in 0..fo::PER_WINDOW {
        let s = w.session(&chain, &[]).await;
        sqlx::query("UPDATE core_agent_sessions SET failover_of = 'as_fake' || n, created_at = ?, runner = ? WHERE id = ?")
            .bind(at(100))
            .bind(if i % 2 == 0 { &w.vm.id } else { &r2 })
            .bind(&s.id)
            .execute(pool)
            .await
            .unwrap();
    }
    let (next, _) = over(&w, &chain, limited(), 200).await;
    let storm = mv(&w, &next.id, "rate_limited", &at(300), true).await;
    assert!(
        matches!(&storm, Moved::Ended { why, .. } if why == "failover storm guard"),
        "{storm:?}"
    );
}

#[tokio::test]
async fn neg_a_woken_attempt_that_was_budget_stopped_moves_for_its_new_end_and_not_the_old_stop() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    let s = w.session(&chain, &[]).await;
    let got = took(w.pick(&s.id, &chain, &at(0)).await);
    alloc::mark_start_sent(pool, &s.id).await.unwrap();
    sqlx::query("UPDATE core_agent_sessions SET harness_session = 'h', gw_stop = 'budget', gw_stop_budget = 'account:1' WHERE id = ?")
        .bind(&s.id)
        .execute(pool)
        .await
        .unwrap();
    store::set_state(pool, &s.id, "running", "t", false, &at(1))
        .await
        .unwrap();
    store::end(pool, &s.id, "ended", &json!({"kind": "succeeded"}), &at(2))
        .await
        .unwrap();
    assert_eq!(
        store::wake(pool, &s.id, Some("more"), &at(3))
            .await
            .unwrap(),
        store::Woken::Reopened
    );
    // The relaunch's grant reserves again: that clears the old stop.
    let mut tx = begin_write(pool).await.unwrap();
    gw::reserve_in(&mut tx, &s.id, got.account, 0, &at(4))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    store::set_state(pool, &s.id, "running", "resumed", true, &at(5))
        .await
        .unwrap();
    store::end(pool, &s.id, "ended", &limited(), &at(6))
        .await
        .unwrap();
    let v = fo::view(pool, &s.id).await.unwrap().unwrap();
    assert_eq!(
        fo::decide(&v),
        Decision::Move("rate_limited".into()),
        "{v:?}"
    );
}

#[tokio::test]
async fn neg_a_foreign_or_deleted_pool_in_a_snapshot_gives_nobody_an_account() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(pool)
        .await
        .unwrap();
    let (mine, theirs) = (w.acct("mine").await, w.acct("theirs").await);
    let gone = w.acct("gone").await;
    sqlx::query("UPDATE core_accounts SET user_id = 2 WHERE id = ?")
        .bind(theirs.id)
        .execute(pool)
        .await
        .unwrap();
    let own = w.keys("own", &[mine.id]).await;
    let foreign = w.keys("foreign", &[theirs.id]).await;
    let vanished = w.keys("vanished", &[gone.id]).await;
    // A first user's snapshot that names only a pool with the second user's account.
    let s = w.session(std::slice::from_ref(&foreign), &[]).await;
    assert!(matches!(
        w.pick(&s.id, std::slice::from_ref(&foreign), &at(0)).await,
        Outcome::Exhausted(_)
    ));
    // A run on its own pool, then the foreign pool, then a pool deleted since: the move ends, and leaves nothing.
    let chain = [own, foreign, vanished.clone()];
    pl::delete(pool, vanished.pool, &w.fx.dev.id, BY)
        .await
        .unwrap();
    let (old, first) = over(&w, &chain, limited(), 10).await;
    assert_eq!(first, mine.id);
    let r = mv(&w, &old.id, "rate_limited", &at(20), true).await;
    assert!(
        matches!(&r, Moved::Ended { why, .. } if why == "no account is available"),
        "{r:?}"
    );
    assert_eq!(
        w.count(
            "SELECT count(*) FROM core_agent_sessions WHERE failover_of = ?",
            &old.id
        )
        .await,
        0
    );
    assert_eq!(w.count(HOLDS, &old.id).await, 0);
}

#[tokio::test]
async fn neg_a_soft_budget_never_skips_a_pool_and_a_hard_one_does() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a1, a2) = (w.acct("hard").await, w.acct("soft").await);
    let (hard, soft) = (
        w.keys("hard", &[a1.id]).await,
        w.keys("soft", &[a2.id]).await,
    );
    for (e, hard_stop) in [(&hard, true), (&soft, false)] {
        let subject = e.pool.to_string();
        let b = NewBudget {
            kind: "pool",
            subject: &subject,
            company: None,
            period: "day",
            token_cap: 1,
            usd_cap_micros: None,
            warn_at_percent: None,
            hard_stop,
        };
        budgets::set(pool, &b, &w.fx.dev.id, BY, NOW).await.unwrap();
    }
    for chain in [vec![hard.clone(), soft.clone()], vec![soft.clone()]] {
        let s = w.session(&chain, &[]).await;
        assert_eq!(took(w.pick(&s.id, &chain, &at(0)).await).account, a2.id);
        w.end(&s.id, &at(1)).await;
    }
    let only = [hard];
    let s = w.session(&only, &[]).await;
    assert!(matches!(
        w.pick(&s.id, &only, &at(2)).await,
        Outcome::Exhausted(_)
    ));
}

#[tokio::test]
async fn neg_a_pinned_session_never_moves_and_a_chain_a_successor_walks_is_not_deleted() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let entry = w.keys("main", &[a1.id, a2.id]).await;
    // A pinned session (no chain): its end moves nothing.
    let pinned = w.session(&[], &[]).await;
    sqlx::query("UPDATE core_agent_sessions SET chain = NULL, account_id = ?, state = 'running' WHERE id = ?")
        .bind(a1.id)
        .bind(&pinned.id)
        .execute(pool)
        .await
        .unwrap();
    store::end(pool, &pinned.id, "ended", &limited(), &at(1))
        .await
        .unwrap();
    assert_eq!(
        mv(&w, &pinned.id, "rate_limited", &at(2), true).await,
        Moved::Skipped
    );
    // A chain the first attempt walked: once it moved, the successor keeps the chain alive.
    let spec = EntrySpec {
        pool: entry.pool,
        model: None,
        harness: None,
    };
    let c = ch::create(pool, 1, "walked", &[spec], &w.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let chain = [entry];
    let (old, _) = over(&w, &chain, limited(), 10).await;
    sqlx::query("UPDATE core_agent_sessions SET chain_id = ? WHERE id = ?")
        .bind(c.id)
        .bind(&old.id)
        .execute(pool)
        .await
        .unwrap();
    let (new, _) = to(mv(&w, &old.id, "rate_limited", &at(20), true).await);
    let refused = ch::delete(pool, c.id, &w.fx.dev.id, BY).await;
    assert!(
        matches!(
            refused,
            Err(crate::store::secrets::Error::Refused {
                code: "conflict",
                ..
            })
        ),
        "{refused:?}"
    );
    assert!(alloc::end_unstarted(pool, &new, &at(30)).await.unwrap());
    ch::delete(pool, c.id, &w.fx.dev.id, BY).await.unwrap();
}
