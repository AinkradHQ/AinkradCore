//! Failover execution, the rest (KAN-438 S6): the hop cap and the storm guard, a person's cancel
//! racing a move, the wake redirect, usage staying on its own attempt, a budget stop's skip, the
//! accounts a successor may never get, the move across account types, and the plan snapshot.

use ainkrad_proto::v2::{PlanLimit, PlanWindow, UpstreamStatus};
use serde_json::json;

use super::allocator::{W, took, w};
use super::failover::{budget, limited, mv, over, row, to};
use super::health::at;
use super::*;
use crate::store::agents::{self as store, SessionSecret, Woken};
use crate::store::alloc::{self, Outcome};
use crate::store::failover::{self as fo, Moved};
use crate::store::{accounts as acc, begin_write, health};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

async fn successors(w: &W, of: &str) -> i64 {
    w.count(
        "SELECT count(*) FROM core_agent_sessions WHERE failover_of = ?",
        of,
    )
    .await
}

#[tokio::test]
async fn the_hop_cap_and_the_storm_guard_end_a_run_and_the_storm_window_passes() {
    let w = w().await;
    let ids: Vec<i64> = [w.acct("a").await, w.acct("b").await, w.acct("c").await]
        .iter()
        .map(|a| a.id)
        .collect();
    let chain = [w.keys("main", &ids).await];
    // Hop cap: an attempt that is already the run's fifth (attempt 4) makes no sixth.
    let (old, _) = over(&w, &chain, limited(), 0).await;
    sqlx::query("UPDATE core_agent_sessions SET attempt = ? WHERE id = ?")
        .bind(fo::MAX_HOPS)
        .bind(&old.id)
        .execute(&w.fx.app.pool)
        .await
        .unwrap();
    let capped = mv(&w, &old.id, "rate_limited", &at(2), true).await;
    assert!(
        matches!(&capped, Moved::Ended { why, .. } if why.starts_with("hop cap")),
        "{capped:?}"
    );
    assert_eq!(successors(&w, &old.id).await, 0);
    // Storm: PER_WINDOW failovers started in the last ten minutes, so the next run ends.
    for _ in 0..fo::PER_WINDOW {
        let s = w.session(&chain, &[]).await;
        sqlx::query("UPDATE core_agent_sessions SET failover_of = 'as_fake' || n, created_at = ? WHERE id = ?")
            .bind(at(100)).bind(&s.id).execute(&w.fx.app.pool).await.unwrap();
    }
    let (next, _) = over(&w, &chain, limited(), 200).await;
    let storm = mv(&w, &next.id, "rate_limited", &at(300), true).await;
    assert!(
        matches!(&storm, Moved::Ended { why, .. } if why == "failover storm guard"),
        "{storm:?}"
    );
    assert_eq!(successors(&w, &next.id).await, 0);
    // The bucket is a window, not a total: ten minutes after the last of them a run may move again.
    let (later, _) = over(&w, &chain, limited(), 800).await;
    to(mv(
        &w,
        &later.id,
        "rate_limited",
        &at(100 + fo::WINDOW_SECS + 1),
        true,
    )
    .await);
}

#[tokio::test]
async fn a_persons_cancel_racing_a_move_leaves_no_live_successor_and_no_hold() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    budget(&w, chain[0].pool).await;
    let live = "SELECT count(*) FROM core_agent_sessions WHERE state NOT IN ('ended', 'lost') AND ? IS NOT NULL";
    let held = "SELECT count(*) FROM core_budget_holds WHERE ? IS NOT NULL";
    // The move first: the cancel (of the old attempt the person knows) finds the successor, and
    // ends it in the Core, which has nothing to ask a runner for.
    let (old, _) = over(&w, &chain, limited(), 0).await;
    let (new, _) = to(mv(&w, &old.id, "rate_limited", &at(5), true).await);
    assert_eq!(fo::cancel_run(pool, &old.id).await.unwrap().newest, new);
    assert!(alloc::end_unstarted(pool, &new, &at(6)).await.unwrap());
    assert_eq!((w.count(live, "x").await, w.count(held, "x").await), (0, 0));
    // The cancel first: it settles every attempt, so the move that follows starts nothing.
    let (old, _) = over(&w, &chain, limited(), 20).await;
    assert_eq!(fo::cancel_run(pool, &old.id).await.unwrap().newest, old.id);
    assert_eq!(
        mv(&w, &old.id, "rate_limited", &at(30), true).await,
        Moved::Skipped
    );
    assert_eq!(
        (
            successors(&w, &old.id).await,
            w.count(live, "x").await,
            w.count(held, "x").await
        ),
        (0, 0, 0)
    );
    // A cancel while the attempt still runs (the stop for a move is on its way): the decision is
    // settled, so when the attempt ends nothing moves and the class written first does not matter.
    let s = w.session(&chain, &[]).await;
    took(w.pick(&s.id, &chain, &at(40)).await);
    alloc::mark_start_sent(pool, &s.id).await.unwrap();
    store::set_state(pool, &s.id, "running", "t", false, &at(41))
        .await
        .unwrap();
    assert!(fo::set_class(pool, &s.id, "quota").await.unwrap());
    fo::cancel_run(pool, &s.id).await.unwrap();
    store::end(
        pool,
        &s.id,
        "ended",
        &json!({"kind": "cancelled", "reason": "x"}),
        &at(42),
    )
    .await
    .unwrap();
    assert_eq!(mv(&w, &s.id, "quota", &at(43), true).await, Moved::Skipped);
    // A started successor is a live session: the cancel's `end_unstarted` refuses it and the stop goes to its runner.
    let (old, _) = over(&w, &chain, limited(), 60).await;
    let (new, _) = to(mv(&w, &old.id, "rate_limited", &at(65), true).await);
    alloc::mark_start_sent(pool, &new).await.unwrap();
    assert!(!alloc::end_unstarted(pool, &new, &at(66)).await.unwrap());
}

#[tokio::test]
async fn a_wake_never_reopens_an_attempt_a_failover_replaced_and_finds_the_newest() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    let (old, _) = over(&w, &chain, limited(), 0).await;
    let (new, _) = to(mv(&w, &old.id, "rate_limited", &at(5), true).await);
    sqlx::query("UPDATE core_agent_sessions SET outcome = ?, harness_session = 'h' WHERE id = ?")
        .bind(json!({"kind": "succeeded"}).to_string())
        .bind(&old.id)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(
        store::wake(pool, &old.id, None, &at(6)).await.unwrap(),
        Woken::Gone
    );
    assert_eq!(row(&w, &old.id).await.1, "ended");
    assert_eq!(fo::newest(pool, &old.id).await.unwrap(), new);
    assert_eq!(fo::newest(pool, &new).await.unwrap(), new);
    // Two hops: the first attempt's id still leads to the last.
    alloc::mark_start_sent(pool, &new).await.unwrap();
    store::end(pool, &new, "ended", &limited(), &at(7))
        .await
        .unwrap();
    let c = w.acct("c").await;
    crate::store::pools::add_member(pool, chain[0].pool, c.id, &w.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let (third, _) = to(mv(&w, &new, "rate_limited", &at(8), true).await);
    assert_eq!(fo::newest(pool, &old.id).await.unwrap(), third);
}

#[tokio::test]
async fn usage_stays_on_the_attempt_that_spent_it_and_is_never_counted_twice() {
    use super::gateway_store::usage;
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    let (old, _) = over(&w, &chain, limited(), 0).await;
    let (new, _) = to(mv(&w, &old.id, "rate_limited", &at(5), true).await);
    // The old attempt's late report (the final read) is absorbed on the old row, on its own account.
    let mut tx = begin_write(pool).await.unwrap();
    crate::store::gateway::absorb(&mut tx, &old.id, &[usage(1, 100, 10)], &at(6))
        .await
        .unwrap();
    crate::store::gateway::absorb(&mut tx, &new, &[usage(1, 50, 5)], &at(7))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT session, account_id, input_tokens FROM core_cost_events ORDER BY input_tokens DESC",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        rows,
        [(old.id.clone(), a1.id, 100), (new.clone(), a2.id, 50)]
    );
    let per = |a: i64| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT coalesce(sum(input_tokens), 0) FROM core_cost_events WHERE account_id = ?",
        )
        .bind(a)
        .fetch_one(pool)
        .await
        .unwrap()
    };
    assert_eq!((per(a1.id).await, per(a2.id).await), (100, 50));
    // A resend of the same report is the same key: no second row.
    let mut tx = begin_write(pool).await.unwrap();
    crate::store::gateway::absorb(&mut tx, &old.id, &[usage(1, 100, 10)], &at(8))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(per(a1.id).await, 100);
}

#[tokio::test]
async fn a_budget_stop_skips_the_pool_it_shares_and_an_account_budget_only_the_account() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a1, a2, b1) = (w.acct("a1").await, w.acct("a2").await, w.acct("b1").await);
    let chain = [
        w.keys("one", &[a1.id, a2.id]).await,
        w.keys("two", &[b1.id]).await,
    ];
    // The pool's budget ran out: the second account of the same pool shares it, so the run skips the entry.
    let (old, _) = over(
        &w,
        &chain,
        json!({"kind": "cancelled", "reason": "stop"}),
        0,
    )
    .await;
    let stop = format!("budget exhausted: pool {} (day, 2026-11-06)", chain[0].pool);
    let code = format!("pool:{}", chain[0].pool);
    sqlx::query("UPDATE core_agent_sessions SET gw_stop = ?, gw_stop_budget = ? WHERE id = ?")
        .bind(&stop)
        .bind(&code)
        .bind(&old.id)
        .execute(pool)
        .await
        .unwrap();
    let (new, picked) = to(mv(&w, &old.id, "budget_pool", &at(5), true).await);
    assert_eq!(picked.unwrap().account, b1.id);
    let skip: String =
        sqlx::query_scalar("SELECT skip_pools FROM core_agent_sessions WHERE id = ?")
            .bind(&new)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(skip, format!("[{}]", chain[0].pool));
    // An account's own budget: only that account is out, the pool stays in the chain.
    let (old, was) = over(
        &w,
        &chain,
        json!({"kind": "cancelled", "reason": "stop"}),
        10,
    )
    .await;
    let stop = format!("budget exhausted: account {was} (day, 2026-11-06)");
    sqlx::query("UPDATE core_agent_sessions SET gw_stop = ?, gw_stop_budget = ? WHERE id = ?")
        .bind(stop)
        .bind(format!("account:{was}"))
        .bind(&old.id)
        .execute(pool)
        .await
        .unwrap();
    let (new, picked) = to(mv(&w, &old.id, "budget_pool", &at(15), true).await);
    assert_ne!(picked.unwrap().account, was);
    let skip: String =
        sqlx::query_scalar("SELECT skip_pools FROM core_agent_sessions WHERE id = ?")
            .bind(&new)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(skip, "[]");
}

#[tokio::test]
async fn a_successor_never_gets_a_disabled_cooling_limited_or_another_users_account() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(pool)
        .await
        .unwrap();
    let a = w.acct("a").await;
    let (off, cold, lim, theirs, good) = (
        w.acct("off").await,
        w.acct("cold").await,
        w.acct("lim").await,
        w.acct("theirs").await,
        w.acct("good").await,
    );
    let by = &w.fx.dev.id;
    acc::set_state(pool, off.id, "disabled", Some("test"), None, by, BY, &at(0))
        .await
        .unwrap();
    acc::set_state(
        pool,
        lim.id,
        "limited",
        Some("manual"),
        None,
        by,
        BY,
        &at(0),
    )
    .await
    .unwrap();
    w.signal(cold.id, UpstreamStatus::RateLimited, Some(600), &at(0))
        .await;
    sqlx::query("UPDATE core_accounts SET user_id = 2 WHERE id = ?")
        .bind(theirs.id)
        .execute(pool)
        .await
        .unwrap();
    let chain = [
        w.keys("one", &[a.id]).await,
        w.keys("two", &[off.id, cold.id, lim.id, theirs.id, good.id])
            .await,
    ];
    let (old, _) = over(&w, &chain, limited(), 1).await;
    let (_, picked) = to(mv(&w, &old.id, "rate_limited", &at(5), true).await);
    assert_eq!(picked.unwrap().account, good.id);
    // Without the good one the run waits for the cooling account (within the bound), never takes the others.
    sqlx::query("DELETE FROM core_pool_members WHERE account_id = ?")
        .bind(good.id)
        .execute(pool)
        .await
        .unwrap();
    let (old, _) = over(&w, &chain, limited(), 10).await;
    let (_, picked) = to(mv(&w, &old.id, "rate_limited", &at(15), true).await);
    assert!(
        picked.is_none(),
        "only the cooling account is left: the successor waits"
    );
}

fn rejected(windows: Vec<PlanWindow>) -> PlanLimit {
    PlanLimit {
        status: "rejected".to_owned(),
        windows,
    }
}

#[test]
fn a_plan_snapshot_only_ever_delays_a_pick_and_never_for_long() {
    let snap = |p: &PlanLimit, at: i64| json!({"at": at, "plan": p}).to_string();
    let win = |u: f64, r: Option<i64>| PlanWindow {
        name: "five_hour".to_owned(),
        utilization: u,
        resets_at: r,
    };
    // Rejected with no reset: a fixed hold from the snapshot's time; after it, nothing.
    let p = rejected(vec![]);
    assert_eq!(
        health::plan_cooling_until(&snap(&p, 1000), 1100),
        Some(1000 + health::REJECTED_SECS)
    );
    assert_eq!(
        health::plan_cooling_until(&snap(&p, 1000), 1000 + health::REJECTED_SECS),
        None
    );
    // Rejected with a reset: until it. A forged far-future reset is clamped.
    let p = rejected(vec![win(1.0, Some(5000))]);
    assert_eq!(
        health::plan_cooling_until(&snap(&p, 1000), 1100),
        Some(5000)
    );
    let p = rejected(vec![win(1.0, Some(1_000_000_000))]);
    assert_eq!(
        health::plan_cooling_until(&snap(&p, 1000), 1100),
        Some(1000 + health::HARNESS_MAX_SECS)
    );
    // The cap is anchored on the snapshot, so it runs out however many picks read it (the forged
    // reset can never hold an account for ever): at 1000 + 6 h it is over, and stays over.
    for now in [1100, 5000, 1000 + health::HARNESS_MAX_SECS - 1] {
        assert!(
            health::plan_cooling_until(&snap(&p, 1000), now).is_some(),
            "{now}"
        );
    }
    for now in [
        1000 + health::HARNESS_MAX_SECS,
        1000 + 2 * health::HARNESS_MAX_SECS,
        100_000_000,
    ] {
        assert_eq!(
            health::plan_cooling_until(&snap(&p, 1000), now),
            None,
            "{now}"
        );
    }
    // A window near its limit counts, one with room does not, and an allowed plan clears it.
    let warn = PlanLimit {
        status: "allowed_warning".to_owned(),
        windows: vec![win(0.96, Some(5000))],
    };
    assert_eq!(
        health::plan_cooling_until(&snap(&warn, 1000), 1100),
        Some(5000)
    );
    let calm = PlanLimit {
        status: "allowed".to_owned(),
        windows: vec![win(0.2, Some(5000))],
    };
    assert_eq!(health::plan_cooling_until(&snap(&calm, 1000), 1100), None);
    assert_eq!(health::plan_cooling_until("not json", 1100), None);
}

#[tokio::test]
async fn a_rejected_plan_with_no_reset_keeps_the_subscription_out_of_picks_until_it_has_cooled() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let sub = w.sub("plan").await;
    let named = SessionSecret {
        name: sub.secret_name.clone(),
        var: "CLAUDE_CODE_OAUTH_TOKEN".to_owned(),
    };
    let s = w.session(&[], std::slice::from_ref(&named)).await;
    let mut tx = begin_write(pool).await.unwrap();
    health::on_plan_limit(&mut tx, &s.id, Some(&rejected(vec![])), &at(0))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let snap: Option<String> =
        sqlx::query_scalar("SELECT plan_limit FROM core_accounts WHERE id = ?")
            .bind(sub.id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(snap.is_some_and(|s| s.contains("rejected")));
    let chain = [w.pool("plan", "claude-sub", &[sub.id]).await];
    // The 60 s cooldown the session's own signal wrote is over at 120 s, and the snapshot still says no.
    let next = w.session(&chain, &[]).await;
    assert!(matches!(
        w.pick(&next.id, &chain, &at(120)).await,
        Outcome::Wait { .. }
    ));
    assert!(matches!(
        w.pick(&next.id, &chain, &at(health::REJECTED_SECS + 5))
            .await,
        Outcome::Picked(_)
    ));
    // The snapshot never disables: the account is active throughout.
    assert_eq!(acc::get(pool, sub.id).await.unwrap().state, "active");
}
