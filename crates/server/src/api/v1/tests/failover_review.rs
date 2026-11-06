//! Failover execution, the review's findings (KAN-438 S6, #144): the plan snapshot cannot hold an
//! account for ever and an admin's "it's fine" clears it; a stale class never moves a woken run; the
//! storm guard counts one user's runs only; a restart moves only what ended recently; a budget stop is
//! a structured code (a denied top-up included); a person's cancel is undone when the stop never
//! reaches the runner.

use ainkrad_proto::v2::{PlanLimit, PlanWindow};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::allocator::{P, p, took, w};
use super::failover::{HOLDS, budget, limited, mv, over, row, to};
use super::failover_more::call;
use super::gateway_store::usage;
use super::health::at;
use super::*;
use crate::store::agents::{self as store, SessionSecret, Woken};
use crate::store::alloc::{self, Outcome};
use crate::store::budgets::{self, NewBudget};
use crate::store::failover::{self as fo, Moved};
use crate::store::{accounts as acc, begin_write, health};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

#[tokio::test]
async fn an_admins_its_fine_clears_the_plan_snapshot_and_a_forged_far_reset_runs_out() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let sub = w.sub("plan").await;
    let named = SessionSecret {
        name: sub.secret_name.clone(),
        var: "CLAUDE_CODE_OAUTH_TOKEN".to_owned(),
    };
    let s = w.session(&[], std::slice::from_ref(&named)).await;
    // A forged event: rejected, and a reset in the year 3000.
    let forged = PlanLimit {
        status: "rejected".to_owned(),
        windows: vec![PlanWindow {
            name: "five_hour".to_owned(),
            utilization: 1.0,
            resets_at: Some(32_503_680_000),
        }],
    };
    let mut tx = begin_write(pool).await.unwrap();
    health::on_plan_limit(&mut tx, &s.id, Some(&forged), &at(0))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let chain = [w.pool("plan", "claude-sub", &[sub.id]).await];
    // Picks later and later: never for ever. Six hours after the snapshot it is over.
    let late = health::HARNESS_MAX_SECS + 5;
    let waiting = w.session(&chain, &[]).await;
    assert!(matches!(
        w.pick(&waiting.id, &chain, &at(120)).await,
        Outcome::Exhausted(_)
    ));
    let next = w.session(&chain, &[]).await;
    assert!(matches!(
        w.pick(&next.id, &chain, &at(late)).await,
        Outcome::Picked(_)
    ));
    // The admin's "it's fine" clears the snapshot at once, and the stored column.
    let again = w.session(&chain, &[]).await;
    sqlx::query("UPDATE core_agent_sessions SET state = 'ended' WHERE id = ?")
        .bind(&next.id)
        .execute(pool)
        .await
        .unwrap();
    let mut tx = begin_write(pool).await.unwrap();
    health::on_plan_limit(&mut tx, &s.id, Some(&forged), &at(late + 10))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(
        w.pick(&again.id, &chain, &at(late + 20)).await,
        Outcome::Exhausted(_)
    ));
    acc::set_state(
        pool,
        sub.id,
        "active",
        None,
        None,
        &w.fx.dev.id,
        BY,
        &at(late + 30),
    )
    .await
    .unwrap();
    let kept: Option<String> =
        sqlx::query_scalar("SELECT plan_limit FROM core_accounts WHERE id = ?")
            .bind(sub.id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(kept, None);
    assert!(matches!(
        w.pick(&again.id, &chain, &at(late + 40)).await,
        Outcome::Picked(_)
    ));
}

#[tokio::test]
async fn a_woken_or_resumed_session_forgets_the_class_of_its_last_run() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let a = w.acct("a").await;
    let chain = [w.keys("main", &[a.id]).await];
    let (s, _) = over(&w, &chain, json!({"kind": "succeeded"}), 0).await;
    let db = pool.clone();
    let class = |id: String| {
        let db = db.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT upstream_class FROM core_agent_sessions WHERE id = ?",
            )
            .bind(id)
            .fetch_one(&db)
            .await
            .unwrap()
        }
    };
    sqlx::query("UPDATE core_agent_sessions SET upstream_class = 'quota', harness_session = 'h' WHERE id = ?")
        .bind(&s.id)
        .execute(pool)
        .await
        .unwrap();
    // Woken the next day: the quota of yesterday's run is not today's.
    assert_eq!(
        store::wake(pool, &s.id, None, &at(86_400)).await.unwrap(),
        Woken::Reopened
    );
    assert_eq!(class(s.id.clone()).await, None);
    // A resumed start (a new epoch) does the same.
    sqlx::query("UPDATE core_agent_sessions SET upstream_class = 'rate_limited' WHERE id = ?")
        .bind(&s.id)
        .execute(pool)
        .await
        .unwrap();
    store::set_state(pool, &s.id, "running", "resumed", true, &at(86_500))
        .await
        .unwrap();
    assert_eq!(class(s.id.clone()).await, None);
}

#[tokio::test]
async fn one_users_failover_storm_never_ends_another_users_run() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(pool)
        .await
        .unwrap();
    let other = super::secrets::runner(&w.fx, "second").await.id;
    sqlx::query("UPDATE core_devices SET user_id = 2 WHERE id = ?")
        .bind(&other)
        .execute(pool)
        .await
        .unwrap();
    let (a, c1, c2) = (w.acct("a").await, w.acct("c1").await, w.acct("c2").await);
    for id in [c1.id, c2.id] {
        sqlx::query("UPDATE core_accounts SET user_id = 2 WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }
    let mine = [w.keys("mine", &[a.id]).await];
    let theirs = [w.keys("theirs", &[c1.id, c2.id]).await];
    // The first user's runs have used the whole bucket.
    for _ in 0..fo::PER_WINDOW {
        let s = w.session(&mine, &[]).await;
        sqlx::query("UPDATE core_agent_sessions SET failover_of = 'as_fake' || n, created_at = ? WHERE id = ?")
            .bind(at(100)).bind(&s.id).execute(pool).await.unwrap();
    }
    let (old, _) = over(&w, &mine, limited(), 200).await;
    let m = mv(&w, &old.id, "rate_limited", &at(300), true).await;
    assert!(
        matches!(&m, Moved::Ended { why, .. } if why == "failover storm guard"),
        "{m:?}"
    );
    // The second user's run still moves.
    let s2 = w.session_by(&theirs, &[], &other).await;
    took(
        w.pick_p(&s2.id, &theirs, &at(200), P { user: 2, ..p() })
            .await,
    );
    alloc::mark_start_sent(pool, &s2.id).await.unwrap();
    store::end(pool, &s2.id, "ended", &limited(), &at(201))
        .await
        .unwrap();
    to(mv(&w, &s2.id, "rate_limited", &at(300), true).await);
}

#[tokio::test]
async fn a_restart_moves_only_what_ended_recently_and_never_a_core_end() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a, b) = (w.acct("a").await, w.acct("b").await);
    let chain = [w.keys("main", &[a.id, b.id]).await];
    let (old, _) = over(&w, &chain, limited(), 0).await;
    let ended = fo::view(pool, &old.id).await.unwrap().unwrap();
    assert!(!ended.done);
    // Listed an hour after it ended? Not any more; within the hour, yes.
    assert_eq!(
        fo::unfinished_since(pool, &at(-3600)).await.unwrap(),
        vec![old.id.clone()]
    );
    assert!(
        fo::unfinished_since(pool, &at(7200))
            .await
            .unwrap()
            .is_empty()
    );
    // A Core's own end is no move even if it is listed.
    let s = w.session(&chain, &[]).await;
    took(w.pick(&s.id, &chain, &at(10)).await);
    alloc::mark_start_sent(pool, &s.id).await.unwrap();
    let core = json!({"kind": "failed", "reason": "x", "fingerprint": "core"});
    store::end(pool, &s.id, "ended", &core, &at(11))
        .await
        .unwrap();
    sqlx::query("UPDATE core_agent_sessions SET upstream_class = 'rate_limited' WHERE id = ?")
        .bind(&s.id)
        .execute(pool)
        .await
        .unwrap();
    let v = fo::view(pool, &s.id).await.unwrap().unwrap();
    assert!(matches!(fo::decide(&v), fo::Decision::End(_)));
}

#[tokio::test]
async fn a_denied_top_up_names_its_budget_and_the_run_moves_skipping_that_pool() {
    use crate::store::gateway as gw;
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a1, b1) = (w.acct("a1").await, w.acct("b1").await);
    let chain = [w.keys("one", &[a1.id]).await, w.keys("two", &[b1.id]).await];
    let s = w.session(&chain, &[]).await;
    took(w.pick(&s.id, &chain, &at(0)).await);
    alloc::mark_start_sent(pool, &s.id).await.unwrap();
    store::set_state(pool, &s.id, "running", "t", false, &at(1))
        .await
        .unwrap();
    // No budget is short yet: a stop would be a ceiling or a session limit.
    let mut conn = pool.acquire().await.unwrap();
    assert_eq!(
        gw::short_budget(&mut conn, a1.id, &s.id, 0, &at(2))
            .await
            .unwrap(),
        None
    );
    drop(conn);
    // The pool's budget now leaves less than one turn needs.
    let subject = chain[0].pool.to_string();
    let b = NewBudget {
        kind: "pool",
        subject: &subject,
        company: None,
        period: "day",
        token_cap: 100_000,
        usd_cap_micros: None,
        warn_at_percent: None,
        hard_stop: true,
    };
    budgets::set(pool, &b, &w.fx.dev.id, BY, &at(3))
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    let short = gw::short_budget(&mut conn, a1.id, &s.id, 0, &at(4))
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        short.as_deref(),
        Some(format!("pool:{}", chain[0].pool).as_str())
    );
    gw::stop(
        pool,
        &s.id,
        "the gateway's ceiling is used up and the budgets leave too little: x",
        short.as_deref(),
    )
    .await
    .unwrap();
    store::end(
        pool,
        &s.id,
        "ended",
        &json!({"kind": "cancelled", "reason": "stop"}),
        &at(5),
    )
    .await
    .unwrap();
    let v = fo::view(pool, &s.id).await.unwrap().unwrap();
    assert_eq!(fo::decide(&v), fo::Decision::Move("budget_pool".into()));
    let (new, picked) = to(mv(&w, &s.id, "budget_pool", &at(6), true).await);
    assert_eq!(picked.unwrap().account, b1.id);
    let skip: String =
        sqlx::query_scalar("SELECT skip_pools FROM core_agent_sessions WHERE id = ?")
            .bind(&new)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(skip, format!("[{}]", chain[0].pool));
    // The report path writes the same code when a budget runs out under a session's usage.
    let (c1, c2) = (w.acct("c1").await, w.acct("c2").await);
    let two = [w.keys("three", &[c1.id, c2.id]).await];
    let t = w.session(&two, &[]).await;
    took(
        w.pick_p(
            &t.id,
            &two,
            &at(10),
            P {
                commit: true,
                ..p()
            },
        )
        .await,
    );
    budget_small(&w, two[0].pool).await;
    let mut tx = begin_write(pool).await.unwrap();
    gw::absorb(&mut tx, &t.id, &[usage(1, 600, 0)], &at(11))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let code: Option<String> =
        sqlx::query_scalar("SELECT gw_stop_budget FROM core_agent_sessions WHERE id = ?")
            .bind(&t.id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(code, Some(format!("pool:{}", two[0].pool)));
}

async fn budget_small(w: &super::allocator::W, pool: i64) {
    let subject = pool.to_string();
    let b = NewBudget {
        kind: "pool",
        subject: &subject,
        company: None,
        period: "day",
        token_cap: 500,
        usd_cap_micros: None,
        warn_at_percent: None,
        hard_stop: true,
    };
    budgets::set(&w.fx.app.pool, &b, &w.fx.dev.id, BY, NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_cancel_that_cannot_reach_the_runner_settles_nothing() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    budget(&w, chain[0].pool).await;
    let s = w.session(&chain, &[]).await;
    took(w.pick(&s.id, &chain, &at(0)).await);
    alloc::mark_start_sent(pool, &s.id).await.unwrap();
    store::set_state(pool, &s.id, "running", "t", false, &at(1))
        .await
        .unwrap();
    // The runner is not connected: the stop fails, and the run is as cancellable as it was.
    let uri = format!("/api/v1/agent-sessions/{}/cancel", s.id);
    let r = call(&w.fx, &w.fx.dev, Method::POST, &uri, Value::Null).await;
    assert_ne!(r.0, StatusCode::OK, "{:?}", r.1);
    assert_eq!(
        row(&w, &s.id).await.2,
        0,
        "nothing settled by a cancel that failed"
    );
    // So the attempt, when it ends for an account reason, still moves the run.
    store::end(pool, &s.id, "ended", &limited(), &at(5))
        .await
        .unwrap();
    to(mv(&w, &s.id, "rate_limited", &at(6), true).await);
}

#[tokio::test]
async fn a_move_across_account_types_carries_one_account_and_says_so() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (sub, key) = (w.sub("plan").await, w.acct("key").await);
    let mut plan = w.pool("plan", "claude-sub", &[sub.id]).await;
    plan.harness = "claude".to_owned();
    let chain = [plan, w.keys("keys", &[key.id]).await];
    let s = w.session(&chain, &[]).await;
    let got = took(w.pick(&s.id, &chain, &at(0)).await);
    assert!(!got.gateway);
    alloc::mark_start_sent(pool, &s.id).await.unwrap();
    store::end(
        pool,
        &s.id,
        "ended",
        &json!({"kind": "failed", "fingerprint": "auth"}),
        &at(1),
    )
    .await
    .unwrap();
    let (new, picked) = to(mv(&w, &s.id, "auth", &at(2), true).await);
    let picked = picked.unwrap();
    assert!(picked.gateway && picked.account == key.id);
    let n = store::get(pool, &new).await.unwrap().unwrap();
    assert_eq!(
        n.secrets.len(),
        1,
        "a subscription is never in a session with another account"
    );
    assert_eq!(n.gateway_account_id, Some(key.id));
    // The provider changed, so the successor's own state event says from and to.
    let note: String = sqlx::query_scalar(
        "SELECT payload FROM events WHERE kind = 'agent.state' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let note: serde_json::Value = serde_json::from_str(&note).unwrap();
    assert_eq!(
        (note["reason"].as_str(), note["session"].as_str()),
        (Some("failover"), Some(new.as_str()))
    );
    assert_eq!(note["from"]["provider"], "claude-sub");
    assert_eq!(note["to"]["provider"], "anthropic");
    // And the other way: an API key to a subscription is delivered as the token, never a gateway.
    let back = [
        w.keys("keys2", &[key.id]).await,
        w.pool("plan2", "claude-sub", &[sub.id]).await,
    ];
    let s = w.session(&back, &[]).await;
    took(w.pick(&s.id, &back, &at(10)).await);
    alloc::mark_start_sent(pool, &s.id).await.unwrap();
    store::end(pool, &s.id, "ended", &limited(), &at(11))
        .await
        .unwrap();
    let (new, picked) = to(mv(&w, &s.id, "rate_limited", &at(12), true).await);
    assert!(!picked.unwrap().gateway);
    let n = store::get(pool, &new).await.unwrap().unwrap();
    assert_eq!((n.gateway_account_id, n.secrets.len()), (None, 1));
    assert_eq!(row(&w, &new).await.0, Some(sub.id));
    assert_eq!(
        w.count(HOLDS, &new).await,
        0,
        "a subscription takes no dollar hold"
    );
}
