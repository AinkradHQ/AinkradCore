//! Failover execution (KAN-438 part B, S6; design §8, §9, §10, §16): the decision table row by
//! row, a move's rows and holds, exactly-once across supervisors and a restart, the cap under
//! concurrent moves (I4), a bounded wait, the hop cap and the storm guard, the cancel race, the wake
//! redirect, usage staying on its own attempt, and the plan snapshot. The seeded walk is in
//! `failover_props`.

use serde_json::{Value, json};
use sqlx::SqlitePool;

use super::allocator::{P, W, p, took, w};
use super::health::at;
use super::*;
use crate::store::agents as store;
use crate::store::alloc::{self, Entry, Outcome};
use crate::store::budgets::{self, NewBudget};
use crate::store::failover::{self as fo, Ctx, Moved};
use crate::store::{accounts as acc, begin_write};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;
pub(super) const HOLDS: &str = "SELECT count(*) FROM core_budget_holds WHERE session = ?";

/// `move_in` in its own write transaction (rolled back unless `commit`).
pub(super) async fn mv_owned(
    pool: SqlitePool,
    old: String,
    class: &str,
    now: String,
    commit: bool,
) -> Moved {
    let min = |_: &Entry| 0u64;
    let serves = |_: &Entry| -> Option<String> { None };
    let cx = Ctx {
        now: &now,
        min_turn: &min,
        serves: &serves,
        wait_max_secs: alloc::WAIT_MAX_SECS,
    };
    let mut tx = begin_write(&pool).await.unwrap();
    let moved = fo::move_in(&mut tx, &old, class, &cx).await.unwrap();
    if commit {
        tx.commit().await.unwrap();
    }
    moved
}

pub(super) async fn mv(w: &W, old: &str, class: &str, now: &str, commit: bool) -> Moved {
    mv_owned(
        w.fx.app.pool.clone(),
        old.to_owned(),
        class,
        now.to_owned(),
        commit,
    )
    .await
}

pub(super) fn to(m: Moved) -> (String, Option<alloc::Picked>) {
    match m {
        Moved::To { session, picked } => (session, picked),
        other => panic!("no successor: {other:?}"),
    }
}

/// A picked, started attempt of `chain` that ended with `outcome` at `t` seconds. Returns it and its account.
pub(super) async fn over(w: &W, chain: &[Entry], outcome: Value, t: i64) -> (store::Session, i64) {
    let pool = &w.fx.app.pool;
    let s = w.session(chain, &[]).await;
    let got = took(w.pick(&s.id, chain, &at(t)).await);
    alloc::mark_start_sent(pool, &s.id).await.unwrap();
    store::set_state(pool, &s.id, "running", "test", false, &at(t))
        .await
        .unwrap();
    store::end(pool, &s.id, "ended", &outcome, &at(t + 1))
        .await
        .unwrap();
    (s, got.account)
}

pub(super) fn limited() -> Value {
    json!({"kind": "failed", "reason": "429", "fingerprint": "rate_limited"})
}

pub(super) async fn row(w: &W, id: &str) -> (Option<i64>, String, i64, Option<String>) {
    sqlx::query_as(
        "SELECT account_id, state, failover_done, failover_of FROM core_agent_sessions WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&w.fx.app.pool)
    .await
    .unwrap()
}

pub(super) async fn budget(w: &W, pool: i64) {
    let subject = pool.to_string();
    let b = NewBudget {
        kind: "pool",
        subject: &subject,
        company: None,
        period: "day",
        token_cap: 100_000_000,
        usd_cap_micros: None,
        warn_at_percent: None,
        hard_stop: true,
    };
    budgets::set(&w.fx.app.pool, &b, &w.fx.dev.id, BY, NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_move_starts_a_successor_with_its_own_account_and_leaves_the_old_row_alone() {
    let w = w().await;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    let (old, first) = over(&w, &chain, limited(), 0).await;
    assert_eq!(first, a1.id);
    let (new, picked) = to(mv(&w, &old.id, "rate_limited", &at(5), true).await);
    assert_eq!(
        picked.unwrap().account,
        a2.id,
        "the run's old account is left out"
    );
    // The old attempt is untouched but settled: one session, one account (I1).
    assert_eq!(
        row(&w, &old.id).await,
        (Some(a1.id), "ended".into(), 1, None)
    );
    let (account, state, _, of) = row(&w, &new).await;
    assert_eq!(
        (account, state.as_str(), of.as_deref()),
        (Some(a2.id), "starting", Some(old.id.as_str()))
    );
    let s = store::get(&w.fx.app.pool, &new).await.unwrap().unwrap();
    assert_eq!(s.gateway_account_id, Some(a2.id));
    assert_eq!(s.secrets.len(), 1, "never two accounts: {:?}", s.secrets);
    assert_eq!(
        crate::store::gateway::account_secret(&s.secrets[0].name),
        Some(("anthropic", a2.id))
    );
    let (run, attempt): (String, i64) =
        sqlx::query_as("SELECT run_id, attempt FROM core_agent_sessions WHERE id = ?")
            .bind(&new)
            .fetch_one(&w.fx.app.pool)
            .await
            .unwrap();
    assert_eq!((run, attempt), (old.id.clone(), 1));
    // Audited, with ids and the class and no value anywhere.
    let details: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'agent.created' AND details LIKE '%from_session%'",
    )
    .fetch_all(&w.fx.app.pool)
    .await
    .unwrap();
    assert_eq!(details.len(), 1);
    assert!(
        details[0].contains("\"class\":\"rate_limited\"") && details[0].contains("\"hop\":1"),
        "{}",
        details[0]
    );
    assert!(
        !details[0].contains("throwaway-account-value"),
        "{}",
        details[0]
    );
    // The same chain, a third attempt: the run never returns to an account it left.
    alloc::mark_start_sent(&w.fx.app.pool, &new).await.unwrap();
    store::end(&w.fx.app.pool, &new, "ended", &limited(), &at(9))
        .await
        .unwrap();
    let again = mv(&w, &new, "rate_limited", &at(10), true).await;
    assert!(matches!(again, Moved::Ended { .. }), "{again:?}");
}

#[tokio::test]
async fn a_started_session_never_moves_and_never_changes_its_account() {
    let w = w().await;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    let s = w.session(&chain, &[]).await;
    took(w.pick(&s.id, &chain, &at(0)).await);
    alloc::mark_start_sent(&w.fx.app.pool, &s.id).await.unwrap();
    store::set_state(&w.fx.app.pool, &s.id, "running", "test", false, &at(1))
        .await
        .unwrap();
    // A live session is not over: nothing moves, nothing is inserted, and a retreat refuses.
    assert_eq!(mv(&w, &s.id, "quota", &at(2), true).await, Moved::Skipped);
    let mut tx = begin_write(&w.fx.app.pool).await.unwrap();
    assert_eq!(alloc::retreat_in(&mut tx, &s.id).await.unwrap(), None);
    drop(tx);
    let sessions = w
        .count(
            "SELECT count(*) FROM core_agent_sessions WHERE ? IS NOT NULL",
            "x",
        )
        .await;
    assert_eq!(sessions, 1);
    assert_eq!(row(&w, &s.id).await.0, Some(a1.id));
}

#[tokio::test]
async fn the_chain_runs_out_with_a_reason_per_entry_and_leaves_no_row_and_no_hold() {
    let w = w().await;
    let (a, b) = (w.acct("a").await, w.acct("b").await);
    let chain = [w.keys("one", &[a.id]).await, w.keys("two", &[b.id]).await];
    budget(&w, chain[0].pool).await;
    budget(&w, chain[1].pool).await;
    let (first, _) = over(&w, &chain, limited(), 0).await;
    let (second, on) = to(mv(&w, &first.id, "rate_limited", &at(3), true).await);
    assert_eq!(on.unwrap().account, b.id);
    alloc::mark_start_sent(&w.fx.app.pool, &second)
        .await
        .unwrap();
    store::end(&w.fx.app.pool, &second, "ended", &limited(), &at(6))
        .await
        .unwrap();
    let last = mv(&w, &second, "rate_limited", &at(7), true).await;
    let Moved::Ended { why, reasons } = last else {
        panic!("{last:?}")
    };
    assert_eq!(why, "no account is available");
    assert!(
        reasons
            .iter()
            .any(|(pos, r)| *pos == 1 && r.contains("already used by this run")),
        "{reasons:?}"
    );
    // The run ended on the last attempt: it says why, and nothing is live or held.
    let outcome: String =
        sqlx::query_scalar("SELECT outcome FROM core_agent_sessions WHERE id = ?")
            .bind(&second)
            .fetch_one(&w.fx.app.pool)
            .await
            .unwrap();
    assert!(
        outcome.contains("entry 2: 1 already used by this run"),
        "{outcome}"
    );
    let live = "SELECT count(*) FROM core_agent_sessions WHERE state NOT IN ('ended', 'lost') AND ? IS NOT NULL";
    assert_eq!(w.count(live, "x").await, 0);
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
            &second
        )
        .await,
        0
    );
    // Forward only: a failure on the second entry never looks back at the first.
    let c = w.acct("c").await;
    let back = [
        w.keys("front", &[c.id]).await,
        w.keys("rear", &[b.id]).await,
    ];
    let r = w.session(&back, &[]).await;
    took(w.pick_p(&r.id, &back, &at(20), P { from: 1, ..p() }).await);
    alloc::mark_start_sent(&w.fx.app.pool, &r.id).await.unwrap();
    store::end(&w.fx.app.pool, &r.id, "ended", &limited(), &at(21))
        .await
        .unwrap();
    let m = mv(&w, &r.id, "rate_limited", &at(22), true).await;
    assert!(
        matches!(m, Moved::Ended { .. }),
        "front entry must not be revisited: {m:?}"
    );
}

#[tokio::test]
async fn the_successors_hold_is_taken_in_the_move_and_a_rolled_back_move_leaves_nothing() {
    let w = w().await;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    budget(&w, chain[0].pool).await;
    let (old, _) = over(&w, &chain, limited(), 0).await;
    let all = "SELECT count(*) FROM core_budget_holds WHERE ? IS NOT NULL";
    assert_eq!(
        w.count(all, "x").await,
        0,
        "the old attempt's hold went back when it ended"
    );
    // Rolled back: no successor, no hold, the old attempt unsettled, no use of the account.
    to(mv(&w, &old.id, "rate_limited", &at(5), false).await);
    assert_eq!((w.count(all, "x").await, row(&w, &old.id).await.2), (0, 0));
    assert_eq!(
        w.count(
            "SELECT count(*) FROM core_agent_sessions WHERE failover_of = ?",
            &old.id
        )
        .await,
        0
    );
    let used = acc::get(&w.fx.app.pool, a2.id).await.unwrap().last_used_at;
    assert_eq!(used, None);
    // Committed: exactly one hold, keyed by the successor.
    let (new, _) = to(mv(&w, &old.id, "rate_limited", &at(6), true).await);
    assert_eq!(w.count(HOLDS, &new).await, 1);
    assert_eq!(w.count(all, "x").await, 1);
    // Again (a second supervisor, a retry): nothing new, still one hold and one successor.
    assert_eq!(
        mv(&w, &old.id, "rate_limited", &at(7), true).await,
        Moved::Skipped
    );
    assert_eq!(
        (
            w.count(all, "x").await,
            w.count(
                "SELECT count(*) FROM core_agent_sessions WHERE failover_of = ?",
                &old.id
            )
            .await
        ),
        (1, 1)
    );
}

#[tokio::test]
async fn two_supervisors_and_a_restart_make_exactly_one_successor() {
    let w = w().await;
    let ids: Vec<i64> = [w.acct("a1").await, w.acct("a2").await, w.acct("a3").await]
        .iter()
        .map(|a| a.id)
        .collect();
    let chain = vec![w.keys("main", &ids).await];
    budget(&w, chain[0].pool).await;
    let (old, _) = over(&w, &chain, limited(), 0).await;
    // The Core went down after the attempt ended and before its move: the scan finds it, once.
    assert_eq!(
        fo::unfinished(&w.fx.app.pool).await.unwrap(),
        std::slice::from_ref(&old.id)
    );
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (pool, id) = (w.fx.app.pool.clone(), old.id.clone());
        tasks.push(tokio::spawn(mv_owned(
            pool,
            id,
            "rate_limited",
            at(5),
            true,
        )));
    }
    let mut made = 0;
    for t in tasks {
        match t.await.unwrap() {
            Moved::To { .. } => made += 1,
            Moved::Skipped => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(made, 1);
    assert!(fo::unfinished(&w.fx.app.pool).await.unwrap().is_empty());
    let succ = "SELECT count(*) FROM core_agent_sessions WHERE failover_of = ?";
    assert_eq!(w.count(succ, &old.id).await, 1);
    let all = "SELECT count(*) FROM core_budget_holds WHERE ? IS NOT NULL";
    assert_eq!(w.count(all, "x").await, 1, "no double reserve");
    // The index is the backstop: a second successor row for the same attempt is refused.
    let dup = sqlx::query("INSERT INTO core_agent_sessions (id, runner, harness, policy, secrets, state, created_by, created_at, updated_at, failover_of) SELECT 'as_dup', runner, harness, policy, secrets, 'starting', created_by, created_at, updated_at, ? FROM core_agent_sessions WHERE id = ?")
        .bind(&old.id)
        .bind(&old.id)
        .execute(&w.fx.app.pool)
        .await;
    assert!(dup.is_err());
}

#[tokio::test]
async fn concurrent_moves_never_put_more_runs_on_an_account_than_its_cap_and_a_wait_is_bounded() {
    let w = w().await;
    let target = w.acct("target").await;
    acc::set_cap(&w.fx.app.pool, target.id, 2, &w.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let back = w.keys("back", &[target.id]).await;
    // Five runs, each failed on an account of its own front pool; all of them move to the same back pool.
    let mut runs = Vec::new();
    for i in 0..5 {
        let front = w.acct(&format!("front{i}")).await;
        let chain = vec![
            w.keys(&format!("front{i}"), &[front.id]).await,
            back.clone(),
        ];
        let (old, _) = over(&w, &chain, limited(), 0).await;
        runs.push((old.id, chain, front.id));
    }
    let mut tasks = Vec::new();
    for (id, _, _) in &runs {
        tasks.push(tokio::spawn(mv_owned(
            w.fx.app.pool.clone(),
            id.clone(),
            "rate_limited",
            at(10),
            true,
        )));
    }
    let (mut on, mut waiting) = (0, Vec::new());
    for t in tasks {
        match to(t.await.unwrap()) {
            (_, Some(p)) => {
                assert_eq!(p.account, target.id);
                on += 1;
            }
            (s, None) => waiting.push(s),
        }
    }
    assert_eq!((on, waiting.len()), (2, 3));
    let live =
        "SELECT count(*) FROM core_agent_sessions WHERE account_id = ? AND state = 'starting'";
    assert_eq!(
        w.count(live, &target.id.to_string()).await,
        2,
        "never over the cap (I4)"
    );
    // A waiting successor has its own row, so its wait is bounded from the first: `since` is the move's time.
    let wid = waiting[0].clone();
    let since: i64 = sqlx::query_scalar(
        "SELECT json_extract(waiting, '$.since') FROM core_agent_sessions WHERE id = ?",
    )
    .bind(&wid)
    .fetch_one(&w.fx.app.pool)
    .await
    .unwrap();
    assert_eq!(since, crate::scheduler::unix_secs(&at(10)).unwrap());
    let of: String = sqlx::query_scalar("SELECT failover_of FROM core_agent_sessions WHERE id = ?")
        .bind(&wid)
        .fetch_one(&w.fx.app.pool)
        .await
        .unwrap();
    let (_, chain, front) = runs.iter().find(|(o, _, _)| *o == of).unwrap().clone();
    let mut conn = w.fx.app.pool.acquire().await.unwrap();
    assert_eq!(
        fo::context_in(&mut conn, &wid).await.unwrap(),
        (vec![front], vec![])
    );
    drop(conn);
    let used = [front];
    let soon = P { used: &used, ..p() };
    assert!(matches!(
        w.pick_p(&wid, &chain, &at(60), soon).await,
        Outcome::Wait { .. }
    ));
    let later = P { used: &used, ..p() };
    let t = 10 + alloc::WAIT_MAX_SECS + 1;
    assert!(
        matches!(
            w.pick_p(&wid, &chain, &at(t), later).await,
            Outcome::Exhausted(_)
        ),
        "no run waits for ever"
    );
}
