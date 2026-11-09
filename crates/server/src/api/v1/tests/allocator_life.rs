//! A chain session's life around the allocator (KAN-437 S4): a lost session that is woken may not
//! take a slot another pick has taken, a session naming its account is counted and never held
//! back, a pick on a session that has stopped takes nothing, a wait ends after `wait_max` in all,
//! and a session whose start was sent keeps its account for good.

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::json;

use super::allocator::{took, w};
use super::health::at;
use super::*;
use crate::store::agents::{self as store, SessionSecret, Woken};
use crate::store::alloc::{self, Outcome, WAIT_MAX_SECS};
use crate::store::budgets::{self, NewBudget};
use crate::store::{accounts as acc, begin_write};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

async fn lose(pool: &sqlx::SqlitePool, id: &str, now: &str) {
    let lost = json!({"kind": "lost", "reason": "the runner never came back"});
    store::end(pool, id, "lost", &lost, now).await.unwrap();
}

async fn live(pool: &sqlx::SqlitePool, account: i64) -> i64 {
    let mut conn = pool.acquire().await.unwrap();
    alloc::live_in(&mut conn, account, "none").await.unwrap()
}

#[tokio::test]
async fn a_wake_or_a_resume_never_takes_a_slot_another_pick_has_taken() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let x = w.acct("x").await;
    acc::set_cap(pool, x.id, 1, &w.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let chain = [w.keys("main", &[x.id]).await];
    let (a, b) = (w.session(&chain, &[]).await, w.session(&chain, &[]).await);
    took(w.pick(&a.id, &chain, &at(0)).await);
    lose(pool, &a.id, &at(1)).await;
    // A is lost and holds nothing: B takes the slot.
    assert_eq!(took(w.pick(&b.id, &chain, &at(2)).await).account, x.id);
    // Both doors back to life refuse while B holds it, and A stays lost.
    assert_eq!(
        store::wake(pool, &a.id, None, &at(3)).await.unwrap(),
        Woken::Busy
    );
    assert!(!store::reopen(pool, &a.id, &at(3)).await.unwrap());
    let state: String = sqlx::query_scalar("SELECT state FROM core_agent_sessions WHERE id = ?")
        .bind(&a.id)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!((state.as_str(), live(pool, x.id).await), ("lost", 1));
    // B ends: the slot is free, the wake goes through, and never two are live.
    w.end(&b.id, &at(4)).await;
    assert_eq!(
        store::wake(pool, &a.id, None, &at(5)).await.unwrap(),
        Woken::Reopened
    );
    assert_eq!(live(pool, x.id).await, 1);
}

#[tokio::test]
async fn a_session_naming_its_account_is_counted_from_its_wake_and_never_held_back_by_the_cap() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let x = w.acct("x").await;
    acc::set_cap(pool, x.id, 1, &w.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let named = SessionSecret {
        name: x.secret_name.clone(),
        var: "ANTHROPIC_API_KEY".to_owned(),
    };
    let mut ids = Vec::new();
    for _ in 0..3 {
        let s = w.session(&[], std::slice::from_ref(&named)).await;
        sqlx::query("UPDATE core_agent_sessions SET chain = NULL WHERE id = ?")
            .bind(&s.id)
            .execute(pool)
            .await
            .unwrap();
        ids.push(s.id);
    }
    // A session from before `account_id` has none on its row: the wake records it.
    sqlx::query("UPDATE core_agent_sessions SET account_id = NULL WHERE id = ?")
        .bind(&ids[2])
        .execute(pool)
        .await
        .unwrap();
    lose(pool, &ids[2], &at(1)).await;
    assert_eq!(
        store::wake(pool, &ids[2], None, &at(2)).await.unwrap(),
        Woken::Reopened
    );
    let held: Option<i64> =
        sqlx::query_scalar("SELECT account_id FROM core_agent_sessions WHERE id = ?")
            .bind(&ids[2])
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(held, Some(x.id), "the wake binds the account");
    assert_eq!(
        live(pool, x.id).await,
        3,
        "and it counts toward the cap from then on"
    );
}

#[tokio::test]
async fn the_migration_binds_every_old_session_to_its_account_ended_ones_too() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let x = w.acct("x").await;
    let named = SessionSecret {
        name: x.secret_name.clone(),
        var: "ANTHROPIC_API_KEY".to_owned(),
    };
    let s = w.session(&[], &[named]).await;
    w.end(&s.id, &at(1)).await;
    sqlx::query("UPDATE core_agent_sessions SET account_id = NULL")
        .execute(pool)
        .await
        .unwrap();
    let up = include_str!("../../../../migrations/0025_scheduler_allocator.up.sql");
    let backfill = &up[up
        .find("UPDATE core_agent_sessions SET account_id")
        .unwrap()..];
    sqlx::query(sqlx::AssertSqlSafe(backfill.to_owned()))
        .execute(pool)
        .await
        .unwrap();
    let held: Option<i64> =
        sqlx::query_scalar("SELECT account_id FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(held, Some(x.id));
}

#[tokio::test]
async fn a_pick_on_a_session_that_has_stopped_takes_no_hold_and_no_account() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let a = w.acct("a").await;
    let entry = w.keys("main", &[a.id]).await;
    let subject = entry.pool.to_string();
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
    budgets::set(pool, &b, &w.fx.dev.id, BY, NOW).await.unwrap();
    let chain = [entry];
    let s = w.session(&chain, &[]).await;
    // Stopped between the supervisor's read and the pick.
    w.end(&s.id, &at(1)).await;
    assert_eq!(w.pick(&s.id, &chain, &at(2)).await, Outcome::Gone);
    let holds = "SELECT count(*) FROM core_budget_holds WHERE session = ?";
    assert_eq!(w.count(holds, &s.id).await, 0, "no orphan hold");
    let used = acc::get(pool, a.id).await.unwrap().last_used_at;
    assert_eq!(used, None);
}

#[tokio::test]
async fn a_session_waits_wait_max_in_all_however_often_it_is_asked() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let a = w.acct("a").await;
    let wait = u64::try_from(WAIT_MAX_SECS).unwrap();
    w.signal(a.id, UpstreamStatus::RateLimited, Some(wait), &at(0))
        .await;
    let chain = [w.keys("main", &[a.id]).await];
    let s = w.session(&chain, &[]).await;
    assert!(matches!(
        w.pick(&s.id, &chain, &at(0)).await,
        Outcome::Wait { .. }
    ));
    // The provider keeps the account cooling: each new window ends within wait_max of the ask,
    // but the session has waited longer than wait_max since its first wait.
    sqlx::query(
        "UPDATE core_accounts SET state = 'cooling', state_reason = 'rate_limited', state_until = ?",
    )
    .bind(at(1700))
    .execute(pool)
    .await
    .unwrap();
    assert!(matches!(
        w.pick(&s.id, &chain, &at(899)).await,
        Outcome::Wait { .. }
    ));
    let got = w.pick(&s.id, &chain, &at(901)).await;
    assert!(matches!(got, Outcome::Exhausted(_)), "{got:?}");
}

#[tokio::test]
async fn a_session_whose_start_was_sent_never_leaves_its_account() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (a, b) = (w.acct("a").await, w.acct("b").await);
    let chain = [w.keys("main", &[a.id, b.id]).await];
    let s = w.session(&chain, &[]).await;
    let first = took(w.pick(&s.id, &chain, NOW).await).account;
    // The start went out and its answer was lost: the row still looks fresh.
    alloc::mark_start_sent(pool, &s.id).await.unwrap();
    let (seq, run): (i64, Option<String>) =
        sqlx::query_as("SELECT last_seq, harness_session FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!((seq, run), (0, None));
    let mut tx = begin_write(pool).await.unwrap();
    assert_eq!(alloc::retreat_in(&mut tx, &s.id).await.unwrap(), None);
    tx.commit().await.unwrap();
    let held: Option<i64> =
        sqlx::query_scalar("SELECT account_id FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(held, Some(first));
}

#[tokio::test]
async fn a_session_is_its_creators_users_and_a_waiting_one_is_cancelled_in_the_core() {
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
    let a = w.acct("a").await;
    let chain = [w.keys("main", &[a.id]).await];
    let mine = w.session(&chain, &[]).await;
    let theirs = w.session_by(&chain, &[], &other).await;
    let u1 = alloc::view(pool, &mine.id).await.unwrap().unwrap().user;
    let u2 = alloc::view(pool, &theirs.id).await.unwrap().unwrap().user;
    assert_eq!((u1, u2), (1, 2));
    // Waiting (the only account cools): cancelled in the Core, no runner asked, holds released.
    w.signal(a.id, UpstreamStatus::RateLimited, Some(600), &at(0))
        .await;
    let s = w.session(&chain, &[]).await;
    assert!(matches!(
        w.pick(&s.id, &chain, &at(1)).await,
        Outcome::Wait { .. }
    ));
    assert!(alloc::end_unstarted(pool, &s.id, &at(2)).await.unwrap());
    let (state, outcome): (String, String) =
        sqlx::query_as("SELECT state, outcome FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(
        state == "ended" && outcome.contains("cancelled"),
        "{state} {outcome}"
    );
    // Once ended it is not started, and a second cancel changes nothing.
    assert!(!alloc::mark_start_sent(pool, &s.id).await.unwrap());
    assert!(!alloc::end_unstarted(pool, &s.id, &at(3)).await.unwrap());
    // A session whose start was sent is the runner's to stop.
    let sent = w.session(&chain, &[]).await;
    assert!(alloc::mark_start_sent(pool, &sent.id).await.unwrap());
    assert!(!alloc::end_unstarted(pool, &sent.id, &at(4)).await.unwrap());
    // And a session that names its account itself (no chain) is never ended this way.
    let plain = w.session(&[], &[]).await;
    sqlx::query("UPDATE core_agent_sessions SET chain = NULL WHERE id = ?")
        .bind(&plain.id)
        .execute(pool)
        .await
        .unwrap();
    assert!(!alloc::end_unstarted(pool, &plain.id, &at(5)).await.unwrap());
}

#[tokio::test]
async fn a_cancel_between_the_grant_and_the_start_mark_leaves_no_hold() {
    use crate::store::gateway as gw;
    let w = w().await;
    let pool = &w.fx.app.pool;
    let a = w.acct("a").await;
    let entry = w.keys("main", &[a.id]).await;
    let subject = entry.pool.to_string();
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
    budgets::set(pool, &b, &w.fx.dev.id, BY, NOW).await.unwrap();
    let chain = [entry];
    let s = w.session(&chain, &[]).await;
    took(w.pick(&s.id, &chain, &at(1)).await);
    // The cancel lands first (it releases the hold and ends the row) ...
    assert!(alloc::end_unstarted(pool, &s.id, &at(2)).await.unwrap());
    // ... then the launch's grant reserves a fresh hold on the ended row ...
    let hold = gw::reserve(pool, &s.id, a.id, 0, &at(3)).await.unwrap();
    assert!(matches!(hold, gw::Hold::Granted(_)));
    let holds = "SELECT count(*) FROM core_budget_holds WHERE session = ?";
    assert_eq!(w.count(holds, &s.id).await, 1);
    // ... and the start mark refuses: the hold goes back at once.
    assert!(!alloc::mark_or_release(pool, &s.id).await.unwrap());
    assert_eq!(w.count(holds, &s.id).await, 0);
    // A live session's mark keeps its hold.
    let live = w.session(&chain, &[]).await;
    took(w.pick(&live.id, &chain, &at(4)).await);
    assert!(alloc::mark_or_release(pool, &live.id).await.unwrap());
    assert_eq!(w.count(holds, &live.id).await, 1);
    // A lost session whose account is full says so (the resume route's own message).
    acc::set_cap(pool, a.id, 1, &w.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let lost = w.session(&chain, &[]).await;
    sqlx::query("UPDATE core_agent_sessions SET account_id = ? WHERE id = ?")
        .bind(a.id)
        .bind(&lost.id)
        .execute(pool)
        .await
        .unwrap();
    lose(pool, &lost.id, &at(5)).await;
    assert!(alloc::account_full(pool, &lost.id).await.unwrap());
}
