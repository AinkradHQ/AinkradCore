//! Failover execution, the API and the ledger (KAN-438 S6): a refused cancel settles nothing and an
//! owner's cancel of the old attempt ends the successor, a subscription attempt's meter rows stay on
//! its own account across a move, and the migration goes down and up.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::allocator::{took, w};
use super::failover::{HOLDS, budget, limited, mv, over, row, to};
use super::health::at;
use super::*;
use crate::auth::testing::TestDevice;
use crate::store::agents as store;
use crate::store::alloc;
use crate::store::begin_write;

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

#[tokio::test]
async fn a_refused_cancel_settles_nothing_and_an_owners_cancel_of_the_old_attempt_ends_the_successor()
 {
    let w = w().await;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    budget(&w, chain[0].pool).await;
    let (old, _) = over(&w, &chain, limited(), 0).await;
    // Another agent device is refused (a session holding secrets answers to its creator or an admin):
    // the refusal comes before anything is settled, so the run still moves.
    let other = super::stepup::plain(&w.fx, "other-agent", &["agent", "read"], true).await;
    assert_eq!(
        super::stepup::step_up(&w.fx, &other).await.0,
        StatusCode::OK
    );
    let uri = format!("/api/v1/agent-sessions/{}/cancel", old.id);
    let r = call(&w.fx, &other, Method::POST, &uri, Value::Null).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope"))
    );
    assert_eq!(row(&w, &old.id).await.2, 0);
    let (new, _) = to(mv(&w, &old.id, "rate_limited", &at(5), true).await);
    // The creator cancels with the id it knows, after the move: the successor, not started, is ended in the Core.
    let r = call(&w.fx, &w.fx.dev, Method::POST, &uri, Value::Null).await;
    assert_eq!(r.0, StatusCode::OK, "{:?}", r.1);
    assert_eq!(row(&w, &new).await.1, "ended");
    assert_eq!(w.count(HOLDS, &new).await, 0);
}

#[tokio::test]
async fn a_subscription_attempt_keeps_its_meter_rows_on_its_own_account_across_a_move() {
    use ainkrad_proto::runner::Tokens;
    let w = w().await;
    let pool = &w.fx.app.pool;
    let (sub, key) = (w.sub("plan").await, w.acct("key").await);
    let chain = [
        w.pool("plan", "claude-sub", &[sub.id]).await,
        w.keys("keys", &[key.id]).await,
    ];
    let s = w.session(&chain, &[]).await;
    took(w.pick(&s.id, &chain, &at(0)).await);
    alloc::mark_start_sent(pool, &s.id).await.unwrap();
    let meter = |input| Tokens {
        input,
        output: 10,
        cache_read: 0,
        cache_write: 0,
        cost_usd_micros: None,
    };
    let mut tx = begin_write(pool).await.unwrap();
    assert!(
        crate::store::usage_meter::record(&mut tx, &s.id, Some(meter(100)), false, &at(1))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    store::end(
        pool,
        &s.id,
        "ended",
        &json!({"kind": "failed", "fingerprint": "auth"}),
        &at(2),
    )
    .await
    .unwrap();
    let (new, _) = to(mv(&w, &s.id, "auth", &at(3), true).await);
    // A late meter reading of the old attempt: its own account, a new key, nothing on the successor.
    let mut tx = begin_write(pool).await.unwrap();
    crate::store::usage_meter::record(&mut tx, &s.id, Some(meter(150)), false, &at(4))
        .await
        .unwrap();
    let on_new = crate::store::usage_meter::record(&mut tx, &new, Some(meter(150)), true, &at(4))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(!on_new, "a gateway session has no meter writer");
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT idempotency_key, account_id, input_tokens FROM core_cost_events ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(
        rows.iter()
            .all(|(k, a, _)| k.starts_with(&format!("hm:{}:", s.id)) && *a == sub.id),
        "{rows:?}"
    );
    assert_eq!(rows.iter().map(|r| r.2).sum::<i64>(), 150, "{rows:?}");
    assert_eq!(
        w.count(
            "SELECT count(*) FROM core_cost_events WHERE session = ?",
            &new
        )
        .await,
        0
    );
}

#[tokio::test]
async fn the_migration_goes_down_and_up_and_settles_what_was_over() {
    use crate::store::migrate::{CORE, CORE_MIGRATIONS, migrate_core, undo};
    let w = w().await;
    let pool = &w.fx.app.pool;
    let a = w.acct("a").await;
    let chain = [w.keys("main", &[a.id]).await];
    let (old, _) = over(&w, &chain, limited(), 0).await;
    let live = w.session(&chain, &[]).await;
    let cols = |p: sqlx::SqlitePool| async move {
        sqlx::query_scalar::<_, String>(
            "SELECT name FROM pragma_table_info('core_agent_sessions') WHERE name IN \
             ('run_id', 'attempt', 'failover_of', 'failover_class', 'failover_done', 'skip_pools') \
             ORDER BY name",
        )
        .fetch_all(&p)
        .await
        .unwrap()
    };
    assert_eq!(cols(pool.clone()).await.len(), 6);
    undo(pool, CORE, CORE_MIGRATIONS, 26).await.unwrap();
    assert!(cols(pool.clone()).await.is_empty());
    let plan: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pragma_table_info('core_accounts') WHERE name = 'plan_limit'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(plan, 0);
    migrate_core(pool).await.unwrap();
    assert_eq!(cols(pool.clone()).await.len(), 6);
    // What was over when the migration ran is settled (no restart moves an old run); what was live is not.
    assert_eq!(
        (row(&w, &old.id).await.2, row(&w, &live.id).await.2),
        (1, 0)
    );
}
