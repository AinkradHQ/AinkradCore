//! The gateway's reports across restarts, prices and signals (KAN-435 G5 review): a runner that lost
//! its state and numbers again from 1 under a newer epoch is not resending; a model the book lost is
//! priced from the grant's snapshot; and an auth signal and its inconclusive end are audited.

use ainkrad_proto::v2::{Ceiling, GatewayReport, GatewayReportKind, UpstreamStatus};

use super::gateway_store::{G, acked, feed, gw as fixture, keys, usage};
use super::*;
use crate::store::agents as store;
use crate::store::gateway as gw;
use crate::store::prices::Price;

fn renumbered(seq: u64, input: u64) -> GatewayReport {
    GatewayReport {
        epoch: 1,
        ..usage(seq, input, 0)
    }
}

async fn actions(g: &G, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(&g.fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_woken_session_whose_runner_lost_its_state_has_its_renumbered_reports_recorded() {
    let g = fixture().await;
    feed(&g, vec![usage(1, 10, 0), usage(2, 20, 0), usage(3, 30, 0)])
        .await
        .unwrap();
    assert_eq!(acked(&g).await, 3);
    // The session was woken (epoch 1) and its runner began again from 1. Until a report of the new
    // epoch is held, the Core acknowledges nothing: 3 would drop the new reports 1..3 unrecorded.
    sqlx::query("UPDATE core_agent_sessions SET resumes = 1 WHERE id = ?")
        .bind(&g.session.id)
        .execute(&g.fx.app.pool)
        .await
        .unwrap();
    assert_eq!(
        gw::ack_after(&g.fx.app.pool, &g.session.id).await.unwrap(),
        0
    );
    // A late resend from epoch 0 is still a resend.
    feed(&g, vec![usage(2, 20, 0)]).await.unwrap();
    assert_eq!(keys(&g).await.len(), 3);
    // The new epoch's 1..4, each at or below (or just above) the old cursor: all of them are recorded.
    let new: Vec<_> = (1..=4).map(|n| renumbered(n, n * 100)).collect();
    feed(&g, new.clone()).await.unwrap();
    let s = format!("gw:{}", g.session.id);
    let all = keys(&g).await;
    assert_eq!(all.len(), 7, "{all:?}");
    assert_eq!(all[3], format!("{s}:1:1"));
    assert_eq!(all[6], format!("{s}:1:4"));
    assert_eq!(
        gw::cursor(&g.fx.app.pool, &g.session.id).await.unwrap(),
        (1, 4)
    );
    assert_eq!(
        gw::ack_after(&g.fx.app.pool, &g.session.id).await.unwrap(),
        4
    );
    // And a resend of those is a resend.
    feed(&g, new).await.unwrap();
    assert_eq!(keys(&g).await.len(), 7);
    let row = store::get(&g.fx.app.pool, &g.session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.usage.input, 10 + 20 + 30 + 100 + 200 + 300 + 400);
}

#[tokio::test]
async fn a_model_the_book_lost_is_priced_from_the_grants_snapshot() {
    let g = fixture().await;
    let snap = Price {
        provider: "anthropic".to_owned(),
        model: "claude-snap".to_owned(),
        version: 1,
        input_per_mtok_micro: 3_000_000,
        output_per_mtok_micro: 15_000_000,
        cache_per_mtok_micro: 300_000,
        priced_at: "2026-11-01T00:00:00Z".to_owned(),
        created_at: "2026-11-01T00:00:00Z".to_owned(),
    };
    let ceiling = Ceiling {
        tokens: u64::MAX,
        usd_micros: u64::MAX,
    };
    gw::save_grant(&g.fx.app.pool, &g.session.id, ceiling, &[snap])
        .await
        .unwrap();
    // The book has no price for it (it never had, or lost it): the snapshot prices the request.
    let snapped = GatewayReport {
        model: Some("claude-snap".to_owned()),
        ..usage(1, 10, 10)
    };
    let other = GatewayReport {
        model: Some("claude-other".to_owned()),
        ..usage(2, 10, 10)
    };
    feed(&g, vec![snapped, other]).await.unwrap();
    let rows = crate::store::costs::list(&g.fx.app.pool, Some(&g.session.id), None, 10)
        .await
        .unwrap();
    assert_eq!(
        (rows[1].basis.as_str(), rows[1].cost_usd_micros),
        ("list_price", Some(180))
    );
    assert_eq!(
        (rows[0].basis.as_str(), rows[0].cost_usd_micros),
        ("unpriced", None)
    );
}

#[tokio::test]
async fn an_auth_signal_and_its_inconclusive_end_are_audited() {
    let g = fixture().await;
    let failed = |seq| GatewayReport {
        kind: GatewayReportKind::Upstream,
        status: UpstreamStatus::AuthFailed,
        model: None,
        ..usage(seq, 0, 0)
    };
    feed(&g, vec![failed(1)]).await.unwrap();
    feed(&g, vec![failed(1)]).await.unwrap();
    assert_eq!(actions(&g, "account.auth_failed").await, 1);
    let (id, _) = gw::pending_auth(&g.fx.app.pool, g.account.id)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..gw::MAX_CONFIRM_TRIES {
        gw::tried(&g.fx.app.pool, id, NOW).await.unwrap();
    }
    assert_eq!(actions(&g, "account.auth_inconclusive").await, 1);
    // One that ends without a test (its session is over and no runner was ready) is audited too.
    feed(&g, vec![failed(2)]).await.unwrap();
    gw::decide(
        &g.fx.app.pool,
        g.account.id,
        "inconclusive",
        "no runner",
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(actions(&g, "account.auth_inconclusive").await, 2);
    assert!(
        gw::pending_auth(&g.fx.app.pool, g.account.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_hold_of_a_pool_the_account_left_does_not_outlive_a_new_reserve() {
    let g = fixture().await;
    let sid = g.session.id.clone();
    let pool = crate::store::pools::create(
        &g.fx.app.pool,
        "p-one",
        "anthropic",
        &g.fx.dev.id,
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    crate::store::pools::add_member(
        &g.fx.app.pool,
        pool.id,
        g.account.id,
        &g.fx.dev.id,
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    let subject = pool.id.to_string();
    let b = crate::store::budgets::NewBudget {
        kind: "pool",
        subject: &subject,
        company: None,
        period: "total",
        token_cap: 9_000_000,
        usd_cap_micros: None,
        warn_at_percent: None,
        hard_stop: true,
    };
    crate::store::budgets::set(&g.fx.app.pool, &b, &g.fx.dev.id, super::super::BY, NOW)
        .await
        .unwrap();
    gw::reserve(&g.fx.app.pool, &sid, g.account.id, 0, NOW)
        .await
        .unwrap();
    let held = |g: &G| {
        let pool = g.fx.app.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM core_budget_holds")
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(held(&g).await, 1);
    // The account leaves the pool: the next reserve has no budget to hold from, and the old hold goes.
    crate::store::pools::remove_member(
        &g.fx.app.pool,
        pool.id,
        g.account.id,
        &g.fx.dev.id,
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    gw::reserve(&g.fx.app.pool, &sid, g.account.id, 0, NOW)
        .await
        .unwrap();
    assert_eq!(held(&g).await, 0);
}
