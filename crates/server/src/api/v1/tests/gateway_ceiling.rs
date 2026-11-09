//! What the budgets do for a gateway session (KAN-435 G5): the hold becomes the ceiling, a ceiling too
//! small for one turn fails the start with the reason, a budget that runs out marks the session to be
//! stopped (and is found again after a lost mark), and a session that ends gives its hold back.

use serde_json::json;

use super::gateway_store::{G, feed, gw, secret, session, usage};
use super::*;
use crate::store::agents as store;
use crate::store::budgets::{self, NewBudget};
use crate::store::gateway as gw;
use crate::store::pools;

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

fn budget<'a>(subject: &'a str, tokens: i64, usd: Option<i64>) -> NewBudget<'a> {
    NewBudget {
        kind: "account",
        subject,
        company: None,
        period: "total",
        token_cap: tokens,
        usd_cap_micros: usd,
        warn_at_percent: None,
        hard_stop: true,
    }
}

async fn cap(g: &G, tokens: i64, usd: Option<i64>) -> budgets::Budget {
    let subject = g.account.id.to_string();
    budgets::set(
        &g.fx.app.pool,
        &budget(&subject, tokens, usd),
        &g.fx.dev.id,
        BY,
        NOW,
    )
    .await
    .unwrap()
}

async fn hold(g: &G, session: &str, min_usd: u64) -> gw::Hold {
    gw::reserve(&g.fx.app.pool, session, g.account.id, min_usd, NOW)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_ceiling_is_what_the_budgets_leave_up_to_the_hold() {
    let g = gw().await;
    let sid = g.session.id.clone();
    // No budget: nothing limits, in both dimensions.
    assert_eq!(
        hold(&g, &sid, 0).await,
        gw::Hold::Granted(ainkrad_proto::v2::Ceiling {
            tokens: u64::MAX,
            usd_micros: u64::MAX
        })
    );
    // More room than a session holds: the hold.
    cap(&g, 1_000_000_000, None).await;
    let gw::Hold::Granted(c) = hold(&g, &sid, 0).await else {
        panic!("denied")
    };
    assert_eq!((c.tokens, c.usd_micros), (gw::HOLD_TOKENS, u64::MAX));
    // Less: what is left. A second session sees the first one's hold as taken.
    cap(&g, 25_000_000, None).await;
    let second = session(&g.fx, &g.vm, &[secret(&g.account.secret_name)]).await;
    let gw::Hold::Granted(a) = hold(&g, &sid, 0).await else {
        panic!("denied")
    };
    let gw::Hold::Granted(second_hold) = hold(&g, &second.id, 0).await else {
        panic!("denied")
    };
    assert_eq!((a.tokens, second_hold.tokens), (20_000_000, 5_000_000));
    // A resume reserves again and replaces its own hold: not counted against itself.
    let gw::Hold::Granted(a2) = hold(&g, &sid, 0).await else {
        panic!("denied")
    };
    assert_eq!(a2.tokens, 20_000_000);
}

#[tokio::test]
async fn a_ceiling_too_small_for_one_turn_refuses_the_start_and_says_why() {
    let g = gw().await;
    let sid = g.session.id.clone();
    cap(&g, 300_000, None).await;
    let gw::Hold::Denied(why) = hold(&g, &sid, 0).await else {
        panic!("granted")
    };
    assert!(
        why.contains("300000") && why.contains("328000") && why.contains("128000"),
        "{why}"
    );
    // Nothing was held by the refusal: the next session still sees the whole of it.
    cap(&g, 400_000, None).await;
    let gw::Hold::Granted(c) = hold(&g, &sid, 0).await else {
        panic!("denied")
    };
    assert_eq!(c.tokens, 400_000);
}

#[tokio::test]
async fn dollars_are_a_ceiling_of_their_own_and_one_turn_must_fit_them() {
    let g = gw().await;
    let sid = g.session.id.clone();
    // A dollars-only budget limits no tokens.
    cap(&g, 0, Some(1_000_000)).await;
    let gw::Hold::Granted(c) = hold(&g, &sid, 500_000).await else {
        panic!("denied")
    };
    assert_eq!((c.tokens, c.usd_micros), (u64::MAX, 1_000_000));
    // A cheapest turn dearer than what is left cannot be admitted.
    let gw::Hold::Denied(why) = hold(&g, &sid, 2_520_000).await else {
        panic!("granted")
    };
    assert!(why.contains("1000000") && why.contains("2520000"), "{why}");
}

#[tokio::test]
async fn the_pools_of_the_account_limit_it_too_and_the_smallest_wins() {
    let g = gw().await;
    let p = pools::create(&g.fx.app.pool, "p-one", "anthropic", &g.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    pools::add_member(&g.fx.app.pool, p.id, g.account.id, &g.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    cap(&g, 9_000_000, None).await;
    let subject = p.id.to_string();
    let pool_budget = NewBudget {
        kind: "pool",
        ..budget(&subject, 4_000_000, None)
    };
    budgets::set(&g.fx.app.pool, &pool_budget, &g.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let gw::Hold::Granted(c) = hold(&g, &g.session.id, 0).await else {
        panic!("denied")
    };
    assert_eq!(c.tokens, 4_000_000);
}

#[tokio::test]
async fn a_budget_that_runs_out_marks_the_session_to_stop_even_after_a_lost_mark() {
    let g = gw().await;
    cap(&g, 700_000, None).await;
    feed(&g, vec![usage(1, 400_000, 0)]).await.unwrap();
    let row = store::get(&g.fx.app.pool, &g.session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.gw_stop, None, "300000 left");
    feed(&g, vec![usage(2, 300_000, 0)]).await.unwrap();
    let row = store::get(&g.fx.app.pool, &g.session.id)
        .await
        .unwrap()
        .unwrap();
    let why = row.gw_stop.expect("nothing left: stop");
    assert!(why.contains("account"), "{why}");
    let exhausted: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'budget.exhausted'")
            .fetch_one(&g.fx.app.pool)
            .await
            .unwrap();
    assert_eq!(exhausted, 1);
    // The mark was lost (a crash before it was acted on): a duplicate answer finds the budget again.
    sqlx::query("UPDATE core_agent_sessions SET gw_stop = NULL WHERE id = ?")
        .bind(&g.session.id)
        .execute(&g.fx.app.pool)
        .await
        .unwrap();
    feed(&g, vec![usage(2, 300_000, 0)]).await.unwrap();
    let row = store::get(&g.fx.app.pool, &g.session.id)
        .await
        .unwrap()
        .unwrap();
    assert!(row.gw_stop.is_some());
    // A new hold (a resume after the budget was raised or reset) lifts it; a denied one does not start.
    let gw::Hold::Denied(_) = hold(&g, &g.session.id, 0).await else {
        panic!("granted")
    };
}

async fn held(g: &G, session: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM core_budget_holds WHERE session = ?")
        .bind(session)
        .fetch_one(&g.fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn ending_a_session_gives_its_hold_back() {
    let g = gw().await;
    cap(&g, 5_000_000, None).await;
    let sid = g.session.id.clone();
    assert!(matches!(hold(&g, &sid, 0).await, gw::Hold::Granted(_)));
    assert_eq!(held(&g, &sid).await, 1);
    let done = json!({"kind": "failed", "reason": "x"});
    store::end(&g.fx.app.pool, &sid, "ended", &done, NOW)
        .await
        .unwrap();
    assert_eq!(held(&g, &sid).await, 0);
}
