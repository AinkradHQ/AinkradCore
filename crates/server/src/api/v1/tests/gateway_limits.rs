//! The account's session limits and the Core's ceiling (KAN-435 G7): the limit caps what a session
//! may be given, less what the session has already spent (a resume does not renew it), and where no
//! budget limits a dimension it is the ceiling by itself.

use super::gateway_store::{feed, gw, usage};
use super::*;
use crate::store::account_keys;
use crate::store::budgets::{self, NewBudget};
use crate::store::gateway as gw;

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

async fn limits(g: &super::gateway_store::G, tokens: Option<i64>, usd: Option<i64>) {
    account_keys::set_session_limits(
        &g.fx.app.pool,
        g.account.id,
        tokens,
        usd,
        &g.fx.dev.id,
        BY,
        NOW,
    )
    .await
    .unwrap();
}

async fn reserve(g: &super::gateway_store::G) -> gw::Hold {
    gw::reserve(&g.fx.app.pool, &g.session.id, g.account.id, 0, NOW)
        .await
        .unwrap()
}

fn granted(h: gw::Hold) -> (u64, u64) {
    let gw::Hold::Granted(c) = h else {
        panic!("denied: {h:?}")
    };
    (c.tokens, c.usd_micros)
}

#[tokio::test]
async fn a_session_limit_is_the_ceiling_where_no_budget_limits_and_caps_the_hold_where_one_does() {
    let g = gw().await;
    assert_eq!(granted(reserve(&g).await), (u64::MAX, u64::MAX));
    limits(&g, Some(1_000_000), Some(7_000_000)).await;
    assert_eq!(granted(reserve(&g).await), (1_000_000, 7_000_000));
    // A budget with more room: the limit still caps what the session is given.
    let subject = g.account.id.to_string();
    let cap = NewBudget {
        kind: "account",
        subject: &subject,
        company: None,
        period: "total",
        token_cap: 50_000_000,
        usd_cap_micros: None,
        warn_at_percent: None,
        hard_stop: true,
    };
    budgets::set(&g.fx.app.pool, &cap, &g.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    assert_eq!(granted(reserve(&g).await), (1_000_000, 7_000_000));
    // A budget with less room wins, as it did.
    let tight = NewBudget {
        token_cap: 600_000,
        ..cap
    };
    budgets::set(&g.fx.app.pool, &tight, &g.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    assert_eq!(granted(reserve(&g).await).0, 600_000);
    // Clearing the limit gives the budgets back all of it.
    limits(&g, None, None).await;
    assert_eq!(granted(reserve(&g).await), (600_000, u64::MAX));
}

#[tokio::test]
async fn what_a_session_already_spent_counts_against_its_limit_across_a_resume() {
    let g = gw().await;
    limits(&g, Some(1_000_000), None).await;
    feed(&g, vec![usage(1, 400_000, 0)]).await.unwrap();
    assert_eq!(granted(reserve(&g).await).0, 600_000);
    // Under what one turn needs: the start is refused, and says it is the session limit.
    feed(&g, vec![usage(2, 300_000, 0)]).await.unwrap();
    let gw::Hold::Denied(why) = reserve(&g).await else {
        panic!("granted")
    };
    assert!(
        why.contains("session limit") && why.contains("300000"),
        "{why}"
    );
    // Another session of the account has its own allowance.
    let other = super::gateway_store::session(
        &g.fx,
        &g.vm,
        &[super::gateway_store::secret(&g.account.secret_name)],
    )
    .await;
    let h = gw::reserve(&g.fx.app.pool, &other.id, g.account.id, 0, NOW)
        .await
        .unwrap();
    assert_eq!(granted(h).0, 1_000_000);
}

#[tokio::test]
async fn a_limit_under_one_turn_is_refused_when_it_is_set() {
    let g = gw().await;
    for (tokens, usd) in [
        (Some(300_000), None),
        (Some(0), None),
        (None, Some(0)),
        (None, Some(-5)),
    ] {
        let r = account_keys::set_session_limits(
            &g.fx.app.pool,
            g.account.id,
            tokens,
            usd,
            &g.fx.dev.id,
            BY,
            NOW,
        )
        .await;
        assert!(r.is_err(), "{tokens:?} {usd:?}");
    }
    let a = crate::store::accounts::get(&g.fx.app.pool, g.account.id)
        .await
        .unwrap();
    assert_eq!(
        (a.session_max_tokens, a.session_max_usd_micros),
        (None, None)
    );
}
