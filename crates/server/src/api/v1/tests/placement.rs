//! N40, N29 and N35 K1/K2: a new account lands in its provider's default pool and the user's
//! default chain, in the transaction that stores it; list prices are shipped; a plain session
//! with no account is refused.

use ainkrad_core::settings::{Key, Scope};

use super::*;
use crate::ops::secretbox::SecretBox;
use crate::store::placement::Placement;
use crate::store::{accounts as acc, chains as ch, pools as pl, prices};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

async fn add(fx: &Fx, provider: &str, label: &str, p: Placement) -> (i64, i64, Option<i64>) {
    let s = SecretBox::new(&[7; 32]);
    let new = acc::NewAccount {
        provider,
        label,
        value: match provider {
            "claude-sub" => "sk-ant-oat01-throwaway-placement-5a91c3d4",
            _ => "throwaway-placement-value-5a91c3d4",
        },
        runners: &[],
        cap: None,
    };
    let (a, (pool, chain)) =
        acc::create_placed(&fx.app.pool, &s, &new, "key", &fx.dev.id, BY, NOW, &p)
            .await
            .unwrap();
    (a.id, pool, chain)
}

#[tokio::test]
async fn a_new_account_gets_a_hidden_pool_of_its_own_the_ai_order_and_a_monthly_limit() {
    let fx = fx().await;
    let p = &fx.app.pool;
    crate::store::settings::set(p, Key::SecretsMode, Scope::Server, "1", BY, NOW)
        .await
        .unwrap();
    crate::store::settings::set(p, Key::SecretsProviderAccounts, Scope::Server, "1", BY, NOW)
        .await
        .unwrap();
    let me = Placement {
        user: 1,
        ..Default::default()
    };
    let (a1, pool, chain) = add(&fx, "anthropic", "one", me).await;
    let chain = chain.expect("a default chain was made");
    let pl1 = pl::get(p, pool).await.unwrap();
    assert!(pl1.hidden && !pl1.is_default && pl1.members == [a1]);
    let c = ch::get(p, chain).await.unwrap();
    assert!(c.hidden && c.is_default && c.entries.len() == 1 && c.entries[0].pool == pool);

    // A second key account of the same provider gets a pool of its own, appended to the order.
    let (a2, pool2, chain2) = add(&fx, "anthropic", "two", me).await;
    assert_ne!(pool2, pool);
    assert_eq!(chain2, Some(chain));
    assert_eq!(pl::get(p, pool2).await.unwrap().members, [a2]);
    assert_eq!(ch::get(p, chain).await.unwrap().entries.len(), 2);

    // Each key account has the $20 monthly limit.
    let usd: i64 = sqlx::query_scalar(
        "SELECT usd_cap_micros FROM core_budgets WHERE subject_kind='account' AND subject_id=? \
         AND period='month'",
    )
    .bind(a1.to_string())
    .fetch_one(p)
    .await
    .unwrap();
    assert_eq!(usd, 20_000_000);

    // Claude plan accounts are appended too, two of them: the order holds several subscriptions.
    let (s1, sp1, _) = add(&fx, "claude-sub", "plan-a", me).await;
    let (s2, sp2, _) = add(&fx, "claude-sub", "plan-b", me).await;
    assert_ne!(sp1, sp2);
    assert_eq!(pl::get(p, sp1).await.unwrap().members, [s1]);
    assert_eq!(pl::get(p, sp2).await.unwrap().members, [s2]);
    let pools: Vec<i64> = ch::get(p, chain)
        .await
        .unwrap()
        .entries
        .iter()
        .map(|e| e.pool)
        .collect();
    assert_eq!(pools, [pool, pool2, sp1, sp2]);

    // A chosen position, and no limit with 0.
    let (a3, ..) = add(
        &fx,
        "openai",
        "oa",
        Placement {
            position: Some(0),
            monthly_usd_micros: Some(0),
            ..me
        },
    )
    .await;
    let first = ch::get(p, chain).await.unwrap().entries[0].provider.clone();
    assert_eq!(first, "openai");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_budgets WHERE subject_id=?")
        .bind(a3.to_string())
        .fetch_one(p)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn the_ai_order_lists_accounts_reorders_them_and_keeps_agent_overrides() {
    use crate::store::chains::order::{self, Spec};
    let fx = fx().await;
    let p = &fx.app.pool;
    crate::store::settings::set(p, Key::SecretsMode, Scope::Server, "1", BY, NOW)
        .await
        .unwrap();
    crate::store::settings::set(p, Key::SecretsProviderAccounts, Scope::Server, "1", BY, NOW)
        .await
        .unwrap();
    let me = Placement {
        user: 1,
        ..Default::default()
    };
    let (a1, ..) = add(&fx, "anthropic", "one", me).await;
    let (a2, ..) = add(&fx, "openai", "two", me).await;
    let (s1, ..) = add(&fx, "claude-sub", "plan", me).await;
    let ids = |o: &order::Order| o.items.iter().map(|i| i.account).collect::<Vec<_>>();
    assert_eq!(ids(&order::get(p, 1).await.unwrap()), [a1, a2, s1]);

    // Reordered as a whole; the same hidden pools are reused, so nothing new appears.
    let pools_before = pl::list(p).await.unwrap().len();
    let spec = |a| Spec {
        account: a,
        model: None,
    };
    order::set(p, 1, None, &[spec(s1), spec(a1), spec(a2)], "d_x", BY, NOW)
        .await
        .unwrap();
    assert_eq!(ids(&order::get(p, 1).await.unwrap()), [s1, a1, a2]);
    assert_eq!(pl::list(p).await.unwrap().len(), pools_before);

    // An account twice, none, and a missing account are refused; the order stays.
    for bad in [vec![spec(a1), spec(a1)], vec![], vec![spec(9999)]] {
        assert!(order::set(p, 1, None, &bad, "d_x", BY, NOW).await.is_err());
    }
    assert_eq!(ids(&order::get(p, 1).await.unwrap()), [s1, a1, a2]);

    // An agent's override; the default order is untouched; clearing it falls back.
    order::set(p, 1, Some("agent-x"), &[spec(a2)], "d_x", BY, NOW)
        .await
        .unwrap();
    let o = order::get(p, 1).await.unwrap();
    assert_eq!((o.overrides.len(), o.overrides[0].items[0].account), (1, a2));
    assert_eq!(ids(&o), [s1, a1, a2]);
    order::clear_agent(p, 1, "agent-x", "d_x", BY).await.unwrap();
    assert!(order::get(p, 1).await.unwrap().overrides.is_empty());
    assert!(order::clear_agent(p, 1, "agent-x", "d_x", BY).await.is_err());
}

#[tokio::test]
async fn a_failed_placement_leaves_no_account() {
    let fx = fx().await;
    let p = &fx.app.pool;
    crate::store::settings::set(p, Key::SecretsMode, Scope::Server, "1", BY, NOW)
        .await
        .unwrap();
    let s = SecretBox::new(&[7; 32]);
    let new = acc::NewAccount {
        provider: "anthropic",
        label: "ghost",
        value: "throwaway-placement-value-5a91c3d4",
        runners: &[],
        cap: None,
    };
    let bad = Placement {
        user: 1,
        chain: Some(9999),
        ..Default::default()
    };
    assert!(
        acc::create_placed(p, &s, &new, "key", &fx.dev.id, BY, NOW, &bad)
            .await
            .is_err()
    );
    assert!(acc::list(p).await.unwrap().is_empty());
    assert!(pl::list(p).await.unwrap().is_empty());
}

#[tokio::test]
async fn list_prices_are_shipped_and_a_manual_price_wins() {
    let fx = fx().await;
    let p = &fx.app.pool;
    let mut conn = p.acquire().await.unwrap();
    let r = prices::rates_in(&mut conn, "anthropic", "claude-sonnet-5-5")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (r.input, r.output, r.cache),
        (2_000_000, 10_000_000, 100_000)
    );
    assert!(
        prices::rates_in(&mut conn, "openai", "gpt-x")
            .await
            .unwrap()
            .is_none()
    );
    drop(conn);
    prices::set(
        p,
        "anthropic",
        "claude-sonnet-5-5",
        [1, 2, 3],
        "2026-11-11T00:00:00Z",
        "d_x",
        BY,
        NOW,
    )
    .await
    .unwrap();
    let mut conn = p.acquire().await.unwrap();
    let r = prices::rates_in(&mut conn, "anthropic", "claude-sonnet-5-5")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.input, 1);
    let listed = prices::list(p).await.unwrap();
    assert_eq!(
        listed
            .iter()
            .filter(|x| x.model == "claude-sonnet-5-5")
            .count(),
        1
    );
    assert!(listed.iter().any(|x| x.model == "claude-opus-5-5"));
}
