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
async fn a_new_account_gets_a_default_pool_a_default_chain_and_a_monthly_limit() {
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
    assert!(pl1.is_default && pl1.members == [a1]);
    let c = ch::get(p, chain).await.unwrap();
    assert!(c.is_default && c.entries.len() == 1 && c.entries[0].pool == pool);

    // A second key account joins the same pool; the chain is not touched.
    let (a2, pool2, chain2) = add(&fx, "anthropic", "two", me).await;
    assert_eq!((pool2, chain2), (pool, Some(chain)));
    assert_eq!(pl::get(p, pool).await.unwrap().members, [a1, a2]);
    assert_eq!(ch::get(p, chain).await.unwrap().entries.len(), 1);

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

    // A Claude plan account is alone in its pool, appended to the default chain; a second one
    // gets a pool of its own.
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
    // The chain takes one subscription entry: the second plan's pool is left out of the default chain.
    assert_eq!(pools, [pool, sp1]);

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
