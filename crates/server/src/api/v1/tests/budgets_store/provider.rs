//! E7 closeout: a budget per provider counts every account of that provider.

use super::*;
use crate::store::alloc::room_in;
use crate::store::failover::{BudgetStop, budget_stop};

fn cost(account: i64, key: &str, tokens: i64) -> NewCost<'_> {
    NewCost {
        session: "s1",
        epoch: 0,
        account_id: Some(account),
        legacy_account_id: None,
        provider: "anthropic",
        harness: "claude",
        model: "m",
        input_tokens: tokens,
        output_tokens: 0,
        cache_tokens: 0,
        reported_usd_micros: None,
        approximate: false,
        subjects: &[],
        idempotency_key: key,
        occurred_at: NOW,
    }
}

#[tokio::test]
async fn a_provider_budget_counts_all_its_accounts_and_stops_every_one_of_them() {
    let (fx, vm, s) = setup().await;
    let runners = std::slice::from_ref(&vm.id);
    let a = make(&fx, &s, "one", V1, runners).await;
    let b = make(&fx, &s, "two", "sk-ant-api03-other", runners).await;
    let p = &fx.app.pool;
    assert_eq!(
        code(
            budgets::set(
                p,
                &bud("provider", "nope", "total", 100),
                &fx.dev.id,
                BY,
                NOW
            )
            .await
        ),
        "not_found"
    );
    let made = set(&fx, &bud("provider", "anthropic", "total", 1_000_000)).await;
    assert_eq!(made.kind, "provider");
    assert!(
        room_in(&mut p.acquire().await.unwrap(), b.id, "s9", false, 0, NOW)
            .await
            .unwrap()
    );
    // Account one spends the whole cap: the provider's counter moves, and account two is out of room.
    costs::record(p, &cost(a.id, "k1", 1_000_000), NOW)
        .await
        .unwrap();
    assert_eq!(standing(&fx, made.id).await.spent, 1_000_000);
    let mut conn = p.acquire().await.unwrap();
    assert!(!room_in(&mut conn, b.id, "s9", false, 0, NOW).await.unwrap());
    assert!(!room_in(&mut conn, a.id, "s9", false, 0, NOW).await.unwrap());
}

#[test]
fn a_gateway_stop_of_a_provider_budget_names_the_provider() {
    assert_eq!(
        budget_stop("provider:claude-sub"),
        Some(BudgetStop::Provider("claude-sub".into()))
    );
    assert_eq!(budget_stop("pool:3"), Some(BudgetStop::Pool(3)));
}
