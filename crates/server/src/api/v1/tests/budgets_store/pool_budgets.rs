//! Budgets of pools that are deleted, raised or re-created.

use super::*;

#[tokio::test]
async fn a_deleted_pool_takes_its_budgets_and_a_pool_that_reuses_its_id_inherits_no_spend() {
    let (fx, vm, s) = setup().await;
    let acct = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    let p1 = pools::create(&fx.app.pool, "p-one", "anthropic", &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    pools::add_member(&fx.app.pool, p1.id, acct.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let b = set(&fx, &bud("pool", &p1.id.to_string(), "total", 1000)).await;
    let by_account = NewCost {
        session: "s1",
        epoch: 0,
        account_id: Some(acct.id),
        legacy_account_id: None,
        provider: "anthropic",
        harness: "claude",
        model: "m",
        input_tokens: 400,
        output_tokens: 0,
        cache_tokens: 0,
        reported_usd_micros: None,
        approximate: false,
        subjects: &[],
        idempotency_key: "k1",
        occurred_at: NOW,
    };
    costs::record(&fx.app.pool, &by_account, NOW).await.unwrap();
    assert_eq!(standing(&fx, b.id).await.spent, 400);
    pools::delete(&fx.app.pool, p1.id, &fx.dev.id, BY)
        .await
        .unwrap();
    assert!(budgets::get(&fx.app.pool, b.id).await.unwrap().is_none());
    // Pool ids are reused: the next pool is the same number, and the ledger still names the old pool,
    // yet a budget set on it counts only what came after the new pool existed.
    let later = "2026-10-22T12:00:00.000Z";
    let p2 = pools::create(&fx.app.pool, "p-two", "anthropic", &fx.dev.id, BY, later)
        .await
        .unwrap();
    assert_eq!(p2.id, p1.id, "the premise: the id was reused");
    let b2 = budgets::set(
        &fx.app.pool,
        &bud("pool", &p2.id.to_string(), "total", 1000),
        &fx.dev.id,
        BY,
        later,
    )
    .await
    .unwrap();
    let fresh = budgets::standing_of(&fx.app.pool, b2.id, later)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fresh.spent, 0);
    // An account's budgets go with it too.
    set(&fx, &bud("account", &acct.id.to_string(), "day", 10)).await;
    acc::delete(&fx.app.pool, acct.id, &fx.dev.id, BY)
        .await
        .unwrap();
    let left = budgets::list(&fx.app.pool, Some("account"), None, None, NOW)
        .await
        .unwrap();
    assert!(left.is_empty());
}

#[tokio::test]
async fn a_correction_of_an_old_pool_event_does_not_reach_the_pool_that_reused_the_id() {
    let (fx, vm, s) = setup().await;
    let acct = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    let p1 = pools::create(&fx.app.pool, "p-one", "anthropic", &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    pools::add_member(&fx.app.pool, p1.id, acct.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let old = NewCost {
        session: "s1",
        epoch: 0,
        account_id: Some(acct.id),
        legacy_account_id: None,
        provider: "anthropic",
        harness: "claude",
        model: "m",
        input_tokens: 400,
        output_tokens: 0,
        cache_tokens: 0,
        reported_usd_micros: Some(100),
        approximate: false,
        subjects: &[],
        idempotency_key: "k1",
        occurred_at: NOW,
    };
    let first = costs::record(&fx.app.pool, &old, NOW).await.unwrap().event;
    pools::delete(&fx.app.pool, p1.id, &fx.dev.id, BY)
        .await
        .unwrap();
    let later = "2026-10-22T12:00:00.000Z";
    let p2 = pools::create(&fx.app.pool, "p-two", "anthropic", &fx.dev.id, BY, later)
        .await
        .unwrap();
    assert_eq!(p2.id, p1.id, "the premise: the id was reused");
    let b2 = budgets::set(
        &fx.app.pool,
        &bud("pool", &p2.id.to_string(), "total", 1000),
        &fx.dev.id,
        BY,
        later,
    )
    .await
    .unwrap();
    // The bill for the old event arrives after the new pool exists: it is the old pool's, not the new one's.
    let mut c = fx.app.pool.acquire().await.unwrap();
    costs::correct_in(&mut c, first.id, 900, "bill-1", later)
        .await
        .unwrap()
        .unwrap();
    drop(c);
    let st = budgets::standing_of(&fx.app.pool, b2.id, later)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((st.spent, st.usd_spent), (0, 0));
    budgets::recompute(&fx.app.pool, BY).await.unwrap();
    let st = budgets::standing_of(&fx.app.pool, b2.id, later)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((st.spent, st.usd_spent), (0, 0));
}

#[tokio::test]
async fn a_raise_needs_the_key_of_the_budgets_own_period_and_answers_with_that_standing() {
    let fx = fx().await;
    let day = set(&fx, &bud("agent", "a1", "day", 100)).await;
    let week = set(&fx, &bud("agent", "a2", "week", 100)).await;
    let month = set(&fx, &bud("agent", "a3", "month", 100)).await;
    let mut tx = crate::store::begin_write(&fx.app.pool).await.unwrap();
    for (id, key) in [
        (day.id, "2026-10"),
        (day.id, "total"),
        (day.id, "2026-13-40"),
        (week.id, "2026-10-22"), // a Thursday, not a Monday
        (week.id, "2026-10"),
        (month.id, "2026-10-22"),
        (month.id, "2026-13"),
        (month.id, "total"),
    ] {
        assert_eq!(
            code(guard::raise_in(&mut tx, id, key, 1, 0, &fx.dev.id, BY).await),
            "bad_request",
            "{id} {key}"
        );
    }
    for (id, key) in [
        (day.id, "2026-10-22"),
        (week.id, "2026-10-19"),
        (month.id, "2026-10"),
    ] {
        guard::raise_in(&mut tx, id, key, 5, 0, &fx.dev.id, BY)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let st = budgets::standing_for(&fx.app.pool, week.id, "2026-10-19", NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((st.period_key.as_str(), st.raised), ("2026-10-19", 5));
    let st = budgets::standing_for(&fx.app.pool, month.id, "2026-10", NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((st.period_key.as_str(), st.raised), ("2026-10", 5));
}

#[tokio::test]
async fn a_budget_with_no_cap_is_refused_and_a_bigger_cap_re_arms_the_exhaustion_alert() {
    let fx = fx().await;
    assert_eq!(
        code(
            budgets::set(
                &fx.app.pool,
                &bud("agent", "a1", "day", 0),
                &fx.dev.id,
                BY,
                NOW
            )
            .await
        ),
        "bad_request"
    );
    let b = set(&fx, &bud("agent", "a1", "total", 100)).await;
    let at = "2026-10-22T10:00:00.000Z";
    assert_eq!(
        spend(&fx, "e1", 100, None, at, &[])
            .await
            .guard
            .newly_exhausted
            .len(),
        1
    );
    // A smaller or equal cap changes nothing about the alert...
    set(&fx, &bud("agent", "a1", "total", 100)).await;
    assert_eq!(
        spend(&fx, "e2", 1, None, at, &[])
            .await
            .guard
            .newly_exhausted
            .len(),
        0
    );
    // ...a bigger one re-arms it, so the next time it runs out is heard.
    set(&fx, &bud("agent", "a1", "total", 200)).await;
    let g = spend(&fx, "e3", 98, None, at, &[]).await.guard;
    assert_eq!(g.newly_exhausted.len(), 0);
    let g = spend(&fx, "e4", 1, None, at, &[]).await.guard;
    assert_eq!(
        (g.newly_exhausted.len(), standing(&fx, b.id).await.spent),
        (1, 200)
    );
}
