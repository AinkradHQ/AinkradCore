//! Account attribution, input checks and usage windows read from the ledger.

use super::*;

#[tokio::test]
async fn an_event_counts_against_its_account_every_pool_it_was_in_and_what_the_caller_named() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    let p = pools::create(&fx.app.pool, "main-pool", "anthropic", &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    pools::add_member(&fx.app.pool, p.id, a.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let mut c = cost("s1", 0, "k1", Some(a.id));
    c.subjects = &[
        ("agent", "a1"),
        ("department", "d1"),
        ("department", "d2"),
        ("sprint", "9"),
    ];
    let id = costs::record(&fx.app.pool, &c, NOW).await.unwrap().event.id;
    let got: Vec<(String, String)> = sqlx::query_as(
        "SELECT kind, subject_id FROM core_cost_subjects WHERE event_id = ? ORDER BY kind, subject_id",
    )
    .bind(id)
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    let (pool_id, acct) = (p.id.to_string(), a.id.to_string());
    let want = [
        ("account", acct.as_str()),
        ("agent", "a1"),
        ("department", "d1"),
        ("department", "d2"),
        ("pool", pool_id.as_str()),
        ("sprint", "9"),
    ];
    assert_eq!(
        got.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>(),
        want
    );
}

#[tokio::test]
async fn bad_input_is_refused_before_it_is_written() {
    let fx = fx().await;
    let bad: Vec<Mutate> = vec![
        Box::new(|c| c.input_tokens = -1),
        Box::new(|c| c.epoch = -1),
        Box::new(|c| c.reported_usd_micros = Some(-1)),
        Box::new(|c| c.harness = "vim"),
        Box::new(|c| c.model = "bad model"),
        Box::new(|c| c.session = ""),
        Box::new(|c| c.idempotency_key = ""),
        Box::new(|c| c.subjects = &[("account", "1")]),
        Box::new(|c| c.subjects = &[("agent", "has space")]),
        Box::new(|c| {
            c.account_id = Some(1);
            c.legacy_account_id = Some(2);
        }),
    ];
    for f in bad {
        let mut c = cost("s1", 0, "k1", None);
        f(&mut c);
        assert_eq!(
            code(costs::record(&fx.app.pool, &c, NOW).await),
            "bad_request",
            "{c:?}"
        );
    }
    assert_eq!(totals(&fx).await.events, 0);
    async fn bad_price(
        fx: &Fx,
        rates: [i64; 3],
        at: &str,
        model: &str,
        provider: &str,
    ) -> Result<prices::Price, Error> {
        prices::set(
            &fx.app.pool,
            provider,
            model,
            rates,
            at,
            &fx.dev.id,
            BY,
            NOW,
        )
        .await
    }
    let ok_rates = [1, 1, 1];
    assert_eq!(
        code(bad_price(&fx, [-1, 1, 1], PRICED, "m", "anthropic").await),
        "bad_request"
    );
    assert_eq!(
        code(bad_price(&fx, [2_000_000_000, 1, 1], PRICED, "m", "anthropic").await),
        "bad_request"
    );
    assert_eq!(
        code(bad_price(&fx, ok_rates, "yesterday", "m", "anthropic").await),
        "bad_request"
    );
    assert_eq!(
        code(bad_price(&fx, ok_rates, "2026-13-45T00:00:00Z", "m", "anthropic").await),
        "bad_request"
    );
    assert_eq!(
        code(bad_price(&fx, ok_rates, PRICED, "bad model", "anthropic").await),
        "bad_request"
    );
    assert_eq!(
        code(bad_price(&fx, ok_rates, PRICED, "m", "nosuch").await),
        "not_found"
    );
}

#[tokio::test]
async fn usage_windows_limits_company_slices_and_drops_read_from_the_ledger() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    let other = make(&fx, &s, "other", "throwaway-account-value-two-77d0be", &[]).await;
    price(&fx, [1_000_000, 1_000_000, 1_000_000]).await;
    // NOW is 2026-10-22T10:00: one hour ago, a day ago, and eight days ago.
    let (recent, old, ancient) = (
        "2026-10-22T09:00:00.000Z",
        "2026-10-21T10:00:00.000Z",
        "2026-10-14T10:00:00.000Z",
    );
    for (key, when, company) in [("r", recent, "7"), ("o", old, "8"), ("x", ancient, "7")] {
        let mut c = cost("s1", 0, key, Some(a.id));
        (c.input_tokens, c.output_tokens, c.cache_tokens) = (100, 50, 0);
        c.occurred_at = when;
        let subject = [("company", company)];
        c.subjects = &subject;
        costs::record(&fx.app.pool, &c, NOW).await.unwrap();
    }
    costs::record(&fx.app.pool, &cost("s9", 0, "z", Some(other.id)), NOW)
        .await
        .unwrap();
    // A limit of 120 tokens in 5 hours: 150 used is over; a message cap of 10 in a day.
    usage::set_limit(
        &fx.app.pool,
        a.id,
        "tokens",
        5 * 3600,
        120,
        None,
        &fx.dev.id,
        BY,
    )
    .await
    .unwrap();
    usage::set_limit(
        &fx.app.pool,
        a.id,
        "messages",
        86_400,
        10,
        Some(50),
        &fx.dev.id,
        BY,
    )
    .await
    .unwrap();
    let mut conn = fx.app.pool.acquire().await.unwrap();
    for _ in 0..6 {
        usage::record_event_in(&mut conn, a.id, Some("s1"), "message", NOW)
            .await
            .unwrap();
    }
    usage::record_event_in(&mut conn, a.id, None, "drop", NOW)
        .await
        .unwrap();
    drop(conn);
    let report = usage::report(&fx.app.pool, None, NOW).await.unwrap();
    assert_eq!(report.len(), 2);
    let r = &report[0];
    assert_eq!(r.account_id, a.id);
    assert_eq!(
        (r.five_hours.total_tokens, r.five_hours.cost_usd_micros),
        (150, 150)
    );
    assert_eq!((r.seven_days.total_tokens, r.five_hours.messages), (300, 6));
    assert_eq!(r.recent_drops, 1);
    let tokens = &r.limits[0];
    assert_eq!(
        (
            tokens.unit.as_str(),
            tokens.used,
            tokens.exhausted,
            tokens.warn_percent
        ),
        ("tokens", 150, true, 80)
    );
    let msgs = &r.limits[1];
    assert_eq!(
        (msgs.used, msgs.exhausted, msgs.warn_percent),
        (6, false, 50)
    );
    assert_eq!(r.max_utilisation_bps, 12_500);
    // Company 7 used 150 in 5 hours (one event) and 300 in 7 days; company 8 only the day-old one.
    let slice = |c: &str| r.by_company.iter().find(|s| s.company == c).unwrap();
    assert_eq!(slice("7").five_hours.total_tokens, 150);
    assert_eq!(slice("7").seven_days.total_tokens, 150);
    assert_eq!(slice("8").five_hours.total_tokens, 0);
    assert_eq!(slice("8").seven_days.total_tokens, 150);
    // The other account has its own usage and no limits.
    assert_eq!(report[1].five_hours.total_tokens, 3_500_000);
    assert!(report[1].limits.is_empty());
    // Limits are audited, refused when malformed, and cleared once.
    assert_eq!(
        code(usage::set_limit(&fx.app.pool, a.id, "bytes", 60, 1, None, &fx.dev.id, BY).await),
        "bad_request"
    );
    assert_eq!(
        code(usage::set_limit(&fx.app.pool, a.id, "tokens", 0, 1, None, &fx.dev.id, BY).await),
        "bad_request"
    );
    assert_eq!(
        code(usage::set_limit(&fx.app.pool, 999, "tokens", 60, 1, None, &fx.dev.id, BY).await),
        "not_found"
    );
    assert!(
        usage::clear_limit(&fx.app.pool, a.id, "tokens", 5 * 3600, &fx.dev.id, BY)
            .await
            .unwrap()
    );
    assert!(
        !usage::clear_limit(&fx.app.pool, a.id, "tokens", 5 * 3600, &fx.dev.id, BY)
            .await
            .unwrap()
    );
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'account.limit_%' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "account.limit_set",
            "account.limit_set",
            "account.limit_cleared"
        ]
    );
}

#[tokio::test]
async fn a_caller_prices_with_its_own_rates_or_not_at_all_and_a_session_is_priced_once_all_its_events_are()
 {
    use crate::store::costs::Pricing;
    use crate::store::prices::Rates;
    let fx = fx().await;
    // The Core's book has a price; the caller's own rates beat it, and `Unpriced` ignores it.
    price(&fx, [9_000_000, 9_000_000, 9_000_000]).await;
    let own = Rates {
        input: 1_000_000,
        output: 2_000_000,
        cache: 0,
        priced_at: "2026-10-01T00:00:00.000Z".to_owned(),
    };
    let mut conn = fx.app.pool.acquire().await.unwrap();
    let a = costs::record_priced_in(
        &mut conn,
        &cost("s1", 0, "k1", None),
        Pricing::Own(own),
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(
        (
            a.event.basis.as_str(),
            a.event.cost_usd_micros,
            a.event.priced_at.as_deref()
        ),
        (
            "list_price",
            Some(1_000_000 + 1_000_000),
            Some("2026-10-01T00:00:00.000Z")
        )
    );
    assert_eq!(
        costs::session_cost(&mut conn, "s1").await.unwrap(),
        Some(2_000_000)
    );
    let b = costs::record_priced_in(
        &mut conn,
        &cost("s1", 1, "k2", None),
        Pricing::Unpriced,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(
        (b.event.basis.as_str(), b.event.cost_usd_micros),
        ("unpriced", None)
    );
    // One unpriced event leaves the session unpriced, and its tokens still add up.
    assert_eq!(costs::session_cost(&mut conn, "s1").await.unwrap(), None);
    assert_eq!(
        costs::session_totals(&mut conn, "s1").await.unwrap(),
        [2_000_000, 1_000_000, 4_000_000, 2_000_000]
    );
    assert_eq!(
        costs::session_totals(&mut conn, "nobody").await.unwrap(),
        [0, 0, 0, 0]
    );
}
