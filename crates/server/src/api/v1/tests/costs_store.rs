//! The Core cost ledger (KAN-449): one row per attempt, idempotent, insert-only, priced from the list
//! price in force or the provider's own report or not at all, corrected by a delta row, and kept
//! when its account is deleted. Usage windows and limits read from it.

use super::accounts_store::{V1, make, setup};
use super::*;
use crate::store::costs::{self, NewCost};
use crate::store::secrets::Error;
use crate::store::{accounts as acc, pools, prices, providers as prov, usage};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

type Mutate = Box<dyn Fn(&mut NewCost<'_>)>;
const PRICED: &str = "2026-11-01T00:00:00Z";

fn cost<'a>(session: &'a str, epoch: i64, key: &'a str, account: Option<i64>) -> NewCost<'a> {
    NewCost {
        session,
        epoch,
        account_id: account,
        legacy_account_id: None,
        provider: "anthropic",
        harness: "claude",
        model: "claude-x",
        input_tokens: 1_000_000,
        output_tokens: 500_000,
        cache_tokens: 2_000_000,
        reported_usd_micros: None,
        approximate: false,
        subjects: &[],
        idempotency_key: key,
        occurred_at: NOW,
    }
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    match r {
        Err(Error::Refused { code, .. }) => code,
        Err(e) => panic!("not a refusal: {e}"),
        Ok(_) => panic!("accepted"),
    }
}

async fn price(fx: &Fx, rates: [i64; 3]) -> prices::Price {
    prices::set(
        &fx.app.pool,
        "anthropic",
        "claude-x",
        rates,
        PRICED,
        &fx.dev.id,
        BY,
        NOW,
    )
    .await
    .unwrap()
}

async fn totals(fx: &Fx) -> costs::Totals {
    let mut c = fx.app.pool.acquire().await.unwrap();
    costs::totals(&mut c).await.unwrap()
}

#[tokio::test]
async fn an_event_is_priced_from_the_list_price_in_force_and_keeps_the_rates_that_priced_it() {
    let fx = fx().await;
    price(&fx, [3_000_000, 15_000_000, 300_000]).await;
    let first = costs::record(&fx.app.pool, &cost("s1", 0, "k1", None), NOW)
        .await
        .unwrap();
    // 1 Mtok in at $3 + 0.5 Mtok out at $15 + 2 Mtok cache at $0.30, in millionths of a dollar.
    assert_eq!(
        first.event.cost_usd_micros,
        Some(3_000_000 + 7_500_000 + 600_000)
    );
    assert_eq!(first.event.basis, "list_price");
    assert_eq!(first.event.priced_at.as_deref(), Some(PRICED));
    // A new price version prices later events only: history keeps its rates.
    let v2 = price(&fx, [6_000_000, 30_000_000, 600_000]).await;
    assert_eq!(v2.version, 2);
    let second = costs::record(&fx.app.pool, &cost("s1", 1, "k2", None), NOW)
        .await
        .unwrap();
    assert_eq!(second.event.cost_usd_micros, Some(2 * 11_100_000));
    let (a, b): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT rate_input FROM core_cost_events WHERE idempotency_key = 'k1'), \
                (SELECT rate_input FROM core_cost_events WHERE idempotency_key = 'k2')",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!((a, b), (3_000_000, 6_000_000));
}

#[tokio::test]
async fn nobody_set_a_price_so_the_cost_is_unknown_not_zero() {
    let fx = fx().await;
    let r = costs::record(&fx.app.pool, &cost("s1", 0, "k1", None), NOW)
        .await
        .unwrap();
    assert_eq!(
        (r.event.cost_usd_micros, r.event.basis.as_str()),
        (None, "unpriced")
    );
    let t = totals(&fx).await;
    assert_eq!((t.events, t.unpriced, t.cost_usd_micros), (1, 1, 0));
    // The database refuses a 0 that is not a price, and a price with no cost.
    let zero = sqlx::query(
        "INSERT INTO core_cost_events (session, epoch, provider, harness, model, input_tokens, \
         output_tokens, cache_tokens, cost_usd_micros, basis, idempotency_key, occurred_at, created_at) \
         VALUES ('s', 0, 'anthropic', 'claude', 'm', 1, 1, 1, 0, 'unpriced', 'z', ?1, ?1)",
    )
    .bind(NOW)
    .execute(&fx.app.pool)
    .await;
    assert!(zero.is_err());
}

#[tokio::test]
async fn the_providers_own_cost_beats_the_list_price() {
    let fx = fx().await;
    price(&fx, [3_000_000, 15_000_000, 300_000]).await;
    let mut c = cost("s1", 0, "k1", None);
    c.reported_usd_micros = Some(1234);
    let r = costs::record(&fx.app.pool, &c, NOW).await.unwrap();
    assert_eq!(
        (
            r.event.cost_usd_micros,
            r.event.basis.as_str(),
            r.event.priced_at
        ),
        (Some(1234), "provider_reported", None)
    );
}

#[tokio::test]
async fn a_user_definitions_own_prices_are_the_fallback_when_the_book_has_none() {
    let fx = fx().await;
    let d = prov::Definition {
        id: "router".to_owned(),
        name: "Router".to_owned(),
        harness: "codex".to_owned(),
        auth_var: "OPENAI_API_KEY".to_owned(),
        base_url: "https://router.example.com/v1".to_owned(),
        usage_parser: "openai".to_owned(),
        delivery: vec!["env".to_owned()],
        login_methods: vec!["paste".to_owned()],
        models: vec![prov::Model {
            id: "vendor/m1".to_owned(),
            input_per_mtok_micro: 2_000_000,
            output_per_mtok_micro: 8_000_000,
        }],
        priced_at: Some("2026-11-01T00:00:00Z".to_owned()),
        builtin: false,
        version: 0,
    };
    prov::create(&fx.app.pool, &d, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let mut c = cost("s1", 0, "k1", None);
    (c.provider, c.harness, c.model) = ("router", "codex", "vendor/m1");
    let r = costs::record(&fx.app.pool, &c, NOW).await.unwrap();
    // The definition has no cache price: cache tokens are priced as input.
    assert_eq!(
        r.event.cost_usd_micros,
        Some(2_000_000 + 4_000_000 + 4_000_000)
    );
    assert_eq!(r.event.basis, "list_price");
    // A model the definition does not list is unpriced.
    c.model = "vendor/other";
    c.idempotency_key = "k2";
    let r = costs::record(&fx.app.pool, &c, NOW).await.unwrap();
    assert_eq!(r.event.basis, "unpriced");
}

#[tokio::test]
async fn a_retried_report_is_a_no_op_and_each_attempt_is_a_delta() {
    let fx = fx().await;
    price(&fx, [1_000_000, 1_000_000, 1_000_000]).await;
    let a = costs::record(&fx.app.pool, &cost("s1", 0, "k1", None), NOW)
        .await
        .unwrap();
    let again = costs::record(&fx.app.pool, &cost("s1", 0, "k1", None), NOW)
        .await
        .unwrap();
    assert_eq!(
        (a.duplicate, again.duplicate, again.event.id),
        (false, true, a.event.id)
    );
    // The runner restarted its meter: epoch 1 reports its own deltas, and the ledger adds them.
    let mut e1 = cost("s1", 1, "k2", None);
    e1.input_tokens = 10;
    e1.output_tokens = 0;
    e1.cache_tokens = 0;
    costs::record(&fx.app.pool, &e1, NOW).await.unwrap();
    let t = totals(&fx).await;
    assert_eq!((t.events, t.tokens), (2, 3_500_000 + 10));
    let by_session = costs::list(&fx.app.pool, Some("s1"), None, 10)
        .await
        .unwrap();
    assert_eq!(
        by_session.iter().map(|e| e.epoch).collect::<Vec<_>>(),
        [1, 0]
    );
}

#[tokio::test]
async fn an_interrupted_turn_is_marked_approximate() {
    let fx = fx().await;
    let mut c = cost("s1", 0, "k1", None);
    c.approximate = true;
    let r = costs::record(&fx.app.pool, &c, NOW).await.unwrap();
    assert!(r.event.approximate);
}

#[tokio::test]
async fn a_correction_adds_the_difference_and_the_ledger_sums_to_the_bill() {
    let fx = fx().await;
    price(&fx, [1_000_000, 1_000_000, 1_000_000]).await;
    let mut c = cost("s1", 0, "k1", None);
    c.subjects = &[("company", "7"), ("agent", "a1")];
    let o = costs::record(&fx.app.pool, &c, NOW).await.unwrap().event;
    assert_eq!(o.cost_usd_micros, Some(3_500_000));
    let mut conn = fx.app.pool.acquire().await.unwrap();
    // The bill came in lower.
    let fix = costs::correct_in(&mut conn, o.id, 3_000_000, "bill-1", NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            fix.basis.as_str(),
            fix.cost_usd_micros,
            fix.corrects_id,
            fix.input_tokens
        ),
        ("billing_corrected", Some(-500_000), Some(o.id), 0)
    );
    // Correcting to what it already is, or retrying the key, adds nothing.
    assert!(
        costs::correct_in(&mut conn, o.id, 3_000_000, "bill-2", NOW)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        costs::correct_in(&mut conn, o.id, 9, "bill-1", NOW)
            .await
            .unwrap()
            .is_none()
    );
    // A second correction is against the running total, and follows the same subjects.
    costs::correct_in(&mut conn, o.id, 3_200_000, "bill-3", NOW)
        .await
        .unwrap()
        .unwrap();
    drop(conn);
    assert_eq!(totals(&fx).await.cost_usd_micros, 3_200_000);
    let subjects: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_cost_subjects WHERE event_id IN \
         (SELECT id FROM core_cost_events WHERE corrects_id IS NOT NULL) AND subject_id IN ('7', 'a1')",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(subjects, 4);
    let mut conn = fx.app.pool.acquire().await.unwrap();
    assert_eq!(
        code(costs::correct_in(&mut conn, 9999, 1, "x", NOW).await),
        "not_found"
    );
    assert_eq!(
        code(costs::correct_in(&mut conn, o.id, -1, "x", NOW).await),
        "bad_request"
    );
}

#[tokio::test]
async fn the_ledger_is_insert_only() {
    let fx = fx().await;
    let mut c = cost("s1", 0, "k1", None);
    c.subjects = &[("agent", "a1")];
    costs::record(&fx.app.pool, &c, NOW).await.unwrap();
    for sql in [
        "UPDATE core_cost_events SET input_tokens = 0",
        "UPDATE core_cost_events SET account_id = 9",
        "DELETE FROM core_cost_events",
        "UPDATE core_cost_subjects SET subject_id = 'x'",
    ] {
        assert!(
            sqlx::query(sql).execute(&fx.app.pool).await.is_err(),
            "{sql}"
        );
    }
    assert_eq!(totals(&fx).await.events, 1);
}

#[tokio::test]
async fn deleting_an_account_leaves_its_cost_history_and_totals() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    price(&fx, [1_000_000, 1_000_000, 1_000_000]).await;
    costs::record(&fx.app.pool, &cost("s1", 0, "k1", Some(a.id)), NOW)
        .await
        .unwrap();
    let before = totals(&fx).await;
    acc::delete(&fx.app.pool, a.id, &fx.dev.id, BY)
        .await
        .unwrap();
    assert_eq!(totals(&fx).await, before);
    let events = costs::list(&fx.app.pool, None, Some(a.id), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
}

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
