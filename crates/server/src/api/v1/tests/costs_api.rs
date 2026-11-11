//! The cost ledger routes (KAN-449): the price list is `read`; the ledger and the usage report are `admin`
//! (no step-up) and show no key, secret name or runner; a price and a limit are `admin` plus a step-up; nothing writes the ledger over HTTP.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::accounts_store::{V1, make, setup};
use super::*;
use crate::store::costs::{self, NewCost};

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

fn price_body() -> Value {
    json!({"provider": "anthropic", "model": "claude-x", "input_per_mtok_micro": 3_000_000,
           "output_per_mtok_micro": 15_000_000, "cache_per_mtok_micro": 300_000,
           "priced_at": "2026-11-01T00:00:00Z"})
}

#[tokio::test]
async fn a_phone_reads_prices_only_and_the_ledger_and_usage_need_admin_and_name_no_secret() {
    let (fx, vm, s) = setup().await;
    let phone = fx.enroll("phone", &["read"]).await;
    let a = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    let (st, p) = call(&fx, &fx.dev, Method::PUT, "/api/v1/prices", price_body()).await;
    assert_eq!(st, StatusCode::OK, "{p}");
    assert_eq!(
        (p["version"].as_i64(), p["priced_at"].as_str()),
        (Some(1), Some("2026-11-01T00:00:00.000Z"))
    );
    let c = NewCost {
        session: "s1",
        epoch: 0,
        account_id: Some(a.id),
        legacy_account_id: None,
        provider: "anthropic",
        harness: "claude",
        model: "claude-x",
        input_tokens: 1_000_000,
        output_tokens: 0,
        cache_tokens: 0,
        reported_usd_micros: None,
        approximate: true,
        subjects: &[("company", "7")],
        idempotency_key: "k1",
        occurred_at: NOW,
    };
    costs::record(&fx.app.pool, &c, NOW).await.unwrap();

    for uri in ["/api/v1/costs", "/api/v1/accounts/usage"] {
        let (st, b) = call(&fx, &phone, Method::GET, uri, Value::Null).await;
        assert_eq!(
            (st, b["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("forbidden_scope")),
            "{uri}: {b}"
        );
    }
    let (st, list) = call(
        &fx,
        &fx.dev,
        Method::GET,
        "/api/v1/costs?session=s1&limit=5",
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{list}");
    let e = &list[0];
    assert_eq!(
        (
            e["cost_usd_micros"].as_i64(),
            e["basis"].as_str(),
            e["approximate"].as_bool()
        ),
        (Some(3_000_000), Some("list_price"), Some(true))
    );
    // Citadel's old account id is a migration aid, not part of the contract.
    assert!(e.get("legacy_account_id").is_none(), "{e}");
    let (_, none) = call(
        &fx,
        &fx.dev,
        Method::GET,
        "/api/v1/costs?session=other",
        Value::Null,
    )
    .await;
    assert_eq!(none, json!([]));
    let (_, prices) = call(&fx, &phone, Method::GET, "/api/v1/prices", Value::Null).await;
    assert!(
        prices
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["model"] == "claude-x"),
        "the set price is listed beside the shipped ones"
    );

    let (st, usage) = call(
        &fx,
        &fx.dev,
        Method::GET,
        "/api/v1/accounts/usage",
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{usage}");
    assert_eq!(usage[0]["five_hours"]["total_tokens"], 1_000_000);
    assert_eq!(usage[0]["by_company"][0]["company"], "7");
    // An event carrying only Citadel's old account id is not counted for any Core account.
    let legacy = NewCost {
        account_id: None,
        legacy_account_id: Some(77),
        idempotency_key: "k2",
        ..c
    };
    costs::record(&fx.app.pool, &legacy, NOW).await.unwrap();
    let (_, again) = call(
        &fx,
        &fx.dev,
        Method::GET,
        "/api/v1/accounts/usage",
        Value::Null,
    )
    .await;
    assert_eq!(
        (
            again.as_array().map(Vec::len),
            again[0]["five_hours"]["total_tokens"].as_i64()
        ),
        (Some(1), Some(1_000_000))
    );
    let mut keys: Vec<_> = usage[0].as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "account_id",
            "by_company",
            "five_hours",
            "limits",
            "max_utilisation_bps",
            "recent_drops",
            "seven_days"
        ]
    );
    for body in [list.to_string(), usage.to_string(), prices.to_string()] {
        assert!(
            !body.contains("acct.") && !body.contains(&vm.id) && !body.contains(V1),
            "{body}"
        );
    }
    // The ledger cannot be written over HTTP, by anyone.
    for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
        let (st, _) = call(&fx, &fx.dev, m, "/api/v1/costs", json!({"session": "s"})).await;
        // Not a route: refused by the scope gate (deny by default), never accepted.
        assert!(
            [
                StatusCode::FORBIDDEN,
                StatusCode::METHOD_NOT_ALLOWED,
                StatusCode::NOT_FOUND
            ]
            .contains(&st),
            "{st}"
        );
    }
}

#[tokio::test]
async fn a_price_and_a_limit_need_admin_and_a_step_up() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    let phone = fx.enroll("phone", &["read"]).await;
    let plain = TestDevice::enroll(
        &fx.app.pool,
        "plain",
        "device",
        &["read", "admin"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    let sess = fx.app.auth.issue_session(&plain.id, fx.clock.unix());
    plain.set_session(Some(sess.id));
    let limit = json!({"unit": "tokens", "window_secs": 3600, "cap": 100});
    let writes = [
        (Method::PUT, "/api/v1/prices".to_owned(), price_body()),
        (
            Method::PUT,
            format!("/api/v1/accounts/{}/limits", a.id),
            limit.clone(),
        ),
        (
            Method::DELETE,
            format!("/api/v1/accounts/{}/limits/tokens/3600", a.id),
            Value::Null,
        ),
    ];
    for (m, uri, body) in &writes {
        let (st, b) = call(&fx, &phone, m.clone(), uri, body.clone()).await;
        assert_eq!(
            (st, b["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("forbidden_scope")),
            "{m} {uri}: {b}"
        );
        let (st, b) = call(&fx, &plain, m.clone(), uri, body.clone()).await;
        assert_eq!(
            (st, b["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("step_up_required")),
            "{m} {uri}: {b}"
        );
    }
    let n: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM core_prices) + (SELECT count(*) FROM core_account_limits)",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(n, 0, "nothing was written");
    // Stepped up: a limit is set, shows in the usage report, is cleared once.
    let (st, b) = call(&fx, &fx.dev, Method::PUT, &writes[1].1, limit).await;
    assert_eq!((st, b["cap"].as_i64()), (StatusCode::OK, Some(100)), "{b}");
    let (_, usage) = call(
        &fx,
        &fx.dev,
        Method::GET,
        "/api/v1/accounts/usage",
        Value::Null,
    )
    .await;
    assert_eq!(usage[0]["limits"][0]["cap"], 100);
    let (_, gone) = call(&fx, &fx.dev, Method::DELETE, &writes[2].1, Value::Null).await;
    assert_eq!(gone["cleared"], true);
    let (_, gone) = call(&fx, &fx.dev, Method::DELETE, &writes[2].1, Value::Null).await;
    assert_eq!(gone["cleared"], false);
    // Malformed writes: 400 for the value, 404 for the account, and nothing quotes the input.
    let bad = json!({"unit": "tokens", "window_secs": 0, "cap": 5});
    let (st, _) = call(&fx, &fx.dev, Method::PUT, &writes[1].1, bad).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        "/api/v1/accounts/999/limits",
        json!({"unit": "tokens", "window_secs": 60, "cap": 5}),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = call(
        &fx,
        &fx.dev,
        Method::DELETE,
        "/api/v1/accounts/999/limits/tokens/60",
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let mut p = price_body();
    p["input_per_mtok_micro"] = json!(-1);
    let (st, _) = call(&fx, &fx.dev, Method::PUT, "/api/v1/prices", p).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let audited: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_events WHERE action IN ('price.set', 'account.limit_set', 'account.limit_cleared') ORDER BY seq")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(audited, ["account.limit_set", "account.limit_cleared"]);
}
