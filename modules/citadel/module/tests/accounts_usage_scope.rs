//! The account usage report names no secret, delivery, runner or config dir to anyone (KAN-432):
//! not in the store type behind it, and not in the JSON a read, company-scoped or admin device
//! gets. The route fields are an explicit list, so a new field has to be added here on purpose.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{Value, json};

async fn broker_secret(fx: &Fx, name: &str) {
    sqlx::query(
        "INSERT INTO core_secrets (name, owner, runners, delivery, version, key_id, sealed, size, \
         created_at, updated_at) VALUES (?, ?, '[\"runner-1\"]', 'file', 1, '0123456789abcdef', ?, 5, 'now', 'now')",
    )
    .bind(name)
    .bind(&fx.dev.id)
    .bind(b"x".as_slice())
    .execute(&fx.app.pool)
    .await
    .unwrap();
}

async fn account(fx: &Fx) -> i64 {
    broker_secret(fx, "claude-main").await;
    let body = json!({"harness": "claude", "label": "main", "secret_name": "claude-main",
                      "config_dir": "accounts/main"});
    let (s, a) = call(fx, Some(&fx.dev), Method::POST, "/accounts", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{a}");
    a["id"].as_i64().unwrap()
}

#[tokio::test]
async fn the_usage_store_carries_no_routing_detail() {
    let fx = fx().await;
    let id = account(&fx).await;
    let now = fx.app.clock.now();
    let all = citadel_module::store::accounts::account_usage(&fx.app.pool, None, &now)
        .await
        .unwrap();
    let a = &all.iter().find(|u| u.account.id.0 == id).unwrap().account;
    assert!(a.secret_name.is_empty(), "secret_name: {:?}", a.secret_name);
    assert!(a.delivery.is_empty(), "delivery: {:?}", a.delivery);
    assert!(a.runners.is_empty(), "runners: {:?}", a.runners);
    // Control: the account itself still has them (the admin list, the lease path).
    let held = citadel_module::store::accounts::get_account(
        &fx.app.pool,
        citadel_module::domain::gov::AccountId(id),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(held.secret_name, "claude-main");
}

/// Every object key in `v`, at any depth.
fn keys(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                out.push(k.clone());
                keys(v, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|v| keys(v, out)),
        _ => {}
    }
}

const ALLOWED: &[&str] = &[
    "id",
    "harness",
    "label",
    "billing",
    "status",
    "status_reason",
    "status_until",
    "last_used_at",
    "plan_tier",
    "signal",
    "company_ids",
    "five_hours",
    "seven_days",
    "max_utilisation_bps",
    "recent_drops",
    "limits",
    "by_company",
    "input_tokens",
    "output_tokens",
    "cache_tokens",
    "total_tokens",
    "messages",
    "cost_usd_micros",
    "unit",
    "window_secs",
    "cap",
    "used",
    "warn_percent",
    "exhausted",
    "company_id",
];

#[tokio::test]
async fn every_usage_reader_gets_only_the_listed_fields() {
    let fx = fx().await;
    let reader = enroll(&fx.app, "reader", &["read"], true).await;
    let id = account(&fx).await;
    let cid = company(&fx).await;
    let (s, v) = call(
        &fx,
        Some(&fx.dev),
        Method::PUT,
        &format!("/accounts/{id}/companies/{cid}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for (who, dev) in [("read", &reader), ("admin", &fx.dev)] {
        for p in [
            "/accounts/usage".to_owned(),
            format!("/companies/{cid}/account-usage"),
        ] {
            let (s, body) = call(&fx, Some(dev), Method::GET, &p, None).await;
            assert_eq!(s, StatusCode::OK, "{who} {p}: {body}");
            assert!(
                body.as_array().is_some_and(|a| !a.is_empty()),
                "{who} {p}: no report"
            );
            let mut found = vec![];
            keys(&body, &mut found);
            for k in &found {
                assert!(
                    ALLOWED.contains(&k.as_str()),
                    "{who} {p} returned the unlisted field {k}"
                );
            }
            let text = body.to_string();
            for leak in ["claude-main", "runner-1", "accounts/main"] {
                assert!(!text.contains(leak), "{who} {p} leaks {leak}: {text}");
            }
        }
    }
}

async fn company(fx: &Fx) -> i64 {
    let body = json!({"name": "A"});
    let (s, c) = call(fx, Some(&fx.dev), Method::POST, "/companies", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{c}");
    c["id"].as_i64().unwrap()
}
