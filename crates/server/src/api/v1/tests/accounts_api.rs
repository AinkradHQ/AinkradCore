//! The account, pool, binding and provider routes (KAN-432): reading is `read` and shows no key,
//! no secret name and no runner scope; every write is `admin` plus a step-up; a key is written,
//! never read. The gate `secrets.provider_accounts` stays 0 throughout.

use ainkrad_core::settings::{Key, Scope};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::ops::secretbox::SecretBox;

const V1: &str = "throwaway-route-value-one-5a91c3";
const V2: &str = "throwaway-route-value-two-77d0be";

async fn setup() -> (Fx, TestDevice, TestDevice) {
    let mut fx = fx().await;
    fx.app.secrets = Some(Arc::new(SecretBox::new(&[7; 32])));
    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(100_000, 1.0),
    });
    crate::store::settings::set(
        &fx.app.pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    let vm = super::secrets::runner(&fx, "vm").await;
    let reader = fx.enroll("phone", &["read"]).await;
    (fx, vm, reader)
}

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

/// An admin whose session never stepped up.
async fn plain_admin(fx: &Fx) -> TestDevice {
    let d = TestDevice::enroll(
        &fx.app.pool,
        "plain",
        "device",
        &["read", "admin"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    let s = fx.app.auth.issue_session(&d.id, fx.clock.unix());
    d.set_session(Some(s.id));
    d
}

async fn create(fx: &Fx, vm: &TestDevice, label: &str, value: &str) -> Value {
    let body = json!({"provider": "anthropic", "label": label, "value": value, "runners": [vm.id]});
    let (s, b) = call(fx, &fx.dev, Method::POST, "/api/v1/accounts", body).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    b
}

#[tokio::test]
async fn a_key_is_written_never_read_and_a_phone_sees_neither_secret_name_nor_runners() {
    let (fx, vm, phone) = setup().await;
    let made = create(&fx, &vm, "claude-main", V1).await;
    let id = made["account"]["id"].as_i64().unwrap();
    assert_eq!(made["runners"], json!([vm.id]));
    assert_eq!(made["account"]["cap"], 4);
    assert_eq!(made["account"]["masked_tail"], &V1[V1.len() - 4..]);
    // What a read device gets: exactly these fields.
    let (s, list) = call(&fx, &phone, Method::GET, "/api/v1/accounts", Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    let mut keys: Vec<_> = list[0].as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "base_url",
            "cap",
            "created_at",
            "id",
            "label",
            "last_test",
            "last_used_at",
            "masked_tail",
            "provider",
            "session_limits",
            "state",
            "state_reason",
            "state_until",
            "updated_at"
        ]
    );
    let (_, one) = call(
        &fx,
        &phone,
        Method::GET,
        &format!("/api/v1/accounts/{id}"),
        Value::Null,
    )
    .await;
    // Sweep every read of the surface, as admin and as a phone: no key, no `acct.` name, no runner id.
    let mut seen = vec![list.to_string(), one.to_string(), made.to_string()];
    for uri in [
        "/api/v1/accounts",
        "/api/v1/accounts/providers",
        "/api/v1/pools",
        "/api/v1/bindings",
        "/api/v1/secrets",
    ] {
        for dev in [&phone, &fx.dev] {
            let (_, b) = call(&fx, dev, Method::GET, uri, Value::Null).await;
            seen.push(b.to_string());
        }
    }
    for (i, text) in seen.iter().enumerate() {
        assert!(!text.contains(V1), "read {i} leaked the key: {text}");
    }
    for text in &seen[..2] {
        assert!(!text.contains("acct.") && !text.contains(&vm.id), "{text}");
    }
    // The audit log holds neither the key nor a base64 of it.
    let audit: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_events")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    assert!(audit.iter().all(|d| !d.contains(V1)));
    // A malformed body is refused with one fixed message that never quotes the input.
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/accounts",
        json!({"provider": "anthropic", "label": "x", "value": V2, "cap": "four"}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    assert!(!b.to_string().contains(V2));
}

#[tokio::test]
async fn every_write_needs_admin_and_a_step_up_and_a_phone_may_only_read() {
    let (fx, _vm, phone) = setup().await;
    let plain = plain_admin(&fx).await;
    let writes = [
        (
            Method::POST,
            "/api/v1/accounts",
            json!({"provider": "anthropic", "label": "a", "value": V1}),
        ),
        (
            Method::PUT,
            "/api/v1/accounts/1/secret",
            json!({"value": V2}),
        ),
        (
            Method::PUT,
            "/api/v1/accounts/1/state",
            json!({"state": "disabled"}),
        ),
        (Method::PUT, "/api/v1/accounts/1/cap", json!({"cap": 8})),
        (Method::DELETE, "/api/v1/accounts/1", Value::Null),
        (Method::POST, "/api/v1/accounts/providers", json!({})),
        (Method::PUT, "/api/v1/accounts/providers/x", json!({})),
        (Method::DELETE, "/api/v1/accounts/providers/x", Value::Null),
        (
            Method::POST,
            "/api/v1/pools",
            json!({"name": "p", "provider": "anthropic"}),
        ),
        (Method::DELETE, "/api/v1/pools/1", Value::Null),
        (Method::PUT, "/api/v1/pools/1/members/1", Value::Null),
        (Method::DELETE, "/api/v1/pools/1/members/1", Value::Null),
        (Method::PUT, "/api/v1/pools/1/default", Value::Null),
        (
            Method::PUT,
            "/api/v1/bindings",
            json!({"agent": "a", "pool_id": 1}),
        ),
        (Method::DELETE, "/api/v1/bindings/a/anthropic", Value::Null),
    ];
    for (m, uri, body) in writes {
        let (s, b) = call(&fx, &phone, m.clone(), uri, body.clone()).await;
        assert_eq!(
            (s, b["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("forbidden_scope")),
            "{m} {uri}: {b}"
        );
        let (s, b) = call(&fx, &plain, m.clone(), uri, body).await;
        assert_eq!(
            (s, b["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("step_up_required")),
            "{m} {uri}: {b}"
        );
    }
    // Nothing was written.
    let n: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM core_accounts) + (SELECT count(*) FROM core_pools)",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(n, 0);
    // A phone and a plain admin read.
    for dev in [&phone, &plain] {
        for uri in [
            "/api/v1/accounts",
            "/api/v1/accounts/providers",
            "/api/v1/pools",
            "/api/v1/bindings",
        ] {
            assert_eq!(
                call(&fx, dev, Method::GET, uri, Value::Null).await.0,
                StatusCode::OK,
                "{uri}"
            );
        }
    }
}

#[tokio::test]
async fn an_account_is_replaced_disabled_capped_and_deleted_through_the_routes() {
    let (fx, vm, _phone) = setup().await;
    let made = create(&fx, &vm, "claude-main", V1).await;
    let id = made["account"]["id"].as_i64().unwrap();
    let base = format!("/api/v1/accounts/{id}");
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &format!("{base}/secret"),
        json!({"value": V2}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["account"]["masked_tail"], &V2[V2.len() - 4..]);
    assert!(!b.to_string().contains(V2));
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &format!("{base}/state"),
        json!({"state": "disabled", "reason": "rotating"}),
    )
    .await;
    assert_eq!(
        (s, b["state"].as_str(), b["state_reason"].as_str()),
        (StatusCode::OK, Some("disabled"), Some("rotating"))
    );
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &format!("{base}/state"),
        json!({"state": "nope"}),
    )
    .await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("bad_request"))
    );
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &format!("{base}/cap"),
        json!({"cap": 8}),
    )
    .await;
    assert_eq!((s, b["cap"].as_i64()), (StatusCode::OK, Some(8)));
    let (s, _) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &format!("{base}/cap"),
        json!({"cap": 65}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/accounts",
        json!({"provider": "anthropic", "label": "claude-main", "value": V1}),
    )
    .await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict"))
    );
    let (s, _) = call(
        &fx,
        &fx.dev,
        Method::GET,
        "/api/v1/accounts/not-a-number",
        Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&fx, &fx.dev, Method::DELETE, &base, Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        call(&fx, &fx.dev, Method::GET, &base, Value::Null).await.0,
        StatusCode::NOT_FOUND
    );
    let (_, secrets) = call(&fx, &fx.dev, Method::GET, "/api/v1/secrets", Value::Null).await;
    assert_eq!(secrets, json!([]), "the key went with the account");
    // The broker off refuses the store and leaves nothing.
    crate::store::settings::set(
        &fx.app.pool,
        Key::SecretsMode,
        Scope::Server,
        "0",
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/accounts",
        json!({"provider": "anthropic", "label": "again", "value": V1}),
    )
    .await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("secrets_disabled"))
    );
    assert_eq!(
        call(&fx, &fx.dev, Method::GET, "/api/v1/accounts", Value::Null)
            .await
            .1,
        json!([])
    );
}

mod pool_routes;
