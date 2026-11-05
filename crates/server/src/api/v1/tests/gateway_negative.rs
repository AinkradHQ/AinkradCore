//! The KAN-445 sweep, extended to the gateway's surface (KAN-435 G8): the account routes G7 added,
//! the answers that carry a rejected or a rotated key, the audit log, and the session limits'
//! out-of-range values. `account_secrets.rs` holds the sweep over the routes without a parameter;
//! this walks the ones that have one, and the writes.

use ainkrad_core::settings::{Key, Scope};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::accounts_gateway as ag;
use super::*;
use crate::ops::secretbox::SecretBox;
use crate::store::{account_keys, providers as prov};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;
/// Dummy keys of the shapes the redactor reads: nothing here is a real credential.
const OR: &str = "sk-or-v1-0123456789abcdefghijklmnopqrstuvwxyzTESTONLY";
const OR2: &str = "sk-or-v1-zyxwvutsrqponmlkjihgfedcba9876543210TESTONLY";
const ANT: &str = "sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyzTESTONLY";
const BAD1: &str = "sk-ant-api03-REJECTEDONE0123456789abcdefghijklmnTESTONLY";
const BAD2: &str = "sk-ant-api03-REJECTEDTWO0123456789abcdefghijklmnTESTONLY";

async fn setup() -> (Fx, TestDevice) {
    let mut fx = fx().await;
    fx.app.secrets = Some(Arc::new(SecretBox::new(&[7; 32])));
    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(100_000, 1.0),
    });
    crate::store::settings::set(&fx.app.pool, Key::SecretsMode, Scope::Server, "1", BY, NOW)
        .await
        .unwrap();
    let vm = super::secrets::runner(&fx, "vm").await;
    (fx, vm)
}

/// The status and the raw text of a call (a route may answer text, not JSON).
async fn call(fx: &Fx, m: Method, uri: &str, body: Value) -> (StatusCode, String) {
    let body = (!body.is_null()).then_some(body);
    let res = router(fx.app.clone())
        .oneshot(req(m, uri, Some(&fx.dev), body))
        .await
        .unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn id_of(text: &str) -> i64 {
    let v: Value = serde_json::from_str(text).unwrap();
    v["account"]["id"]
        .as_i64()
        .or_else(|| v["account"]["id"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or_else(|| panic!("no id: {text}"))
}

#[tokio::test]
async fn no_gateway_answer_or_audit_row_holds_a_key_stored_rotated_or_rejected() {
    let (fx, vm) = setup().await;
    ag::open_gate(&fx).await;
    let p = &fx.app.pool;
    prov::create(
        p,
        &ag::router("openrouter", Some("sk-or-v1-")),
        "d_x",
        BY,
        NOW,
    )
    .await
    .unwrap();
    let mut seen: Vec<(String, String)> = Vec::new();
    let go = |m: Method, uri: String, body: Value| {
        let fx = &fx;
        async move {
            let (st, text) = call(fx, m, &uri, body).await;
            (st, text, uri)
        }
    };
    let mut note = |r: &(StatusCode, String, String)| seen.push((r.2.clone(), r.1.clone()));

    let or = go(
        Method::POST,
        "/api/v1/accounts".into(),
        json!({"provider": "openrouter", "label": "or-main", "value": OR}),
    )
    .await;
    assert_eq!(or.0, StatusCode::OK, "{}", or.1);
    note(&or);
    let or_id = id_of(&or.1);
    let ant = go(
        Method::POST,
        "/api/v1/accounts".into(),
        json!({"provider": "anthropic", "label": "claude", "value": ANT}),
    )
    .await;
    assert_eq!(ant.0, StatusCode::OK, "{}", ant.1);
    note(&ant);
    let ant_id = id_of(&ant.1);
    // A key for another host, pasted at create and at rotation: refused, and the refusal does not
    // echo what was pasted.
    let bad = go(
        Method::POST,
        "/api/v1/accounts".into(),
        json!({"provider": "openrouter", "label": "wrong", "value": BAD1}),
    )
    .await;
    assert!(bad.0.is_client_error(), "{} {}", bad.0, bad.1);
    note(&bad);
    let bad = go(
        Method::PUT,
        format!("/api/v1/accounts/{or_id}/secret"),
        json!({"value": BAD2}),
    )
    .await;
    assert!(bad.0.is_client_error(), "{} {}", bad.0, bad.1);
    note(&bad);
    // A rotation: neither the old nor the new value comes back.
    let rot = go(
        Method::PUT,
        format!("/api/v1/accounts/{or_id}/secret"),
        json!({"value": OR2}),
    )
    .await;
    assert_eq!(rot.0, StatusCode::OK, "{}", rot.1);
    note(&rot);
    for (m, uri, body) in [
        (
            Method::PUT,
            format!("/api/v1/accounts/{or_id}/session-limits"),
            json!({"max_tokens": 400_000}),
        ),
        (
            Method::POST,
            format!("/api/v1/accounts/{or_id}/test"),
            Value::Null,
        ),
    ] {
        let r = go(m, uri, body).await;
        note(&r);
    }
    account_keys::record_test(p, or_id, "auth_failed", 12, &vm.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    // Every route that can be read, the parameterised account ones among them.
    let mut paths: Vec<String> = super::super::scopes::ROUTES
        .iter()
        .filter(|(m, p, _)| *m == "GET" && !p.contains('{') && !p.ends_with("/ws"))
        .map(|(_, p, _)| (*p).to_owned())
        .collect();
    for id in [or_id, ant_id] {
        paths.push(format!("/api/v1/accounts/{id}"));
    }
    let mut answered = 0;
    for uri in paths {
        let r = go(Method::GET, uri, Value::Null).await;
        assert!(!r.0.is_server_error(), "{}: {}", r.2, r.0);
        answered += usize::from(r.0 == StatusCode::OK);
        note(&r);
    }
    assert!(answered >= 8, "only {answered} routes answered 200");
    let audit: Option<String> =
        sqlx::query_scalar("SELECT group_concat(details, ' ') FROM audit_events")
            .fetch_one(p)
            .await
            .unwrap();
    let audit = audit.unwrap_or_default();
    assert!(
        audit.contains("account.tested") || audit.contains("auth_failed"),
        "no audit row to check"
    );
    for key in [OR, OR2, ANT, BAD1, BAD2] {
        for (uri, text) in &seen {
            assert!(!text.contains(key), "{uri} carried a key");
        }
        assert!(!audit.contains(key), "the audit log carries a key");
    }
}

#[tokio::test]
async fn session_limits_out_of_range_are_refused_and_change_nothing() {
    let (fx, vm, s) = super::accounts_store::setup().await;
    let a = super::accounts_store::make(
        &fx,
        &s,
        "claude-main",
        super::accounts_store::V1,
        std::slice::from_ref(&vm.id),
    )
    .await;
    let uri = format!("/api/v1/accounts/{}/session-limits", a.id);
    let good = json!({"max_tokens": 400_000, "max_usd_micros": 5_000_000});
    assert_eq!(
        call(&fx, Method::PUT, &uri, good.clone()).await.0,
        StatusCode::OK
    );
    let floor = i64::try_from(crate::store::gateway::MIN_CEILING_TOKENS).unwrap();
    let bad = [
        json!({"max_tokens": 1_000_000_000_001_i64}),
        json!({"max_usd_micros": 1_000_000_000_001_i64}),
        json!({"max_tokens": i64::MAX}),
        json!({"max_usd_micros": i64::MIN}),
        json!({"max_tokens": 9_223_372_036_854_775_808_u64}),
        json!({"max_usd_micros": 18_446_744_073_709_551_615_u64}),
        json!({"max_tokens": 1.5}),
        json!({"max_usd_micros": true}),
        json!({"max_tokens": [400_000]}),
        json!({"max_tokens": floor - 1}),
        json!({"max_usd_micros": 0}),
    ];
    for b in &bad {
        let (st, text) = call(&fx, Method::PUT, &uri, b.clone()).await;
        assert!(st.is_client_error(), "{b}: {st} {text}");
    }
    // Nothing moved, and nothing was audited beyond the one good set.
    let (_, one) = call(
        &fx,
        Method::GET,
        &format!("/api/v1/accounts/{}", a.id),
        Value::Null,
    )
    .await;
    let one: Value = serde_json::from_str(&one).unwrap();
    assert_eq!(one["session_limits"], good);
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'account.session_limits_set'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(n, 1);
    // The edges themselves are allowed.
    let edge = json!({"max_tokens": floor, "max_usd_micros": 1_000_000_000_000_i64});
    assert_eq!(call(&fx, Method::PUT, &uri, edge).await.0, StatusCode::OK);
}
