//! Exporting secrets (E2-6, D-4): the values come back to an elevated admin device, audited
//! without them; no step-up, no scope, no broker and too many asks are refused; accounts, module
//! secrets and files stay out.

use ainkrad_core::settings::Key;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::secrets::{V1, V2, broker, call, code, create, post_secret, set, trail};
use super::*;

const EXPORT: &str = "/api/v1/secrets/export";

#[tokio::test]
async fn an_owner_exports_the_values_and_the_audit_row_never_holds_them() {
    let (fx, _vm) = broker().await;
    create(&fx, "git.token", V1, &[]).await;
    create(&fx, "other.key", V2, &[]).await;
    let (s, all) = call(&fx, &fx.dev, Method::POST, EXPORT, Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{all}");
    assert_eq!(all["count"], 2);
    assert_eq!(all["items"][0]["name"], "git.token");
    assert_eq!(all["items"][0]["value"], V1);
    assert_eq!(all["items"][1]["value"], V2);
    let t = trail(&fx).await;
    assert!(t.contains("secret.exported"), "{t}");
    assert!(!t.contains(V1) && !t.contains(V2), "{t}");
}

#[tokio::test]
async fn an_export_leaves_out_accounts_module_secrets_and_files() {
    let (fx, _vm) = broker().await;
    create(&fx, "git.token", V1, &[]).await;
    create(&fx, "brain.key", V2, &[]).await;
    create(&fx, "leyline.key", V2, &[]).await;
    post_secret(&fx, json!({"name": "acct.anthropic.main", "value": V2})).await;
    let file =
        json!({"name": "ssh.config", "kind": "file", "file_name": "config", "value": "aGVsbG8="});
    post_secret(&fx, file).await;
    let (s, all) = call(&fx, &fx.dev, Method::POST, EXPORT, Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{all}");
    assert_eq!(all["count"], 1, "{all}");
    assert_eq!(all["items"][0]["name"], "git.token");
}

#[tokio::test]
async fn exporting_needs_a_step_up_the_admin_scope_and_a_live_broker() {
    let (fx, vm) = broker().await;
    create(&fx, "git.token", V1, &[]).await;
    let reader = fx.enroll("phone", &["read"]).await;
    for dev in [&reader, &vm] {
        let r = call(&fx, dev, Method::POST, EXPORT, Value::Null).await;
        assert_eq!(code(&r), (StatusCode::FORBIDDEN, "forbidden_scope"));
    }
    let mac = TestDevice::enroll(
        &fx.app.pool,
        "mac",
        "device",
        &ALL,
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    let s = fx.app.auth.issue_session(&mac.id, fx.clock.unix());
    mac.set_session(Some(s.id));
    let r = call(&fx, &mac, Method::POST, EXPORT, Value::Null).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "step_up_required"));
    set(&fx, Key::SecretsMode, 0).await;
    let r = call(&fx, &fx.dev, Method::POST, EXPORT, Value::Null).await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, "secrets_disabled"));
    assert!(!trail(&fx).await.contains(V1));
}

#[tokio::test]
async fn exporting_is_rate_limited_per_device() {
    let (fx, _vm) = broker().await;
    create(&fx, "git.token", V1, &[]).await;
    for _ in 0..2 {
        let r = call(&fx, &fx.dev, Method::POST, EXPORT, Value::Null).await;
        assert_eq!(r.0, StatusCode::OK);
    }
    let r = call(&fx, &fx.dev, Method::POST, EXPORT, Value::Null).await;
    assert_eq!(code(&r), (StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn nothing_that_carries_an_exported_value_is_debug() {
    use std::marker::PhantomData;
    trait NotDebug {
        const IS: bool = false;
    }
    struct Probe<T>(PhantomData<T>);
    impl<T> NotDebug for Probe<T> {}
    #[allow(dead_code)]
    impl<T: std::fmt::Debug> Probe<T> {
        const IS: bool = true;
    }
    assert!(!Probe::<super::super::secret_export::SecretsExport>::IS);
    assert!(!Probe::<crate::store::secrets::Exported>::IS);
}
