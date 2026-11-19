//! Showing and exporting secrets (E2-6, D-4): the value comes back to an elevated admin device,
//! audited without it; no step-up, no scope, no broker, no secret and too many asks are refused.

use ainkrad_core::settings::Key;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::secrets::{V1, V2, broker, call, code, create, set, trail};
use super::*;

const REVEAL: &str = "/api/v1/secrets/git.token/reveal";
const EXPORT: &str = "/api/v1/secrets/export";

#[tokio::test]
async fn an_owner_sees_a_value_and_the_audit_row_never_holds_it() {
    let (fx, _vm) = broker().await;
    assert_eq!(create(&fx, "git.token", V1, &[]).await.0, StatusCode::OK);
    let (s, got) = call(&fx, &fx.dev, Method::POST, REVEAL, Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{got}");
    assert_eq!((&got["value"], &got["version"]), (&json!(V1), &json!(1)));
    assert_eq!(got["hide_after_secs"], 15);
    let t = trail(&fx).await;
    assert!(
        t.contains("secret.revealed") && t.contains("git.token"),
        "{t}"
    );
    assert!(!t.contains(V1), "{t}");

    create(&fx, "other.key", V2, &[]).await;
    let (s, all) = call(&fx, &fx.dev, Method::POST, EXPORT, Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{all}");
    assert_eq!(all["count"], 2);
    assert_eq!(all["items"][0]["name"], "git.token");
    assert_eq!(all["items"][1]["value"], V2);
    let t = trail(&fx).await;
    assert!(t.contains("secret.exported") && !t.contains(V2), "{t}");
}

#[tokio::test]
async fn showing_needs_a_step_up_the_admin_scope_and_a_live_broker() {
    let (fx, vm) = broker().await;
    create(&fx, "git.token", V1, &[]).await;
    let reader = fx.enroll("phone", &["read"]).await;
    for dev in [&reader, &vm] {
        for uri in [REVEAL, EXPORT] {
            let r = call(&fx, dev, Method::POST, uri, Value::Null).await;
            assert_eq!(
                code(&r),
                (StatusCode::FORBIDDEN, "forbidden_scope"),
                "{uri}"
            );
        }
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
    for uri in [REVEAL, EXPORT] {
        let r = call(&fx, &mac, Method::POST, uri, Value::Null).await;
        assert_eq!(
            code(&r),
            (StatusCode::FORBIDDEN, "step_up_required"),
            "{uri}"
        );
    }
    let missing = "/api/v1/secrets/nope/reveal";
    let r = call(&fx, &fx.dev, Method::POST, missing, Value::Null).await;
    assert_eq!(r.0, StatusCode::NOT_FOUND);
    set(&fx, Key::SecretsMode, 0).await;
    let r = call(&fx, &fx.dev, Method::POST, REVEAL, Value::Null).await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, "secrets_disabled"));
    assert!(!trail(&fx).await.contains(V1));
}

#[tokio::test]
async fn showing_is_rate_limited_per_device() {
    let (fx, _vm) = broker().await;
    create(&fx, "git.token", V1, &[]).await;
    for _ in 0..5 {
        let r = call(&fx, &fx.dev, Method::POST, REVEAL, Value::Null).await;
        assert_eq!(r.0, StatusCode::OK);
    }
    let r = call(&fx, &fx.dev, Method::POST, REVEAL, Value::Null).await;
    assert_eq!(code(&r), (StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn nothing_that_carries_a_shown_value_is_debug() {
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
    assert!(!Probe::<super::super::secret_reveal::RevealedSecret>::IS);
    assert!(!Probe::<super::super::secret_reveal::SecretsExport>::IS);
    assert!(!Probe::<crate::store::secrets::Revealed>::IS);
    assert!(!Probe::<crate::store::secrets::Exported>::IS);
}
