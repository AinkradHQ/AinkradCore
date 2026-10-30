//! The secrets broker (E2-07): stored sealed, listed without a value, rotated, leased to one
//! runner and redeemed once; and the refusals: G-SEC off and real-shaped values, wrong scope,
//! no step-up, out of scope, another runner, spent, expired, a revoked runner, every bound, no
//! master key, and a malformed body that never echoes the value.

use ainkrad_core::settings::{Key, Scope};
use axum::http::{Method, StatusCode};
use serde_json::json;

use super::*;
use crate::ops::secretbox::SecretBox;

const V1: &str = "throwaway-value-one-7f3a9c";
const V2: &str = "throwaway-value-two-1b8e4d";

async fn set(fx: &Fx, key: Key, value: i64) {
    let by = super::super::BY;
    crate::store::settings::set(
        &fx.app.pool,
        key,
        Scope::Server,
        &value.to_string(),
        by,
        NOW,
    )
    .await
    .unwrap();
}

/// A fixture with a master key and the broker in throwaway mode (1), and a runner with a
/// session.
async fn broker() -> (Fx, TestDevice) {
    let mut fx = fx().await;
    fx.app.secrets = Some(Arc::new(SecretBox::new(&[7; 32])));
    set(&fx, Key::SecretsMode, 1).await;
    let runner = runner(&fx, "vm").await;
    (fx, runner)
}

pub(super) async fn runner(fx: &Fx, name: &str) -> TestDevice {
    let r = TestDevice::enroll(
        &fx.app.pool,
        name,
        "runner",
        &["runner"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    let s = fx.app.auth.issue_session(&r.id, fx.clock.unix());
    r.set_session(Some(s.id));
    r
}

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

async fn create(fx: &Fx, name: &str, value: &str, runners: &[&str]) -> (StatusCode, Value) {
    let body = json!({"name": name, "value": value, "runners": runners});
    call(fx, &fx.dev, Method::POST, "/api/v1/secrets", body).await
}

async fn lease(fx: &Fx, name: &str, runner: &str, ttl: Option<i64>) -> (StatusCode, Value) {
    let uri = format!("/api/v1/secrets/{name}/leases");
    let body = json!({"runner": runner, "ttl_secs": ttl});
    call(fx, &fx.dev, Method::POST, &uri, body).await
}

async fn redeem(fx: &Fx, runner: &TestDevice, lease: &Value) -> (StatusCode, Value) {
    let body = json!({"lease": lease["lease"]});
    call(
        fx,
        runner,
        Method::POST,
        "/api/v1/secret-leases/redeem",
        body,
    )
    .await
}

fn code(r: &(StatusCode, Value)) -> (StatusCode, &str) {
    (r.0, r.1["code"].as_str().unwrap_or(""))
}

/// Every text the store holds about secrets outside the sealed column: audit rows, events.
async fn trail(fx: &Fx) -> String {
    let audit: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_events")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    let events: Vec<String> = sqlx::query_scalar("SELECT payload FROM events")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    [audit, events].concat().join("\n")
}

#[tokio::test]
async fn a_secret_is_sealed_listed_without_its_value_rotated_and_leased_once() {
    let (fx, vm) = broker().await;
    let made = create(&fx, "git.token", V1, &[vm.id.as_str()]).await;
    assert_eq!(made.0, StatusCode::OK, "{}", made.1);
    assert_eq!(
        (&made.1["version"], &made.1["size"], &made.1["delivery"]),
        (&json!(1), &json!(V1.len()), &json!("env"))
    );
    assert!(!made.1.to_string().contains(V1));
    let (sealed, key_id): (Vec<u8>, String) =
        sqlx::query_as("SELECT sealed, key_id FROM core_secrets WHERE name = 'git.token'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert!(!sealed.windows(V1.len()).any(|w| w == V1.as_bytes()));
    assert_eq!(key_id, fx.app.secrets.as_ref().unwrap().key_id());
    let listed = fx.ok("/api/v1/secrets").await;
    assert_eq!(listed[0]["name"], "git.token");
    assert!(!listed.to_string().contains(V1), "{listed}");
    // A second one of the same name is a conflict.
    assert_eq!(
        code(&create(&fx, "git.token", V2, &[]).await),
        (StatusCode::CONFLICT, "conflict")
    );

    let l = lease(&fx, "git.token", &vm.id, None).await;
    assert_eq!(l.0, StatusCode::OK, "{}", l.1);
    let got = redeem(&fx, &vm, &l.1).await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    // Review L6: the redemption is audited as the user's device action, naming the runner.
    let (kind, by): (String, String) = sqlx::query_as(
        "SELECT actor_kind, json_extract(details, '$.by_device') FROM audit_events \
         WHERE action = 'secret.redeemed'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!((kind.as_str(), by.as_str()), ("user", vm.id.as_str()));
    assert_eq!(
        (&got.1["value"], &got.1["version"], &got.1["name"]),
        (&json!(V1), &json!(1), &json!("git.token"))
    );
    assert_eq!(
        code(&redeem(&fx, &vm, &l.1).await),
        (StatusCode::GONE, "lease_expired"),
        "once"
    );

    let uri = "/api/v1/secrets/git.token";
    let rotated = call(&fx, &fx.dev, Method::PUT, uri, json!({"value": V2})).await;
    assert_eq!(rotated.1["version"], 2, "{}", rotated.1);
    assert_eq!(rotated.1["runners"], json!([vm.id]), "the scope is kept");
    let l = lease(&fx, "git.token", &vm.id, Some(30)).await;
    assert_eq!(redeem(&fx, &vm, &l.1).await.1["value"], V2);

    let t = trail(&fx).await;
    assert!(!t.contains(V1) && !t.contains(V2), "{t}");
    for action in [
        "secret.created",
        "secret.rotated",
        "secret.leased",
        "secret.redeemed",
    ] {
        assert!(t.contains(action), "{action}: {t}");
    }
    // Deleted with its leases; listing and deleting work with the broker off.
    let l = lease(&fx, "git.token", &vm.id, None).await;
    set(&fx, Key::SecretsMode, 0).await;
    let gone = call(&fx, &fx.dev, Method::DELETE, uri, Value::Null).await;
    assert_eq!(gone.0, StatusCode::OK, "{}", gone.1);
    assert_eq!(fx.ok("/api/v1/secrets").await, json!([]));
    set(&fx, Key::SecretsMode, 1).await;
    assert_eq!(redeem(&fx, &vm, &l.1).await.0, StatusCode::NOT_FOUND);
    assert!(trail(&fx).await.contains("secret.deleted"));
}

#[tokio::test]
async fn gate_g_sec_and_the_bounds_refuse() {
    let (fx, vm) = broker().await;
    // Off (the default) refuses stores, grants and redemptions.
    create(&fx, "a", V1, &[vm.id.as_str()]).await;
    let l = lease(&fx, "a", &vm.id, None).await;
    set(&fx, Key::SecretsMode, 0).await;
    assert_eq!(
        code(&create(&fx, "b", V1, &[]).await),
        (StatusCode::CONFLICT, "secrets_disabled")
    );
    assert_eq!(
        code(&lease(&fx, "a", &vm.id, None).await),
        (StatusCode::CONFLICT, "secrets_disabled")
    );
    assert_eq!(
        code(&redeem(&fx, &vm, &l.1).await),
        (StatusCode::CONFLICT, "secrets_disabled")
    );
    // Throwaway mode refuses a value shaped like a real credential; mode 2 takes it.
    set(&fx, Key::SecretsMode, 1).await;
    let real = ainkrad_proto::redact::PLANTED[0].1;
    let r = create(&fx, "real", real, &[]).await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, "real_secret_refused"));
    assert!(!r.1.to_string().contains(real));
    set(&fx, Key::SecretsMode, 2).await;
    assert_eq!(create(&fx, "real", real, &[]).await.0, StatusCode::OK);
    set(&fx, Key::SecretsMode, 1).await;

    // Bounds: the size, the count, a lease's lifetime, the live leases.
    set(&fx, Key::SecretsMaxBytes, 16).await;
    assert_eq!(
        code(&create(&fx, "big", &"x".repeat(17), &[]).await),
        (StatusCode::BAD_REQUEST, "too_large")
    );
    assert_eq!(
        code(&create(&fx, "empty", "", &[]).await),
        (StatusCode::BAD_REQUEST, "bad_request")
    );
    set(&fx, Key::SecretsMaxCount, 2).await;
    assert_eq!(
        code(&create(&fx, "third", "x", &[]).await),
        (StatusCode::CONFLICT, "limit_reached")
    );
    assert_eq!(
        code(&lease(&fx, "a", &vm.id, Some(121)).await),
        (StatusCode::BAD_REQUEST, "bad_request")
    );
    set(&fx, Key::SecretsMaxLeases, 2).await;
    assert_eq!(lease(&fx, "a", &vm.id, None).await.0, StatusCode::OK);
    assert_eq!(
        code(&lease(&fx, "a", &vm.id, None).await),
        (StatusCode::CONFLICT, "limit_reached")
    );
    // Bad names and deliveries.
    for (name, delivery) in [("Bad", "env"), ("a/b", "env"), ("ok.name", "smtp")] {
        let body = json!({"name": name, "value": "x", "delivery": delivery});
        let r = call(&fx, &fx.dev, Method::POST, "/api/v1/secrets", body).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{name} {delivery}: {}", r.1);
    }
}

#[tokio::test]
async fn leases_go_only_to_their_runner_in_scope_and_not_after_expiry_or_revocation() {
    let (fx, vm) = broker().await;
    let other = runner(&fx, "other").await;
    create(&fx, "k", V1, &[vm.id.as_str()]).await;
    // Out of scope, or not a runner at all: no lease.
    assert_eq!(
        lease(&fx, "k", &other.id, None).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        lease(&fx, "k", &fx.dev.id, None).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        lease(&fx, "nope", &vm.id, None).await.0,
        StatusCode::NOT_FOUND
    );

    // Another runner, and a device that is not a runner (the admin holds every scope), are
    // told the lease does not exist, and the lease still works for its own runner.
    let l = lease(&fx, "k", &vm.id, Some(60)).await;
    assert_eq!(
        code(&redeem(&fx, &other, &l.1).await),
        (StatusCode::NOT_FOUND, "not_found")
    );
    assert_eq!(redeem(&fx, &fx.dev, &l.1).await.0, StatusCode::NOT_FOUND);
    let bogus = json!({"lease": "l_00000000000000000000000000"});
    assert_eq!(redeem(&fx, &vm, &bogus).await.0, StatusCode::NOT_FOUND);
    assert_eq!(redeem(&fx, &vm, &l.1).await.0, StatusCode::OK);

    // Rotated after the grant (review M2): the lease is dropped, the new value needs a new one.
    let l = lease(&fx, "k", &vm.id, None).await;
    let uri = "/api/v1/secrets/k";
    let r = call(
        &fx,
        &fx.dev,
        Method::PUT,
        uri,
        json!({"value": "rotated-once"}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(redeem(&fx, &vm, &l.1).await.0, StatusCode::NOT_FOUND);
    let revoked: i64 = sqlx::query_scalar(
        "SELECT json_extract(details, '$.leases_revoked') FROM audit_events \
         WHERE action = 'secret.rotated' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(revoked, 1);

    // Expired.
    let l = lease(&fx, "k", &vm.id, Some(10)).await;
    fx.clock.advance(11);
    assert_eq!(
        code(&redeem(&fx, &vm, &l.1).await),
        (StatusCode::GONE, "lease_expired")
    );
    // Narrowed out of scope after the grant.
    let l = lease(&fx, "k", &vm.id, None).await;
    let r = call(
        &fx,
        &fx.dev,
        Method::PUT,
        uri,
        json!({"value": V2, "runners": []}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(redeem(&fx, &vm, &l.1).await.0, StatusCode::NOT_FOUND);
    // Revoked: the gate refuses the runner before the broker sees it.
    let r = call(
        &fx,
        &fx.dev,
        Method::PUT,
        uri,
        json!({"value": V2, "runners": [vm.id]}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    let l = lease(&fx, "k", &vm.id, None).await;
    let revoke = format!("/api/v1/devices/{}", vm.id);
    let r = call(&fx, &fx.dev, Method::DELETE, &revoke, Value::Null).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(
        code(&redeem(&fx, &vm, &l.1).await),
        (StatusCode::UNAUTHORIZED, "auth_failed")
    );
    assert!(!trail(&fx).await.contains(V2));
}

#[tokio::test]
async fn management_needs_admin_and_a_step_up_and_redemption_needs_runner() {
    let (fx, vm) = broker().await;
    create(&fx, "k", V1, &[vm.id.as_str()]).await;
    let reader = fx
        .enroll("phone", &["read", "approve", "agent", "terminal"])
        .await;
    let forbidden = (StatusCode::FORBIDDEN, "forbidden_scope");
    for (m, uri) in [
        (Method::GET, "/api/v1/secrets"),
        (Method::POST, "/api/v1/secrets"),
        (Method::PUT, "/api/v1/secrets/k"),
        (Method::DELETE, "/api/v1/secrets/k"),
        (Method::POST, "/api/v1/secrets/k/leases"),
        (Method::POST, "/api/v1/secret-leases/redeem"),
    ] {
        let r = call(&fx, &reader, m.clone(), uri, json!({})).await;
        assert_eq!(code(&r), forbidden, "{m} {uri}");
        if uri != "/api/v1/secret-leases/redeem" {
            let r = call(&fx, &vm, m.clone(), uri, json!({})).await;
            assert_eq!(code(&r), forbidden, "runner {m} {uri}");
        }
    }
    // An admin device that has not stepped up may list, and nothing else.
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
    assert_eq!(
        call(&fx, &mac, Method::GET, "/api/v1/secrets", Value::Null)
            .await
            .0,
        StatusCode::OK
    );
    let step_up = (StatusCode::FORBIDDEN, "step_up_required");
    for (m, uri, body) in [
        (
            Method::POST,
            "/api/v1/secrets",
            json!({"name": "x", "value": V2}),
        ),
        (Method::PUT, "/api/v1/secrets/k", json!({"value": V2})),
        (Method::DELETE, "/api/v1/secrets/k", Value::Null),
        (
            Method::POST,
            "/api/v1/secrets/k/leases",
            json!({"runner": vm.id}),
        ),
    ] {
        assert_eq!(
            code(&call(&fx, &mac, m.clone(), uri, body).await),
            step_up,
            "{m} {uri}"
        );
    }
    assert!(!trail(&fx).await.contains(V2));
}

#[tokio::test]
async fn no_master_key_and_malformed_bodies_never_echo_a_value() {
    let (mut fx, vm) = broker().await;
    // A value in a body of the wrong shape: the fixed message, never serde's (which quotes).
    let body = json!({"name": 7, "value": V1});
    let r = call(&fx, &fx.dev, Method::POST, "/api/v1/secrets", body).await;
    assert_eq!(code(&r), (StatusCode::BAD_REQUEST, "bad_request"));
    let body = json!({"value": [V1]});
    let r = call(&fx, &fx.dev, Method::PUT, "/api/v1/secrets/k", body).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST);
    assert!(!r.1.to_string().contains(V1), "{}", r.1);
    create(&fx, "k", V1, &[vm.id.as_str()]).await;
    let l = lease(&fx, "k", &vm.id, None).await;
    fx.app.secrets = None;
    let unavailable = (StatusCode::SERVICE_UNAVAILABLE, "secrets_unavailable");
    assert_eq!(code(&create(&fx, "j", V1, &[]).await), unavailable);
    assert_eq!(code(&redeem(&fx, &vm, &l.1).await), unavailable);
    // Another master key: the sealed value is named as such, and the lease is not spent.
    fx.app.secrets = Some(Arc::new(SecretBox::new(&[8; 32])));
    assert_eq!(code(&redeem(&fx, &vm, &l.1).await), unavailable);
    fx.app.secrets = Some(Arc::new(SecretBox::new(&[7; 32])));
    assert_eq!(redeem(&fx, &vm, &l.1).await.1["value"], V1);
    assert!(!trail(&fx).await.contains(V1));
}

/// Review L4 and the value structs: nothing that carries a value or a live lease implements
/// `Debug`, so no `{:?}` can print one. (Autoref probe: the inherent `IS` exists only for
/// `T: Debug`; otherwise the trait's `false` is found.)
#[test]
#[allow(clippy::assertions_on_constants)] // the point: each is decided at compile time
fn nothing_that_carries_a_value_or_a_lease_is_debug() {
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
    use super::super::secrets as api;
    use crate::store::secrets as store;
    assert!(Probe::<String>::IS, "the probe sees Debug");
    assert!(!Probe::<api::LeaseGrant>::IS);
    assert!(!Probe::<api::RedeemLease>::IS);
    assert!(!Probe::<api::NewSecret>::IS);
    assert!(!Probe::<api::RotateSecret>::IS);
    assert!(!Probe::<api::LeasedSecret>::IS);
    assert!(!Probe::<store::Redeemed>::IS);
    assert!(!Probe::<store::NewValue<'static>>::IS);
}

/// Review L5 (with E2-08, where the Core grants leases itself): one runner holds at most a
/// quarter of `secrets.max_leases`; another runner in scope still gets its own.
#[tokio::test]
async fn one_runner_cannot_hold_every_live_lease() {
    let (fx, vm) = broker().await;
    let other = runner(&fx, "vm2").await;
    let made = create(&fx, "git.token", V1, &[vm.id.as_str(), other.id.as_str()]).await;
    assert_eq!(made.0, StatusCode::OK, "{}", made.1);
    set(&fx, Key::SecretsMaxLeases, 8).await;
    for _ in 0..2 {
        assert_eq!(
            lease(&fx, "git.token", &vm.id, None).await.0,
            StatusCode::OK
        );
    }
    assert_eq!(
        code(&lease(&fx, "git.token", &vm.id, None).await),
        (StatusCode::CONFLICT, "limit_reached")
    );
    assert_eq!(
        lease(&fx, "git.token", &other.id, None).await.0,
        StatusCode::OK
    );
}
