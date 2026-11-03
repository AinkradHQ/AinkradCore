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
    post_secret(fx, body).await
}

/// `POST /secrets`, except for an `acct.*` name: the general routes refuse those (accounts are
/// managed through the accounts API), so the broker's own rules are exercised straight at the
/// store, answering the way the route would.
pub(super) async fn post_secret(fx: &Fx, body: Value) -> (StatusCode, Value) {
    match body["name"].as_str().filter(|n| n.starts_with("acct.")) {
        Some(n) => via_store(fx, n, &body, true).await,
        None => call(fx, &fx.dev, Method::POST, "/api/v1/secrets", body).await,
    }
}

/// `PUT /secrets/{name}`, with the same `acct.*` exception as [`post_secret`].
pub(super) async fn put_secret(fx: &Fx, name: &str, body: Value) -> (StatusCode, Value) {
    match name.starts_with("acct.") {
        true => via_store(fx, name, &body, false).await,
        false => {
            let uri = format!("/api/v1/secrets/{name}");
            call(fx, &fx.dev, Method::PUT, &uri, body).await
        }
    }
}

async fn via_store(fx: &Fx, name: &str, body: &Value, create: bool) -> (StatusCode, Value) {
    use crate::store::secrets as st;
    let runners: Option<Vec<String>> = body
        .get("runners")
        .and_then(|r| serde_json::from_value(r.clone()).ok());
    let new = st::NewValue {
        value: body["value"].as_str().unwrap_or_default(),
        runners: runners.as_deref(),
        delivery: body["delivery"].as_str(),
    };
    let sealer = fx.app.secrets.clone().unwrap();
    let by = super::super::BY;
    let r = match create {
        true => st::create(&fx.app.pool, &sealer, name, &new, &fx.dev.id, by, NOW).await,
        false => st::rotate(&fx.app.pool, &sealer, name, &new, &fx.dev.id, by, NOW).await,
    };
    match r {
        Ok(m) => (
            StatusCode::OK,
            json!({"name": m.name, "version": m.version}),
        ),
        Err(e) => {
            let e: super::super::ApiError = e.into();
            (e.status, json!({"code": e.code, "message": e.message}))
        }
    }
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

/// A module's own jobs open only `<module>.…` secrets, with the broker on, audited and never
/// with the value in the trail.
#[tokio::test]
async fn a_module_opens_only_its_own_secrets_and_it_is_audited() {
    let (fx, vm) = broker().await;
    for name in ["citadel.forge.tok", "git.token"] {
        let made = create(&fx, name, V1, &[vm.id.as_str()]).await;
        assert_eq!(made.0, StatusCode::OK, "{}", made.1);
    }
    let sealer = fx.app.secrets.clone().unwrap();
    let open = |module: &'static str, name: &'static str| {
        let (pool, sealer) = (fx.app.pool.clone(), sealer.clone());
        async move { crate::store::secrets::open_for_module(&pool, &sealer, module, name, "test").await }
    };
    let value = open("citadel", "citadel.forge.tok").await.unwrap();
    assert_eq!(&*value, V1);
    // Another module's name, a platform secret, a traversal and a missing one all look absent.
    for (m, n) in [
        ("other", "citadel.forge.tok"),
        ("citadel", "git.token"),
        ("citadel", "citadel.missing"),
        ("citadel", "citadel.../x"),
    ] {
        let e = open(m, n).await.err().unwrap();
        assert!(e.to_string().starts_with("not_found"), "{m} {n}: {e}");
    }
    let t = trail(&fx).await;
    assert!(t.contains("secret.used") && !t.contains(V1), "{t}");
    set(&fx, Key::SecretsMode, 0).await;
    let e = open("citadel", "citadel.forge.tok").await.err().unwrap();
    assert!(e.to_string().starts_with("secrets_disabled"), "{e}");
}

fn planted(kind: &str) -> &'static str {
    ainkrad_proto::redact::PLANTED
        .iter()
        .find(|(k, _)| *k == kind)
        .unwrap()
        .1
}

/// The narrow gate (`secrets.provider_accounts`): only a provider-account secret may be
/// real-shaped, only while the gate is on, and only in mode 1; everything else is unchanged.
#[tokio::test]
async fn the_provider_account_gate_lets_only_account_secrets_be_real() {
    let (fx, _vm) = broker().await;
    let real = planted("anthropic_key");
    let gh = planted("github_token");
    let refused = (StatusCode::CONFLICT, "real_secret_refused");
    let bad = (StatusCode::BAD_REQUEST, "bad_request");
    let account = "acct.anthropic.main";
    let others = [
        "git.token",
        "forge.token",
        "linear.api",
        "acctx.anthropic.m",
    ];
    let unknown = [
        "acct.",
        "acct.nobody.x",
        "acct.anthropic",
        "acct.anthropic.",
        "acct.anthropic.-",
        "acct.anthropic..",
        "acct.anthropic.-.-",
    ];

    // Gate off (the default): an account secret is refused like any other; unknown kinds fail
    // closed.
    for n in others.iter().chain(&[account]) {
        assert_eq!(code(&create(&fx, n, real, &[]).await), refused, "{n}");
    }
    for n in unknown {
        assert_eq!(code(&create(&fx, n, V1, &[]).await), bad, "off {n}");
    }
    // Gate on, mode 1: the account secret is accepted, every other real value still refused.
    set(&fx, Key::SecretsProviderAccounts, 1).await;
    for n in others {
        for v in [gh, real] {
            let r = create(&fx, n, v, &[]).await;
            assert_eq!(code(&r), refused, "{n}");
            assert!(!r.1.to_string().contains(v));
        }
    }
    for n in unknown {
        assert_eq!(code(&create(&fx, n, V1, &[]).await), bad, "on {n}");
    }
    assert_eq!(create(&fx, account, real, &[]).await.0, StatusCode::OK);
    // A rotation follows the same rule, by name.
    create(&fx, "git.token", V1, &[]).await;
    let r = put_secret(&fx, "git.token", json!({"value": gh})).await;
    assert_eq!(code(&r), refused);
    let r = put_secret(&fx, account, json!({"value": real})).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    // The gate never turns the broker on.
    set(&fx, Key::SecretsMode, 0).await;
    for n in ["acct.openai.b", "acct.nobody.b"] {
        assert_eq!(
            code(&create(&fx, n, real, &[]).await),
            (StatusCode::CONFLICT, "secrets_disabled"),
            "{n}"
        );
    }
    // Gate off again: creating is refused once more, and so is rotating the existing account
    // secret with a real value.
    set(&fx, Key::SecretsMode, 1).await;
    set(&fx, Key::SecretsProviderAccounts, 0).await;
    assert_eq!(
        code(&create(&fx, "acct.openai.b", real, &[]).await),
        refused
    );
    let r = put_secret(&fx, account, json!({"value": real})).await;
    assert_eq!(code(&r), refused);
    // Mode 2 is unchanged by the gate, on or off: a real git secret is taken, and so is an
    // unknown acct. name (it is only fail-closed below mode 2).
    set(&fx, Key::SecretsMode, 2).await;
    assert_eq!(
        code(&create(&fx, "git.token", gh, &[]).await),
        (StatusCode::CONFLICT, "conflict"),
        "the name exists; the value is not the reason"
    );
    assert_eq!(create(&fx, "git.two", gh, &[]).await.0, StatusCode::OK);
    set(&fx, Key::SecretsProviderAccounts, 1).await;
    assert_eq!(create(&fx, "git.three", gh, &[]).await.0, StatusCode::OK);
    assert_eq!(
        create(&fx, "acct.nobody.x", gh, &[]).await.0,
        StatusCode::OK
    );
    assert!(!trail(&fx).await.contains(real));
}

/// Review: an account name is not a licence for any credential. Another kind of key under an
/// account name is refused, on create and rotate; the provider's own shape and a shapeless
/// token (OAuth, subscription) are taken.
#[tokio::test]
async fn an_account_secret_must_not_look_like_another_credential() {
    let (fx, _vm) = broker().await;
    set(&fx, Key::SecretsProviderAccounts, 1).await;
    let refused = (StatusCode::CONFLICT, "real_secret_refused");
    let foreign = [
        planted("github_token"),
        planted("aws_key"),
        planted("aws_secret"),
        planted("pem_block"),
        planted("runner_key"),
        planted("run_token"),
        planted("bearer"),
        planted("openai_key"),
        planted("google_key"),
    ];
    assert_eq!(
        create(
            &fx,
            "acct.anthropic.x",
            "oauth-token-without-any-known-shape",
            &[]
        )
        .await
        .0,
        StatusCode::OK
    );
    let uri = "acct.anthropic.x";
    for (i, v) in foreign.iter().enumerate() {
        let r = create(&fx, &format!("acct.anthropic.n{i}"), v, &[]).await;
        assert_eq!(code(&r), refused, "create {i}");
        assert!(!r.1.to_string().contains(v));
        let r = put_secret(&fx, uri, json!({"value": v})).await;
        assert_eq!(code(&r), refused, "rotate {i}");
    }
    // A foreign key after the provider's own, with a space or glued on, is refused (the glued
    // forms are the redactor's one-token trap, `single_own_key` covers them).
    let mixed = format!("{} {}", planted("anthropic_key"), planted("github_token"));
    assert_eq!(
        code(&create(&fx, "acct.anthropic.m", &mixed, &[]).await),
        refused
    );
    // The provider's own shape is accepted, on create and rotate; each provider its own.
    let own = [
        ("anthropic", "anthropic_key"),
        ("openai", "openai_key"),
        ("google", "google_key"),
    ];
    for (p, k) in own {
        let r = create(&fx, &format!("acct.{p}.own"), planted(k), &[]).await;
        assert_eq!(r.0, StatusCode::OK, "{p}: {}", r.1);
        let uri = format!("acct.{p}.own");
        let r = put_secret(&fx, &uri, json!({"value": planted(k)})).await;
        assert_eq!(r.0, StatusCode::OK, "{p}: {}", r.1);
    }
    let r = put_secret(&fx, uri, json!({"value": "another-shapeless-token-9"})).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    // askpass is for git: refused for an account secret, create and rotate.
    let body = json!({"name": "acct.openai.ask", "value": V1, "delivery": "askpass"});
    let r = post_secret(&fx, body).await;
    assert_eq!(code(&r), (StatusCode::BAD_REQUEST, "bad_request"));
    let r = put_secret(&fx, uri, json!({"value": V2, "delivery": "askpass"})).await;
    assert_eq!(code(&r), (StatusCode::BAD_REQUEST, "bad_request"));
    // The audit rows are tagged, and hold no value.
    let tagged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action IN ('secret.created', 'secret.rotated') \
         AND json_extract(details, '$.kind') = 'provider_account'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert!(tagged >= 8, "{tagged}");
    // `gate_lifted` marks only the rows where the gate admitted a real-shaped value.
    let lifted: Vec<String> = sqlx::query_scalar(
        "SELECT json_extract(details, '$.name') FROM audit_events \
         WHERE json_extract(details, '$.gate_lifted') = 1",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert!(lifted.iter().all(|n| n.ends_with(".own")), "{lifted:?}");
    assert_eq!(lifted.len(), 6, "{lifted:?}");
    let t = trail(&fx).await;
    for v in foreign.iter().chain(&[mixed.as_str()]) {
        assert!(!t.contains(v));
    }
    assert!(!t.contains(planted("anthropic_key")) && !t.contains("shapeless"));
    // No open_for_module can reach acct.* names.
    let sealer = fx.app.secrets.clone().unwrap();
    let r = crate::store::secrets::open_for_module(
        &fx.app.pool,
        &sealer,
        "acct",
        "acct.anthropic.x",
        "test",
    )
    .await;
    assert!(
        matches!(
            r,
            Err(crate::store::secrets::Error::Refused {
                code: "not_found",
                ..
            })
        ),
        "a module named acct opened an account secret"
    );
}

/// Straight to the store (the API is rate limited): `Ok` or the refusal's code.
async fn stored(fx: &Fx, name: &str, value: &str, rotate: bool) -> Result<(), &'static str> {
    use crate::store::secrets as st;
    let new = st::NewValue {
        value,
        runners: None,
        delivery: None,
    };
    let sealer = fx.app.secrets.clone().unwrap();
    let by = super::super::BY;
    let r = match rotate {
        false => st::create(&fx.app.pool, &sealer, name, &new, &fx.dev.id, by, NOW).await,
        true => st::rotate(&fx.app.pool, &sealer, name, &new, &fx.dev.id, by, NOW).await,
    };
    match r {
        Ok(_) => Ok(()),
        Err(st::Error::Refused { code, .. }) => Err(code),
        Err(e) => panic!("{e}"),
    }
}

/// Review: the redactor reads a foreign key glued to the provider's own as one token. Each
/// glued form, for each provider, is refused on create and rotate; the key alone is not.
#[tokio::test]
async fn a_foreign_key_glued_to_the_providers_own_is_refused() {
    let (fx, _vm) = broker().await;
    set(&fx, Key::SecretsProviderAccounts, 1).await;
    let foreign = [
        planted("github_token"),
        // The second GitHub shape (the fine-grained token), picked by kind, not by index.
        ainkrad_proto::redact::PLANTED
            .iter()
            .filter(|(k, _)| *k == "github_token")
            .nth(1)
            .unwrap()
            .1,
        planted("aws_key"),
        planted("runner_key"),
        planted("pem_block"),
    ];
    let providers = [
        ("anthropic", "anthropic_key"),
        ("openai", "openai_key"),
        ("google", "google_key"),
    ];
    // Every fixture of the provider's kind: openai has two (`sk-proj-` and the bare `sk-`).
    let fixtures = providers.iter().flat_map(|(p, k)| {
        ainkrad_proto::redact::PLANTED
            .iter()
            .filter(move |(kind, _)| kind == k)
            .map(move |(_, v)| (*p, *v))
    });
    for (p, own) in fixtures {
        let name = format!("acct.{p}.g");
        let _ =
            crate::store::secrets::delete(&fx.app.pool, &name, &fx.dev.id, super::super::BY).await;
        assert_eq!(stored(&fx, &name, own, false).await, Ok(()), "{p}");
        for f in foreign {
            for sep in ["", "-", "_", "\n", " ", "\t"] {
                let new = format!("acct.{p}.new");
                let v = format!("{own}{sep}{f}");
                let want = Err("real_secret_refused");
                assert_eq!(stored(&fx, &new, &v, false).await, want, "{p} {sep:?} {f}");
                assert_eq!(
                    stored(&fx, &name, &v, true).await,
                    want,
                    "{p} rot {sep:?} {f}"
                );
                // The foreign key first is refused as well.
                let v = format!("{f}{sep}{own}");
                assert_eq!(
                    stored(&fx, &new, &v, false).await,
                    want,
                    "{p} rev {sep:?} {f}"
                );
            }
        }
        // The key with surrounding whitespace is still the key.
        let v = format!("  {own}\n");
        assert_eq!(stored(&fx, &name, &v, true).await, Ok(()), "{p}");
    }
}

/// askpass is refused for account names in every mode; the rest of mode 2 is unchanged.
#[tokio::test]
async fn account_secrets_are_never_delivered_by_askpass() {
    let (fx, _vm) = broker().await;
    set(&fx, Key::SecretsMode, 2).await;
    let body = json!({"name": "acct.openai.ask", "value": V1, "delivery": "askpass"});
    let r = post_secret(&fx, body).await;
    assert_eq!(code(&r), (StatusCode::BAD_REQUEST, "bad_request"));
    let body = json!({"name": "git.ask", "value": V1, "delivery": "askpass"});
    let r = call(&fx, &fx.dev, Method::POST, "/api/v1/secrets", body).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
}

/// A malformed `acct.` name is `Other` in mode 2, and was still allowed `askpass`; and a secret
/// already stored with `askpass` under an account name is not redeemed (KAN-453).
#[tokio::test]
async fn askpass_is_refused_for_any_acct_name_at_store_and_at_redeem() {
    let (fx, vm) = broker().await;
    set(&fx, Key::SecretsMode, 2).await;
    for name in ["acct.unknown.x", "acct.", "acct.openai"] {
        let body = json!({"name": name, "value": V1, "delivery": "askpass"});
        let r = call(&fx, &fx.dev, Method::POST, "/api/v1/secrets", body).await;
        assert_eq!(
            code(&r),
            (StatusCode::BAD_REQUEST, "bad_request"),
            "{name}: {}",
            r.1
        );
    }
    // One stored with env, switched to askpass behind the API's back, is not handed out.
    let r = create(&fx, "acct.openai.legacy", V1, &[vm.id.as_str()]).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    sqlx::query("UPDATE core_secrets SET delivery = 'askpass' WHERE name = 'acct.openai.legacy'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let l = lease(&fx, "acct.openai.legacy", &vm.id, None).await;
    assert_eq!(l.0, StatusCode::OK, "{}", l.1);
    let r = redeem(&fx, &vm, &l.1).await;
    assert_eq!(
        code(&r),
        (StatusCode::BAD_REQUEST, "bad_request"),
        "{}",
        r.1
    );
    assert!(!r.1.to_string().contains(V1));
}

/// The shape check scans at most 512 bytes (it is quadratic): one key of exactly that length is
/// the provider's own, one byte more is refused as too long to check (KAN-453).
#[tokio::test]
async fn the_account_shape_check_pins_its_512_byte_scan_cap() {
    let (fx, _vm) = broker().await;
    set(&fx, Key::SecretsProviderAccounts, 1).await;
    let own = planted("anthropic_key");
    let pad = |n: usize| format!("{own}{}", "A".repeat(n - own.len()));
    assert_eq!(
        stored(&fx, "acct.anthropic.cap", &pad(512), false).await,
        Ok(())
    );
    assert_eq!(
        stored(&fx, "acct.anthropic.cap2", &pad(513), false).await,
        Err("real_secret_refused")
    );
}

#[test]
fn secrets_are_classified_by_name() {
    use crate::store::secrets::{Kind, kind_of};
    for (n, p) in [
        ("acct.anthropic.a", "anthropic"),
        ("acct.openai.work-1", "openai"),
        ("acct.google.x.y", "google"),
    ] {
        let Kind::ProviderAccount { provider, .. } = kind_of(n).unwrap() else {
            panic!("{n}");
        };
        assert_eq!(provider, p, "{n}");
    }
    for n in [
        "git.token",
        "acct",
        "accts.anthropic.a",
        "my.acct.anthropic.a",
    ] {
        assert_eq!(kind_of(n).unwrap(), Kind::Other, "{n}");
    }
    for n in [
        "acct.",
        "acct.x",
        "acct.anthropic",
        "acct.anthropic.",
        "acct.Anthropic.a",
        "acct.anthropic.-",
        "acct.anthropic..",
        "acct.openai._-.",
    ] {
        assert!(kind_of(n).is_err(), "{n}");
    }
}

/// Flipping the gate is an admin setting write: it needs a step-up and leaves a `setting.set`
/// audit row.
#[tokio::test]
async fn flipping_the_provider_account_gate_needs_a_step_up_and_is_audited() {
    let (fx, _vm) = broker().await;
    let uri = "/api/v1/settings/server/secrets.provider_accounts";
    let body = json!({"value": 1});
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
    let r = call(&fx, &mac, Method::PUT, uri, body.clone()).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "step_up_required"));
    let reader = fx.enroll("phone", &["read", "approve", "agent"]).await;
    let r = call(&fx, &reader, Method::PUT, uri, body.clone()).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "forbidden_scope"));
    async fn audited(fx: &Fx) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM audit_events WHERE action = 'setting.set' \
             AND details LIKE '%secrets.provider_accounts%'",
        )
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
    }
    assert_eq!(audited(&fx).await, 0);
    let r = call(&fx, &fx.dev, Method::PUT, uri, body).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(audited(&fx).await, 1);
    // Default off, and bounded to 0 or 1.
    let r = call(&fx, &fx.dev, Method::PUT, uri, json!({"value": 2})).await;
    assert_eq!(code(&r), (StatusCode::BAD_REQUEST, "out_of_bounds"));
}
