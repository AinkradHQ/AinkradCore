//! The gateway's account API (KAN-435 G7): a user-defined provider holds keys only of its declared
//! shape, bound to its host; a definition that holds keys is gateway-only and never shares a key
//! prefix; the session-limits and test routes.

use ainkrad_core::settings::{Key, Scope};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::accounts_store::{V1, make, setup};
use super::*;
use crate::store::providers::{self as prov, Definition, Model};
use crate::store::secrets::Error;
use crate::store::{account_keys, accounts as acc};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;
/// Dummy keys of the shapes the redactor reads: nothing here is a real credential.
const OR: &str = "sk-or-v1-0123456789abcdefghijklmnopqrstuvwxyzTESTONLY";
const OR2: &str = "sk-or-v1-zyxwvutsrqponmlkjihgfedcba9876543210TESTONLY";
const ANT: &str = "sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyzTESTONLY";

fn router(id: &str, prefix: Option<&str>) -> Definition {
    Definition {
        id: id.to_owned(),
        name: "Router".to_owned(),
        harness: "codex".to_owned(),
        auth_var: "OPENAI_API_KEY".to_owned(),
        base_url: "https://openrouter.ai/api/v1".to_owned(),
        usage_parser: "openai".to_owned(),
        delivery: vec!["gateway".to_owned()],
        login_methods: vec!["paste".to_owned()],
        models: vec![Model {
            id: "vendor/model-1".to_owned(),
            input_per_mtok_micro: 3_000_000,
            output_per_mtok_micro: 15_000_000,
        }],
        priced_at: Some("2026-11-01".to_owned()),
        wire: String::new(),
        key_prefix: prefix.map(str::to_owned),
        test_path: None,
        builtin: false,
        version: 0,
    }
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    match r {
        Err(Error::Refused { code, .. }) => code,
        Err(e) => panic!("not a refusal: {e}"),
        Ok(_) => panic!("accepted"),
    }
}

async fn open_gate(fx: &Fx) {
    crate::store::settings::set(
        &fx.app.pool,
        Key::SecretsProviderAccounts,
        Scope::Server,
        "1",
        BY,
        NOW,
    )
    .await
    .unwrap();
}

async fn store(
    fx: &Fx,
    s: &crate::ops::secretbox::SecretBox,
    provider: &str,
    label: &str,
    value: &str,
) -> Result<acc::Account, Error> {
    let new = acc::NewAccount {
        provider,
        label,
        value,
        runners: &[],
        cap: None,
    };
    acc::create(&fx.app.pool, s, &new, &fx.dev.id, BY, NOW).await
}

#[tokio::test]
async fn a_user_provider_holds_only_keys_of_its_own_prefix_and_never_a_built_ins() {
    let (fx, _vm, s) = setup().await;
    open_gate(&fx).await;
    prov::create(
        &fx.app.pool,
        &router("openrouter", Some("sk-or-v1-")),
        "d_x",
        BY,
        NOW,
    )
    .await
    .unwrap();
    let a = store(&fx, &s, "openrouter", "or-main", OR).await.unwrap();
    assert_eq!(a.secret_name, format!("acct.openrouter.{}", a.id));
    assert_eq!(a.base_url, "https://openrouter.ai/api/v1");
    // Another provider's key, a throwaway with no shape, and an unrelated shape: none is its key.
    for key in [ANT, V1, "AIzaSyTESTONLY0123456789abcdefghijklmnop"] {
        assert_eq!(
            code(store(&fx, &s, "openrouter", "or-bad", key).await),
            "bad_request",
            "{key}"
        );
    }
    // Its key is not OpenAI's, nor an OpenAI key its, and a built-in's own shape stays its own.
    assert_eq!(
        code(store(&fx, &s, "openai", "oa-bad", OR).await),
        "bad_request"
    );
    assert_eq!(
        code(store(&fx, &s, "openai", "oa-ant", ANT).await),
        "bad_request"
    );
    assert_eq!(
        code(store(&fx, &s, "google", "g-ant", ANT).await),
        "bad_request"
    );
    store(&fx, &s, "anthropic", "ant-ok", ANT).await.unwrap();
    // A replacement is held to the same rule, and the account keeps its tail.
    let err = acc::replace_secret(&fx.app.pool, &s, a.id, ANT, None, &fx.dev.id, BY, NOW).await;
    assert_eq!(code(err), "bad_request");
    let b = acc::replace_secret(&fx.app.pool, &s, a.id, OR2, None, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    assert_eq!(b.masked_tail, "ONLY");
    // The broker's general routes still refuse an `acct.` name, so no key reaches a user provider but through here.
    let body = json!({"name": "acct.openrouter.99", "value": OR});
    let (st, _) = send(
        &fx.app,
        req(Method::POST, "/api/v1/secrets", Some(&fx.dev), Some(body)),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_user_provider_without_a_key_prefix_holds_no_key() {
    let (fx, _vm, s) = setup().await;
    open_gate(&fx).await;
    let mut d = router("noprefix", None);
    d.delivery = vec!["env".to_owned(), "gateway".to_owned()];
    prov::create(&fx.app.pool, &d, "d_x", BY, NOW)
        .await
        .unwrap();
    assert_eq!(
        code(store(&fx, &s, "noprefix", "np", OR).await),
        "bad_request"
    );
    // An env-only definition is not delivered through the gateway at all.
    let mut e = router("envonly", None);
    e.delivery = vec!["env".to_owned()];
    prov::create(&fx.app.pool, &e, "d_x", BY, NOW)
        .await
        .unwrap();
    assert_eq!(
        code(store(&fx, &s, "envonly", "eo", V1).await),
        "bad_request"
    );
    // The built-ins are delivered through the gateway only.
    for p in prov::built_in() {
        assert_eq!(p.delivery, ["gateway"], "{}", p.id);
        assert!(!p.wire.is_empty() && p.key_prefix.is_none());
    }
}

#[tokio::test]
async fn a_definition_that_holds_keys_is_gateway_only_speaks_its_harness_wire_and_shares_no_prefix()
{
    let fx = fx().await;
    let p = &fx.app.pool;
    let bad = |d: Definition| {
        let p = p.clone();
        async move { code(prov::create(&p, &d, "d_x", BY, NOW).await) }
    };
    // A prefix needs the gateway alone: an env key would sit in the sandbox beside a user's host.
    let mut env = router("a1", Some("sk-or-v1-"));
    env.delivery = vec!["env".to_owned(), "gateway".to_owned()];
    assert_eq!(bad(env).await, "bad_request");
    // A short prefix, and one that is, extends or shadows a built-in shape.
    for prefix in [
        "sk-or",
        "sk-ant-",
        "sk-ant-oat01-x",
        "sk-",
        "AIzaSy",
        "sk-proj-abc",
        "sk-adm",
        "tok-0123456789abcdef-",
    ] {
        assert_eq!(
            bad(router("a2", Some(prefix))).await,
            "bad_request",
            "{prefix}"
        );
    }
    // The wire is its harness's own.
    let mut wrong = router("a3", Some("tok-aaaa-"));
    wrong.wire = "anthropic-messages".to_owned();
    assert_eq!(bad(wrong).await, "bad_request");
    let mut unknown = router("a4", Some("tok-bbbb-"));
    unknown.wire = "grpc".to_owned();
    assert_eq!(bad(unknown).await, "bad_request");
    // An absent wire is the harness's: stored, and read back.
    let d = prov::create(p, &router("openrouter", Some("sk-or-v1-")), "d_x", BY, NOW)
        .await
        .unwrap();
    assert_eq!(d.wire, "openai-responses");
    assert_eq!(
        prov::get(p, "openrouter").await.unwrap().wire,
        "openai-responses"
    );
    // Two definitions never share a prefix, nor nest one in another, whichever came first.
    for prefix in ["sk-or-v1-", "sk-or-v1-abc", "sk-or-v"] {
        assert_eq!(
            bad(router("other", Some(prefix))).await,
            "bad_request",
            "{prefix}"
        );
    }
    prov::create(p, &router("other", Some("sk-or-v2-")), "d_x", BY, NOW)
        .await
        .unwrap();
    let mut moved = router("other", Some("sk-or-v1-9"));
    moved.version = 0;
    assert_eq!(
        code(prov::replace(p, &moved, "d_x", BY, NOW).await),
        "bad_request"
    );
}

#[tokio::test]
async fn a_definition_with_accounts_keeps_its_harness_wire_and_key_prefix() {
    let (fx, _vm, s) = setup().await;
    open_gate(&fx).await;
    let p = &fx.app.pool;
    prov::create(p, &router("openrouter", Some("sk-or-v1-")), "d_x", BY, NOW)
        .await
        .unwrap();
    store(&fx, &s, "openrouter", "or-main", OR).await.unwrap();
    let mut changed = router("openrouter", Some("sk-or-v2-"));
    assert_eq!(
        code(prov::replace(p, &changed, "d_x", BY, NOW).await),
        "conflict"
    );
    changed = router("openrouter", Some("sk-or-v1-"));
    changed.harness = "claude".to_owned();
    changed.auth_var = "ANTHROPIC_API_KEY".to_owned();
    changed.usage_parser = "anthropic".to_owned();
    assert!(prov::replace(p, &changed, "d_x", BY, NOW).await.is_err());
    // What does not bind a key moves freely (a name, the models).
    let mut renamed = router("openrouter", Some("sk-or-v1-"));
    renamed.name = "OpenRouter".to_owned();
    assert_eq!(
        prov::replace(p, &renamed, "d_x", BY, NOW)
            .await
            .unwrap()
            .version,
        2
    );
}

#[tokio::test]
async fn an_online_model_is_refused_in_a_definition_and_in_the_price_book() {
    let fx = fx().await;
    let p = &fx.app.pool;
    let mut d = router("openrouter", Some("sk-or-v1-"));
    d.models[0].id = "vendor/model-1:online".to_owned();
    assert_eq!(
        code(prov::create(p, &d, "d_x", BY, NOW).await),
        "bad_request"
    );
    prov::create(p, &router("openrouter", Some("sk-or-v1-")), "d_x", BY, NOW)
        .await
        .unwrap();
    let set = |model: &'static str| {
        let p = p.clone();
        async move {
            crate::store::prices::set(
                &p,
                "openrouter",
                model,
                [1, 2, 3],
                "2026-11-01T00:00:00Z",
                "d_x",
                BY,
                NOW,
            )
            .await
        }
    };
    assert!(set("vendor/model-1:online").await.is_err());
    assert!(set("vendor/model-1:ONLINE").await.is_err());
    assert!(set("vendor/model-1").await.is_ok());
}

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

#[tokio::test]
async fn session_limits_are_set_cleared_validated_and_audited() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "claude-main", V1, std::slice::from_ref(&vm.id)).await;
    let uri = format!("/api/v1/accounts/{}/session-limits", a.id);
    let (st, b) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &uri,
        json!({"max_tokens": 400_000, "max_usd_micros": 5_000_000}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(
        b["session_limits"],
        json!({"max_tokens": 400_000, "max_usd_micros": 5_000_000})
    );
    let (_, one) = call(
        &fx,
        &fx.dev,
        Method::GET,
        &format!("/api/v1/accounts/{}", a.id),
        Value::Null,
    )
    .await;
    assert_eq!(one["session_limits"]["max_tokens"], 400_000);
    for bad in [
        json!({"max_tokens": 1000}),
        json!({"max_tokens": -1}),
        json!({"max_usd_micros": 0}),
        json!({"max_tokens": "lots"}),
    ] {
        let (st, b) = call(&fx, &fx.dev, Method::PUT, &uri, bad.clone()).await;
        assert!(st.is_client_error(), "{bad}: {st} {b}");
    }
    // A dimension left out is cleared; both out: no limits at all.
    let (_, b) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &uri,
        json!({"max_tokens": 500_000}),
    )
    .await;
    assert_eq!(
        b["session_limits"],
        json!({"max_tokens": 500_000, "max_usd_micros": null})
    );
    let (_, b) = call(&fx, &fx.dev, Method::PUT, &uri, json!({})).await;
    assert_eq!(b["session_limits"], Value::Null);
    let (st, _) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        "/api/v1/accounts/999/session-limits",
        json!({}),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'account.session_limits_set'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(n, 3);
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

#[tokio::test]
async fn the_test_route_needs_admin_and_a_runner_and_is_limited_to_one_a_minute() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "claude-main", V1, std::slice::from_ref(&vm.id)).await;
    let uri = format!("/api/v1/accounts/{}/test", a.id);
    // A phone may not.
    let phone = fx.enroll("phone", &["read"]).await;
    let (st, b) = call(&fx, &phone, Method::POST, &uri, Value::Null).await;
    assert_eq!(
        (st, b["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope"))
    );
    // It is not destructive: an admin who never stepped up gets past the gate (and the session
    // limits, which raise what a session may spend, need the step-up: `accounts_api`).
    let plain = plain_admin(&fx).await;
    let (st, b) = call(&fx, &plain, Method::POST, &uri, Value::Null).await;
    assert_eq!(
        (st, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("no_runner")),
        "{b}"
    );
    // No runner is connected in this fixture: nothing is leased, and the answer says why.
    let (st, b) = call(&fx, &fx.dev, Method::POST, &uri, Value::Null).await;
    assert_eq!(
        (st, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("no_runner")),
        "{b}"
    );
    let leases: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secret_leases")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(leases, 0);
    let (st, _) = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/accounts/999/test",
        Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // A recorded test shows on the account (a status class, a time) and holds off the next one.
    account_keys::record_test(&fx.app.pool, a.id, "ok", 42, &vm.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let (_, one) = call(
        &fx,
        &fx.dev,
        Method::GET,
        &format!("/api/v1/accounts/{}", a.id),
        Value::Null,
    )
    .await;
    assert_eq!(one["last_test"]["result"], "ok");
    let (st, b) = call(&fx, &fx.dev, Method::POST, &uri, Value::Null).await;
    assert_eq!(
        (st, b["code"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")),
        "{b}"
    );
    // The audit row names the account and the class, and holds no key.
    let row: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'account.tested' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert!(
        row.contains("\"result\":\"ok\"") && !row.contains(V1),
        "{row}"
    );
}

#[tokio::test]
async fn a_test_path_is_a_plain_path_and_a_provider_without_one_cannot_be_tested() {
    let (fx, _vm, s) = setup().await;
    open_gate(&fx).await;
    let p = &fx.app.pool;
    // Only a plain path under the base URL.
    for bad in [
        "key", "/", "/a/../b", "/k?x=1", "//a", "/a b", "/a/./b", "/k#f", "/a%2fb",
    ] {
        let mut d = router("a1", Some("sk-or-v1-"));
        d.test_path = Some(bad.to_owned());
        assert_eq!(
            code(prov::create(p, &d, "d_x", BY, NOW).await),
            "bad_request",
            "{bad}"
        );
    }
    let mut d = router("openrouter", Some("sk-or-v1-"));
    assert!(prov::create(p, &d, "d_x", BY, NOW).await.is_ok());
    let a = store(&fx, &s, "openrouter", "or-main", OR).await.unwrap();
    // OpenRouter's model list is public: a revoked key would read as `ok`. Without a declared
    // authenticated path nothing is sent, nothing is leased, and the answer is `inconclusive`.
    let uri = format!("/api/v1/accounts/{}/test", a.id);
    let (st, b) = call(&fx, &fx.dev, Method::POST, &uri, Value::Null).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(
        (b["result"].as_str(), b["runner"].as_str()),
        (Some("inconclusive"), Some(""))
    );
    let leases: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secret_leases")
        .fetch_one(p)
        .await
        .unwrap();
    assert_eq!(leases, 0);
    let (_, one) = call(
        &fx,
        &fx.dev,
        Method::GET,
        &format!("/api/v1/accounts/{}", a.id),
        Value::Null,
    )
    .await;
    assert_eq!(one["last_test"]["result"], "inconclusive");
    // Declaring the path is what makes a test mean something (the hub test sends it).
    d.test_path = Some("/key".to_owned());
    d.version = 0;
    assert_eq!(
        prov::replace(p, &d, "d_x", BY, NOW)
            .await
            .unwrap()
            .test_path
            .as_deref(),
        Some("/key")
    );
}

#[tokio::test]
async fn a_secret_name_cannot_borrow_another_accounts_host() {
    let (fx, _vm, s) = setup().await;
    open_gate(&fx).await;
    let p = &fx.app.pool;
    prov::create(p, &router("openrouter", Some("sk-or-v1-")), "d_x", BY, NOW)
        .await
        .unwrap();
    prov::create(p, &router("other", Some("sk-or-v2-")), "d_x", BY, NOW)
        .await
        .unwrap();
    let a = store(&fx, &s, "openrouter", "or-main", OR).await.unwrap();
    // `acct.other.<id>` names the OpenRouter account's id, but no account of `other` has it: the
    // key is not bound to that account's host, so it is refused.
    let name = format!("acct.other.{}", a.id);
    let key = "sk-or-v2-0123456789abcdefghijklmnopqrstuvwxyzTESTONLY";
    let new = crate::store::secrets::NewValue {
        value: key,
        runners: Some(&[]),
        delivery: Some("env"),
    };
    let r = crate::store::secrets::create(p, &s, &name, &new, &fx.dev.id, BY, NOW).await;
    assert_eq!(code(r), "bad_request");
}
