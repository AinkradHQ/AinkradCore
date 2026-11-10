//! The negative suite for provider-account secrets (KAN-445), the one that has to be green before
//! the first real key is stored: no API path returns a value, a backup holds it only sealed, a
//! revoked device cannot lease it, masking fails closed after a rotation or a deletion, a session
//! naming one must be sandboxed and keep it in its harness's own variable (KAN-433, KAN-429), and
//! a device without `admin` can neither name nor lease one. The gate `secrets.provider_accounts`
//! stays 0 throughout: a throwaway value with no key shape is allowed in mode 1 either way.

use ainkrad_core::settings::{Key, Scope};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::ops::secretbox::SecretBox;
use crate::store::secrets as st;

const NAME: &str = "acct.anthropic.main";
const V1: &str = "throwaway-acct-value-one-5a91c3";
const V2: &str = "throwaway-acct-value-two-77d0be";

async fn broker() -> (Fx, TestDevice) {
    let mut fx = fx().await;
    fx.app.secrets = Some(Arc::new(SecretBox::new(&[7; 32])));
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
    (fx, vm)
}

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

/// The status and the raw text of a GET (a route may answer text, not JSON).
async fn raw_get(fx: &Fx, dev: &TestDevice, uri: &str) -> (StatusCode, String) {
    let res = router(fx.app.clone())
        .oneshot(req(Method::GET, uri, Some(dev), None))
        .await
        .unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn store_account(fx: &Fx, vm: &TestDevice, value: &str) {
    let body = json!({"name": NAME, "value": value, "runners": [vm.id]});
    let r = super::secrets::post_secret(fx, body).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
}

/// A session names an API-key account by the account model's own name (`acct.<provider>.<id>`):
/// any other label would be an env secret, which no session may hold (KAN-435 G7).
fn session_body(harness: &str, var: &str, policy: Value) -> Value {
    json!({"runner": "d_00000000000000000000000000", "harness": harness, "policy": policy,
           "secrets": [{"name": "acct.anthropic.7", "var": var}]})
}

fn sandboxed() -> Value {
    json!({"mode": "ask", "min_isolation": "process"})
}

#[tokio::test]
async fn no_api_path_returns_an_account_secrets_value() {
    let (fx, vm) = broker().await;
    store_account(&fx, &vm, V1).await;
    let lease = call(
        &fx,
        &fx.dev,
        Method::POST,
        &format!("/api/v1/secrets/{NAME}/leases"),
        json!({"runner": vm.id}),
    )
    .await;
    assert_eq!(lease.0, StatusCode::OK, "{}", lease.1);
    assert!(
        !lease.1.to_string().contains(V1),
        "the lease carries the id only"
    );
    // A session naming it, so the session routes have something to show.
    let policy = sandboxed();
    let secrets = [crate::store::agents::SessionSecret {
        name: NAME.into(),
        var: "ANTHROPIC_API_KEY".into(),
    }];
    let new = crate::store::agents::NewSession {
        runner: &vm.id,
        harness: "claude",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &secrets,
        created_by: &fx.dev.id,
    };
    let s = crate::store::agents::create(&fx.app.pool, &new, super::super::BY, NOW)
        .await
        .unwrap();
    // Rotated, so both the old and the new value must stay out of every answer.
    let rotated = super::secrets::put_secret(&fx, NAME, json!({"value": V2})).await;
    assert_eq!(rotated.0, StatusCode::OK, "{}", rotated.1);
    let mut paths: Vec<String> = super::super::scopes::ROUTES
        .iter()
        // The Core machine's routes answer 503 here on purpose: no host helper in a test.
        .filter(|(m, p, _)| {
            *m == "GET" && !p.contains('{') && !p.ends_with("/ws") && !p.starts_with("/api/v1/system/")
        })
        .map(|(_, p, _)| (*p).to_owned())
        .collect();
    paths.push(format!("/api/v1/agent-sessions/{}", s.id));
    paths.push(format!("/api/v1/agent-sessions/{}/transcript", s.id));
    assert!(
        paths.len() >= 12,
        "the sweep must cover the contract: {paths:?}"
    );
    let mut answered = 0;
    for p in &paths {
        let (status, text) = raw_get(&fx, &fx.dev, p).await;
        assert!(!status.is_server_error(), "{p}: {status}");
        answered += usize::from(status == StatusCode::OK);
        for v in [V1, V2] {
            assert!(!text.contains(v), "GET {p} returned a secret value");
        }
    }
    assert!(answered >= 8, "only {answered} routes answered 200");
    // Control, so the sweep proves something: the one path that does carry the value is the
    // runner's own redemption of its own lease. The rotation dropped the first lease.
    let fresh = call(
        &fx,
        &fx.dev,
        Method::POST,
        &format!("/api/v1/secrets/{NAME}/leases"),
        json!({"runner": vm.id}),
    )
    .await;
    let r = call(
        &fx,
        &vm,
        Method::POST,
        "/api/v1/secret-leases/redeem",
        json!({"lease": fresh.1["lease"]}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert!(
        r.1.to_string().contains(V2),
        "the control must see the value"
    );
}

#[tokio::test]
async fn a_backup_holds_an_account_secret_only_sealed() {
    let (fx, vm) = broker().await;
    store_account(&fx, &vm, V1).await;
    let dest = std::env::temp_dir().join(format!("acct-backup-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&dest);
    crate::store::backup(&fx.app.pool, &dest).await.unwrap();
    let bytes = std::fs::read(&dest).unwrap();
    let _ = std::fs::remove_file(&dest);
    let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    assert!(
        has(NAME.as_bytes()),
        "control: the backup does hold the row"
    );
    assert!(
        !has(V1.as_bytes()),
        "the backup holds the value in plaintext"
    );
    // Nor in any common re-encoding of it.
    let hex: String = V1.bytes().map(|b| format!("{b:02x}")).collect();
    assert!(!has(hex.as_bytes()));
}

#[tokio::test]
async fn a_revoked_admin_cannot_lease_and_a_revoked_runner_cannot_redeem_an_account_secret() {
    let (fx, vm) = broker().await;
    store_account(&fx, &vm, V1).await;
    let admin = super::stepup::plain(&fx, "second-admin", &["admin", "read"], true).await;
    assert_eq!(super::stepup::step_up(&fx, &admin).await.0, StatusCode::OK);
    let uri = format!("/api/v1/secrets/{NAME}/leases");
    let ok = call(&fx, &admin, Method::POST, &uri, json!({"runner": vm.id})).await;
    assert_eq!(
        ok.0,
        StatusCode::OK,
        "control: before the revocation: {}",
        ok.1
    );
    // The runner holds a live lease, then both devices are revoked.
    let held = call(&fx, &fx.dev, Method::POST, &uri, json!({"runner": vm.id})).await;
    for id in [&admin.id, &vm.id] {
        let r = call(
            &fx,
            &fx.dev,
            Method::DELETE,
            &format!("/api/v1/devices/{id}"),
            Value::Null,
        )
        .await;
        assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    }
    let r = call(&fx, &admin, Method::POST, &uri, json!({"runner": vm.id})).await;
    assert_eq!(r.0, StatusCode::UNAUTHORIZED, "{}", r.1);
    let r = call(
        &fx,
        &vm,
        Method::POST,
        "/api/v1/secret-leases/redeem",
        json!({"lease": held.1["lease"]}),
    )
    .await;
    assert_eq!(r.0, StatusCode::UNAUTHORIZED, "{}", r.1);
    assert!(!r.1.to_string().contains(V1));
}

#[tokio::test]
async fn masking_an_account_secret_fails_closed_after_a_rotation_or_a_deletion() {
    let (fx, vm) = broker().await;
    store_account(&fx, &vm, V1).await;
    let sealer = fx.app.secrets.clone().unwrap();
    let names = [NAME.to_owned()];
    // A session that began after the secret was stored can be masked.
    let began = "2026-10-22T11:00:00.000Z";
    let got = st::open_for_masking(&fx.app.pool, &sealer, &names, began)
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "control");
    // Rotated after the session began: the agent may hold the old value, so refuse.
    fx.clock.advance(7200);
    let later = crate::scheduler::iso_of_unix(fx.clock.unix());
    let new = st::NewValue {
        value: V2,
        runners: None,
        delivery: None,
    };
    st::rotate(
        &fx.app.pool,
        &sealer,
        NAME,
        &new,
        &fx.dev.id,
        super::super::BY,
        &later,
    )
    .await
    .unwrap();
    let r = st::open_for_masking(&fx.app.pool, &sealer, &names, began).await;
    assert!(
        matches!(
            &r,
            Err(st::Error::Refused {
                code: "secrets_unavailable",
                ..
            })
        ),
        "rotated"
    );
    // Deleted: refused as well.
    st::delete(&fx.app.pool, NAME, &fx.dev.id, super::super::BY)
        .await
        .unwrap();
    let r = st::open_for_masking(&fx.app.pool, &sealer, &names, began).await;
    assert!(
        matches!(
            &r,
            Err(st::Error::Refused {
                code: "secrets_unavailable",
                ..
            })
        ),
        "deleted"
    );
}

#[tokio::test]
async fn a_session_naming_an_account_secret_must_be_sandboxed_and_keep_it_in_its_harnesss_variable()
{
    let (fx, _vm) = broker().await;
    let post = |body: Value| call(&fx, &fx.dev, Method::POST, "/api/v1/agent-sessions", body);
    // KAN-429: any other variable, another harness's, a redirecting one beside it.
    for (harness, var) in [
        ("claude", "HTTPS_PROXY"),
        ("claude", "ANTHROPIC_BASE_URL"),
        ("claude", "OPENAI_API_KEY"),
    ] {
        let r = post(session_body(harness, var, sandboxed())).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{harness} {var}: {}", r.1);
        assert!(
            r.1.to_string().contains("authentication variables"),
            "{}",
            r.1
        );
    }
    // The secret is Anthropic's: another provider's harness refuses it even in its own variable,
    // and a harness with no provider takes none.
    for (harness, var) in [
        ("codex", "OPENAI_API_KEY"),
        ("agy", "GEMINI_API_KEY"),
        ("fake", "ANTHROPIC_API_KEY"),
    ] {
        let r = post(session_body(harness, var, sandboxed())).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{harness} {var}: {}", r.1);
        assert!(r.1.to_string().contains("its own provider"), "{}", r.1);
    }
    let mut both = session_body("claude", "ANTHROPIC_API_KEY", sandboxed());
    both["secrets"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "git.token", "var": "HTTPS_PROXY"}));
    let r = post(both).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST, "{}", r.1);
    assert!(r.1.to_string().contains("redirect"), "{}", r.1);
    // KAN-433: no sandbox asked for.
    for policy in [
        json!({"mode": "ask"}),
        json!({"mode": "ask", "min_isolation": "none"}),
    ] {
        let r = post(session_body("claude", "ANTHROPIC_API_KEY", policy)).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{}", r.1);
        assert!(r.1.to_string().contains("sandboxed"), "{}", r.1);
    }
    // Control: the allowed variable and a sandbox pass the checks above and stop later, at the
    // runner (this device id is not connected), not as a 400 about the secret.
    let r = post(session_body("claude", "ANTHROPIC_API_KEY", sandboxed())).await;
    let text = r.1.to_string();
    assert!(
        !text.contains("authentication variables") && !text.contains("sandboxed"),
        "{}: {text}",
        r.0
    );
}

#[tokio::test]
async fn a_device_without_admin_can_neither_name_nor_lease_nor_list_an_account_secret() {
    let (fx, vm) = broker().await;
    store_account(&fx, &vm, V1).await;
    let agent = super::stepup::plain(&fx, "agent-only", &["agent", "read", "approve"], true).await;
    assert_eq!(super::stepup::step_up(&fx, &agent).await.0, StatusCode::OK);
    // A valid, sandboxed request naming the account secret: stopped by the scope, not later.
    let r = call(
        &fx,
        &agent,
        Method::POST,
        "/api/v1/agent-sessions",
        session_body("claude", "ANTHROPIC_API_KEY", sandboxed()),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope")),
        "{}",
        r.1
    );
    // No route of the secrets broker is open to it, and a redemption is for runners.
    for (m, uri, body) in [
        (Method::GET, "/api/v1/secrets".to_owned(), Value::Null),
        (
            Method::POST,
            format!("/api/v1/secrets/{NAME}/leases"),
            json!({"runner": vm.id}),
        ),
        (
            Method::PUT,
            format!("/api/v1/secrets/{NAME}"),
            json!({"value": V2}),
        ),
        (
            Method::DELETE,
            format!("/api/v1/secrets/{NAME}"),
            Value::Null,
        ),
        (
            Method::POST,
            "/api/v1/secret-leases/redeem".to_owned(),
            json!({"lease": "l_x"}),
        ),
    ] {
        let r = call(&fx, &agent, m.clone(), &uri, body).await;
        assert_eq!(r.0, StatusCode::FORBIDDEN, "{m} {uri}: {}", r.1);
    }
}
