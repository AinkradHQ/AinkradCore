//! Ainkrad's OAuth apps over the API (C5): secrets are write-only and sealed, a change takes
//! effect in the ONE shared Jira, the GitHub App's key renews installation tokens, and the
//! redirect address follows the port setting.

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;
use super::*;

const URI: &str = "/api/v1/connections";
const APPS: &str = "/api/v1/connection-apps";

/// A throwaway RSA key made with the `openssl` tool for each run; it signs nothing real.
fn pem() -> String {
    let out = std::process::Command::new("openssl")
        .args(["genrsa", "2048"])
        .output()
        .expect("the openssl tool makes the test key");
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

/// A line of the key's body: it must be in no response, event or audit row.
fn mark(pem: &str) -> String {
    pem.lines().nth(2).unwrap().to_owned()
}

#[tokio::test]
async fn a_secret_field_is_write_only_and_sealed_and_a_value_field_shows_itself() {
    let cx = cx().await;
    let got = cx
        .ok(Method::GET, &format!("{APPS}/jira"), Value::Null)
        .await;
    assert_eq!(got["configured"], false);
    assert!(
        got["fields"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["set"] == false)
    );
    let put = cx
        .ok(
            Method::PUT,
            &format!("{APPS}/jira"),
            json!({"fields": {"client_id": "client-id-8c41", "client_secret": CLIENT_SECRET}}),
        )
        .await;
    assert_eq!(put["configured"], true);
    let field = |name: &str| {
        put["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == name)
            .unwrap()
            .clone()
    };
    assert_eq!(
        (
            field("client_id")["set"].clone(),
            field("client_id")["value"].clone()
        ),
        (json!(true), json!("client-id-8c41"))
    );
    let secret = field("client_secret");
    assert_eq!(
        (&secret["set"], &secret["secret"], &secret["value"]),
        (&json!(true), &json!(true), &Value::Null)
    );
    assert_eq!(put["redirect_uri"], "http://127.0.0.1:47613/callback");
    assert_eq!(
        cx.ok(Method::GET, &format!("{APPS}/jira"), Value::Null)
            .await,
        put
    );
    // Sealed at rest, and the audit row names the fields only.
    let blobs: Vec<Vec<u8>> = sqlx::query_scalar("SELECT sealed FROM core_connection_apps")
        .fetch_all(&cx.fx.app.pool)
        .await
        .unwrap();
    let needle = CLIENT_SECRET.as_bytes();
    assert!(
        blobs
            .iter()
            .all(|b| !b.windows(needle.len()).any(|w| w == needle))
    );
    let audit: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'connection.app_set' ORDER BY seq LIMIT 1",
    )
    .fetch_one(&cx.fx.app.pool)
    .await
    .unwrap();
    assert!(
        audit.contains("client_secret") && !audit.contains(CLIENT_SECRET),
        "{audit}"
    );
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_config_change_reaches_the_one_shared_jira_and_ends_the_old_sign_ins() {
    let cx = cx().await;
    let jira = Arc::clone(cx.fx.app.connections.jira());
    let registered = cx.fx.app.connections.registry().get("jira").unwrap();
    let same = |a: &Arc<crate::connections::jira::Jira>| {
        Arc::as_ptr(a).cast::<()>() == Arc::as_ptr(registered).cast::<()>()
    };
    assert!(same(&jira) && !jira.app_configured());
    cx.configure().await;
    assert!(
        jira.app_configured(),
        "the instance everyone holds got the app"
    );
    assert!(
        Arc::ptr_eq(&jira, cx.fx.app.connections.jira()) && same(&jira),
        "still one instance"
    );
    // A sign-in started now, then the app changes: that sign-in cannot finish any more.
    let old = start(&cx, "jira", json!({})).await.1;
    cx.ok(
        Method::PUT,
        &format!("{APPS}/jira"),
        json!({"fields": {"client_id": "client-id-2222", "loopback_port": "50123"}}),
    )
    .await;
    assert!(
        Arc::ptr_eq(&jira, cx.fx.app.connections.jira()),
        "still one instance"
    );
    let r = cx
        .admin(
            Method::POST,
            &format!("{URI}/flows/{}/callback", old["id"].as_str().unwrap()),
            json!({"code": CODE, "state": old["state"]}),
        )
        .await;
    assert_eq!(r.1["error_code"], "unknown_state", "{}", r.1);
    // A sign-in started after the change uses the new client and redirect, and connects.
    let v = start(&cx, "jira", json!({})).await.1;
    let url = v["authorize_url"].as_str().unwrap();
    assert_eq!(param(url, "client_id"), "client-id-2222");
    assert_eq!(
        param(url, "redirect_uri"),
        "http://127.0.0.1:50123/callback"
    );
    let done = cx
        .admin(
            Method::POST,
            &format!("{URI}/flows/{}/callback", v["id"].as_str().unwrap()),
            json!({"code": CODE, "state": v["state"]}),
        )
        .await;
    assert_eq!(done.1["step"], "connected", "{}", done.1);
    assert_eq!(
        cx.jf.last("POST /oauth/token").unwrap().body["client_id"],
        "client-id-2222"
    );
    // Cleared: Sign in is off again, with the plain refusal.
    let off = cx
        .ok(
            Method::PUT,
            &format!("{APPS}/jira"),
            json!({"fields": {"client_secret": null}}),
        )
        .await;
    assert_eq!(off["configured"], false);
    assert!(!jira.app_configured());
    assert_eq!(
        code(&start(&cx, "jira", json!({})).await),
        (409, "not_configured".to_owned())
    );
    cx.assert_clean().await;
}

#[tokio::test]
async fn the_config_is_validated_and_refused_while_the_broker_is_off() {
    let cx = cx().await;
    let put = |kind: &str, fields: Value| {
        cx.admin(
            Method::PUT,
            &format!("{APPS}/{kind}"),
            json!({"fields": fields}),
        )
    };
    let bad = [
        ("jira", "an unknown field", json!({"nope": "x"})),
        ("jira", "another kind's field", json!({"app_id": "1"})),
        (
            "jira",
            "a client id with a space",
            json!({"client_id": "a b"}),
        ),
        ("jira", "an empty client id", json!({"client_id": ""})),
        ("jira", "a low port", json!({"loopback_port": "80"})),
        (
            "jira",
            "a port that is not one",
            json!({"loopback_port": "abc"}),
        ),
        ("jira", "no fields", json!({})),
        (
            "github",
            "a key that is no key",
            json!({"app_id": "1", "app_key": "not a pem"}),
        ),
        ("github", "a key without its id", json!({"app_key": pem()})),
        ("github", "a bad id", json!({"app_id": "1 2"})),
        ("github", "a bad slug", json!({"app_slug": "a/b"})),
    ];
    for (kind, why, fields) in bad {
        let r = put(kind, fields).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{why}: {}", r.1);
    }
    for kind in ["svn", "{kind}"] {
        assert_eq!(
            code(
                &cx.admin(Method::GET, &format!("{APPS}/{kind}"), Value::Null)
                    .await
            )
            .0,
            404
        );
        assert_eq!(code(&put(kind, json!({"client_id": "x"})).await).0, 404);
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_connection_apps")
        .fetch_one(&cx.fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "a refusal stores nothing");
    crate::store::settings::set(
        &cx.fx.app.pool,
        ainkrad_core::settings::Key::SecretsMode,
        ainkrad_core::settings::Scope::Server,
        "0",
        ainkrad_core::audit::AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    let r = put("jira", json!({"client_id": "x"})).await;
    assert_eq!(code(&r), (409, "secrets_disabled".to_owned()), "{}", r.1);
    cx.assert_clean().await;
}

#[tokio::test]
async fn the_github_app_mints_and_renews_installation_tokens_before_they_end() {
    let cx = cx().await;
    let key = pem();
    let by_kind = |all: &Value| {
        all.as_array()
            .unwrap()
            .iter()
            .find(|d| d["kind"] == "github")
            .unwrap()
            .clone()
    };
    let before = by_kind(
        &cx.ok(Method::GET, "/api/v1/connection-kinds", Value::Null)
            .await,
    );
    assert_eq!(before["install_url"], Value::Null);
    let set = cx
        .ok(
            Method::PUT,
            &format!("{APPS}/github"),
            json!({"fields": {"app_id": "123456", "app_key": key, "app_slug": "ainkrad-test"}}),
        )
        .await;
    assert_eq!(set["app_install_configured"], true);
    assert_eq!(
        set["configured"], false,
        "the device flow needs its client id"
    );
    let key_field = set["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "app_key")
        .unwrap();
    assert_eq!(
        (&key_field["set"], &key_field["value"]),
        (&json!(true), &Value::Null)
    );
    let after = by_kind(
        &cx.ok(Method::GET, "/api/v1/connection-kinds", Value::Null)
            .await,
    );
    assert_eq!(
        after["install_url"],
        "https://github.com/apps/ainkrad-test/installations/new"
    );
    let methods: Vec<(String, bool)> = after["auth_methods"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["id"].as_str().unwrap().to_owned(),
                m["available"].as_bool().unwrap(),
            )
        })
        .collect();
    assert!(methods.contains(&("app_install".to_owned(), true)));
    // An installation connection: a token is minted with the App's signed JWT, then tested.
    let inst = |token: &str| {
        cx.gh.push(
            201,
            &[],
            &format!(r#"{{"token":"{token}","expires_at":"2026-10-22T11:00:00Z"}}"#),
        );
        cx.gh.push(
            403,
            &[],
            r#"{"message":"Resource not accessible by integration"}"#,
        );
        cx.gh.push(
            200,
            &[],
            r#"{"total_count":1,"repositories":[{"owner":{"login":"octo-org","id":9}}]}"#,
        );
    };
    inst("c5inst-4d8a2f6e1b9c0a37");
    let body = json!({"kind": "github", "name": "app", "auth_method": "app_install", "installation_id": 77});
    let made = cx.ok(Method::POST, URI, body).await;
    let id = made["id"].as_i64().unwrap();
    assert_eq!(
        (&made["identity"], &made["auth_method"]),
        (&json!("octo-org"), &json!("app_install"))
    );
    assert_eq!(made["expires_at"], "2026-10-22T11:00:00.000Z");
    assert_eq!(cx.gh.seen()[0].path, "/app/installations/77/access_tokens");
    assert!(
        cx.gh.seen()[0]
            .header("authorization")
            .unwrap()
            .starts_with("Bearer ey"),
        "signed with the App key"
    );
    assert_eq!(
        crate::store::connections::apps::installation_of(&cx.fx.app.pool, 1, id)
            .await
            .unwrap(),
        Some(77)
    );
    // Far from its end: a test mints nothing.
    cx.gh.push(403, &[], r#"{"message":"x"}"#);
    cx.gh.push(
        200,
        &[],
        r#"{"repositories":[{"owner":{"login":"octo-org","id":9}}]}"#,
    );
    cx.ok(Method::POST, &format!("{URI}/{id}/test"), Value::Null)
        .await;
    let mints = |cx: &Cx| {
        cx.gh
            .seen()
            .iter()
            .filter(|s| s.path.ends_with("/access_tokens"))
            .count()
    };
    assert_eq!(mints(&cx), 1);
    // Within five minutes of its end: the test mints a new one first and seals it as version 2.
    sqlx::query("UPDATE core_connection_secrets SET expires_at = '2026-10-22T10:02:00.000Z' WHERE connection_id = ?")
        .bind(id)
        .execute(&cx.fx.app.pool)
        .await
        .unwrap();
    inst("c5inst-9e1f3a5c7b2d4f60");
    let v = cx
        .ok(Method::POST, &format!("{URI}/{id}/test"), Value::Null)
        .await;
    assert_eq!(mints(&cx), 2);
    assert_eq!(
        (&v["status"], &v["expires_at"]),
        (&json!("active"), &json!("2026-10-22T11:00:00.000Z"))
    );
    let (m, version) = crate::store::connections::secret::open(
        &cx.fx.app.pool,
        cx.fx.app.secrets.as_deref().unwrap(),
        1,
        id,
    )
    .await
    .unwrap();
    assert_eq!((m.access(), version), ("c5inst-9e1f3a5c7b2d4f60", 2));
    // The App is not configured any more: no token is minted, the old one is simply tested.
    cx.ok(
        Method::PUT,
        &format!("{APPS}/github"),
        json!({"fields": {"app_key": null}}),
    )
    .await;
    assert!(!cx.fx.app.connections.github().installer().configured());
    cx.assert_clean_also(&[
        "c5inst-4d8a2f6e1b9c0a37",
        "c5inst-9e1f3a5c7b2d4f60",
        &mark(&key),
    ])
    .await;
}
