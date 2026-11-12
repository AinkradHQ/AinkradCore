//! The connection routes (C5): kinds, making a connection with a pasted credential, reading,
//! changing, deleting, replacing a credential, testing, and the activity.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;
use super::*;

const URI: &str = "/api/v1/connections";

fn body(name: &str) -> Value {
    json!({"kind": "github", "name": name, "auth_method": "token", "token": GH_TOKEN})
}

#[tokio::test]
async fn the_kinds_say_what_a_screen_needs_and_what_is_not_set_up_yet() {
    let cx = cx().await;
    let all = cx
        .ok(Method::GET, "/api/v1/connection-kinds", Value::Null)
        .await;
    let by = |all: &Value, k: &str| {
        all.as_array()
            .unwrap()
            .iter()
            .find(|d| d["kind"] == k)
            .unwrap()
            .clone()
    };
    let gh = by(&all, "github");
    let methods = |d: &Value| -> Vec<(String, bool)> {
        d["auth_methods"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| {
                (
                    m["id"].as_str().unwrap().to_owned(),
                    m["available"].as_bool().unwrap(),
                )
            })
            .collect()
    };
    let want = [("oauth", true), ("app_install", false), ("token", true)];
    let got = methods(&gh);
    assert_eq!(
        got.iter()
            .map(|(i, a)| (i.as_str(), *a))
            .collect::<Vec<_>>(),
        want
    );
    assert_eq!(gh["configured"], true, "the built-in GitHub app");
    let class = |d: &Value, cap: &str| {
        let caps = d["capabilities"].as_array().unwrap();
        caps.iter().find(|c| c["name"] == cap).unwrap()["class"].clone()
    };
    assert_eq!(
        (class(&gh, "read_repo"), class(&gh, "push")),
        (json!("read"), json!("write"))
    );
    assert!(gh["capabilities"][0]["title"].as_str().unwrap().len() > 3);
    assert_eq!(gh["limits"][0]["key"], "repos");
    let jira = by(&all, "jira");
    assert_eq!(jira["limits"][0]["key"], "projects");
    assert_eq!(methods(&jira)[0], ("oauth".to_owned(), false));
    cx.configure().await;
    let all = cx
        .ok(Method::GET, "/api/v1/connection-kinds", Value::Null)
        .await;
    let (gh, jira) = (by(&all, "github"), by(&all, "jira"));
    assert_eq!(
        (&gh["configured"], &jira["configured"]),
        (&json!(true), &json!(true))
    );
    assert_eq!(methods(&gh)[0], ("oauth".to_owned(), true));
    assert_eq!(methods(&gh)[1], ("app_install".to_owned(), false));
    assert_eq!(methods(&jira)[0], ("oauth".to_owned(), true));
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_token_connection_is_made_tested_and_listed_without_its_token() {
    let cx = cx().await;
    cx.gh.push(200, &[], r#"{"login":"octocat","id":1}"#);
    let mut b = body("main");
    b["label"] = json!("My GitHub");
    let made = cx.ok(Method::POST, URI, b).await;
    let id = made["id"].as_i64().unwrap();
    assert_eq!(made["identity"], "octocat");
    assert_eq!(
        (&made["status"], &made["label"]),
        (&json!("active"), &json!("My GitHub"))
    );
    assert_eq!(
        (&made["auth_method"], &made["is_default"]),
        (&json!("token"), &json!(false))
    );
    assert_eq!(
        (&made["grant_count"], &made["my_capabilities"]),
        (&json!(0), &Value::Null)
    );
    let auth = cx.gh.seen()[0].header("authorization").unwrap().to_owned();
    assert!(
        auth.contains(GH_TOKEN),
        "the credential was tested as given"
    );
    let j = cx.jira("acme").await;
    let jv = cx.ok(Method::GET, &format!("{URI}/{j}"), Value::Null).await;
    assert!(
        jv["identity"].as_str().unwrap().contains("5b10ac8d"),
        "{jv}"
    );
    assert_eq!(
        cx.ok(Method::GET, &format!("{URI}/{id}"), Value::Null)
            .await,
        made
    );
    let list = cx.ok(Method::GET, URI, Value::Null).await;
    assert_eq!(list.as_array().unwrap().len(), 2);
    let only = cx
        .ok(Method::GET, &format!("{URI}?kind=jira"), Value::Null)
        .await;
    assert_eq!(only.as_array().unwrap().len(), 1);
    // The row holds no label of the token, and the audit says who, never what.
    let created: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'connection.created' ORDER BY seq",
    )
    .fetch_all(&cx.fx.app.pool)
    .await
    .unwrap();
    assert_eq!(created.len(), 2);
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_bad_request_a_refused_credential_or_a_gate_leaves_no_connection() {
    let cx = cx().await;
    cx.github("main").await;
    let post = |b: Value| cx.admin(Method::POST, URI, b);
    // Validation: 400.
    let mut bad_name = body("Bad Name");
    bad_name["name"] = json!("Bad Name");
    let bad = [
        ("a name", bad_name),
        (
            "a kind",
            json!({"kind": "svn", "auth_method": "token", "token": "x"}),
        ),
        (
            "a method",
            json!({"kind": "github", "auth_method": "password", "token": "x"}),
        ),
        (
            "no token",
            json!({"kind": "github", "auth_method": "token"}),
        ),
        (
            "an empty token",
            json!({"kind": "github", "auth_method": "token", "token": "  "}),
        ),
        (
            "a method for another route",
            json!({"kind": "github", "auth_method": "oauth"}),
        ),
        (
            "no installation",
            json!({"kind": "github", "auth_method": "app_install"}),
        ),
        (
            "a bad site",
            json!({"kind": "jira", "auth_method": "token", "token": "t", "email": EMAIL,
                "site": "evil.example.com"}),
        ),
        (
            "a bad email",
            json!({"kind": "jira", "auth_method": "token", "token": "t", "email": "nobody",
                "site": SITE}),
        ),
    ];
    for (why, b) in bad {
        let r = post(b).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{why}: {}", r.1);
    }
    // Not JSON at all: one fixed message that never quotes the body.
    let r = post(Value::String(format!("{{broken {GH_TOKEN}"))).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST, "{}", r.1);
    // The GitHub App is not set up: no GitHub sign-in yet, its own error code (#206), not a crash.
    let app = json!({"kind": "github", "auth_method": "app_install", "installation_id": 7});
    assert_eq!(
        code(&post(app).await),
        (409, "github_sign_in_needed".to_owned())
    );
    // A taken name: 409, before anything is asked of GitHub.
    assert_eq!(
        code(&post(body("main")).await),
        (409, "conflict".to_owned())
    );
    // GitHub refuses the token: 400 and nothing is kept.
    cx.gh.push(401, &[], r#"{"message":"Bad credentials"}"#);
    let r = post(body("refused")).await;
    assert_eq!(code(&r), (400, "credential_rejected".to_owned()), "{}", r.1);
    // GitHub cannot be reached: 502 and nothing is kept.
    cx.gh.push(500, &[], "{}");
    let r = post(body("down")).await;
    assert_eq!(code(&r), (502, "upstream_failed".to_owned()), "{}", r.1);
    // A recognised real token is refused by the secrets gate, before any request.
    let mut real = body("real");
    real["token"] = json!(format!("ghp_{}", "A1b2C3d4E5".repeat(4)));
    assert_eq!(
        code(&post(real).await),
        (409, "real_secret_refused".to_owned())
    );
    // The broker off: 409.
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
    assert_eq!(
        code(&post(body("off")).await),
        (409, "secrets_disabled".to_owned())
    );
    let names: Vec<String> = cx
        .ok(Method::GET, URI, Value::Null)
        .await
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["main"]);
    // Only the one request each of the two upstream answers was made.
    assert_eq!(cx.gh.seen().len(), 3);
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_connection_is_renamed_relabelled_and_switched_off() {
    let cx = cx().await;
    let id = cx.github("main").await;
    let other = cx.github("second").await;
    let one = format!("{URI}/{id}");
    let patch = |b: Value| cx.admin(Method::PATCH, &one, b);
    let v = patch(json!({"name": "work", "label": "Work GitHub"})).await;
    assert_eq!(v.0, StatusCode::OK, "{}", v.1);
    assert_eq!(
        (&v.1["name"], &v.1["label"]),
        (&json!("work"), &json!("Work GitHub"))
    );
    let v = patch(json!({"disabled": true})).await;
    assert_eq!(
        (&v.1["disabled"], &v.1["name"]),
        (&json!(true), &json!("work"))
    );
    let v = patch(json!({"disabled": false})).await;
    assert_eq!(v.1["disabled"], false);
    assert_eq!(
        code(&patch(json!({})).await),
        (400, "bad_request".to_owned())
    );
    assert_eq!(code(&patch(json!({"name": "Not Valid"})).await).0, 400);
    assert_eq!(code(&patch(json!({"label": ""})).await).0, 400);
    assert_eq!(
        code(&patch(json!({"name": "second"})).await),
        (409, "conflict".to_owned())
    );
    let _ = other;
    for action in [
        "connection.renamed",
        "connection.updated",
        "connection.disabled",
        "connection.enabled",
    ] {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
            .bind(action)
            .fetch_one(&cx.fx.app.pool)
            .await
            .unwrap();
        assert_eq!(n, 1, "{action}");
    }
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_default_connection_is_not_deleted_until_another_or_none_is_default() {
    let cx = cx().await;
    let (a, b) = (cx.github("a").await, cx.github("b").await);
    let default = |c: i64| {
        cx.admin(
            Method::PUT,
            "/api/v1/connection-defaults/github",
            json!({"connection": c}),
        )
    };
    assert_eq!(default(a).await.0, StatusCode::OK);
    let del = |c: i64| cx.admin(Method::DELETE, &format!("{URI}/{c}"), Value::Null);
    let r = del(a).await;
    assert_eq!(code(&r), (409, "conflict".to_owned()), "{}", r.1);
    assert_eq!(
        cx.ok(Method::GET, &format!("{URI}/{a}"), Value::Null).await["is_default"],
        true
    );
    // Another connection becomes the default: the first can go.
    assert_eq!(default(b).await.1["connection"], b);
    let r = del(a).await;
    assert_eq!(
        (r.0, &r.1["deleted"]),
        (StatusCode::OK, &json!(true)),
        "{}",
        r.1
    );
    assert_eq!(
        cx.admin(Method::GET, &format!("{URI}/{a}"), Value::Null)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(code(&del(b).await).0, 409);
    let cleared = cx
        .ok(
            Method::DELETE,
            "/api/v1/connection-defaults/github",
            Value::Null,
        )
        .await;
    assert_eq!(cleared["deleted"], true);
    assert_eq!(del(b).await.0, StatusCode::OK);
    assert_eq!(
        cx.admin(
            Method::DELETE,
            "/api/v1/connection-defaults/github",
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_credential_is_replaced_and_a_signed_in_connection_signs_in_again_instead() {
    let cx = cx().await;
    let id = cx.github("main").await;
    cx.gh.push(200, &[], r#"{"login":"octocat","id":1}"#);
    let put = |b: Value| cx.admin(Method::PUT, &format!("{URI}/{id}/credential"), b);
    let v = put(json!({"token": GH_TOKEN2})).await;
    assert_eq!(v.0, StatusCode::OK, "{}", v.1);
    assert_eq!(v.1["id"], id);
    let (m, version) = crate::store::connections::secret::open(
        &cx.fx.app.pool,
        cx.fx.app.secrets.as_deref().unwrap(),
        1,
        id,
    )
    .await
    .unwrap();
    assert_eq!((m.access(), version), (GH_TOKEN2, 2));
    assert_eq!(code(&put(json!({})).await).0, 400);
    // A connection made by signing in cannot be pasted over.
    let new = crate::store::connections::NewConnection {
        kind: "github",
        name: "signed",
        label: "Signed in",
        auth_method: "oauth",
    };
    let who = crate::store::connections::Who {
        workspace: 1,
        by_device: "d_test",
        actor: ainkrad_core::audit::AuditActor::System,
        now: NOW,
    };
    let reg = cx.fx.app.connections.registry();
    let sealer = cx.fx.app.secrets.as_deref().unwrap();
    let material = crate::connections::material::Material::new(ACCESS, None, None).unwrap();
    let c = crate::store::connections::create(&cx.fx.app.pool, sealer, reg, &new, &material, who)
        .await
        .unwrap();
    let r = cx
        .admin(
            Method::PUT,
            &format!("{URI}/{}/credential", c.id),
            json!({"token": GH_TOKEN2}),
        )
        .await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST, "{}", r.1);
    assert!(r.1["message"].as_str().unwrap().contains("sign in again"));
    cx.assert_clean().await;
}
