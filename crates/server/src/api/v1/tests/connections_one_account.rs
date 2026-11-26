//! One account is one connection: a sign-in's connection takes a pasted token of the same account
//! (and becomes a `token` one, its grants kept), and a second connection for an account already
//! connected is refused.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;

const URI: &str = "/api/v1/connections";
const OCTOCAT: &str = r#"{"login":"octocat","id":583231}"#;

/// A GitHub sign-in (device flow) as octocat; its connection id.
async fn signed_in(cx: &Cx) -> i64 {
    cx.configure().await;
    cx.gh.push(200, &[], START);
    cx.gh.push(
        200,
        &[],
        &format!(r#"{{"access_token":"{GH_TOKEN}","token_type":"bearer","scope":"repo"}}"#),
    );
    cx.gh.push(200, &[], OCTOCAT);
    let id = start(cx, "github", json!({})).await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    until(cx, &id, "connected").await["connection"]
        .as_i64()
        .unwrap()
}

async fn version(cx: &Cx, id: i64) -> (String, i64) {
    let sealer = cx.fx.app.secrets.as_deref().unwrap();
    let (m, v) = crate::store::connections::secret::open(&cx.fx.app.pool, sealer, 1, id)
        .await
        .unwrap();
    (m.access().to_owned(), v)
}

#[tokio::test]
async fn a_sign_in_takes_a_token_of_the_same_account_and_keeps_its_grants() {
    let cx = cx().await;
    let id = signed_in(&cx).await;
    let grants = format!("{URI}/{id}/grants");
    let grant = json!({"grantee_kind": "user", "grantee": "1",
        "capabilities": ["read_repo", "pr_write"], "limits": {"repos": ["octo/app"]}});
    cx.ok(Method::PUT, &grants, grant).await;
    let before = cx.ok(Method::GET, &grants, Value::Null).await;
    let put = |b: Value| cx.admin(Method::PUT, &format!("{URI}/{id}/credential"), b);
    // Without a token a sign-in is still refreshed by signing in again.
    let r = put(json!({})).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST, "{}", r.1);
    assert!(r.1["message"].as_str().unwrap().contains("sign in again"));
    cx.gh.push(200, &[], OCTOCAT); // the same account?
    cx.gh.push(200, &[], OCTOCAT); // the test of the new credential
    let v = put(json!({"token": GH_TOKEN2})).await;
    assert_eq!(v.0, StatusCode::OK, "{}", v.1);
    assert_eq!(
        (
            &v.1["id"],
            &v.1["name"],
            &v.1["auth_method"],
            &v.1["identity"]
        ),
        (
            &json!(id),
            &json!("github-1"),
            &json!("token"),
            &json!("octocat")
        )
    );
    assert_eq!(version(&cx, id).await, (GH_TOKEN2.to_owned(), 2));
    assert_eq!(cx.ok(Method::GET, &grants, Value::Null).await, before);
    let audit: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'connection.secret_replaced'",
    )
    .fetch_one(&cx.fx.app.pool)
    .await
    .unwrap();
    assert!(audit.contains(r#""auth_method":"token""#), "{audit}");
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_token_of_another_account_does_not_replace_a_sign_in() {
    let cx = cx().await;
    let id = signed_in(&cx).await;
    cx.gh.push(200, &[], r#"{"login":"hubot","id":2}"#);
    let r = cx
        .admin(
            Method::PUT,
            &format!("{URI}/{id}/credential"),
            json!({"token": GH_TOKEN2}),
        )
        .await;
    assert_eq!(code(&r), (409, "different_account".to_owned()), "{}", r.1);
    assert!(
        r.1["message"]
            .as_str()
            .unwrap()
            .contains("another GitHub account"),
        "{}",
        r.1
    );
    let c = cx
        .ok(Method::GET, &format!("{URI}/{id}"), Value::Null)
        .await;
    assert_eq!(c["auth_method"], "oauth");
    assert_eq!(version(&cx, id).await, (GH_TOKEN.to_owned(), 1));
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_second_connection_for_the_same_account_is_refused() {
    let cx = cx().await;
    let main = cx.github("main").await;
    let same = r#"{"login":"octocat-main","id":583231}"#;
    // A pasted token of the same account.
    cx.gh.push(200, &[], same);
    let body =
        json!({"kind": "github", "name": "again", "auth_method": "token", "token": GH_TOKEN2});
    let r = cx.admin(Method::POST, URI, body).await;
    assert_eq!(code(&r), (409, "already_connected".to_owned()), "{}", r.1);
    assert!(
        r.1["message"].as_str().unwrap().contains("as main"),
        "{}",
        r.1
    );
    // A sign-in of the same account.
    cx.configure().await;
    cx.gh.push(200, &[], START);
    cx.gh.push(
        200,
        &[],
        &format!(r#"{{"access_token":"{GH_TOKEN2}","token_type":"bearer","scope":"repo"}}"#),
    );
    cx.gh.push(200, &[], same);
    let flow = start(&cx, "github", json!({})).await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut v = Value::Null;
    for _ in 0..150 {
        v = cx
            .ok(Method::GET, &format!("{URI}/flows/{flow}"), Value::Null)
            .await;
        if v["step"] == "failed" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(v["error_code"], "already_connected", "{v}");
    let all = connections(&cx).await;
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(all[0]["id"], main);
    // Another account is a connection of its own.
    cx.gh.push(200, &[], r#"{"login":"hubot","id":2}"#);
    let body =
        json!({"kind": "github", "name": "hubot", "auth_method": "token", "token": GH_TOKEN2});
    assert_eq!(cx.admin(Method::POST, URI, body).await.0, StatusCode::OK);
    cx.assert_clean().await;
}

/// Signs in again for connection `id` with `token`, the fake saying `me` (asked twice: the same
/// account?, then the test); the flow's last view.
async fn sign_in_again(cx: &Cx, id: i64, token: &str, me: &str) -> Value {
    cx.gh.push(200, &[], START);
    cx.gh.push(
        200,
        &[],
        &format!(r#"{{"access_token":"{token}","token_type":"bearer","scope":"repo"}}"#),
    );
    cx.gh.push(200, &[], me);
    cx.gh.push(200, &[], me);
    let r = start(cx, "github", json!({"connection": id})).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    let flow = r.1["id"].as_str().unwrap().to_owned();
    for _ in 0..150 {
        let v = cx
            .ok(Method::GET, &format!("{URI}/flows/{flow}"), Value::Null)
            .await;
        if v["step"] == "failed" || v["step"] == "connected" {
            return v;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the flow never ended");
}

#[tokio::test]
async fn a_token_connection_signed_in_again_is_a_sign_in_again_and_keeps_its_grants() {
    let cx = cx().await;
    let id = signed_in(&cx).await;
    let grants = format!("{URI}/{id}/grants");
    let grant = json!({"grantee_kind": "user", "grantee": "1",
        "capabilities": ["read_repo"], "limits": {"repos": ["octo/app"]}});
    cx.ok(Method::PUT, &grants, grant).await;
    let before = cx.ok(Method::GET, &grants, Value::Null).await;
    cx.gh.push(200, &[], OCTOCAT);
    cx.gh.push(200, &[], OCTOCAT);
    let body = json!({"token": GH_TOKEN2});
    cx.ok(Method::PUT, &format!("{URI}/{id}/credential"), body)
        .await;
    let v = sign_in_again(&cx, id, GH_TOKEN, OCTOCAT).await;
    assert_eq!(
        (&v["step"], &v["connection"]),
        (&json!("connected"), &json!(id)),
        "{v}"
    );
    let c = cx
        .ok(Method::GET, &format!("{URI}/{id}"), Value::Null)
        .await;
    assert_eq!(
        (&c["auth_method"], &c["name"]),
        (&json!("oauth"), &json!("github-1"))
    );
    assert_eq!(version(&cx, id).await, (GH_TOKEN.to_owned(), 3));
    assert_eq!(cx.ok(Method::GET, &grants, Value::Null).await, before);
    assert_eq!(connections(&cx).await.len(), 1);
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_sign_in_of_another_account_does_not_take_over_a_token_connection() {
    let cx = cx().await;
    cx.configure().await;
    let id = cx.github("main").await; // octocat-main
    let v = sign_in_again(&cx, id, GH_TOKEN2, OCTOCAT).await;
    assert_eq!(v["error_code"], "different_account", "{v}");
    let c = cx
        .ok(Method::GET, &format!("{URI}/{id}"), Value::Null)
        .await;
    assert_eq!(c["auth_method"], "token");
    assert_eq!(version(&cx, id).await, (GH_TOKEN.to_owned(), 1));
    cx.assert_clean().await;
}
