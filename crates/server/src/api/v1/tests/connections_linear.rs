//! Linear through the API (C8): the app config, "Sign in with Linear" as a flow (one workspace, no
//! site to choose), a personal API key, and a re-sign-in that must stay in its own workspace.
//! The adapter is the loopback one; nothing real is asked.

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;
use crate::connections::broker::{Broker, Limits};
use crate::connections::github::Github;
use crate::connections::linear::tests as lt;

const URI: &str = "/api/v1/connections";
const APPS: &str = "/api/v1/connection-apps/linear";
/// Shapeless on purpose.
const LKEY: &str = "c8key-4a7d2e9b1c63f580";

/// The C5 fixture with the broker's Linear pointed at a loopback fake (and no app yet).
async fn lcx() -> (Cx, lt::Fx) {
    let mut c = cx().await;
    let l = lt::fx(false).await;
    let jira = c.fx.app.connections.jira().clone();
    let mut reg = c.fx.app.connections.registry().clone();
    reg.register(l.linear.clone()).unwrap();
    let broker = Broker::with(reg, Github::strict(), jira, Limits::default());
    c.fx.app.connections = Arc::new(broker.with_linear(l.linear.clone()));
    let tokens = json!({"access_token": ACCESS, "token_type": "Bearer",
        "refresh_token": REFRESH, "expires_in": 86399});
    l.fake.reply("POST /oauth/token", 200, tokens);
    (c, l)
}

async fn configure(c: &Cx) -> Value {
    let fields = json!({"client_id": "lin-client-1", "client_secret": CLIENT_SECRET});
    c.ok(Method::PUT, APPS, json!({"fields": fields})).await
}

async fn begin(c: &Cx, extra: Value) -> (StatusCode, Value) {
    start(c, "linear", extra).await
}

async fn callback(c: &Cx, id: &str, state: &str) -> (StatusCode, Value) {
    let body = json!({"code": CODE, "state": state});
    c.admin(Method::POST, &format!("{URI}/flows/{id}/callback"), body)
        .await
}

fn linear_kind(all: &Value) -> Value {
    let found = all
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["kind"] == "linear");
    found.expect("linear is a kind").clone()
}

#[tokio::test]
async fn linear_is_a_kind_whose_sign_in_waits_for_its_app() {
    let (c, _l) = lcx().await;
    let kinds = c
        .ok(Method::GET, "/api/v1/connection-kinds", Value::Null)
        .await;
    let k = linear_kind(&kinds);
    assert_eq!(k["title"], "Linear");
    assert_eq!(k["configured"], false);
    assert_eq!(k["limits"][0]["key"], "teams");
    let oauth = &k["auth_methods"][0];
    assert_eq!(
        (&oauth["id"], &oauth["available"]),
        (&json!("oauth"), &json!(false))
    );
    // The token method needs no app.
    assert_eq!(k["auth_methods"][1]["available"], true);
    let r = begin(&c, json!({})).await;
    assert_eq!(code(&r), (409, "not_configured".to_owned()), "{}", r.1);
    let set = configure(&c).await;
    assert_eq!(set["configured"], true);
    assert_eq!(set["redirect_uri"], "http://127.0.0.1:47613/callback");
    let kinds = c
        .ok(Method::GET, "/api/v1/connection-kinds", Value::Null)
        .await;
    let k = linear_kind(&kinds);
    assert_eq!(
        (&k["configured"], &k["auth_methods"][0]["available"]),
        (&json!(true), &json!(true))
    );
    c.assert_clean().await;
}

#[tokio::test]
async fn the_app_config_is_write_only_for_its_secret_and_checks_its_values() {
    let (c, _l) = lcx().await;
    for (name, bad) in [
        ("client_id", "has space"),
        ("client_id", ""),
        ("loopback_port", "80"),
        ("loopback_port", "x"),
        ("client_secret", ""),
    ] {
        let r = c
            .admin(Method::PUT, APPS, json!({"fields": {name: bad}}))
            .await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{name}={bad}: {}", r.1);
    }
    let r = c
        .admin(Method::PUT, APPS, json!({"fields": {"app_key": "x"}}))
        .await;
    assert_eq!(
        r.0,
        StatusCode::BAD_REQUEST,
        "a GitHub field is no Linear field"
    );
    let set = configure(&c).await;
    let field = |n: &str| {
        let all = set["fields"].as_array().unwrap();
        all.iter().find(|f| f["name"] == n).unwrap().clone()
    };
    assert_eq!(field("client_id")["value"], "lin-client-1");
    assert_eq!(
        (
            &field("client_secret")["set"],
            &field("client_secret")["value"]
        ),
        (&json!(true), &Value::Null)
    );
    // The port setting moves the redirect the Mac app registers.
    let moved = c
        .ok(
            Method::PUT,
            APPS,
            json!({"fields": {"loopback_port": "50001"}}),
        )
        .await;
    assert_eq!(moved["redirect_uri"], "http://127.0.0.1:50001/callback");
    c.assert_clean().await;
}

#[tokio::test]
async fn the_redirect_is_exchanged_with_core_own_verifier_and_one_workspace_is_connected() {
    let (c, l) = lcx().await;
    configure(&c).await;
    let (s, v) = begin(&c, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (id, state) = (v["id"].as_str().unwrap(), v["state"].as_str().unwrap());
    assert_eq!(
        (&v["step"], &v["user_code"]),
        (&json!("waiting"), &Value::Null)
    );
    let url = v["authorize_url"].as_str().unwrap();
    assert!(url.contains("/oauth/authorize?"), "{url}");
    assert_eq!(param(url, "state"), state);
    assert_eq!(param(url, "client_id"), "lin-client-1");
    assert_eq!(
        param(url, "redirect_uri"),
        "http://127.0.0.1:47613/callback"
    );
    assert_eq!(param(url, "scope"), "read,issues:create,comments:create");
    assert_eq!(param(url, "code_challenge_method"), "S256");
    assert!(!url.contains("verifier") && !url.contains(CLIENT_SECRET));
    assert_ne!(id, state, "the flow's id is not the redirect's state");
    let done = callback(&c, id, state).await;
    assert_eq!(done.0, StatusCode::OK, "{}", done.1);
    assert_eq!(done.1["step"], "connected", "{}", done.1);
    assert_eq!(done.1["identity"], format!("{} at {}", lt::ME, lt::ORG));
    let conn = done.1["connection"].as_i64().unwrap();
    let got = c
        .ok(Method::GET, &format!("{URI}/{conn}"), Value::Null)
        .await;
    let show = (
        &got["kind"],
        &got["auth_method"],
        &got["label"],
        &got["name"],
    );
    assert_eq!(
        show,
        (
            &json!("linear"),
            &json!("oauth"),
            &json!("Linear"),
            &json!("linear-1")
        )
    );
    // Core exchanged the code with its own verifier and the app's secret, as a form.
    let sent = l.fake.last("POST /oauth/token").unwrap();
    assert_eq!(l.fake.bad(), 0);
    assert_eq!(
        (&sent.body["code"], &sent.body["client_secret"]),
        (&json!(CODE), &json!(CLIENT_SECRET))
    );
    assert!(sent.body["code_verifier"].as_str().unwrap().len() >= 43);
    // A replay is refused and makes nothing more.
    let again = callback(&c, id, state).await;
    assert_eq!(code(&again), (409, "conflict".to_owned()), "{}", again.1);
    assert_eq!(connections(&c).await.len(), 1);
    c.assert_clean().await;
}

#[tokio::test]
async fn a_state_that_is_not_this_flows_is_refused_and_leaves_it_waiting() {
    let (c, l) = lcx().await;
    configure(&c).await;
    let (a, b) = (begin(&c, json!({})).await.1, begin(&c, json!({})).await.1);
    let (ida, sa) = (a["id"].as_str().unwrap(), a["state"].as_str().unwrap());
    let sb = b["state"].as_str().unwrap();
    for wrong in ["forged", sb, ""] {
        let r = callback(&c, ida, wrong).await;
        assert_eq!(
            code(&r),
            (400, "bad_request".to_owned()),
            "{wrong}: {}",
            r.1
        );
    }
    assert_eq!(l.fake.count("POST /oauth/token"), 0);
    let v = c
        .ok(Method::GET, &format!("{URI}/flows/{ida}"), Value::Null)
        .await;
    assert_eq!(v["step"], "waiting");
    assert_eq!(callback(&c, ida, sa).await.1["step"], "connected");
    c.assert_clean().await;
}

#[tokio::test]
async fn signing_in_again_stays_in_the_workspace_the_connection_was_made_in() {
    let (c, l) = lcx().await;
    configure(&c).await;
    let v = begin(&c, json!({})).await.1;
    let first = callback(&c, v["id"].as_str().unwrap(), v["state"].as_str().unwrap()).await;
    let conn = first.1["connection"].as_i64().unwrap();
    // Another workspace has a team ENG too: its sign-in is refused, nothing is replaced.
    l.fake.data("Viewer", lt::viewer("other"));
    let (s, v) = begin(&c, json!({"connection": conn})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let r = callback(&c, v["id"].as_str().unwrap(), v["state"].as_str().unwrap()).await;
    assert_eq!(r.1["step"], "failed", "{}", r.1);
    assert_eq!(r.1["error_code"], "wrong_workspace", "{}", r.1);
    let now = c
        .ok(Method::GET, &format!("{URI}/{conn}"), Value::Null)
        .await;
    assert_eq!(now["identity"], format!("{} at {}", lt::ME, lt::ORG));
    assert_eq!(connections(&c).await.len(), 1);
    // The same workspace signs in again: the credential is replaced, no second connection.
    l.fake.data("Viewer", lt::viewer(lt::ORG));
    let v = begin(&c, json!({"connection": conn})).await.1;
    let r = callback(&c, v["id"].as_str().unwrap(), v["state"].as_str().unwrap()).await;
    assert_eq!(r.1["step"], "connected", "{}", r.1);
    assert_eq!(r.1["connection"], conn);
    assert_eq!(connections(&c).await.len(), 1);
    c.assert_clean().await;
}

#[tokio::test]
async fn a_personal_api_key_is_tested_at_once_and_a_refused_one_is_not_kept() {
    let (c, l) = lcx().await;
    let body = json!({"kind": "linear", "name": "mine", "auth_method": "token", "token": LKEY});
    let made = c.ok(Method::POST, URI, body.clone()).await;
    assert_eq!(
        (&made["kind"], &made["auth_method"]),
        (&json!("linear"), &json!("token"))
    );
    assert_eq!(made["identity"], format!("{} at {}", lt::ME, lt::ORG));
    // The key went to Linear as it is, with no Bearer.
    assert_eq!(
        l.fake.last("GQL Viewer").unwrap().auth.as_deref(),
        Some(LKEY)
    );
    // A key that is not usable text is refused before Linear is asked.
    let before = l.fake.seen().len();
    for bad in ["", "has space in it", "short"] {
        let mut b = body.clone();
        b["name"] = json!("bad");
        b["token"] = json!(bad);
        let r = c.admin(Method::POST, URI, b).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{bad:?}: {}", r.1);
    }
    assert_eq!(l.fake.seen().len(), before);
    // A key Linear refuses is not stored.
    l.fake.on("GQL Viewer", |_| {
        lt::Reply::error(401, "AUTHENTICATION_ERROR")
    });
    let mut b = body.clone();
    b["name"] = json!("refused");
    let r = c.admin(Method::POST, URI, b).await;
    assert_eq!(code(&r), (400, "credential_rejected".to_owned()), "{}", r.1);
    assert_eq!(connections(&c).await.len(), 1);
    c.assert_clean_also(&[LKEY]).await;
}
