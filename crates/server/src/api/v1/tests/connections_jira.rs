//! "Sign in with Atlassian" as a flow (C5): the Mac app catches the redirect and hands `code` and
//! `state` to Core, which exchanges with its own PKCE verifier, connects the site, or waits for a
//! choice among several; a wrong `state` or a replay is refused; nothing secret is shown.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;
use crate::connections::jira::tests as jt;

const URI: &str = "/api/v1/connections";
const BETA: &str = "7d0c4b1e-0000-4000-8000-000000000001";

async fn begin(cx: &Cx, extra: Value) -> Value {
    let (s, v) = start(cx, "jira", extra).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

async fn callback(cx: &Cx, id: &str, code: &str, state: &str) -> (StatusCode, Value) {
    let body = json!({"code": code, "state": state});
    cx.admin(Method::POST, &format!("{URI}/flows/{id}/callback"), body)
        .await
}

fn two_sites(cx: &Cx) {
    cx.jf.reply(
        "GET /oauth/token/accessible-resources",
        200,
        json!([
            {"id": jt::CLOUD, "url": jt::SITE, "name": "Acme", "scopes": ["read:jira-work"]},
            {"id": BETA, "url": "https://beta.atlassian.net", "name": "Beta", "scopes": ["read:jira-work"]},
        ]),
    );
}

#[tokio::test]
async fn the_redirect_is_exchanged_with_core_own_verifier_and_one_site_is_connected() {
    let cx = cx().await;
    cx.configure().await;
    let v = begin(&cx, json!({})).await;
    let (id, state) = (v["id"].as_str().unwrap(), v["state"].as_str().unwrap());
    assert_eq!(
        (&v["step"], &v["user_code"]),
        (&json!("waiting"), &Value::Null)
    );
    let url = v["authorize_url"].as_str().unwrap();
    assert!(url.contains("/authorize?"), "{url}");
    assert_eq!(param(url, "state"), state);
    assert_eq!(param(url, "client_id"), "client-id-8c41");
    assert_eq!(
        param(url, "redirect_uri"),
        "http://127.0.0.1:47613/callback"
    );
    assert_eq!(param(url, "code_challenge_method"), "S256");
    assert!(!url.contains("verifier") && !url.contains(CLIENT_SECRET));
    assert_ne!(id, state, "the flow's id is not the redirect's state");
    let done = callback(&cx, id, CODE, state).await;
    assert_eq!(done.0, StatusCode::OK, "{}", done.1);
    assert_eq!(done.1["step"], "connected", "{}", done.1);
    assert!(done.1["identity"].as_str().unwrap().contains("5b10ac8d"));
    let conn = done.1["connection"].as_i64().unwrap();
    let c = cx
        .ok(Method::GET, &format!("{URI}/{conn}"), Value::Null)
        .await;
    assert_eq!(
        (&c["kind"], &c["auth_method"], &c["label"], &c["name"]),
        (
            &json!("jira"),
            &json!("oauth"),
            &json!("Acme"),
            &json!("jira-1")
        )
    );
    // Core exchanged the code with its own verifier and the app's secret, over its own channel.
    let sent = cx.jf.last("POST /oauth/token").unwrap().body;
    assert_eq!(sent["code"], CODE);
    assert!(sent["code_verifier"].as_str().unwrap().len() >= 43);
    assert_eq!(sent["redirect_uri"], "http://127.0.0.1:47613/callback");
    // A replay is refused and makes nothing more.
    let again = callback(&cx, id, CODE, state).await;
    assert_eq!(code(&again), (409, "conflict".to_owned()), "{}", again.1);
    assert_eq!(connections(&cx).await.len(), 1);
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_state_that_is_not_this_flows_is_refused_and_leaves_it_waiting() {
    let cx = cx().await;
    cx.configure().await;
    let (a, b) = (begin(&cx, json!({})).await, begin(&cx, json!({})).await);
    let (ida, sa) = (a["id"].as_str().unwrap(), a["state"].as_str().unwrap());
    let (idb, sb) = (b["id"].as_str().unwrap(), b["state"].as_str().unwrap());
    // Nonsense, and the other flow's state: both refused, neither flow moved, nothing exchanged.
    for wrong in ["forged", sb, ""] {
        let r = callback(&cx, ida, CODE, wrong).await;
        assert_eq!(
            code(&r),
            (400, "bad_request".to_owned()),
            "{wrong}: {}",
            r.1
        );
    }
    assert_eq!(cx.jf.count("POST /oauth/token"), 0);
    for id in [ida, idb] {
        let v = cx
            .ok(Method::GET, &format!("{URI}/flows/{id}"), Value::Null)
            .await;
        assert_eq!(v["step"], "waiting");
    }
    // Each flow's own state still finishes it, once.
    assert_eq!(callback(&cx, ida, CODE, sa).await.1["step"], "connected");
    assert_eq!(callback(&cx, idb, CODE, sb).await.1["step"], "connected");
    assert_eq!(connections(&cx).await.len(), 2);
    cx.assert_clean().await;
}

#[tokio::test]
async fn several_sites_wait_for_a_choice_and_make_exactly_one_connection() {
    let cx = cx().await;
    cx.configure().await;
    two_sites(&cx);
    let v = begin(&cx, json!({"name": "work", "label": "Work Jira"})).await;
    let (id, state) = (v["id"].as_str().unwrap(), v["state"].as_str().unwrap());
    let r = callback(&cx, id, CODE, state).await;
    assert_eq!(r.1["step"], "choose_site", "{}", r.1);
    let sites: Vec<&str> = r.1["sites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(sites, ["Acme", "Beta"]);
    assert!(
        connections(&cx).await.is_empty(),
        "nothing is connected before the choice"
    );
    // A site that is not a choice, and the redirect again: refused, the flow still waits.
    let choose = |site: &str| {
        cx.admin(
            Method::POST,
            &format!("{URI}/flows/{id}/choose"),
            json!({"site": site}),
        )
    };
    assert_eq!(
        code(&choose("../etc").await),
        (400, "bad_request".to_owned())
    );
    assert_eq!(code(&callback(&cx, id, CODE, state).await).0, 409);
    let done = choose(BETA).await;
    assert_eq!(done.0, StatusCode::OK, "{}", done.1);
    // `GET /me` is the fake's; the site test asks `accessible-resources`, which lists Beta.
    assert_eq!(done.1["step"], "connected", "{}", done.1);
    let all = connections(&cx).await;
    assert_eq!(all.len(), 1);
    assert_eq!(
        (&all[0]["name"], &all[0]["label"]),
        (&json!("work"), &json!("Work Jira"))
    );
    assert_eq!(
        code(&choose(BETA).await).0,
        409,
        "a second choice makes nothing"
    );
    assert_eq!(connections(&cx).await.len(), 1);
    cx.assert_clean().await;
}

#[tokio::test]
async fn an_exchange_that_fails_ends_the_flow_plainly_and_a_bad_body_is_a_400() {
    let cx = cx().await;
    cx.configure().await;
    cx.jf.reply(
        "POST /oauth/token",
        400,
        json!({"error": "invalid_grant", "echo": CODE}),
    );
    let v = begin(&cx, json!({})).await;
    let (id, state) = (v["id"].as_str().unwrap(), v["state"].as_str().unwrap());
    let bad = cx
        .admin(
            Method::POST,
            &format!("{URI}/flows/{id}/callback"),
            json!({"state": state}),
        )
        .await;
    assert_eq!(bad.0, StatusCode::BAD_REQUEST, "no code: {}", bad.1);
    let r = callback(&cx, id, CODE, state).await;
    assert_eq!(
        (r.0, &r.1["step"], &r.1["error_code"]),
        (StatusCode::OK, &json!("failed"), &json!("exchange_failed")),
        "{}",
        r.1
    );
    assert!(r.1["error_message"].as_str().unwrap().len() > 10);
    // The state is spent: the same redirect again is a replay.
    assert_eq!(code(&callback(&cx, id, CODE, state).await).0, 409);
    // No refresh token (offline access not granted): a plain failure too.
    cx.jf.reply(
        "POST /oauth/token",
        200,
        json!({"access_token": ACCESS, "expires_in": 3600}),
    );
    let v = begin(&cx, json!({})).await;
    let r = callback(
        &cx,
        v["id"].as_str().unwrap(),
        CODE,
        v["state"].as_str().unwrap(),
    )
    .await;
    assert_eq!(r.1["error_code"], "no_refresh_token", "{}", r.1);
    assert!(connections(&cx).await.is_empty());
    cx.assert_clean().await;
}

#[tokio::test]
async fn signing_in_again_keeps_the_site_and_refuses_another_one() {
    let cx = cx().await;
    cx.configure().await;
    let v = begin(&cx, json!({})).await;
    let first = callback(
        &cx,
        v["id"].as_str().unwrap(),
        CODE,
        v["state"].as_str().unwrap(),
    )
    .await;
    let conn = first.1["connection"].as_i64().unwrap();
    // The same site again: the credential is replaced, the connection stays.
    let v = begin(&cx, json!({"connection": conn})).await;
    let r = callback(
        &cx,
        v["id"].as_str().unwrap(),
        CODE,
        v["state"].as_str().unwrap(),
    )
    .await;
    assert_eq!(
        (&r.1["step"], &r.1["connection"]),
        (&json!("connected"), &json!(conn)),
        "{}",
        r.1
    );
    let (_, version) = crate::store::connections::secret::open(
        &cx.fx.app.pool,
        cx.fx.app.secrets.as_deref().unwrap(),
        1,
        conn,
    )
    .await
    .unwrap();
    assert_eq!(version, 2);
    assert_eq!(connections(&cx).await.len(), 1);
    // An account that does not reach this connection's site: refused, nothing replaced.
    cx.jf.reply(
        "GET /oauth/token/accessible-resources",
        200,
        json!([{"id": BETA, "url": "https://beta.atlassian.net", "name": "Beta", "scopes": ["read:jira-work"]}]),
    );
    let v = begin(&cx, json!({"connection": conn})).await;
    let r = callback(
        &cx,
        v["id"].as_str().unwrap(),
        CODE,
        v["state"].as_str().unwrap(),
    )
    .await;
    assert_eq!(r.1["error_code"], "wrong_site", "{}", r.1);
    let (_, version) = crate::store::connections::secret::open(
        &cx.fx.app.pool,
        cx.fx.app.secrets.as_deref().unwrap(),
        1,
        conn,
    )
    .await
    .unwrap();
    assert_eq!(version, 2, "the credential was not replaced");
    cx.assert_clean().await;
}
