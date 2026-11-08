//! Slack through the API (C9): the app config (an `https` redirect, since Slack refuses a loopback
//! one), "Add to Slack" as a flow (one workspace, no site to choose), a pasted bot token, and a
//! re-sign-in or a replaced token that must stay in its own workspace. The adapter is the loopback
//! one; nothing real is asked.

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;
use crate::connections::broker::{Broker, Limits};
use crate::connections::github::Github;
use crate::connections::slack::tests as st;

mod more;

const URI: &str = "/api/v1/connections";
const APPS: &str = "/api/v1/connection-apps/slack";
const REDIRECT: &str = "https://core.example.test/connections/slack/callback";
/// Shapeless on purpose (short bodies: the redactor names none).
const TOK: &str = "xoxb-test-111-222-api1";
const TOK2: &str = "xoxb-test-111-222-api2";
const IDENTITY: &str = "U012AB3CD in T012AB3CD";

/// The C5 fixture with the broker's Slack pointed at a loopback fake (and no app yet).
async fn scx() -> (Cx, st::Fx) {
    let mut c = cx().await;
    let l = st::fx(false).await;
    let jira = c.fx.app.connections.jira().clone();
    let mut reg = c.fx.app.connections.registry().clone();
    reg.register(l.slack.clone()).unwrap();
    let broker = Broker::with(reg, Github::strict(), jira, Limits::default());
    c.fx.app.connections = Arc::new(broker.with_slack(l.slack.clone()));
    let install = json!({"access_token": st::ACCESS, "token_type": "bot",
        "bot_user_id": st::BOT_USER, "team": {"id": st::TEAM, "name": "Acme"}});
    l.fake.reply("oauth.v2.access", st::Reply::ok(install));
    (c, l)
}

/// From now on Slack installs and answers `auth.test` for workspace `team`.
fn workspace(l: &st::Fx, team: &str) {
    let install = json!({"access_token": st::ACCESS, "token_type": "bot",
        "bot_user_id": st::BOT_USER, "team": {"id": team, "name": "Other"}});
    l.fake.reply("oauth.v2.access", st::Reply::ok(install));
    l.fake
        .reply("auth.test", st::Reply::ok(st::auth_test(team)));
}

/// The app config with the https redirect page said to exist, plus `extra` fields.
async fn configure_with(c: &Cx, extra: Value) -> Value {
    let mut fields = json!({"client_id": "1234.5678", "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT, "catcher_ready": "true"});
    for (k, v) in extra.as_object().unwrap() {
        fields[k] = v.clone();
    }
    c.ok(Method::PUT, APPS, json!({"fields": fields})).await
}

async fn configure(c: &Cx) -> Value {
    configure_with(c, json!({})).await
}

async fn begin(c: &Cx, extra: Value) -> (StatusCode, Value) {
    start(c, "slack", extra).await
}

async fn callback(c: &Cx, id: &str, state: &str) -> (StatusCode, Value) {
    let body = json!({"code": CODE, "state": state});
    c.admin(Method::POST, &format!("{URI}/flows/{id}/callback"), body)
        .await
}

/// Starts a flow (for `connection`, when given) and hands its redirect back.
async fn sign_in(c: &Cx, extra: Value) -> Value {
    let v = begin(c, extra).await.1;
    callback(c, v["id"].as_str().unwrap(), v["state"].as_str().unwrap())
        .await
        .1
}

fn slack_kind(all: &Value) -> Value {
    let found = all
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["kind"] == "slack");
    found.expect("slack is a kind").clone()
}

fn token_body(name: &str, token: &str) -> Value {
    json!({"kind": "slack", "name": name, "auth_method": "token", "token": token})
}

#[tokio::test]
async fn slack_is_a_kind_whose_sign_in_waits_for_its_app() {
    let (c, _l) = scx().await;
    let kinds = c
        .ok(Method::GET, "/api/v1/connection-kinds", Value::Null)
        .await;
    let k = slack_kind(&kinds);
    assert_eq!(k["title"], "Slack");
    assert_eq!(k["configured"], false);
    assert_eq!(k["limits"][0]["key"], "channels");
    let oauth = &k["auth_methods"][0];
    assert_eq!(
        (&oauth["id"], &oauth["available"]),
        (&json!("oauth"), &json!(false))
    );
    assert_eq!(
        k["auth_methods"][1]["available"], true,
        "the token method needs no app"
    );
    let r = begin(&c, json!({})).await;
    assert_eq!(code(&r), (409, "not_configured".to_owned()), "{}", r.1);
    // A config without its redirect is not a usable app.
    let half = json!({"fields": {"client_id": "1234.5678", "client_secret": CLIENT_SECRET}});
    assert_eq!(c.ok(Method::PUT, APPS, half).await["configured"], false);
    // An https redirect with no page behind it yet is not a usable sign-in: the bot token is the
    // working method, and a start says so.
    let fields = json!({"client_id": "1234.5678", "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT});
    let set = c.ok(Method::PUT, APPS, json!({"fields": fields})).await;
    assert_eq!(set["configured"], false);
    let kinds = c
        .ok(Method::GET, "/api/v1/connection-kinds", Value::Null)
        .await;
    let k = slack_kind(&kinds);
    assert_eq!(
        (&k["configured"], &k["auth_methods"][0]["available"]),
        (&json!(false), &json!(false))
    );
    assert_eq!(k["auth_methods"][1]["available"], true);
    let r = begin(&c, json!({})).await;
    assert_eq!(code(&r), (409, "not_configured".to_owned()), "{}", r.1);
    // Said false it stays off; said true (with the redirect) it is on.
    let off = json!({"fields": {"catcher_ready": "false"}});
    assert_eq!(c.ok(Method::PUT, APPS, off).await["configured"], false);
    let set = configure(&c).await;
    assert_eq!(set["configured"], true);
    let kinds = c
        .ok(Method::GET, "/api/v1/connection-kinds", Value::Null)
        .await;
    let k = slack_kind(&kinds);
    assert_eq!(
        (&k["configured"], &k["auth_methods"][0]["available"]),
        (&json!(true), &json!(true))
    );
    c.assert_clean().await;
}

#[tokio::test]
async fn the_app_config_is_write_only_for_its_secret_and_takes_only_an_https_redirect() {
    let (c, _l) = scx().await;
    for (name, bad) in [
        ("client_id", "has space"),
        ("client_id", ""),
        ("client_secret", ""),
        ("redirect_uri", "http://127.0.0.1:47613/callback"),
        ("redirect_uri", "http://core.example.test/cb"),
        ("redirect_uri", "https://127.0.0.1/cb"),
        ("redirect_uri", "https://core.example.test/cb?x=1"),
        ("redirect_uri", "javascript:alert(1)"),
        ("redirect_uri", ""),
        ("loopback_port", "50001"),
        ("catcher_ready", "yes"),
        ("catcher_ready", ""),
        ("token_rotation", "1"),
        ("token_rotation", "TRUE"),
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
        "a GitHub field is no Slack field"
    );
    let set = configure(&c).await;
    let field = |n: &str| {
        set["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == n)
            .unwrap()
            .clone()
    };
    assert_eq!(field("client_id")["value"], "1234.5678");
    assert_eq!(field("redirect_uri")["value"], REDIRECT);
    assert_eq!(
        (
            &field("client_secret")["set"],
            &field("client_secret")["value"]
        ),
        (&json!(true), &Value::Null)
    );
    c.assert_clean().await;
}

#[tokio::test]
async fn the_redirect_is_exchanged_and_one_workspace_is_connected() {
    let (c, l) = scx().await;
    configure(&c).await;
    let (s, v) = begin(&c, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (id, state) = (v["id"].as_str().unwrap(), v["state"].as_str().unwrap());
    assert_eq!(
        (&v["step"], &v["user_code"]),
        (&json!("waiting"), &Value::Null)
    );
    let url = v["authorize_url"].as_str().unwrap();
    assert!(url.contains("/oauth/v2/authorize?"), "{url}");
    assert_eq!(param(url, "state"), state);
    assert_eq!(param(url, "client_id"), "1234.5678");
    assert_eq!(param(url, "redirect_uri"), REDIRECT);
    assert_eq!(param(url, "scope"), crate::connections::slack::SCOPES);
    assert!(
        !url.contains("code_challenge")
            && !url.contains("user_scope")
            && !url.contains(CLIENT_SECRET)
    );
    assert_ne!(id, state, "the flow's id is not the redirect's state");
    let done = callback(&c, id, state).await;
    assert_eq!(done.0, StatusCode::OK, "{}", done.1);
    assert_eq!(done.1["step"], "connected", "{}", done.1);
    assert_eq!(done.1["identity"], IDENTITY);
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
            &json!("slack"),
            &json!("oauth"),
            &json!("Slack"),
            &json!("slack-1")
        )
    );
    // Core exchanged the code with the app's secret and its own redirect, as a form.
    let sent = l.fake.last("oauth.v2.access").unwrap();
    assert_eq!(l.fake.bad(), 0);
    assert_eq!(
        (&sent.form["code"], &sent.form["client_secret"]),
        (&json!(CODE), &json!(CLIENT_SECRET))
    );
    assert_eq!(sent.form["redirect_uri"], REDIRECT);
    // A replay is refused and makes nothing more.
    let again = callback(&c, id, state).await;
    assert_eq!(code(&again), (409, "conflict".to_owned()), "{}", again.1);
    assert_eq!(connections(&c).await.len(), 1);
    c.assert_clean_also(&[st::ACCESS]).await;
}

#[tokio::test]
async fn a_state_that_is_not_this_flows_is_refused_and_leaves_it_waiting() {
    let (c, l) = scx().await;
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
    assert_eq!(l.fake.count("oauth.v2.access"), 0);
    let v = c
        .ok(Method::GET, &format!("{URI}/flows/{ida}"), Value::Null)
        .await;
    assert_eq!(v["step"], "waiting");
    assert_eq!(callback(&c, ida, sa).await.1["step"], "connected");
    c.assert_clean().await;
}

#[tokio::test]
async fn signing_in_again_stays_in_the_workspace_the_connection_was_made_in() {
    let (c, l) = scx().await;
    configure(&c).await;
    let first = sign_in(&c, json!({})).await;
    let conn = first["connection"].as_i64().unwrap();
    // Another workspace: refused, nothing is replaced, and the authorize address hints the right one.
    workspace(&l, "T999AB3CD");
    let (s, v) = begin(&c, json!({"connection": conn})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        param(v["authorize_url"].as_str().unwrap(), "team"),
        st::TEAM
    );
    let r = callback(&c, v["id"].as_str().unwrap(), v["state"].as_str().unwrap()).await;
    assert_eq!(
        (&r.1["step"], &r.1["error_code"]),
        (&json!("failed"), &json!("wrong_workspace")),
        "{}",
        r.1
    );
    let now = c
        .ok(Method::GET, &format!("{URI}/{conn}"), Value::Null)
        .await;
    assert_eq!(now["identity"], IDENTITY);
    assert_eq!(connections(&c).await.len(), 1);
    // The same workspace signs in again: the credential is replaced, no second connection.
    workspace(&l, st::TEAM);
    let r = sign_in(&c, json!({"connection": conn})).await;
    assert_eq!(
        (&r["step"], &r["connection"]),
        (&json!("connected"), &json!(conn)),
        "{r}"
    );
    assert_eq!(connections(&c).await.len(), 1);
    c.assert_clean_also(&[st::ACCESS]).await;
}

#[tokio::test]
async fn a_connection_with_no_recorded_workspace_is_not_replaced_unless_the_change_is_confirmed() {
    let (c, l) = scx().await;
    configure(&c).await;
    let first = sign_in(&c, json!({})).await;
    let conn = first["connection"].as_i64().unwrap();
    sqlx::query("UPDATE core_connections SET identity = NULL WHERE id = ?")
        .bind(conn)
        .execute(&c.fx.app.pool)
        .await
        .unwrap();
    let r = sign_in(&c, json!({"connection": conn})).await;
    assert_eq!(
        (&r["step"], &r["error_code"]),
        (&json!("failed"), &json!("identity_unknown")),
        "{r}"
    );
    // Confirmed: the sign-in replaces it, and the connection records the workspace again.
    let r = sign_in(
        &c,
        json!({"connection": conn, "confirm_identity_change": true}),
    )
    .await;
    assert_eq!(
        (&r["step"], &r["identity"]),
        (&json!("connected"), &json!(IDENTITY)),
        "{r}"
    );
    // Confirmed, a different workspace is still refused: confirming only covers a missing identity.
    workspace(&l, "T999AB3CD");
    let r = sign_in(
        &c,
        json!({"connection": conn, "confirm_identity_change": true}),
    )
    .await;
    assert_eq!(
        (&r["step"], &r["error_code"]),
        (&json!("failed"), &json!("wrong_workspace")),
        "{r}"
    );
    assert_eq!(connections(&c).await.len(), 1);
    c.assert_clean_also(&[st::ACCESS]).await;
}
