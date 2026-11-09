//! Microsoft Teams through the API (C10): the app config (a client id and a tenant, no secret),
//! "Sign in with Microsoft" as a device code flow (a code to type, then connected), a re-sign-in
//! that must stay in its own tenant, and the ways in that do not exist (no pasted token). The
//! adapter is the loopback one; nothing real is asked.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;
use crate::connections::broker::{Broker, Limits};
use crate::connections::github::Github;
use crate::connections::teams::tests as tt;

const URI: &str = "/api/v1/connections";
const APPS: &str = "/api/v1/connection-apps/teams";
const DEVICE_CODE_TEXT: &str = "GMMhmHCXhWEzkobqIHGG_EnNYYsAkukHspeYUk9E8";

/// The C5 fixture with the broker's Teams pointed at a loopback fake (and no app yet).
async fn tcx() -> (Cx, tt::Fx) {
    let mut c = cx().await;
    let t = tt::fx(false).await;
    let jira = c.fx.app.connections.jira().clone();
    let mut reg = c.fx.app.connections.registry().clone();
    reg.register(t.teams.clone()).unwrap();
    let broker = Broker::with(reg, Github::strict(), jira, Limits::default());
    c.fx.app.connections = Arc::new(broker.with_teams(t.teams.clone()));
    t.fake.reply(
        "devicecode",
        tt::Reply::ok(
            json!({"device_code": DEVICE_CODE_TEXT, "user_code": "LM4FXGDPW",
            "verification_uri": "https://microsoft.com/devicelogin", "expires_in": 900,
            "interval": 1, "message": "never shown"}),
        ),
    );
    (c, t)
}

fn grant(tid: &str, oid: &str) -> Value {
    json!({"token_type": "Bearer", "scope": "x", "expires_in": 3599, "access_token": tt::ACCESS,
        "refresh_token": tt::REFRESH, "id_token": tt::id_token_as(tt::CLIENT, tid, oid)})
}

/// The token endpoint says "pending" once, then grants a sign-in of `tid` by the usual user.
fn approves(t: &tt::Fx, tid: &str) {
    approves_as(t, tid, tt::USER);
}

/// The same, signed in by the user `oid`.
fn approves_as(t: &tt::Fx, tid: &str, oid: &str) {
    let n = Arc::new(AtomicUsize::new(0));
    let body = grant(tid, oid);
    t.fake.on("token", move |_| {
        if n.fetch_add(1, Ordering::SeqCst) == 0 {
            tt::Reply::entra(400, "authorization_pending")
        } else {
            tt::Reply::ok(body.clone())
        }
    });
}

async fn configure(c: &Cx) -> Value {
    let fields = json!({"client_id": tt::CLIENT});
    c.ok(Method::PUT, APPS, json!({"fields": fields})).await
}

async fn begin(c: &Cx, extra: Value) -> (StatusCode, Value) {
    start(c, "teams", extra).await
}

/// Polls flow `id` until it is over; the step it ended as.
async fn ended(c: &Cx, id: &str) -> Value {
    for _ in 0..150 {
        let uri = format!("{URI}/flows/{id}");
        let v = c.ok(Method::GET, &uri, Value::Null).await;
        let now = v["step"].as_str().unwrap().to_owned();
        if ["connected", "failed", "denied", "expired"].contains(&now.as_str()) {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the flow never ended");
}

fn teams_kind(all: &Value) -> Value {
    let found = all
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["kind"] == "teams");
    found.expect("teams is a kind").clone()
}

fn secrets() -> [&'static str; 4] {
    [tt::ACCESS, tt::REFRESH, DEVICE_CODE_TEXT, "never shown"]
}

#[tokio::test]
async fn teams_is_a_kind_whose_sign_in_waits_for_its_app_and_has_no_token_method() {
    let (c, _t) = tcx().await;
    let kinds = c
        .ok(Method::GET, "/api/v1/connection-kinds", Value::Null)
        .await;
    let k = teams_kind(&kinds);
    assert_eq!(k["title"], "Microsoft Teams");
    assert_eq!(k["configured"], false);
    assert_eq!(k["limits"][0]["key"], "channels");
    let methods = k["auth_methods"].as_array().unwrap();
    assert_eq!(methods.len(), 1, "no token paste");
    assert_eq!(
        (&methods[0]["id"], &methods[0]["available"]),
        (&json!("oauth"), &json!(false))
    );
    let r = begin(&c, json!({})).await;
    assert_eq!(code(&r), (409, "not_configured".to_owned()), "{}", r.1);
    let set = configure(&c).await;
    assert_eq!(set["configured"], true);
    let kinds = c
        .ok(Method::GET, "/api/v1/connection-kinds", Value::Null)
        .await;
    assert_eq!(teams_kind(&kinds)["auth_methods"][0]["available"], true);
    c.assert_clean().await;
}

#[tokio::test]
async fn the_app_config_takes_a_client_id_and_a_tenant_and_no_secret() {
    let (c, _t) = tcx().await;
    for (name, bad) in [
        ("client_id", "has space"),
        ("client_id", ""),
        ("tenant", "common"),
        ("tenant", "consumers"),
        ("tenant", "contoso.onmicrosoft.com"),
        ("tenant", "9188040d-6c67-4c5b-b112-36a304b66dad"),
        ("tenant", "../x"),
        ("client_secret", "anything-at-all-1234"),
        ("redirect_uri", "https://example.test/cb"),
    ] {
        let r = c
            .admin(Method::PUT, APPS, json!({"fields": {name: bad}}))
            .await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{name}={bad}: {}", r.1);
    }
    let set = c
        .ok(
            Method::PUT,
            APPS,
            json!({"fields": {"client_id": tt::CLIENT, "tenant": tt::TENANT}}),
        )
        .await;
    let field = |n: &str| {
        set["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == n)
            .unwrap()
            .clone()
    };
    assert_eq!(field("client_id")["value"], tt::CLIENT);
    assert_eq!(field("tenant")["value"], tt::TENANT);
    assert_eq!(set["fields"].as_array().unwrap().len(), 2);
    c.assert_clean().await;
}

#[tokio::test]
async fn the_device_code_flow_shows_a_code_then_connects_one_tenant() {
    let (c, t) = tcx().await;
    configure(&c).await;
    approves(&t, tt::TENANT);
    let (s, v) = begin(&c, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["step"], "waiting");
    assert_eq!(v["user_code"], "LM4FXGDPW");
    assert_eq!(v["verification_uri"], "https://microsoft.com/devicelogin");
    assert_eq!(v["authorize_url"], Value::Null);
    assert!(!v.to_string().contains(DEVICE_CODE_TEXT) && !v.to_string().contains("never shown"));
    let id = v["id"].as_str().unwrap().to_owned();
    let done = until(&c, &id, "connected").await;
    assert_eq!(done["identity"], format!("{} in {}", tt::USER, tt::TENANT));
    let conn = done["connection"].as_i64().unwrap();
    let got = c
        .ok(Method::GET, &format!("{URI}/{conn}"), Value::Null)
        .await;
    let show = (
        &got["kind"],
        &got["auth_method"],
        &got["label"],
        &got["name"],
    );
    let want = (
        &json!("teams"),
        &json!("oauth"),
        &json!("Microsoft Teams"),
        &json!("teams-1"),
    );
    assert_eq!(show, want);
    assert_eq!(
        t.fake.bad(),
        0,
        "a public client: no secret, no Authorization"
    );
    assert_eq!(connections(&c).await.len(), 1);
    // The connection works: it was tested with its own token.
    let sent = t.fake.last("me").unwrap();
    assert_eq!(sent.auth, Some(format!("Bearer {}", tt::ACCESS)));
    c.assert_clean_also(&secrets()).await;
}

#[tokio::test]
async fn a_declined_sign_in_makes_nothing() {
    let (c, t) = tcx().await;
    configure(&c).await;
    t.fake
        .reply("token", tt::Reply::entra(400, "authorization_declined"));
    let v = begin(&c, json!({})).await.1;
    let end = ended(&c, v["id"].as_str().unwrap()).await;
    assert_eq!(end["step"], "denied", "{end}");
    assert!(connections(&c).await.is_empty());
    // A grant for a tenant this app is not limited to is refused with a plain error.
    let (c, t) = tcx().await;
    c.ok(
        Method::PUT,
        APPS,
        json!({"fields": {"client_id": tt::CLIENT, "tenant": tt::TENANT}}),
    )
    .await;
    approves(&t, tt::OTHER_TENANT);
    let v = begin(&c, json!({})).await.1;
    let end = ended(&c, v["id"].as_str().unwrap()).await;
    assert_eq!(
        (&end["step"], &end["error_code"]),
        (&json!("failed"), &json!("wrong_tenant")),
        "{end}"
    );
    assert!(connections(&c).await.is_empty());
    c.assert_clean_also(&secrets()).await;
}

async fn forget_tenant(c: &Cx, id: i64) {
    sqlx::query("UPDATE core_connections SET identity = NULL WHERE id = ?")
        .bind(id)
        .execute(&c.fx.app.pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_re_sign_in_must_land_in_the_tenant_the_connection_was_made_in() {
    let (c, t) = tcx().await;
    configure(&c).await;
    approves(&t, tt::TENANT);
    let v = begin(&c, json!({})).await.1;
    let conn = until(&c, v["id"].as_str().unwrap(), "connected").await["connection"]
        .as_i64()
        .unwrap();
    // The code is asked for AT the connection's tenant; a grant of another tenant is refused.
    approves(&t, tt::OTHER_TENANT);
    let v = begin(&c, json!({"connection": conn})).await.1;
    assert!(
        t.fake
            .last("devicecode")
            .unwrap()
            .path
            .starts_with(&format!("/{}/", tt::TENANT))
    );
    let end = ended(&c, v["id"].as_str().unwrap()).await;
    assert_eq!(
        (&end["step"], &end["error_code"]),
        (&json!("failed"), &json!("wrong_tenant")),
        "{end}"
    );
    let now = c
        .ok(Method::GET, &format!("{URI}/{conn}"), Value::Null)
        .await;
    assert_eq!(now["identity"], format!("{} in {}", tt::USER, tt::TENANT));
    // The same tenant replaces the credential of the same connection.
    approves(&t, tt::TENANT);
    let v = begin(&c, json!({"connection": conn})).await.1;
    let end = until(&c, v["id"].as_str().unwrap(), "connected").await;
    assert_eq!(end["connection"], conn);
    assert_eq!(connections(&c).await.len(), 1);
    // A connection that records no tenant has nothing to compare with: refused unless confirmed.
    forget_tenant(&c, conn).await;
    approves(&t, tt::OTHER_TENANT);
    let v = begin(&c, json!({"connection": conn})).await.1;
    let end = ended(&c, v["id"].as_str().unwrap()).await;
    assert_eq!(
        (&end["step"], &end["error_code"]),
        (&json!("failed"), &json!("identity_unknown")),
        "{end}"
    );
    approves(&t, tt::OTHER_TENANT);
    let extra = json!({"connection": conn, "confirm_identity_change": true});
    let v = begin(&c, extra).await.1;
    let end = until(&c, v["id"].as_str().unwrap(), "connected").await;
    assert_eq!(
        end["identity"],
        format!("{} in {}", tt::USER, tt::OTHER_TENANT)
    );
    c.assert_clean_also(&secrets()).await;
}

#[tokio::test]
async fn there_is_no_way_in_but_the_sign_in() {
    let (c, t) = tcx().await;
    configure(&c).await;
    approves(&t, tt::TENANT);
    let v = begin(&c, json!({})).await.1;
    let conn = until(&c, v["id"].as_str().unwrap(), "connected").await["connection"]
        .as_i64()
        .unwrap();
    // A pasted token cannot make a connection, nor replace a credential (an hour-long access
    // token cannot be renewed, and the tenant could not be checked).
    let body = json!({"kind": "teams", "name": "pasted", "auth_method": "token", "token": "paste-0123456789abcdef"});
    let r = c.admin(Method::POST, URI, body).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST, "{}", r.1);
    let r = c
        .admin(
            Method::PUT,
            &format!("{URI}/{conn}/credential"),
            json!({"token": "paste-0123456789abcdef"}),
        )
        .await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST, "{}", r.1);
    assert_eq!(connections(&c).await.len(), 1);
    c.assert_clean_also(&["paste-0123456789abcdef"]).await;
}

#[tokio::test]
async fn changing_the_app_ends_a_waiting_sign_in() {
    let (c, t) = tcx().await;
    configure(&c).await;
    t.fake
        .reply("token", tt::Reply::entra(400, "authorization_pending"));
    let v = begin(&c, json!({})).await.1;
    c.ok(
        Method::PUT,
        APPS,
        json!({"fields": {"client_id": "another-client-1"}}),
    )
    .await;
    let end = ended(&c, v["id"].as_str().unwrap()).await;
    assert_eq!(
        (&end["step"], &end["error_code"]),
        (&json!("failed"), &json!("app_changed")),
        "{end}"
    );
    assert!(connections(&c).await.is_empty());
}

#[tokio::test]
async fn another_user_of_the_same_tenant_replaces_the_credential_only_when_confirmed() {
    let (c, t) = tcx().await;
    configure(&c).await;
    approves(&t, tt::TENANT);
    let v = begin(&c, json!({})).await.1;
    let conn = until(&c, v["id"].as_str().unwrap(), "connected").await["connection"]
        .as_i64()
        .unwrap();
    let colleague = "11111111-2222-4333-8444-555555555555";
    approves_as(&t, tt::TENANT, colleague);
    let v = begin(&c, json!({"connection": conn})).await.1;
    let end = ended(&c, v["id"].as_str().unwrap()).await;
    assert_eq!(
        (&end["step"], &end["error_code"]),
        (&json!("failed"), &json!("different_account")),
        "{end}"
    );
    // Nothing was replaced: no new credential was tested.
    let before = t.fake.count("me");
    let now = c
        .ok(Method::GET, &format!("{URI}/{conn}"), Value::Null)
        .await;
    assert_eq!(now["identity"], format!("{} in {}", tt::USER, tt::TENANT));
    assert_eq!(t.fake.count("me"), before);
    // Confirmed, it is the same connection with the new credential.
    approves_as(&t, tt::TENANT, colleague);
    let extra = json!({"connection": conn, "confirm_identity_change": true});
    let v = begin(&c, extra).await.1;
    let end = until(&c, v["id"].as_str().unwrap(), "connected").await;
    assert_eq!(end["connection"], conn);
    assert_eq!(connections(&c).await.len(), 1);
    // A confirmation never carries a sign-in into another tenant.
    approves(&t, tt::OTHER_TENANT);
    let extra = json!({"connection": conn, "confirm_identity_change": true});
    let v = begin(&c, extra).await.1;
    let end = ended(&c, v["id"].as_str().unwrap()).await;
    assert_eq!(
        (&end["step"], &end["error_code"]),
        (&json!("failed"), &json!("wrong_tenant")),
        "{end}"
    );
    c.assert_clean_also(&secrets()).await;
}
