//! The second review of C5: who may change Ainkrad's apps, an installation held by one workspace,
//! sign-in flows that really end (cancel, config change, caps), a paced test, and the health
//! event's audience.

use std::time::Duration;

use axum::body::to_bytes;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::connections_apps::{mark, pem};
use super::connections_fx::*;
use super::{NOW, req};
use crate::connections::jira::tests as jt;

const URI: &str = "/api/v1/connections";
const APPS: &str = "/api/v1/connection-apps";
const PENDING: &str = r#"{"error":"authorization_pending"}"#;

fn flow(id: &str) -> String {
    format!("{URI}/flows/{id}")
}

fn granted(token: &str) -> String {
    format!(r#"{{"access_token":"{token}","token_type":"bearer","scope":"repo"}}"#)
}

fn whoami(login: &str) -> String {
    format!(r#"{{"login":"{login}","id":583231}}"#)
}

async fn begin(cx: &Cx, kind: &str) -> Value {
    let (s, v) = start(cx, kind, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

async fn callback(cx: &Cx, v: &Value) -> (StatusCode, Value) {
    let id = v["id"].as_str().unwrap();
    let body = json!({"code": CODE, "state": v["state"]});
    cx.admin(Method::POST, &format!("{}/callback", flow(id)), body)
        .await
}

// ----- 1 the apps are the Core owner's ---------------------------------------------------------

#[tokio::test]
async fn only_the_cores_owner_changes_the_apps_and_other_admins_read_only_whether_they_are_set() {
    let cx = cx().await;
    cx.configure().await;
    let pending = begin(&cx, "jira").await;
    let other = other_admin(&cx).await;
    let put = cx
        .call(
            &other,
            Method::PUT,
            &format!("{APPS}/jira"),
            json!({"fields": {"client_id": "evil-1"}}),
        )
        .await;
    assert_eq!(code(&put), (403, "forbidden_scope".to_owned()), "{}", put.1);
    let put = cx
        .call(
            &other,
            Method::PUT,
            &format!("{APPS}/github"),
            json!({"fields": {"client_id": null}}),
        )
        .await;
    assert_eq!(code(&put).0, 403);
    // They read whether Sign in is set up, and nothing of the fields or the redirect.
    let got = cx
        .call(&other, Method::GET, &format!("{APPS}/jira"), Value::Null)
        .await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    assert_eq!(
        (&got.1["configured"], &got.1["fields"]),
        (&json!(true), &json!([]))
    );
    assert_eq!(got.1["redirect_uri"], Value::Null);
    assert!(!got.1.to_string().contains("client-id-8c41"));
    // The owner still sees all of it, nothing was changed, and the pending sign-in goes on.
    let mine = cx
        .ok(Method::GET, &format!("{APPS}/jira"), Value::Null)
        .await;
    assert_eq!(mine["fields"][0]["value"], "client-id-8c41");
    assert_eq!(callback(&cx, &pending).await.1["step"], "connected");
    cx.assert_clean().await;
}

// ----- 2 an installation belongs to one workspace -------------------------------------------------

async fn app_set(cx: &Cx) -> String {
    let key = pem();
    let set = json!({"fields": {"app_id": "123456", "app_key": key, "app_slug": "ainkrad-test"}});
    cx.ok(Method::PUT, &format!("{APPS}/github"), set).await;
    key
}

fn install(cx: &Cx, installation: i64, token: &str) {
    let account = format!(r#"{{"id":{installation},"account":{{"login":"octo-org"}}}}"#);
    cx.gh.push(200, &[], &account);
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
        r#"{"repositories":[{"owner":{"login":"octo-org","id":9}}]}"#,
    );
}

fn app_install(name: &str, installation: i64) -> Value {
    json!({"kind": "github", "name": name, "auth_method": "app_install", "installation_id": installation})
}

#[tokio::test]
async fn an_installation_is_held_by_the_first_workspace_that_uses_it_and_must_exist() {
    let cx = cx().await;
    let key = app_set(&cx).await;
    let other = other_admin(&cx).await;
    install(&cx, 77, "c5inst-aaaa1111bbbb2222");
    let mine = cx.ok(Method::POST, URI, app_install("app", 77)).await["id"]
        .as_i64()
        .unwrap();
    // Another workspace is refused before anything is asked of GitHub, and creates nothing.
    let asked = cx.gh.seen().len();
    let r = cx
        .call(&other, Method::POST, URI, app_install("theirs", 77))
        .await;
    assert_eq!(code(&r), (409, "conflict".to_owned()), "{}", r.1);
    assert_eq!(cx.gh.seen().len(), asked);
    assert_eq!(
        cx.call(&other, Method::GET, URI, Value::Null).await.1,
        json!([])
    );
    // Another installation is theirs, and then mine to refuse.
    install(&cx, 78, "c5inst-cccc3333dddd4444");
    let r = cx
        .call(&other, Method::POST, URI, app_install("theirs", 78))
        .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    let r = cx.admin(Method::POST, URI, app_install("again", 78)).await;
    assert_eq!(code(&r), (409, "conflict".to_owned()), "{}", r.1);
    // A replacement through an installation another workspace holds leaves the old pair intact.
    let r = cx
        .admin(
            Method::PUT,
            &format!("{URI}/{mine}/credential"),
            json!({"installation_id": 78}),
        )
        .await;
    assert_eq!(code(&r), (409, "conflict".to_owned()), "{}", r.1);
    let (_, version) = crate::store::connections::secret::open(
        &cx.fx.app.pool,
        cx.fx.app.secrets.as_deref().unwrap(),
        1,
        mine,
    )
    .await
    .unwrap();
    assert_eq!(version, 1);
    let held = crate::store::connections::apps::installation_of(&cx.fx.app.pool, 1, mine).await;
    assert_eq!(held.unwrap(), Some(77));
    // An installation that does not exist on GitHub is refused, and claimed by no one.
    cx.gh.push(404, &[], r#"{"message":"Not Found"}"#);
    let r = cx.admin(Method::POST, URI, app_install("ghost", 99)).await;
    assert_eq!(r.0, StatusCode::BAD_GATEWAY, "{}", r.1);
    assert_eq!(
        crate::store::connections::apps::claimed_by(&cx.fx.app.pool, 99)
            .await
            .unwrap(),
        None
    );
    cx.assert_clean_also(&["c5inst-aaaa1111bbbb2222", &mark(&key)])
        .await;
}

// ----- 3 4 flows: caps, cancel and what a refused start leaves --------------------------------

#[tokio::test]
async fn a_cancelled_or_refused_sign_in_leaves_no_pending_entry_and_the_cap_is_a_429() {
    let cx = cx().await;
    cx.configure().await;
    let jira = cx.fx.app.connections.jira().clone();
    // Start and cancel eight times (Jira's own cap per user is eight): none is left behind.
    for _ in 0..8 {
        let v = begin(&cx, "jira").await;
        cx.ok(
            Method::DELETE,
            &flow(v["id"].as_str().unwrap()),
            Value::Null,
        )
        .await;
    }
    assert_eq!(jira.pending(), 0);
    let first = begin(&cx, "jira").await;
    assert_eq!(jira.pending(), 1, "a start after them works");
    // Four waiting: the fifth is refused (429 `too_many_flows`) and leaves nothing.
    for _ in 0..3 {
        begin(&cx, "jira").await;
    }
    let r = start(&cx, "jira", json!({})).await;
    assert_eq!(code(&r), (429, "too_many_flows".to_owned()), "{}", r.1);
    assert_eq!(jira.pending(), 4);
    // Without the app set up it is the other refusal.
    cx.ok(
        Method::PUT,
        &format!("{APPS}/jira"),
        json!({"fields": {"client_secret": null}}),
    )
    .await;
    assert_eq!(jira.pending(), 0, "ended with the app");
    assert_eq!(
        code(&start(&cx, "jira", json!({})).await),
        (409, "not_configured".to_owned())
    );
    let _ = first;
    cx.assert_clean().await;
}

#[tokio::test]
async fn finished_flows_are_capped_per_user_and_the_oldest_goes_first() {
    let cx = cx().await;
    cx.configure().await;
    cx.jf
        .reply("POST /oauth/token", 400, json!({"error": "invalid_grant"}));
    let mut ids = Vec::new();
    for _ in 0..18 {
        let v = begin(&cx, "jira").await;
        let r = callback(&cx, &v).await;
        assert_eq!(r.1["step"], "failed", "{}", r.1);
        ids.push(v["id"].as_str().unwrap().to_owned());
    }
    let cxr = &cx;
    let status =
        |id: String| async move { cxr.admin(Method::GET, &flow(&id), Value::Null).await.0 };
    for old in &ids[..2] {
        assert_eq!(
            status(old.clone()).await,
            StatusCode::NOT_FOUND,
            "the oldest were dropped"
        );
    }
    for fresh in &ids[2..] {
        assert_eq!(status(fresh.clone()).await, StatusCode::OK);
    }
}

// ----- 5 A: a config write ends only the flows of the kind whose app changed --------------------

#[tokio::test]
async fn a_config_write_ends_the_flows_of_the_kind_that_changed_and_no_others() {
    let cx = cx().await;
    cx.configure().await;
    let pending = begin(&cx, "jira").await;
    // GitHub's client id changes: the device flow ends and stops polling; Jira's goes on.
    cx.gh.push(200, &[], START);
    let device = begin(&cx, "github").await;
    let did = device["id"].as_str().unwrap();
    cx.ok(
        Method::PUT,
        &format!("{APPS}/github"),
        json!({"fields": {"client_id": "Iv1.other99"}}),
    )
    .await;
    let v = cx.ok(Method::GET, &flow(did), Value::Null).await;
    assert_eq!(
        (&v["step"], &v["error_code"]),
        (&json!("failed"), &json!("app_changed")),
        "{v}"
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        cx.gh.seen().len(),
        1,
        "only the code request: nothing polls after the change"
    );
    let still = cx
        .ok(
            Method::GET,
            &flow(pending["id"].as_str().unwrap()),
            Value::Null,
        )
        .await;
    assert_eq!(still["step"], "waiting");
    // A write that leaves the Atlassian app as it is (the same values, or only the port field set
    // to its default) keeps the pending sign-in; it finishes.
    cx.ok(
        Method::PUT,
        &format!("{APPS}/jira"),
        json!({"fields": {"client_id": "client-id-8c41"}}),
    )
    .await;
    cx.ok(
        Method::PUT,
        &format!("{APPS}/github"),
        json!({"fields": {"app_slug": "x-app"}}),
    )
    .await;
    assert_eq!(callback(&cx, &pending).await.1["step"], "connected");
    // And the Atlassian app really changing ends a waiting Atlassian flow.
    let next = begin(&cx, "jira").await;
    cx.ok(
        Method::PUT,
        &format!("{APPS}/jira"),
        json!({"fields": {"client_id": "client-id-9999"}}),
    )
    .await;
    let v = cx
        .ok(
            Method::GET,
            &flow(next["id"].as_str().unwrap()),
            Value::Null,
        )
        .await;
    assert_eq!(v["error_code"], "app_changed", "{v}");
    cx.assert_clean().await;
}

// ----- 6 B: a cancel stops a finishing sign-in ------------------------------------------------

#[tokio::test]
async fn a_sign_in_cancelled_during_the_exchange_makes_and_replaces_nothing() {
    let cx = cx().await;
    cx.configure().await;
    let body = json!({"access_token": ACCESS, "refresh_token": REFRESH, "expires_in": 3600});
    cx.jf.on("POST /oauth/token", move |_| {
        jt::Reply::json(200, body.clone()).delayed(700)
    });
    let v = begin(&cx, "jira").await;
    let id = v["id"].as_str().unwrap().to_owned();
    let (done, cancelled) = tokio::join!(callback(&cx, &v), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        cx.ok(Method::DELETE, &flow(&id), Value::Null).await
    });
    assert_eq!(cancelled["deleted"], true);
    assert_eq!(done.1["error_code"], "cancelled", "{}", done.1);
    assert!(connections(&cx).await.is_empty(), "no connection was made");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_connection_secrets")
        .fetch_one(&cx.fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_cancel_that_returned_is_never_followed_by_a_credential_write() {
    let cx = cx().await;
    cx.configure().await;
    // A GitHub flow whose token arrives while the person cancels: whichever wins, a cancel that
    // has returned leaves no connection behind.
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], PENDING);
    cx.gh.push(200, &[], &granted(GH_TOKEN));
    cx.gh.push(200, &[], &whoami("octocat"));
    let v = begin(&cx, "github").await;
    let id = v["id"].as_str().unwrap().to_owned();
    cx.ok(Method::DELETE, &flow(&id), Value::Null).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(connections(&cx).await.is_empty());
    assert_eq!(cx.gh.seen().len(), 1, "the poll task stopped");
}

// ----- C: a GitHub re-sign-in must be the same account --------------------------------------------

#[tokio::test]
async fn a_github_sign_in_again_as_another_account_is_refused_unless_confirmed() {
    let cx = cx().await;
    cx.configure().await;
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], &granted(GH_TOKEN));
    cx.gh.push(200, &[], &whoami("octocat"));
    let first = begin(&cx, "github").await;
    let conn = until(&cx, first["id"].as_str().unwrap(), "connected").await["connection"]
        .as_i64()
        .unwrap();
    let version = || async {
        let sealer = cx.fx.app.secrets.as_deref().unwrap();
        let (m, v) = crate::store::connections::secret::open(&cx.fx.app.pool, sealer, 1, conn)
            .await
            .unwrap();
        (m.access().to_owned(), v)
    };
    // Another GitHub account signs in: refused, the credential stays as it was.
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], &granted(GH_TOKEN2));
    cx.gh.push(200, &[], &whoami("mallory"));
    let again = start(&cx, "github", json!({"connection": conn})).await.1;
    let r = until_failed(&cx, again["id"].as_str().unwrap()).await;
    assert_eq!(r["error_code"], "different_account", "{r}");
    assert_eq!(version().await, (GH_TOKEN.to_owned(), 1));
    // Confirmed, it replaces the credential and the connection reads as the new account.
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], &granted(GH_TOKEN2));
    cx.gh.push(200, &[], &whoami("mallory"));
    let body = json!({"connection": conn, "confirm_identity_change": true});
    let again = start(&cx, "github", body).await.1;
    let done = until(&cx, again["id"].as_str().unwrap(), "connected").await;
    assert_eq!(done["identity"], "mallory");
    assert_eq!(version().await, (GH_TOKEN2.to_owned(), 2));
    cx.assert_clean().await;
}

async fn until_failed(cx: &Cx, id: &str) -> Value {
    for _ in 0..150 {
        let v = cx.ok(Method::GET, &flow(id), Value::Null).await;
        if v["step"] == "failed" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the flow never failed");
}

// ----- 7 the test is paced -----------------------------------------------------------------------

async fn raw(cx: &Cx, uri: &str) -> (StatusCode, axum::http::HeaderMap, Value) {
    let r = req(Method::POST, uri, Some(&cx.fx.dev), None);
    let res = crate::api::router(cx.fx.app.clone())
        .oneshot(r)
        .await
        .unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn a_connection_is_tested_at_most_every_ten_seconds_and_a_user_thirty_times_in_ten_minutes() {
    let cx = cx().await;
    let id = cx.github("main").await;
    let uri = format!("{URI}/{id}/test");
    cx.fx.clock.advance(11);
    cx.gh.push(200, &[], &whoami("octocat"));
    assert_eq!(raw(&cx, &uri).await.0, StatusCode::OK);
    let asked = cx.gh.seen().len();
    let (s, headers, body) = raw(&cx, &uri).await;
    assert_eq!(
        (s, body["code"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited"))
    );
    let wait: u64 = headers
        .get("retry-after")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=10).contains(&wait), "{wait}");
    assert_eq!(
        cx.gh.seen().len(),
        asked,
        "a refused test asks the service for nothing"
    );
    cx.fx.clock.advance(11);
    cx.gh.push(200, &[], &whoami("octocat"));
    assert_eq!(raw(&cx, &uri).await.0, StatusCode::OK);
    // Thirty tests in the window in all (two are used), then the user waits.
    let sealer = cx.fx.app.secrets.as_deref().unwrap();
    let reg = cx.fx.app.connections.registry();
    let who = crate::store::connections::Who {
        workspace: 1,
        by_device: "d_test",
        actor: ainkrad_core::audit::AuditActor::System,
        now: NOW,
    };
    let mut more = Vec::new();
    for n in 0..29 {
        let name = format!("more-{n}");
        let new = crate::store::connections::NewConnection {
            kind: "github",
            name: &name,
            label: "More",
            auth_method: "token",
        };
        let m = crate::connections::material::Material::new(
            &format!("c5more-{n:04}-7f3a9d41e0b2"),
            None,
            None,
        )
        .unwrap();
        more.push(
            crate::store::connections::create(&cx.fx.app.pool, sealer, reg, &new, &m, who)
                .await
                .unwrap()
                .id,
        );
    }
    for id in &more[..28] {
        cx.gh.push(200, &[], &whoami("octocat"));
        assert_eq!(
            raw(&cx, &format!("{URI}/{id}/test")).await.0,
            StatusCode::OK,
            "{id}"
        );
    }
    let last = format!("{URI}/{}/test", more[28]);
    let (s, _, body) = raw(&cx, &last).await;
    assert_eq!(
        (s, body["code"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited"))
    );
    cx.fx.clock.advance(601);
    cx.gh.push(200, &[], &whoami("octocat"));
    assert_eq!(raw(&cx, &last).await.0, StatusCode::OK);
    // Another workspace's connection is a 404, not a pace.
    let other = other_admin(&cx).await;
    let r = cx.call(&other, Method::POST, &uri, Value::Null).await;
    assert_eq!(code(&r).0, 404);
}

// ----- 8 the health event is for admins ----------------------------------------------------------

#[tokio::test]
async fn a_read_device_does_not_receive_the_connection_health_event() {
    let cx = cx().await;
    let id = cx.github("main").await;
    sqlx::query("UPDATE core_connections SET status = 'unhealthy', state_reason = 'auth_suspected', auth_pending = 1 WHERE id = ?")
        .bind(id)
        .execute(&cx.fx.app.pool)
        .await
        .unwrap();
    cx.fx.clock.advance(11);
    cx.gh.push(401, &[], r#"{"message":"Bad credentials"}"#);
    cx.ok(Method::POST, &format!("{URI}/{id}/test"), Value::Null)
        .await;
    assert_eq!(cx.health_events().await.len(), 1);
    let reader = cx.fx.enroll("reader", &["read", "agent"]).await;
    let events = "/api/v1/events?after=0&limit=1000";
    let seen = cx.call(&reader, Method::GET, events, Value::Null).await;
    assert_eq!(seen.0, StatusCode::OK, "{}", seen.1);
    assert!(
        !seen.1.to_string().contains("connection.health"),
        "{}",
        seen.1
    );
    let admin = cx.admin(Method::GET, events, Value::Null).await;
    assert!(admin.1.to_string().contains("connection.health"));
    // The contract says who sees it.
    let spec: Value = serde_json::from_str(&super::super::spec::json()).unwrap();
    assert_eq!(
        spec["components"]["schemas"]["Event"]["x-event-scopes"]["connection.health"],
        "admin"
    );
}
