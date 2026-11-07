//! The review's other fixes (C5): a GitHub sign-in again is the same account, a flow whose
//! connection exists is never failed by a config change, the test is paced, and the health
//! event's audience.

use std::time::Duration;

use axum::body::to_bytes;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::connections_fx::*;
use super::connections_review::{begin, flow, granted, whoami};
use super::{NOW, req};
use crate::connections::jira::tests as jt;

const URI: &str = "/api/v1/connections";
const APPS: &str = "/api/v1/connection-apps";

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

// ----- a config change never fails a flow whose connection exists ------------------------------

#[tokio::test]
async fn a_config_change_leaves_a_flow_alone_once_its_connection_is_made() {
    let cx = cx().await;
    cx.configure().await;
    // The connection is written, then tested: the test is slow, and the app changes meanwhile.
    cx.jf.on("GET /me", |_| {
        jt::Reply::json(200, json!({"account_id": "5b10ac8d", "name": "Ann Lee"})).delayed(900)
    });
    let v = begin(&cx, "jira").await;
    let id = v["id"].as_str().unwrap().to_owned();
    let body = json!({"code": CODE, "state": v["state"]});
    let (done, mid) = tokio::join!(
        cx.admin(Method::POST, &format!("{}/callback", flow(&id)), body),
        async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            let put = json!({"fields": {"client_id": "client-id-9999"}});
            cx.ok(Method::PUT, &format!("{APPS}/jira"), put).await;
            cx.ok(Method::GET, &flow(&id), Value::Null).await
        }
    );
    // While its connection exists it is not failed (it is only being tested) ...
    assert_eq!(mid["step"], "approved", "{mid}");
    // ... and it ends connected, with the one connection: nothing to sign in for twice.
    assert_eq!(done.1["step"], "connected", "{}", done.1);
    assert_eq!(connections(&cx).await.len(), 1);
    cx.assert_clean().await;
}

// ----- a lookup that fails does not let another account through ----------------------------------

#[tokio::test]
async fn a_github_sign_in_again_whose_account_cannot_be_checked_is_refused_unless_confirmed() {
    let cx = cx().await;
    cx.configure().await;
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], &granted(GH_TOKEN));
    cx.gh.push(200, &[], &whoami("octocat"));
    let first = begin(&cx, "github").await;
    let conn = until(&cx, first["id"].as_str().unwrap(), "connected").await["connection"]
        .as_i64()
        .unwrap();
    // GitHub cannot say whose the new token is: fail closed, the credential stays.
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], &granted(GH_TOKEN2));
    cx.gh.push(500, &[], "{}");
    let again = start(&cx, "github", json!({"connection": conn})).await.1;
    let r = until_failed(&cx, again["id"].as_str().unwrap()).await;
    assert_eq!(r["error_code"], "identity_unavailable", "{r}");
    let sealer = cx.fx.app.secrets.as_deref().unwrap();
    let (m, version) = crate::store::connections::secret::open(&cx.fx.app.pool, sealer, 1, conn)
        .await
        .unwrap();
    assert_eq!((m.access(), version), (GH_TOKEN, 1));
    // Confirmed, the person has decided: it goes through.
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], &granted(GH_TOKEN2));
    cx.gh.push(200, &[], &whoami("octocat"));
    let body = json!({"connection": conn, "confirm_identity_change": true});
    let again = start(&cx, "github", body).await.1;
    until(&cx, again["id"].as_str().unwrap(), "connected").await;
    cx.assert_clean().await;
}
