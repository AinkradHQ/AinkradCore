//! "Sign in with GitHub" (the device flow) as a flow, and what every flow guarantees: its owner,
//! its caps, its expiry, and that a credential is stored once and never shown (C5). The Atlassian
//! flow is in `connections_jira`.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;

const URI: &str = "/api/v1/connections";
const PENDING: &str = r#"{"error":"authorization_pending"}"#;

fn granted(token: &str) -> String {
    format!(r#"{{"access_token":"{token}","token_type":"bearer","scope":"repo"}}"#)
}

fn whoami() -> &'static str {
    r#"{"login":"octocat","id":583231}"#
}

#[tokio::test]
async fn without_the_app_set_up_a_sign_in_says_so_plainly() {
    let cx = cx().await;
    for kind in ["github", "jira"] {
        let r = start(&cx, kind, json!({})).await;
        assert_eq!(code(&r), (409, "not_configured".to_owned()), "{}", r.1);
        assert!(
            r.1["message"].as_str().unwrap().contains("not set up"),
            "{}",
            r.1
        );
    }
    assert_eq!(code(&start(&cx, "svn", json!({})).await).0, 400);
    assert_eq!(
        code(&start(&cx, "github", json!({"name": "Bad Name"})).await).0,
        400
    );
    assert_eq!(
        code(&start(&cx, "github", json!({"connection": 99})).await).0,
        404
    );
    assert!(cx.gh.seen().is_empty(), "nothing was asked of GitHub");
}

#[tokio::test]
async fn the_device_flow_shows_a_code_waits_and_connects_once() {
    let cx = cx().await;
    cx.configure().await;
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], PENDING);
    cx.gh.push(200, &[], &granted(GH_TOKEN));
    cx.gh.push(200, &[], whoami());
    let (s, v) = start(&cx, "github", json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (&v["step"], &v["user_code"]),
        (&json!("waiting"), &json!("WDJB-MJHT"))
    );
    assert_eq!(v["verification_uri"], "https://github.com/login/device");
    assert_eq!(
        (&v["interval"], &v["authorize_url"]),
        (&json!(1), &Value::Null)
    );
    let id = v["id"].as_str().unwrap().to_owned();
    assert!(id.starts_with("cf_") && !v.to_string().contains(DEVICE_CODE));
    let done = until(&cx, &id, "connected").await;
    assert_eq!(done["identity"], "octocat");
    let conn = done["connection"].as_i64().unwrap();
    let c = cx
        .ok(Method::GET, &format!("{URI}/{conn}"), Value::Null)
        .await;
    assert_eq!(
        (&c["name"], &c["label"], &c["auth_method"], &c["identity"]),
        (
            &json!("github-1"),
            &json!("GitHub"),
            &json!("oauth"),
            &json!("octocat")
        )
    );
    // Four requests in all: the code, two polls, the test; the device code never left Core.
    let seen = cx.gh.seen();
    assert_eq!(seen.len(), 4);
    assert_eq!(seen[0].path, "/login/device/code");
    assert!(
        seen[0].body.contains("client_id=Iv1.abc123"),
        "{}",
        seen[0].body
    );
    assert!(seen[1].body.contains(DEVICE_CODE) && seen[2].path == "/login/oauth/access_token");
    assert!(seen[3].header("authorization").unwrap().contains(GH_TOKEN));
    // The finished flow stays readable, and a redirect is not what a GitHub flow waits for.
    assert_eq!(
        cx.ok(Method::GET, &format!("{URI}/flows/{id}"), Value::Null)
            .await["step"],
        "connected"
    );
    let r = cx
        .admin(
            Method::POST,
            &format!("{URI}/flows/{id}/callback"),
            json!({"code": CODE, "state": "x"}),
        )
        .await;
    assert_eq!(code(&r).0, 409, "{}", r.1);
    assert_eq!(connections(&cx).await.len(), 1, "exactly one connection");
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_denied_an_expired_and_a_refused_sign_in_end_plainly_and_make_nothing() {
    let cx = cx().await;
    cx.configure().await;
    // The person says no.
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], r#"{"error":"access_denied"}"#);
    let id = start(&cx, "github", json!({})).await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    until(&cx, &id, "denied").await;
    // The code runs out (GitHub's own say).
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], r#"{"error":"expired_token"}"#);
    let id = start(&cx, "github", json!({})).await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    until(&cx, &id, "expired").await;
    // The code is short-lived: it expires by the clock with no request at all.
    cx.gh.push(
        200,
        &[],
        &START.replace("\"expires_in\":900", "\"expires_in\":1"),
    );
    let before = cx.gh.seen().len();
    let id = start(&cx, "github", json!({})).await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    until(&cx, &id, "expired").await;
    assert_eq!(cx.gh.seen().len(), before + 1, "only the code request");
    // A recognised real token is refused by the secrets gate: a plain `failed` step, not a 500.
    let real = format!("ghp_{}", "A1b2C3d4E5".repeat(4));
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], &granted(&real));
    let id = start(&cx, "github", json!({})).await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let v = until_failed(&cx, &id).await;
    assert_eq!(v["error_code"], "real_secret_refused", "{v}");
    assert!(!v.to_string().contains(&real));
    assert!(
        connections(&cx).await.is_empty(),
        "no flow made a connection"
    );
    cx.assert_clean().await;
}

async fn until_failed(cx: &Cx, id: &str) -> Value {
    for _ in 0..150 {
        let v = cx
            .ok(Method::GET, &format!("{URI}/flows/{id}"), Value::Null)
            .await;
        if v["step"] == "failed" {
            return v;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the flow never failed");
}

#[tokio::test]
async fn signing_in_again_replaces_the_credential_of_the_same_connection() {
    let cx = cx().await;
    cx.configure().await;
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], &granted(GH_TOKEN));
    cx.gh.push(200, &[], whoami());
    let id = start(&cx, "github", json!({})).await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let conn = until(&cx, &id, "connected").await["connection"]
        .as_i64()
        .unwrap();
    // A pasted-token connection is not signed in again; a missing or other kind's one is refused.
    let token = cx.github("pasted").await;
    for (c, want) in [(token, 400), (conn + 1000, 404)] {
        assert_eq!(
            start(&cx, "github", json!({"connection": c}))
                .await
                .0
                .as_u16(),
            want
        );
    }
    let jira = cx.jira("acme").await;
    assert_eq!(
        start(&cx, "github", json!({"connection": jira})).await.0,
        StatusCode::BAD_REQUEST
    );
    // Sign in again: the credential is replaced, the connection and its name stay.
    cx.gh.push(200, &[], START);
    cx.gh.push(200, &[], &granted(GH_TOKEN2));
    cx.gh.push(200, &[], whoami()); // the same account? (asked before the credential is replaced)
    cx.gh.push(200, &[], whoami()); // the test of the new credential
    let again = start(&cx, "github", json!({"connection": conn})).await.1;
    let done = until(&cx, again["id"].as_str().unwrap(), "connected").await;
    assert_eq!(done["connection"], conn);
    let (m, version) = crate::store::connections::secret::open(
        &cx.fx.app.pool,
        cx.fx.app.secrets.as_deref().unwrap(),
        1,
        conn,
    )
    .await
    .unwrap();
    assert_eq!((m.access(), version), (GH_TOKEN2, 2));
    assert_eq!(
        connections(&cx).await.len(),
        3,
        "no new connection was made"
    );
    // A name that is taken is refused at the start, before anyone signs in.
    let before = cx.gh.seen().len();
    let r = start(&cx, "github", json!({"name": "github-1"})).await;
    assert_eq!(code(&r), (409, "conflict".to_owned()), "{}", r.1);
    assert_eq!(cx.gh.seen().len(), before);
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_flow_belongs_to_the_user_and_device_that_started_it() {
    let cx = cx().await;
    cx.configure().await;
    let started = start(&cx, "jira", json!({})).await.1;
    let id = started["id"].as_str().unwrap().to_owned();
    let flow = format!("{URI}/flows/{id}");
    let second_device = cx.fx.enroll("second device", &["read", "admin"]).await;
    let other_user = other_admin(&cx).await;
    for dev in [&second_device, &other_user] {
        let calls = [
            (Method::GET, flow.clone(), Value::Null),
            (Method::DELETE, flow.clone(), Value::Null),
            (
                Method::POST,
                format!("{flow}/callback"),
                json!({"code": CODE, "state": started["state"]}),
            ),
            (Method::POST, format!("{flow}/choose"), json!({"site": "x"})),
        ];
        for (m, uri, body) in calls {
            let r = cx.call(dev, m.clone(), &uri, body).await;
            assert_eq!(
                code(&r),
                (404, "not_found".to_owned()),
                "{m} {uri}: {}",
                r.1
            );
        }
    }
    // Not an id of ours at all.
    for bad in ["nope", "cf_short", "d_00000000000000000000000000"] {
        let r = cx
            .admin(Method::GET, &format!("{URI}/flows/{bad}"), Value::Null)
            .await;
        assert_eq!(code(&r), (404, "not_found".to_owned()), "{bad}");
    }
    // It is still the owner's, untouched; the owner cancels it and it is gone.
    assert_eq!(
        cx.ok(Method::GET, &flow, Value::Null).await["step"],
        "waiting"
    );
    assert_eq!(
        cx.ok(Method::DELETE, &flow, Value::Null).await["deleted"],
        true
    );
    assert_eq!(
        cx.admin(Method::GET, &flow, Value::Null).await.0,
        StatusCode::NOT_FOUND
    );
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_user_has_at_most_four_sign_ins_waiting() {
    let cx = cx().await;
    cx.configure().await;
    let mut ids = Vec::new();
    for _ in 0..4 {
        let r = start(&cx, "jira", json!({})).await;
        assert_eq!(r.0, StatusCode::OK, "{}", r.1);
        ids.push(r.1["id"].as_str().unwrap().to_owned());
    }
    let r = start(&cx, "jira", json!({})).await;
    assert_eq!(code(&r), (429, "too_many_flows".to_owned()), "{}", r.1);
    // Another user is not held back by it; cancelling one makes room.
    let other = other_admin(&cx).await;
    let r = cx
        .call(
            &other,
            Method::POST,
            &format!("{URI}/start"),
            json!({"kind": "jira"}),
        )
        .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    cx.ok(
        Method::DELETE,
        &format!("{URI}/flows/{}", ids[0]),
        Value::Null,
    )
    .await;
    assert_eq!(start(&cx, "jira", json!({})).await.0, StatusCode::OK);
    cx.assert_clean().await;
}
