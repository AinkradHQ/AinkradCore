//! No credential is in any response, event, audit row or the database file (C5): a scan over a
//! full session of use, with upstream answers that echo the very secrets Core holds, error
//! bodies and flow polls included.

use axum::http::Method;
use serde_json::{Value, json};

use super::connections_fx::*;

const URI: &str = "/api/v1/connections";

#[tokio::test]
async fn no_secret_is_in_any_body_event_audit_row_or_the_database_file() {
    let cx = cx().await;
    // The upstream echoes what Core sent it, in the places a careless Core would repeat.
    cx.jf.reply(
        "POST /oauth/token",
        200,
        json!({"access_token": ACCESS, "refresh_token": REFRESH,
        "expires_in": 3600, "echo": CODE}),
    );
    cx.configure().await;
    cx.ok(
        Method::PUT,
        "/api/v1/connection-apps/jira",
        json!({"fields": {"loopback_port": "50124"}}),
    )
    .await;
    // A token connection, a refused one whose error echoes the token, and a jira one.
    let gh = cx.github("main").await;
    cx.gh.push(
        401,
        &[],
        &format!(r#"{{"message":"Bad credentials {GH_TOKEN2}","token":"{GH_TOKEN2}"}}"#),
    );
    let refused = cx
        .admin(
            Method::POST,
            URI,
            json!({"kind": "github", "name": "x", "auth_method": "token", "token": GH_TOKEN2}),
        )
        .await;
    assert_eq!(refused.0.as_u16(), 400, "{}", refused.1);
    let jira = cx.jira("acme").await;
    // An Atlassian sign-in whose code the service echoes back in its failure.
    cx.jf.reply(
        "POST /oauth/token",
        400,
        json!({"error": "invalid_grant", "echo": CODE, "token": REFRESH}),
    );
    let v = start(&cx, "jira", json!({})).await.1;
    let flow = v["id"].as_str().unwrap().to_owned();
    let failed = cx
        .admin(
            Method::POST,
            &format!("{URI}/flows/{flow}/callback"),
            json!({"code": CODE, "state": v["state"]}),
        )
        .await;
    assert_eq!(failed.1["step"], "failed", "{}", failed.1);
    cx.admin(Method::GET, &format!("{URI}/flows/{flow}"), Value::Null)
        .await;
    // A GitHub device flow that ends in a stored credential.
    cx.gh.push(200, &[], START);
    cx.gh.push(
        200,
        &[],
        &format!(r#"{{"access_token":"{GH_TOKEN2}","token_type":"bearer","scope":"repo"}}"#),
    );
    cx.gh.push(200, &[], r#"{"login":"octocat","id":1}"#);
    let d = start(&cx, "github", json!({})).await.1;
    until(&cx, d["id"].as_str().unwrap(), "connected").await;
    // Every read and write route, as the admin, as a reader and as a stranger.
    let reader = cx.fx.enroll("reader", &["read"]).await;
    cx.ok(
        Method::PUT,
        &format!("{URI}/{gh}/grants"),
        json!({"grantee_kind": "role", "grantee": "member"}),
    )
    .await;
    cx.ok(
        Method::PUT,
        "/api/v1/connection-defaults/github",
        json!({"connection": gh}),
    )
    .await;
    cx.gh.push(200, &[], r#"{"login":"octocat","id":1}"#);
    let all = [
        (Method::GET, "/api/v1/connection-kinds".to_owned()),
        (Method::GET, URI.to_owned()),
        (Method::GET, format!("{URI}/{gh}")),
        (Method::GET, format!("{URI}/{jira}")),
        (Method::GET, format!("{URI}/{gh}/grants")),
        (Method::GET, format!("{URI}/{gh}/activity")),
        (Method::GET, "/api/v1/connection-defaults".to_owned()),
        (Method::GET, "/api/v1/connection-apps/jira".to_owned()),
        (Method::GET, "/api/v1/connection-apps/github".to_owned()),
        (Method::POST, format!("{URI}/{gh}/test")),
        (Method::GET, "/api/v1/events?after=0&limit=1000".to_owned()),
        (Method::GET, "/api/v1/audit?limit=200".to_owned()),
    ];
    for (m, uri) in &all {
        cx.admin(m.clone(), uri, Value::Null).await;
        cx.call(&reader, m.clone(), uri, Value::Null).await;
    }
    let stranger = cx.fx.stranger();
    cx.call(&stranger, Method::GET, URI, Value::Null).await;
    // Error bodies: junk that carries a secret, a missing row, a wrong method.
    let junk = Value::String(format!("{{{GH_TOKEN} {CLIENT_SECRET}"));
    for (m, uri) in [
        (Method::POST, URI.to_owned()),
        (Method::PUT, format!("{URI}/{gh}/credential")),
        (Method::PUT, "/api/v1/connection-apps/jira".to_owned()),
        (Method::PUT, format!("{URI}/{gh}/grants")),
        (Method::POST, format!("{URI}/start")),
        (Method::PATCH, format!("{URI}/{gh}")),
    ] {
        let r = cx.admin(m, &uri, junk.clone()).await;
        assert_eq!(r.0.as_u16(), 400, "{}", r.1);
    }
    cx.admin(Method::GET, &format!("{URI}/999999"), Value::Null)
        .await;
    cx.assert_clean().await;
    // The database file, after its log is folded in, holds only sealed bytes.
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&cx.fx.app.pool)
        .await
        .unwrap();
    let path = cx
        .fx
        .app
        .pool
        .connect_options()
        .get_filename()
        .to_path_buf();
    let bytes = std::fs::read(path).unwrap();
    for s in SECRETS
        .iter()
        .filter(|s| **s != DEVICE_CODE && **s != PEM_MARK)
    {
        assert!(
            !bytes.windows(s.len()).any(|w| w == s.as_bytes()),
            "{s} is in the database file"
        );
    }
}
