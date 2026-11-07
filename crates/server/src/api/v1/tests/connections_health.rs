//! A test decides a pending auth failure and raises health events; the activity of a connection
//! (C5).

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;

use crate::store::connections::resolve::{Context, record_use};

const URI: &str = "/api/v1/connections";

#[tokio::test]
async fn a_test_decides_a_pending_auth_failure_and_raises_one_health_event_each_way() {
    let cx = cx().await;
    let id = cx.github("main").await;
    let suspect = || async {
        sqlx::query(
            "UPDATE core_connections SET status = 'unhealthy', state_reason = 'auth_suspected', \
             auth_pending = 1 WHERE id = ?",
        )
        .bind(id)
        .execute(&cx.fx.app.pool)
        .await
        .unwrap();
    };
    let test = || cx.admin(Method::POST, &format!("{URI}/{id}/test"), Value::Null);
    suspect().await;
    cx.gh.push(401, &[], r#"{"message":"Bad credentials"}"#);
    let v = test().await;
    assert_eq!(v.0, StatusCode::OK, "{}", v.1);
    assert_eq!(
        (&v.1["status"], &v.1["state_reason"]),
        (&json!("disabled"), &json!("auth_failed"))
    );
    let last = cx.health_events().await.pop().unwrap();
    assert_eq!(
        last,
        json!({"connection": id, "user": 1, "kind": "github", "state": "disabled",
               "reason": "auth_failed"})
    );
    // A new credential clears it; a test that passes keeps it clear.
    cx.gh.push(200, &[], r#"{"login":"octocat","id":1}"#);
    let put = cx
        .admin(
            Method::PUT,
            &format!("{URI}/{id}/credential"),
            json!({"token": GH_TOKEN2}),
        )
        .await;
    assert_eq!(put.1["status"], "active", "{}", put.1);
    assert_eq!(
        cx.health_events().await.pop().unwrap()["reason"],
        "auth_cleared"
    );
    cx.gh.push(200, &[], r#"{"login":"octocat","id":1}"#);
    let v = test().await;
    assert_eq!(
        (&v.1["status"], &v.1["identity"]),
        (&json!("active"), &json!("octocat"))
    );
    assert!(v.1["last_tested_at"].is_string());
    // Suspected again and the service cannot be reached: still no verdict.
    suspect().await;
    cx.gh.push(500, &[], "{}");
    let v = test().await;
    assert_eq!(v.1["state_reason"], "auth_suspected", "{}", v.1);
    // The events carry ids and fixed codes, nothing else.
    for e in cx.health_events().await {
        let mut keys: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["connection", "kind", "reason", "state", "user"],
            "{e}"
        );
    }
    cx.assert_clean().await;
}

#[tokio::test]
async fn the_activity_lists_uses_newest_first_without_payloads() {
    let cx = cx().await;
    let id = cx.github("main").await;
    let reg = cx.fx.app.connections.registry();
    let c = Context {
        workspace: 1,
        user: 1,
        role: "admin",
        agent: Some("agent-1"),
        session: Some("as_01"),
        capability: "read_repo",
        operation: Some("github.get_issue"),
        resource: None,
        allowlist: None,
    };
    for (result, code) in [("ok", None), ("refused", Some("capability_missing"))] {
        let use_ = ("github.get_issue", result, code);
        record_use(&cx.fx.app.pool, reg, Some(id), "github", use_, &c)
            .await
            .unwrap();
    }
    let uri = format!("{URI}/{id}/activity");
    let all = cx.ok(Method::GET, &uri, Value::Null).await;
    let all = all.as_array().unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0]["result"], "refused");
    assert_eq!(all[0]["code"], "capability_missing");
    assert_eq!(
        (&all[1]["result"], &all[1]["action"], &all[1]["kind"]),
        (&json!("ok"), &json!("github.get_issue"), &json!("github"))
    );
    assert_eq!(
        (&all[1]["session"], &all[1]["agent"]),
        (&json!("as_01"), &json!("agent-1"))
    );
    let mut keys: Vec<&str> = all[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "action", "agent", "at", "code", "kind", "result", "seq", "session"
        ]
    );
    let page = cx
        .ok(Method::GET, &format!("{uri}?limit=1"), Value::Null)
        .await;
    assert_eq!(page.as_array().unwrap().len(), 1);
    let seq = all[0]["seq"].as_i64().unwrap();
    let older = cx
        .ok(Method::GET, &format!("{uri}?before={seq}"), Value::Null)
        .await;
    assert_eq!(older.as_array().unwrap().len(), 1);
    assert_eq!(older[0]["result"], "ok");
    cx.assert_clean().await;
}
