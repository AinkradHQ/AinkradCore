//! The picker's list (`GET /connections/{id}/resources`): the repositories of a GitHub
//! connection against the loopback fake, newest first, searched, admin only, and no token in
//! the path or any body.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;

fn repo(owner: &str, name: &str, pushed: &str) -> Value {
    json!({"name": name, "owner": {"login": owner}, "default_branch": "main",
           "description": "", "pushed_at": pushed})
}

#[tokio::test]
async fn a_github_connection_lists_its_repositories_newest_first_and_searchable() {
    let cx = cx().await;
    let id = cx.github("octo").await;
    cx.gh.push(
        200,
        &[],
        &Value::Array(vec![
            repo("acme", "old", "2026-01-02T03:04:05Z"),
            repo("acme", "web", "2026-11-18T10:00:00Z"),
        ])
        .to_string(),
    );
    let uri = format!("/api/v1/connections/{id}/resources");
    let r = cx.ok(Method::GET, &uri, Value::Null).await;
    assert_eq!(r["key"], "repos");
    assert_eq!(r["truncated"], false);
    let ids: Vec<_> = r["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, ["acme/web", "acme/old"]);
    assert_eq!(r["resources"][0]["updated_at"], "2026-11-18T10:00:00.000Z");
    // Searching reads the cached list: one call to GitHub in all.
    let r = cx
        .ok(Method::GET, &format!("{uri}?q=OLD"), Value::Null)
        .await;
    assert_eq!(r["resources"].as_array().unwrap().len(), 1);
    assert_eq!(r["resources"][0]["id"], "acme/old");
    let calls = cx.gh.seen();
    let list: Vec<_> = calls
        .iter()
        .filter(|c| c.path.starts_with("/user/repos"))
        .collect();
    assert_eq!(list.len(), 1);
    assert!(!list[0].path.contains(GH_TOKEN));
    cx.assert_clean().await;
}

#[tokio::test]
async fn only_an_admin_reads_it_and_another_id_is_not_found() {
    let cx = cx().await;
    let id = cx.github("octo").await;
    let reader = cx.fx.enroll("reader", &["read"]).await;
    let (status, _) = cx
        .call(
            &reader,
            Method::GET,
            &format!("/api/v1/connections/{id}/resources"),
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = cx
        .admin(
            Method::GET,
            "/api/v1/connections/9999/resources",
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
