//! Projects from GitHub (P2-01): the repo list (grouped, searched, paged) and creating from repos
//! against the loopback GitHub fake; no real token, and none in any body, event or audit row.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;

const LIST: &str = "/api/v1/projects/github/repos";
const FROM: &str = "/api/v1/projects/from-github";

fn repo(owner: &str, name: &str, branch: &str) -> Value {
    json!({"name": name, "owner": {"login": owner}, "private": name == "vault",
           "default_branch": branch, "description": "d"})
}

/// A connection that is the workspace default; the fake is then scripted by the test.
async fn setup() -> (Cx, i64) {
    let cx = cx().await;
    let id = cx.github("octo").await;
    cx.ok(
        Method::PUT,
        "/api/v1/connection-defaults/github",
        json!({"connection": id}),
    )
    .await;
    (cx, id)
}

fn four() -> String {
    Value::Array(vec![
        repo("zed", "b", "main"),
        repo("acme", "web", "trunk"),
        repo("acme", "api", "main"),
        repo("acme", "vault", "main"),
    ])
    .to_string()
}

#[tokio::test]
async fn the_list_is_grouped_by_owner_searched_and_paged() {
    let (cx, id) = setup().await;
    cx.gh.push(200, &[], &four());
    let r = cx.ok(Method::GET, LIST, Value::Null).await;
    assert_eq!(r["connection_id"], id);
    assert_eq!(r["total"], 4);
    let owners = r["owners"].as_array().unwrap();
    assert_eq!(owners[0]["owner"], "acme");
    assert_eq!(owners[0]["repos"][0]["full_name"], "acme/api");
    assert_eq!(owners[0]["repos"][1]["private"], true);
    assert_eq!(owners[1]["owner"], "zed");
    // The token went to GitHub as a header, never in the path.
    let seen = cx.gh.seen();
    let last = seen.last().unwrap();
    assert!(last.path.starts_with("/user/repos?"), "{}", last.path);
    assert!(!last.path.contains(GH_TOKEN));

    // Searching and paging reuse the cached list: no new GitHub call.
    let r = cx
        .ok(Method::GET, &format!("{LIST}?q=WEB"), Value::Null)
        .await;
    assert_eq!(r["total"], 1);
    assert_eq!(r["owners"][0]["repos"][0]["default_branch"], "trunk");

    let r = cx
        .ok(
            Method::GET,
            &format!("{LIST}?per_page=2&page=2"),
            Value::Null,
        )
        .await;
    assert_eq!(r["total"], 4);
    assert_eq!(r["has_more"], false);
    assert_eq!(r["owners"][0]["repos"][0]["full_name"], "acme/web");
    cx.assert_clean().await;
}

#[tokio::test]
async fn create_fills_name_slug_branch_and_binds_the_connection_to_the_project() {
    let (cx, _) = setup().await;
    cx.gh
        .push(200, &[], &repo("acme", "Shop.Front", "develop").to_string());
    cx.gh
        .push(200, &[], &repo("acme", "shop-api", "main").to_string());
    let p = cx
        .ok(
            Method::POST,
            FROM,
            json!({"repos": ["acme/Shop.Front", "acme/shop-api"]}),
        )
        .await;
    assert_eq!(p["source"], "github");
    assert_eq!(p["slug"], "shop-front");
    assert_eq!(p["name"], "Shop.Front");
    assert_eq!(p["repos"][0]["default_branch"], "develop");
    assert_eq!(p["repos"][0]["is_primary"], true);
    assert_eq!(
        p["repos"][1]["remote_url"],
        "https://github.com/acme/shop-api.git"
    );
    // The picked connection is the workspace default: no per-project binding is written.
    let rows = |pid: i64| {
        sqlx::query_scalar::<_, i64>(
            "SELECT connection_id FROM core_connection_bindings WHERE scope_kind = 'project' \
             AND scope_ref = ?",
        )
        .bind(pid.to_string())
        .fetch_all(&cx.fx.app.pool)
    };
    assert!(rows(p["id"].as_i64().unwrap()).await.unwrap().is_empty());
    // Another connection, picked explicitly, is bound to the new project.
    let other = cx.github("other").await;
    cx.gh
        .push(200, &[], &repo("acme", "tool", "main").to_string());
    let q = cx
        .ok(
            Method::POST,
            FROM,
            json!({"repos": ["acme/tool"], "connection_id": other}),
        )
        .await;
    assert_eq!(rows(q["id"].as_i64().unwrap()).await.unwrap(), [other]);

    // The same name again: the slug gets -2, then -3.
    for want in ["shop-front-2", "shop-front-3"] {
        cx.gh
            .push(200, &[], &repo("acme", "Shop.Front", "develop").to_string());
        let p = cx
            .ok(Method::POST, FROM, json!({"repos": ["acme/Shop.Front"]}))
            .await;
        assert_eq!(p["slug"], want);
    }
    // An explicit taken slug is a conflict, and an unseen repo leaves no project behind.
    cx.gh.push(200, &[], &repo("acme", "x", "main").to_string());
    let r = cx
        .admin(
            Method::POST,
            FROM,
            json!({"repos": ["acme/x"], "slug": "shop-front"}),
        )
        .await;
    assert_eq!(r.0, StatusCode::CONFLICT, "{}", r.1);
    cx.gh.push(404, &[], "{}");
    let r = cx
        .admin(Method::POST, FROM, json!({"repos": ["acme/hidden"]}))
        .await;
    assert_eq!(r.0, StatusCode::NOT_FOUND, "{}", r.1);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_projects")
        .fetch_one(&cx.fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 3);
    cx.assert_clean().await;
}

#[tokio::test]
async fn no_connection_and_upstream_failures_are_plain_and_clean() {
    let cx = cx().await;
    let r = cx.admin(Method::GET, LIST, Value::Null).await;
    assert_eq!(r.0, StatusCode::CONFLICT);
    assert_eq!(r.1["code"], "no_connection");
    let id = cx.github("octo").await;
    cx.gh.push(401, &[], &format!("bad credentials {GH_TOKEN}"));
    let r = cx
        .admin(Method::GET, &format!("{LIST}?connection={id}"), Value::Null)
        .await;
    assert_eq!(r.0, StatusCode::BAD_GATEWAY, "{}", r.1);
    assert_eq!(r.1["code"], "auth_failed");
    cx.assert_clean().await;
    let r = cx.admin(Method::POST, FROM, json!({"repos": []})).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST);
}
