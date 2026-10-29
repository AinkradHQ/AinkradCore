//! A project's repos (E15.16): added, changed, ordered, made primary and removed; an issue's
//! repos set and read back; bad values refused.

use citadel_core::work::ProjectMode;
use serde_json::json;

use super::*;

#[tokio::test]
async fn repos_round_trip_through_the_api() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "REP", ProjectMode::Kanban).await;
    let p = a.project.0;
    let send_as = |m: Method, uri: String, body: Option<Value>| {
        send(&fx.app, req(m, &uri, Some(&fx.key), body))
    };
    assert_eq!(
        fx.ok(&format!("/api/v1/projects/{p}/repos")).await,
        json!([])
    );
    let core = fx
        .ok_post(
            &format!("/api/v1/projects/{p}/repos"),
            json!({"name": "core", "url": "/srv/core.git",
                   "forge": {"kind": "github", "repo": "acme/core", "token_file": "/etc/t"},
                   "commands": {"test": "cargo test"}}),
        )
        .await;
    assert_eq!(core["primary"], true);
    assert_eq!(core["forge"]["api_url"], "https://api.github.com");
    assert_eq!(core["commands"]["test"], "cargo test");
    let app = fx
        .ok_post(
            &format!("/api/v1/projects/{p}/repos"),
            json!({"name": "app", "url": "/srv/app.git", "default_branch": "development"}),
        )
        .await;
    assert_eq!(
        (app["primary"].clone(), app["position"].clone()),
        (json!(false), json!(1))
    );
    for bad in [
        json!({"name": "core", "url": "/srv/x.git"}),
        json!({"name": "x", "url": "https://u:p@h/x.git"}),
        json!({"name": "x", "url": "/srv/x.git", "forge": {"kind": "svn", "repo": "a", "token_file": "/t"}}),
    ] {
        let (status, body) = fx
            .post(&format!("/api/v1/projects/{p}/repos"), bad.clone())
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }

    let uri = format!("/api/v1/repos/{}", app["id"]);
    let (status, set) = send_as(
        Method::PUT,
        uri.clone(),
        Some(json!({"name": "app",
        "url": "/srv/app2.git", "commands": {"lint": "make lint"}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(
        (set["url"].clone(), set["default_branch"].clone()),
        (json!("/srv/app2.git"), json!("main"))
    );

    let order = format!("/api/v1/projects/{p}/repo-order");
    let (status, ordered) =
        send_as(Method::PUT, order, Some(json!({"repos": ["app", "core"]}))).await;
    assert_eq!(status, StatusCode::OK, "{ordered}");
    assert_eq!(ordered[0]["name"], "app");
    let primary = fx.ok_post(&format!("{uri}/primary"), json!({})).await;
    assert_eq!(primary[0]["primary"], true);

    let issue = format!("/api/v1/issues/{}/repos", a.issue.0);
    assert_eq!(fx.ok(&issue).await["repos"], json!(["app"]));
    let (status, both) = send_as(
        Method::PUT,
        issue.clone(),
        Some(json!({"repos": ["core", "app"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{both}");
    assert_eq!(both["repos"], json!(["app", "core"]));
    let core_uri = format!("/api/v1/repos/{}", core["id"]);
    let (status, body) = send_as(Method::DELETE, core_uri.clone(), None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an open issue touches it: {body}"
    );
    send_as(Method::PUT, issue, Some(json!({"repos": []}))).await;
    let (status, left) = send_as(Method::DELETE, core_uri, None).await;
    assert_eq!(status, StatusCode::OK, "{left}");
    assert_eq!(left.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn an_issue_without_an_explicit_repo_is_flagged_only_in_a_multi_repo_project() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "IMP", ProjectMode::Kanban).await;
    let (p, uri) = (a.project.0, format!("/api/v1/issues/{}", a.issue.0));
    let repos = format!("/api/v1/projects/{p}/repos");
    let add = |name: &'static str| {
        fx.ok_post(
            &repos,
            json!({"name": name, "url": format!("/srv/{name}.git")}),
        )
    };
    add("core").await;
    assert!(fx.ok(&uri).await.get("repo_implicit").is_none(), "one repo");
    add("app").await;
    assert_eq!(fx.ok(&uri).await["repo_implicit"], true);
    let set = send(
        &fx.app,
        req(
            Method::PUT,
            &format!("{uri}/repos"),
            Some(&fx.key),
            Some(json!({"repos": ["app"]})),
        ),
    )
    .await;
    assert_eq!(set.0, StatusCode::OK, "{}", set.1);
    assert!(fx.ok(&uri).await.get("repo_implicit").is_none(), "explicit");
}
