//! A project's repos through the Core's gate (E15.16): added, changed, ordered, made primary and
//! removed; an issue's repos set and read back; bad values refused. Ported from the monolith's
//! `api/v1/tests/repos.rs`, and the stubs of its `review.rs` (API minor 16) that belong to other
//! slices.

mod common;
mod work_seed;

use axum::http::{Method, StatusCode};
use citadel_module::domain::work::ProjectMode;
use common::*;
use serde_json::{Value, json};
use work_seed::*;

async fn send_as(fx: &Fx, m: Method, uri: String, body: Option<Value>) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), m, &uri, body).await
}

#[tokio::test]
async fn repos_round_trip_through_the_api() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "REP", ProjectMode::Kanban).await;
    let p = a.project;
    assert_eq!(ok(&fx, &format!("/projects/{p}/repos")).await, json!([]));
    let core = ok_post(
        &fx,
        &format!("/projects/{p}/repos"),
        json!({"name": "core", "url": "https://example.test/core.git",
               "forge": {"kind": "github", "repo": "acme/core", "token_file": "/etc/t"},
               "commands": {"test": "cargo test"}}),
    )
    .await;
    assert_eq!(core["primary"], true);
    assert_eq!(core["forge"]["api_url"], "https://api.github.com");
    assert_eq!(core["commands"]["test"], "cargo test");
    let app = ok_post(
        &fx,
        &format!("/projects/{p}/repos"),
        json!({"name": "app", "url": "https://example.test/app.git", "default_branch": "development"}),
    )
    .await;
    assert_eq!(
        (app["primary"].clone(), app["position"].clone()),
        (json!(false), json!(1))
    );
    for bad in [
        json!({"name": "local", "url": "/srv/x.git"}),
        json!({"name": "core", "url": "https://example.test/x.git"}),
        json!({"name": "x", "url": "https://u:p@h/x.git"}),
        json!({"name": "x", "url": "https://example.test/x.git", "forge": {"kind": "svn", "repo": "a", "token_file": "/t"}}),
    ] {
        let (status, body) = post(&fx, &format!("/projects/{p}/repos"), bad.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }

    let uri = format!("/repos/{}", app["id"]);
    let (status, set) = send_as(
        &fx,
        Method::PUT,
        uri.clone(),
        Some(json!({"name": "app",
        "url": "https://example.test/app2.git", "commands": {"lint": "make lint"}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(
        (set["url"].clone(), set["default_branch"].clone()),
        (json!("https://example.test/app2.git"), json!("main"))
    );

    let order = format!("/projects/{p}/repo-order");
    let (status, ordered) = send_as(
        &fx,
        Method::PUT,
        order,
        Some(json!({"repos": ["app", "core"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ordered}");
    assert_eq!(ordered[0]["name"], "app");
    let primary = ok_post(&fx, &format!("{uri}/primary"), json!({})).await;
    assert_eq!(primary[0]["primary"], true);

    let issue = format!("/issues/{}/repos", a.issue);
    assert_eq!(ok(&fx, &issue).await["repos"], json!(["app"]));
    let (status, both) = send_as(
        &fx,
        Method::PUT,
        issue.clone(),
        Some(json!({"repos": ["core", "app"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{both}");
    assert_eq!(both["repos"], json!(["app", "core"]));
    let core_uri = format!("/repos/{}", core["id"]);
    let (status, body) = send_as(&fx, Method::DELETE, core_uri.clone(), None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an open issue touches it: {body}"
    );
    send_as(&fx, Method::PUT, issue, Some(json!({"repos": []}))).await;
    let (status, left) = send_as(&fx, Method::DELETE, core_uri, None).await;
    assert_eq!(status, StatusCode::OK, "{left}");
    assert_eq!(left.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn an_issue_without_an_explicit_repo_is_flagged_only_in_a_multi_repo_project() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "IMP", ProjectMode::Kanban).await;
    let (p, uri) = (a.project, format!("/issues/{}", a.issue));
    let repos = format!("/projects/{p}/repos");
    let add = |name: &'static str| {
        ok_post(
            &fx,
            &repos,
            json!({"name": name, "url": format!("https://example.test/{name}.git")}),
        )
    };
    add("core").await;
    assert!(
        ok(&fx, &uri).await.get("repo_implicit").is_none(),
        "one repo"
    );
    add("app").await;
    assert_eq!(ok(&fx, &uri).await["repo_implicit"], true);
    let set = call(
        &fx,
        Some(&fx.dev),
        Method::PUT,
        &format!("{uri}/repos"),
        Some(json!({"repos": ["app"]})),
    )
    .await;
    assert_eq!(set.0, StatusCode::OK, "{}", set.1);
    assert!(
        ok(&fx, &uri).await.get("repo_implicit").is_none(),
        "explicit"
    );
}

// The monolith's `api/v1/tests/review.rs` (API minor 16) tests three routes that are not this
// slice's: an issue's PRs (`/issues/{id}/prs`: forge, S6), the audit log newest first within a
// company (the Core's `/audit`, which has no company scope), and a project's knowledge with a
// human's decision on a proposal (`/projects/{id}/knowledge`, `/knowledge/{id}/accept`: S5).

#[tokio::test]
#[ignore = "S6: /issues/{id}/prs reads the forge's pull requests"]
async fn an_issues_prs_are_listed_in_repo_order() {
    unimplemented!("S6: citadel_issue_prs rows listed in repo order, 404 for another company");
}

#[tokio::test]
#[ignore = "the Core's /audit has no per-company scope (company is in the details)"]
async fn the_audit_log_pages_newest_first_within_the_company() {
    unimplemented!(
        "paged by `before`, `kind` prefix, `target`, `actor`, scoped by X-Citadel-Company"
    );
}

#[tokio::test]
#[ignore = "S5: the knowledge routes (propose, accept, reject, supersede) are governance's"]
async fn knowledge_is_listed_and_a_human_decides_proposals() {
    unimplemented!("S5: list with truncated bodies, accept/reject/retire/supersede, company scope");
}
