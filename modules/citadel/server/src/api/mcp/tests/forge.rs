//! `open_pr`: only on a project with a repo on a forge; a waiting request takes the new title;
//! `get_issue` shows the PR.

use std::path::PathBuf;

use citadel_core::audit::AuditActor;
use citadel_core::work::{ProjectRepo, UserId};
use ainkrad_providers::Kind;
use serde_json::json;

use super::plan::{ok, refused};
use super::*;
use crate::store::forge::{ProjectForge, set_project_forge};
use crate::store::work::{get_issue, set_project_repo};

#[tokio::test]
async fn open_pr_needs_a_forge_and_shows_on_the_issue() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let project = get_issue(pool, a.issue).await.unwrap().unwrap().project_id;
    let pr = json!({"title": "AAA-1: Do the thing"});
    let why = refused(&fx, &a, "open_pr", pr.clone()).await;
    assert!(why.contains("no repo on a forge"), "{why}");

    let repo = ProjectRepo {
        project_id: project,
        url: "https://example.test/git/a.git".to_owned(),
        default_branch: "develop".to_owned(),
    };
    set_project_repo(pool, &repo).await.unwrap();
    let why = refused(&fx, &a, "open_pr", pr.clone()).await;
    assert!(
        why.contains("no repo on a forge"),
        "a repo alone is not a forge: {why}"
    );
    let mut forge = ProjectForge {
        project_id: project,
        kind: Kind::GitHub,
        api_url: "https://api.github.com".to_owned(),
        repo: "acme/a".to_owned(),
        token_file: PathBuf::from("relative/token"),
    };
    let by = AuditActor::User(UserId(1));
    assert!(
        set_project_forge(pool, &forge, by).await.is_err(),
        "relative token path"
    );
    forge.token_file = PathBuf::from("/etc/citadel/github-token");
    for bad in ["../x", "/abs", "a b"] {
        let f = ProjectForge {
            repo: bad.to_owned(),
            ..forge.clone()
        };
        assert!(set_project_forge(pool, &f, by).await.is_err(), "{bad}");
    }
    assert!(set_project_forge(pool, &forge, by).await.unwrap());

    let asked = ok(&fx, &a, "open_pr", pr).await;
    assert_eq!(asked["state"], "requested");
    assert_eq!(
        (asked["head"].as_str(), asked["base"].as_str()),
        (Some("citadel/AAA-1"), Some("develop"))
    );
    ok(
        &fx,
        &a,
        "open_pr",
        json!({"title": "AAA-1: Better title", "body": "Why."}),
    )
    .await;
    let issue = ok(&fx, &a, "get_issue", json!({})).await;
    assert_eq!(issue["pr"]["state"], "requested");
    let title: String = sqlx::query_scalar("SELECT title FROM issue_prs")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(title, "AAA-1: Better title");
}
