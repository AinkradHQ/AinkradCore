//! AIN-52: a rewritten issue branch lands over the head the server last confirmed. Run A pushes
//! the branch; run B amends its commit, which is not a fast-forward, and its push leases on A's
//! head (`--force-with-lease`) and lands. The confirmed head then moves to B's.

use citadel_core::work::ProjectMode;
use citadel_server::store::forge::pushed_head;
use ainkrad_providers::{Kind, fake};
use serde_json::json;

use super::stage::{Stage, git};

#[tokio::test]
async fn a_rewritten_branch_lands_over_the_head_the_server_confirmed() {
    let mut stage = Stage::new("lease").await;
    let o = stage.org().await;
    let project = stage.project(&o, "LS", ProjectMode::Kanban).await;
    let (api, hub) = fake::github("forge_token").await;
    let origin = stage
        .on_forge(project, Kind::GitHub, &api, "forge_token")
        .await;
    hub.lock().unwrap().git = Some(origin.clone());
    let issue = stage.issue(project, "Add the export", None).await;
    let repo: i64 =
        sqlx::query_scalar("SELECT id FROM project_repos WHERE project_id = ? AND is_primary = 1")
            .bind(project.0)
            .fetch_one(&stage.pool)
            .await
            .unwrap();
    let branch = "refs/heads/citadel/LS-1";

    let n = stage
        .play(
            issue,
            &[("open_pr", json!({"title": "LS-1: Export", "body": "b"}))],
        )
        .await;
    stage
        .script(
            issue,
            n,
            "echo one > export.txt && git add -A && git commit -qm 'Add the export'",
        )
        .await;
    stage.assign(issue, o.dev).await;
    assert_eq!(stage.ended(issue, 1).await, "succeeded");
    let first = git(&origin, &["rev-parse", branch]);
    assert_eq!(
        pushed_head(&stage.pool, issue, repo).await.unwrap(),
        Some(first.trim().to_owned())
    );

    let n = stage.play(issue, &[]).await;
    stage
        .script(
            issue,
            n,
            "echo two > export.txt && git add -A && git commit -q --amend -m 'Add the export'",
        )
        .await;
    stage.wake(issue, o.dev).await;
    assert_eq!(stage.ended(issue, 2).await, "succeeded");
    let second = git(&origin, &["rev-parse", branch]);
    assert_ne!(first, second, "the rewrite landed");
    assert_eq!(
        pushed_head(&stage.pool, issue, repo).await.unwrap(),
        Some(second.trim().to_owned())
    );
}
