//! AIN-46: a PR requested by a run opens once that run's branch push is confirmed (`branch_pushed`),
//! even while a later run on the same issue is live. Against a fake GitHub: run A asks for the PR
//! and pushes its branch; run B is queued on the issue before the poller's pass; the PR still
//! opens on that pass.

use ainkrad_core::work::ProjectMode;
use ainkrad_core_server::store::exec::tick;
use ainkrad_core_server::store::forge::{PrPhase, issue_pr};
use ainkrad_providers::{Kind, fake};
use serde_json::json;

use super::stage::{Stage, git};

#[tokio::test]
async fn a_confirmed_push_opens_the_pr_while_a_later_run_is_live() {
    let mut stage = Stage::new("push-confirmed").await;
    let o = stage.org().await;
    let project = stage.project(&o, "PC", ProjectMode::Kanban).await;
    let (api, hub) = fake::github("forge_token").await;
    let origin = stage
        .on_forge(project, Kind::GitHub, &api, "forge_token")
        .await;
    hub.lock().unwrap().git = Some(origin.clone());

    let issue = stage.issue(project, "Add the export", None).await;
    let n = stage
        .play(
            issue,
            &[(
                "open_pr",
                json!({"title": "PC-1: Add the export", "body": "Adds export."}),
            )],
        )
        .await;
    let commit = "echo export > export.txt && git add -A && git commit -qm 'Add the export'";
    stage.script(issue, n, commit).await;
    stage.assign(issue, o.dev).await;
    assert_eq!(stage.ended(issue, 1).await, "succeeded");

    // Run A's push is confirmed; run B is queued on the issue before the poller's pass.
    let branch = "citadel/PC-1";
    let pushed = git(&origin, &["rev-parse", &format!("refs/heads/{branch}")]);
    stage.wake(issue, o.dev).await;
    tick(&stage.pool, &stage.now()).await.unwrap();
    let live: Vec<String> = sqlx::query_scalar(
        "SELECT state FROM runs WHERE issue_id = ? AND state IN ('queued', 'claimed', 'running')",
    )
    .bind(issue.0)
    .fetch_all(&stage.pool)
    .await
    .unwrap();
    assert_eq!(live.len(), 1, "run B is live on the issue: {live:?}");
    stage.poll().await;

    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert_eq!((pr.phase, pr.number), (PrPhase::Open, Some(1)));
    assert_eq!(pr.head_sha.as_deref(), Some(pushed.as_str()));
}
