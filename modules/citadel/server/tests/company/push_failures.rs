//! #103 against a fake GitHub whose git remote refuses a push the way GitHub refuses a token
//! without the `workflow` scope: the reason reaches the issue once, the PR request says it and is
//! held (no retry storm), a `workflow_push` approval lists the workflow files, approving lets
//! the PR open once a human has pushed the branch, and rejecting sends the reply to the agent.

use std::path::PathBuf;

use citadel_core::gov::{Approval, ApprovalKind, ApprovalStatus};
use citadel_core::work::{IssueId, ProjectMode};
use citadel_server::api::v1::ADMIN;
use citadel_server::store::forge::{PrPhase, issue_pr};
use citadel_server::store::gov::{decide_approval, list_approvals};
use citadel_server::store::work::list_comments;
use ainkrad_providers::Kind;
use ainkrad_providers::fake::{self, Hub, Shared};
use serde_json::{Value, json};

use super::stage::{Org, Stage, git};

const REFUSAL: &str = "refusing to allow a Personal Access Token to create or update workflow \
                       `.github/workflows/images.yml` without `workflow` scope";

struct Refused {
    stage: Stage,
    o: Org,
    issue: IssueId,
    origin: PathBuf,
    hub: Shared<Hub>,
}

/// A developer's run commits a workflow file and asks for its PR; the remote refuses the push.
async fn refused(name: &str, refusal: &str) -> Refused {
    let mut stage = Stage::new(name).await;
    let o = stage.org().await;
    let project = stage.project(&o, "GW", ProjectMode::Kanban).await;
    let (api, hub) = fake::github("ghp_fake_token_for_push_tests_0001").await;
    let origin = stage
        .on_forge(
            project,
            Kind::GitHub,
            &api,
            "ghp_fake_token_for_push_tests_0001",
        )
        .await;
    hub.lock().unwrap().git = Some(origin.clone());
    let hook = origin.join("hooks/pre-receive");
    std::fs::write(&hook, format!("#!/bin/sh\necho '{refusal}' >&2\nexit 1\n")).unwrap();
    std::fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let issue = stage.issue(project, "CI images", None).await;
    let n = stage
        .play(issue, &[("open_pr", json!({"title": "GW-1"}))])
        .await;
    let commit = "mkdir -p .github/workflows && echo 'on: push' > .github/workflows/images.yml \
                  && git add -A && git commit -qm CI";
    stage.script(issue, n, commit).await;
    stage.assign(issue, o.dev).await;
    stage.ended(issue, 1).await;
    Refused {
        stage,
        o,
        issue,
        origin,
        hub,
    }
}

fn posts(hub: &Shared<Hub>) -> usize {
    let hub = hub.lock().unwrap();
    hub.requests
        .iter()
        .filter(|r| *r == "POST /repos/acme/app/pulls")
        .count()
}

async fn approval(r: &Refused) -> Approval {
    let all = list_approvals(&r.stage.pool, r.o.company).await.unwrap();
    let mut held: Vec<_> = all
        .into_iter()
        .filter(|a| a.kind == ApprovalKind::WorkflowPush)
        .collect();
    assert_eq!(held.len(), 1, "one workflow_push approval");
    held.remove(0)
}

async fn said(r: &Refused, what: &str) -> usize {
    list_comments(&r.stage.pool, r.issue)
        .await
        .unwrap()
        .into_iter()
        .filter(|c| c.body.contains(what))
        .count()
}

#[tokio::test]
async fn a_workflow_refusal_is_said_once_held_and_opens_once_a_human_pushes() {
    let r = refused("push-workflow", REFUSAL).await;
    assert_eq!(said(&r, "Pushing citadel/GW-1 failed").await, 1);
    assert_eq!(said(&r, "without `workflow` scope").await, 1);
    let pr = issue_pr(&r.stage.pool, r.issue).await.unwrap().unwrap();
    assert_eq!(pr.phase, PrPhase::Requested);
    let error = pr.last_error.unwrap();
    assert!(error.starts_with("push rejected: "), "{error}");
    assert!(error.contains("workflow` scope"), "{error}");
    assert!(pr.push_held.is_some());
    let a = approval(&r).await;
    assert_eq!(a.status, ApprovalStatus::Pending);
    assert_eq!(a.issue_id, Some(r.issue));
    let p: Value = serde_json::from_str(&a.payload).unwrap();
    assert_eq!(p["files"], json!([".github/workflows/images.yml"]));
    assert_eq!(p["branch"], "citadel/GW-1");
    assert!(p["summary"].as_str().unwrap().contains("git push origin"));
    assert!(p["rejection"].as_str().unwrap().contains("workflow"));

    // Held: each poll looks for the branch (a refused open), says nothing more, wakes nobody.
    for _ in 0..3 {
        r.stage.poll().await;
    }
    assert_eq!(posts(&r.hub), 3);
    let pr = issue_pr(&r.stage.pool, r.issue).await.unwrap().unwrap();
    assert_eq!((pr.phase, pr.number), (PrPhase::Requested, None));
    assert!(pr.last_error.unwrap().starts_with("push rejected: "));
    assert_eq!(said(&r, "not pushed yet").await, 0);
    assert_eq!(said(&r, "Pushing citadel/GW-1 failed").await, 1);
    assert_eq!(r.stage.runs_on(r.issue).await, 1, "nobody was woken");
    let texts: Vec<String> = sqlx::query_scalar(
        "SELECT payload FROM run_events UNION ALL SELECT details FROM audit_events \
         UNION ALL SELECT body FROM comments UNION ALL SELECT payload FROM approvals",
    )
    .fetch_all(&r.stage.pool)
    .await
    .unwrap();
    assert!(
        !texts.iter().any(|t| t.contains("ghp_fake_token")),
        "a token leaked"
    );

    // Approved: a human pushes it (with credentials that may), and the PR opens.
    let now = r.stage.now();
    decide_approval(&r.stage.pool, a.id, true, ADMIN, None, &now)
        .await
        .unwrap();
    assert_eq!(said(&r, "Workflow push of citadel/GW-1 approved").await, 1);
    r.stage.poll().await;
    let pr = issue_pr(&r.stage.pool, r.issue).await.unwrap().unwrap();
    assert_eq!(pr.number, None, "not on the forge yet");
    std::fs::remove_file(r.origin.join("hooks/pre-receive")).unwrap();
    let tree = r
        .stage
        .dir
        .join(format!("work/worktrees/issue-{}", r.issue.0));
    let origin = r.origin.display().to_string();
    git(&tree, &["push", "-q", &origin, "citadel/GW-1:citadel/GW-1"]);
    r.stage.poll().await;
    let pr = issue_pr(&r.stage.pool, r.issue).await.unwrap().unwrap();
    assert_eq!((pr.phase, pr.number), (PrPhase::Open, Some(1)));
    assert_eq!(pr.last_error, None);
    assert_eq!(r.stage.runs_on(r.issue).await, 1, "approving woke nobody");
}

#[tokio::test]
async fn a_rejected_workflow_push_sends_the_reply_to_the_agent() {
    let r = refused("push-workflow-rejected", REFUSAL).await;
    let a = approval(&r).await;
    let now = r.stage.now();
    let reply = "Leave CI alone; drop images.yml.";
    decide_approval(&r.stage.pool, a.id, false, ADMIN, Some(reply), &now)
        .await
        .unwrap();
    assert_eq!(said(&r, reply).await, 1);
    assert_eq!(said(&r, "drop the workflow-file change").await, 1);
    let woke: Vec<String> = sqlx::query_scalar(
        "SELECT reason FROM wake_requests WHERE agent_id = ? AND source = 'approval'",
    )
    .bind(r.o.dev.0)
    .fetch_all(&r.stage.pool)
    .await
    .unwrap();
    assert!(woke.iter().any(|w| w.contains(reply)), "{woke:?}");
}

/// A refusal for good that is not about workflow files (a protected branch) holds the request
/// too, but opens no approval; one retrying may fix waits for the next run, as before.
#[tokio::test]
async fn other_refusals_hold_or_wait_without_an_approval() {
    let r = refused("push-protected", "GH006: Protected branch update failed").await;
    assert_eq!(said(&r, "Retrying will not help").await, 1);
    let pr = issue_pr(&r.stage.pool, r.issue).await.unwrap().unwrap();
    assert!(pr.push_held.is_some());
    assert!(pr.last_error.unwrap().contains("GH006"));
    let all = list_approvals(&r.stage.pool, r.o.company).await.unwrap();
    assert!(all.iter().all(|a| a.kind != ApprovalKind::WorkflowPush));

    let r = refused("push-busy", "the server is busy, try again later").await;
    let pr = issue_pr(&r.stage.pool, r.issue).await.unwrap().unwrap();
    assert_eq!(pr.push_held, None);
    assert!(pr.last_error.unwrap().contains("try again later"));
    assert_eq!(said(&r, "Pushing citadel/GW-1 failed").await, 1);
    for _ in 0..3 {
        r.stage.poll().await;
    }
    assert_eq!(
        posts(&r.hub),
        1,
        "one attempt, then it waits for the next run's push"
    );
    let pr = issue_pr(&r.stage.pool, r.issue).await.unwrap().unwrap();
    assert!(pr.last_error.unwrap().starts_with("push rejected: "));
    assert_eq!(said(&r, "not pushed yet").await, 0);
    assert_eq!(r.stage.runs_on(r.issue).await, 1, "nobody was woken");
}
