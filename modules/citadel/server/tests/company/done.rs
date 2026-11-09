//! E9.3's acceptance, the done flow (#16) on both forges with fake harnesses: the developer is
//! done → its QA agent verifies → a `pr_merge` approval → the owner approves → Citadel merges
//! with a merge commit → the issue is done. And each way back to the developer: QA fails it,
//! the owner rejects the merge, the forge refuses the merge.

use citadel_core::gov::{ApprovalKind, ApprovalStatus};
use citadel_core::work::{IssueId, IssueState, NextActor, ProjectMode};
use citadel_server::store::forge::{PrPhase, issue_pr};
use citadel_server::store::gov::{decide_approval, list_approvals};
use citadel_server::store::work::{get_issue, list_comments};
use ainkrad_providers::Kind;
use serde_json::json;

use super::forges::{forge, set_checks, set_checks_on};
use super::stage::{ADMIN, Org, Stage, git};

/// The developer's run on `issue`: commit, start, ask for the PR, done. Then the QA agent's
/// first look, before the PR is open: its pass is refused.
async fn develop(stage: &mut Stage, o: &Org, issue: IssueId) {
    let key = stage.key(issue).await;
    let n = stage
        .play(
            issue,
            &[
                ("transition", json!({"transition": "start"})),
                ("open_pr", json!({"title": format!("{key}: Feature")})),
                ("transition", json!({"transition": "done"})),
            ],
        )
        .await;
    stage
        .script(
            issue,
            n,
            "echo x > x.txt && git add -A && git commit -qm Feature",
        )
        .await;
    stage
        .play(
            issue,
            &[(
                "qa_verdict",
                json!({"verdict": "pass", "notes": "Too early"}),
            )],
        )
        .await;
    stage.assign(issue, o.dev).await;
    stage.ended(issue, n as i64).await;
    let done = &stage.replies(issue, n).await[2];
    assert_eq!(done["state"], "in_review", "{done}");
    assert_eq!(
        done["next_actor"],
        json!({"agent": o.qa.0}),
        "QA reviews, not the lead"
    );
    stage.ended(issue, n as i64 + 1).await;
    let early = &stage.replies(issue, n + 1).await[0];
    assert!(
        early["error"].as_str().unwrap().contains("not open yet"),
        "{early}"
    );
}

async fn waits_on(stage: &Stage, issue: IssueId) -> (IssueState, Option<NextActor>) {
    let i = get_issue(&stage.pool, issue).await.unwrap().unwrap();
    (i.state, i.next_actor)
}

#[tokio::test]
async fn done_qa_approve_merge_on_github() {
    done_flow(Kind::GitHub, "DG").await;
}

#[tokio::test]
async fn done_qa_approve_merge_on_gitlab() {
    done_flow(Kind::GitLab, "DL").await;
}

async fn done_flow(kind: Kind, key: &str) {
    let mut stage = Stage::new(&format!("done-{}", kind.as_str())).await;
    let o = stage.org().await;
    let project = stage.project(&o, key, ProjectMode::Kanban).await;
    let (api, hub) = forge(kind).await;
    let origin = stage.on_forge(project, kind, &api, "forge_token").await;
    hub.lock().unwrap().git = Some(origin.clone());
    let issue = stage.issue(project, "Feature", None).await;
    develop(&mut stage, &o, issue).await;

    // The PR opens with its checks running: QA is not woken, and a pass is refused.
    let sha = git(
        &origin,
        &["rev-parse", &format!("refs/heads/citadel/{key}-1")],
    );
    set_checks_on(kind, &hub, &sha, "pending");
    stage.poll().await;
    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert_eq!((pr.phase, pr.checks.as_str()), (PrPhase::Open, "pending"));
    assert_eq!(
        stage.runs_on(issue).await,
        2,
        "nobody woken while checks run"
    );
    let pass = [(
        "qa_verdict",
        json!({"verdict": "pass", "notes": "Looks right"}),
    )];
    let n = stage.play(issue, &pass).await;
    stage.wake(issue, o.qa).await;
    stage.ended(issue, n as i64).await;
    let pending = &stage.replies(issue, n).await[0];
    assert!(
        pending["error"].as_str().unwrap().contains("pending"),
        "{pending}"
    );

    // Checks pass: QA is woken and passes it; the merge waits on the owner.
    let n = stage.play(issue, &pass).await;
    set_checks(kind, &hub, "success");
    stage.poll().await;
    stage.ended(issue, n as i64).await;
    let passed = &stage.replies(issue, n).await[0];
    assert_eq!(passed["verdict"], "pass", "{passed}");
    let approval = passed["approval_id"].as_i64().unwrap();
    assert_eq!(
        waits_on(&stage, issue).await,
        (IssueState::InReview, Some(NextActor::Human(ADMIN))),
        "the owner merges"
    );
    let a = list_approvals(&stage.pool, o.company)
        .await
        .unwrap()
        .into_iter()
        .find(|a| a.id.0 == approval)
        .unwrap();
    assert_eq!(
        (a.kind, a.status),
        (ApprovalKind::PrMerge, ApprovalStatus::Pending)
    );
    assert_eq!(a.requested_by, o.qa);

    decide_approval(
        &stage.pool,
        a.id,
        true,
        ADMIN,
        Some("Ship it"),
        &stage.now(),
    )
    .await
    .unwrap();
    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert_eq!(pr.phase, PrPhase::Merging);
    assert!(
        hub.lock().unwrap().merges.is_empty(),
        "nothing merges before the poller"
    );
    stage.poll().await;
    {
        let hub = hub.lock().unwrap();
        assert_eq!(hub.merges, [(1, "merge".to_owned())]);
        // The merge commit reads `Merge <head>: <issue title>`, and the merged head branch goes.
        let title = format!("Merge citadel/{key}-1: Feature");
        assert_eq!(hub.merge_titles, [(1, title)]);
        assert_eq!(hub.deleted, [format!("citadel/{key}-1")]);
    }
    assert_eq!(waits_on(&stage, issue).await, (IssueState::Done, None));
    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert_eq!(pr.phase, PrPhase::Merged);
    let said: Vec<String> = list_comments(&stage.pool, issue)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.body)
        .collect();
    assert!(
        said.contains(&"QA passed: Looks right".to_owned()),
        "{said:?}"
    );
    assert!(said.contains(&"PR #1 merged.".to_owned()), "{said:?}");
    // The merge wakes the product owner, and nobody else, so it runs on the merge (R7a).
    stage.ended(issue, 5).await;
    let last: i64 =
        sqlx::query_scalar("SELECT agent_id FROM runs WHERE issue_id = ? ORDER BY id DESC LIMIT 1")
            .bind(issue.0)
            .fetch_one(&stage.pool)
            .await
            .unwrap();
    assert_eq!(last, o.po.0, "the merge woke the product owner");
    assert_eq!(stage.runs_on(issue).await, 5, "and only it");
}

/// QA fails it, the owner rejects the merge, the forge refuses the merge: each time the issue
/// goes back to its developer, who is woken, with the reason in a comment.
#[tokio::test]
async fn every_way_back_reaches_the_developer() {
    let mut stage = Stage::new("done-back").await;
    let o = stage.org().await;
    let project = stage.project(&o, "DB", ProjectMode::Kanban).await;
    let (api, hub) = forge(Kind::GitHub).await;
    let origin = stage
        .on_forge(project, Kind::GitHub, &api, "forge_token")
        .await;
    hub.lock().unwrap().git = Some(origin);
    let issue = stage.issue(project, "Feature", None).await;
    develop(&mut stage, &o, issue).await;
    let back = (IssueState::InProgress, Some(NextActor::Agent(o.dev)));
    let done = [("transition", json!({"transition": "done"}))];
    let pass = [("qa_verdict", json!({"verdict": "pass", "notes": "Fixed"}))];

    // The PR opens (no checks): QA is woken and fails it; the developer is done again; QA
    // passes it.
    let fail = [(
        "qa_verdict",
        json!({"verdict": "fail", "notes": "Export is empty"}),
    )];
    let n = stage.play(issue, &fail).await;
    stage.play(issue, &done).await;
    stage.play(issue, &pass).await;
    stage.poll().await;
    stage.ended(issue, n as i64 + 2).await;
    assert_eq!(stage.replies(issue, n).await[0]["verdict"], "fail");
    assert_eq!(stage.replies(issue, n + 1).await[0]["state"], "in_review");
    assert_eq!(stage.replies(issue, n + 2).await[0]["verdict"], "pass");
    let said = list_comments(&stage.pool, issue).await.unwrap();
    assert!(said.iter().any(|c| c.body == "QA failed: Export is empty"));
    let history: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE entity_kind = 'issue' AND action LIKE 'issue.%' \
         ORDER BY seq",
    )
    .fetch_all(&stage.pool)
    .await
    .unwrap();
    assert!(
        history.ends_with(&[
            "issue.in_review".to_owned(),
            "issue.in_progress".to_owned(),
            "issue.in_review".to_owned(),
            "issue.in_review".to_owned(),
        ]),
        "{history:?}"
    );

    // The owner rejects the merge: back to the developer, who is done again; QA passes again.
    let n = stage.play(issue, &done).await;
    stage.play(issue, &pass).await;
    let merges = |stage: &Stage| {
        let pool = stage.pool.clone();
        let company = o.company;
        async move {
            list_approvals(&pool, company)
                .await
                .unwrap()
                .into_iter()
                .filter(|a| a.kind == ApprovalKind::PrMerge)
                .collect::<Vec<_>>()
        }
    };
    let first = merges(&stage).await[0].id;
    let now = stage.now();
    decide_approval(
        &stage.pool,
        first,
        false,
        ADMIN,
        Some("Not this week"),
        &now,
    )
    .await
    .unwrap();
    assert_eq!(waits_on(&stage, issue).await, back);
    assert_eq!(
        issue_pr(&stage.pool, issue).await.unwrap().unwrap().phase,
        PrPhase::Open
    );
    stage.ended(issue, n as i64 + 1).await;

    // Approved this time, but the forge will not merge it: back to the developer.
    let second = merges(&stage).await;
    assert_eq!(second.len(), 2);
    assert_eq!(second[1].status, ApprovalStatus::Pending);
    hub.lock().unwrap().unmergeable.push(1);
    let now = stage.now();
    decide_approval(&stage.pool, second[1].id, true, ADMIN, None, &now)
        .await
        .unwrap();
    stage.poll().await;
    assert_eq!(waits_on(&stage, issue).await, back);
    let pr = issue_pr(&stage.pool, issue).await.unwrap().unwrap();
    assert_eq!(pr.phase, PrPhase::Open);
    assert_eq!(
        pr.last_error.as_deref(),
        Some("HTTP 405: Pull Request is not mergeable")
    );
    let said = list_comments(&stage.pool, issue).await.unwrap();
    let refused = "Merging PR #1 failed: HTTP 405: Pull Request is not mergeable";
    assert!(said.iter().any(|c| c.body == refused));
    stage.ended(issue, n as i64 + 2).await;
}

/// Without an active QA agent the team lead reviews; done without a PR is plain done.
#[tokio::test]
async fn the_lead_reviews_when_there_is_no_qa_and_no_pr_means_plain_done() {
    let mut stage = Stage::new("done-lead").await;
    let o = stage.org().await;
    let project = stage.project(&o, "DN", ProjectMode::Kanban).await;
    let (api, _hub) = forge(Kind::GitHub).await;
    stage
        .on_forge(project, Kind::GitHub, &api, "forge_token")
        .await;
    sqlx::query("UPDATE agents SET status = 'paused' WHERE id = ?")
        .bind(o.qa.0)
        .execute(&stage.pool)
        .await
        .unwrap();
    let start = ("transition", json!({"transition": "start"}));
    let done = ("transition", json!({"transition": "done"}));

    let with_pr = stage.issue(project, "With a PR", None).await;
    let open = ("open_pr", json!({"title": "DN-1"}));
    stage
        .play(with_pr, &[start.clone(), open, done.clone()])
        .await;
    stage.assign(with_pr, o.dev).await;
    stage.ended(with_pr, 1).await;
    assert_eq!(
        waits_on(&stage, with_pr).await,
        (IssueState::InReview, Some(NextActor::Agent(o.lead)))
    );

    // Something to show for it (E15.7): here a comment, as there is no PR.
    let plain = stage.issue(project, "No PR", None).await;
    let said = ("comment", json!({"body": "Checked: nothing to change."}));
    stage.play(plain, &[start, said, done]).await;
    stage.assign(plain, o.dev).await;
    stage.ended(plain, 1).await;
    assert_eq!(waits_on(&stage, plain).await, (IssueState::Done, None));
}

/// Checks the forge token cannot read (no Checks or Actions scope) neither block QA forever nor
/// pass silently: QA is woken and may pass on the commit statuses, and the merge approval the
/// owner decides says the CI checks were not read.
#[tokio::test]
async fn a_pass_on_unreadable_checks_says_so_in_the_approval() {
    let mut stage = Stage::new("done-no-checks").await;
    let o = stage.org().await;
    let project = stage.project(&o, "DN", ProjectMode::Kanban).await;
    let (api, hub) = forge(Kind::GitHub).await;
    let origin = stage
        .on_forge(project, Kind::GitHub, &api, "forge_token")
        .await;
    hub.lock().unwrap().git = Some(origin);
    hub.lock().unwrap().forbidden = vec!["check-runs", "runs"];
    let issue = stage.issue(project, "Feature", None).await;
    develop(&mut stage, &o, issue).await;
    let pass = [(
        "qa_verdict",
        json!({"verdict": "pass", "notes": "Read the diff"}),
    )];
    let n = stage.play(issue, &pass).await;
    stage.poll().await;
    stage.ended(issue, n as i64).await;
    let passed = &stage.replies(issue, n).await[0];
    let approval = passed["approval_id"].as_i64().unwrap();
    let a = list_approvals(&stage.pool, o.company)
        .await
        .unwrap()
        .into_iter()
        .find(|a| a.id.0 == approval)
        .unwrap();
    assert!(
        a.payload.contains("can't be read with this token"),
        "{}",
        a.payload
    );
}
