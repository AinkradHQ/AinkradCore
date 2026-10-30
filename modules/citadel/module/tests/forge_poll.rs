//! E9.1-E9.3 against a fake GitHub: a requested PR opens once its branch is pushed, its checks
//! come back to the issue, an approved merge happens at the head the approver saw (a moved head
//! is refused by the forge and the PR stays open), a PR with no head merges nothing, and the
//! poller runs as the scheduler's job.

mod common;
mod forge_seed;
mod gov_seed;

use axum::http::{Method, StatusCode};
use citadel_module::domain::gov::{ApprovalKind, NewApproval};
use citadel_module::store::forge::PrPhase;
use citadel_module::store::gov::open_approval;
use forge_seed::*;
use serde_json::{Value, json};

async fn approve_merge(r: &Rig, payload: Value) -> i64 {
    let n = NewApproval {
        company_id: r.s.company,
        kind: ApprovalKind::PrMerge,
        issue_id: Some(r.s.issue),
        sprint_id: None,
        agent_id: None,
        requested_by: r.s.agent,
        payload: payload.to_string(),
    };
    let id = open_approval(r.pool(), &n, NOW).await.unwrap().id.0;
    let uri = format!("/approvals/{id}/decide-forge");
    let res = call(
        &r.fx,
        Some(&r.fx.dev),
        Method::POST,
        &uri,
        Some(json!({"approve": true})),
    )
    .await;
    assert_eq!(res.0, StatusCode::OK, "{res:?}");
    id
}

async fn comments(r: &Rig) -> Vec<String> {
    sqlx::query_scalar("SELECT body FROM citadel_comments ORDER BY id")
        .fetch_all(r.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn a_pushed_request_opens_follows_its_checks_and_merges_at_the_approved_head() {
    let r = rig().await;
    // Nothing is due before the branch is reported pushed.
    let asked = citadel_module::store::forge::request_pr(
        r.pool(),
        r.s.issue,
        None,
        r.s.agent,
        ("Ship it", "Body"),
    )
    .await
    .unwrap();
    r.sync().await;
    assert!(
        r.hub.lock().unwrap().requests.is_empty(),
        "no call before the push"
    );
    r.pushed(&asked.head, "aaaa1111").await;
    r.sync().await;
    let pr = r.pr().await;
    assert_eq!((pr.phase, pr.number), (PrPhase::Open, Some(1)));
    let head = r.hub.lock().unwrap().prs[&1].head_sha.clone();
    assert_eq!(pr.head_sha.as_deref(), Some(head.as_str()));
    assert!(
        comments(&r)
            .await
            .iter()
            .any(|c| c.starts_with("PR #1 opened"))
    );
    // The token reached the forge only as the bearer it wants (the fake refuses any other).
    assert!(
        r.hub
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|q| q.starts_with("POST /repos/acme/core/pulls"))
    );

    // Checks: a failure and then a pass are commented once each.
    r.hub
        .lock()
        .unwrap()
        .checks(1, &[("build", "completed", Some("failure"))]);
    r.sync().await;
    assert_eq!(r.pr().await.checks, "failure");
    r.hub
        .lock()
        .unwrap()
        .checks(1, &[("build", "completed", Some("success"))]);
    r.sync().await;
    r.sync().await;
    assert_eq!(r.pr().await.checks, "success");
    let said = comments(&r).await;
    assert_eq!(
        said.iter().filter(|c| c.contains("checks failed")).count(),
        1,
        "{said:?}"
    );
    assert_eq!(
        said.iter().filter(|c| c.contains("checks passed")).count(),
        1,
        "{said:?}"
    );

    // Approved at this head: it merges with a merge commit, and its branch goes.
    approve_merge(&r, json!({"pr": 1, "repo_id": r.repo, "head_sha": head})).await;
    assert_eq!(r.pr().await.phase, PrPhase::Merging);
    r.sync().await;
    assert_eq!(r.pr().await.phase, PrPhase::Merged);
    let hub = r.hub.lock().unwrap();
    assert_eq!(hub.merges, [(1, "merge".to_owned())]);
    assert!(
        hub.merge_titles[0].1.starts_with("Merge "),
        "{:?}",
        hub.merge_titles
    );
    assert_eq!(hub.deleted, [asked.head.clone()]);
}

#[tokio::test]
async fn a_head_that_moved_after_the_approval_is_never_merged() {
    let r = rig().await;
    r.requested("aaaa1111").await;
    r.sync().await;
    let approved = r.hub.lock().unwrap().prs[&1].head_sha.clone();
    approve_merge(
        &r,
        json!({"pr": 1, "repo_id": r.repo, "head_sha": approved}),
    )
    .await;
    // The branch moves on the forge between the approval and the poller's merge.
    r.hub.lock().unwrap().prs.get_mut(&1).unwrap().head_sha = "bbbb2222".to_owned();
    r.sync().await;
    let hub = r.hub.lock().unwrap();
    assert!(
        hub.merges.is_empty(),
        "the forge refused the moved head: {:?}",
        hub.merges
    );
    drop(hub);
    let pr = r.pr().await;
    assert_eq!(pr.phase, PrPhase::Open, "back to open for a new look");
    assert!(pr.last_error.unwrap().contains("409"), "the forge said so");
}

#[tokio::test]
async fn an_approved_pr_with_no_recorded_head_merges_nothing() {
    let r = rig().await;
    r.requested("aaaa1111").await;
    r.sync().await;
    sqlx::query("UPDATE citadel_issue_prs SET state = 'merging', head_sha = NULL")
        .execute(r.pool())
        .await
        .unwrap();
    let before = r.hub.lock().unwrap().requests.len();
    r.sync().await;
    assert_eq!(r.hub.lock().unwrap().merges.len(), 0);
    assert_eq!(
        r.hub.lock().unwrap().requests.len(),
        before,
        "not even a merge call"
    );
    let pr = r.pr().await;
    assert_eq!(pr.phase, PrPhase::Open);
    assert!(pr.last_error.unwrap().contains("no head"));
}

#[tokio::test]
async fn a_workflow_push_refusal_waits_for_a_human_and_then_the_pr_opens() {
    let r = rig().await;
    let asked = citadel_module::store::forge::request_pr(
        r.pool(),
        r.s.issue,
        None,
        r.s.agent,
        ("Ship it", "Body"),
    )
    .await
    .unwrap();
    let by = citadel_module::store::forge::PushReporter {
        issue: r.s.issue,
        agent: r.s.agent,
        run: Some(1),
    };
    let refused = json!({"type": "push_failed", "repo": "app", "branch": asked.head,
        "sha": "cccc3333", "workflow_files": [".github/workflows/ci.yml"],
        "reason": "refusing to allow a Personal Access Token to create or update workflow without `workflow` scope"});
    citadel_module::store::forge::push_reported(r.pool(), by, &refused, NOW)
        .await
        .unwrap();
    let held = r.pr().await;
    assert_eq!(
        held.push_held.as_deref(),
        Some("cccc3333"),
        "held under the head"
    );
    let approval: (i64, String) = sqlx::query_as(
        "SELECT id, payload FROM citadel_approvals WHERE kind = 'workflow_push' AND status = 'pending'",
    )
    .fetch_one(r.pool())
    .await
    .unwrap();
    let payload: Value = serde_json::from_str(&approval.1).unwrap();
    assert_eq!(payload["head_sha"], "cccc3333");
    // Held and unpushed: the open is tried quietly each pass (the fake has no such branch only
    // when a repo is attached; here it opens), so release it through the step-up decision.
    let uri = format!("/approvals/{}/decide-forge", approval.0);
    let res = call(
        &r.fx,
        Some(&r.fx.dev),
        Method::POST,
        &uri,
        Some(json!({"approve": true})),
    )
    .await;
    assert_eq!(res.0, StatusCode::OK, "{res:?}");
    assert_eq!(
        r.pr().await.push_held,
        None,
        "the approved head released the hold"
    );
    r.sync().await;
    assert_eq!(r.pr().await.phase, PrPhase::Open);
}

#[tokio::test]
async fn the_poller_runs_as_the_schedulers_job_and_a_failed_pass_stores_no_secret() {
    use ainkrad_core_server::jobs::Run;
    use ainkrad_core_server::module::Module;
    let r = rig().await;
    let citadel = citadel_module::Citadel::with_forge(r.rt.clone());
    let jobs = citadel.jobs();
    let names: Vec<_> = jobs.iter().map(|j| j.name).collect();
    assert_eq!(names, ["forge_poll", "linear_sync"]);
    assert!(
        citadel_module::Citadel::default().jobs().is_empty(),
        "no runtime, no jobs"
    );
    r.requested("aaaa1111").await;
    let run = Run {
        owner: "citadel".into(),
        job: "forge_poll".into(),
        id: 1,
        key: "k".into(),
        attempt: 1,
        due_at: NOW.into(),
        payload: json!({}),
    };
    jobs[0].handler.run(&run).await.unwrap();
    assert_eq!(r.pr().await.phase, PrPhase::Open);
    let used: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'secret.used'")
            .fetch_one(r.pool())
            .await
            .unwrap();
    assert_eq!(
        used, 1,
        "the credential was opened once for the pass, and audited"
    );
}
