//! The done flow on two repos (E9.3, E15.16, decisions #53 and #54): QA passes an issue whose PRs
//! are open, one approval covers every head, the approved PRs merge one at a time in repo order
//! and the issue is done once all are; a moved head on any of them stops the whole approval; a
//! merge that fails after another merged re-opens an approval for the rest.

mod common;
mod forge_seed;
mod gov_seed;

use axum::http::{Method, StatusCode};
use citadel_module::domain::org::{AgentId, AgentStatus, Harness, NewAgent, OrgRole};
use citadel_module::domain::work::{
    IssueId, IssueKind, IssueState, IssueTransition, NewIssue, NextActor,
};
use citadel_module::store::forge::{PrPhase, issue_prs, qa_verdict, request_pr, submit_for_qa};
use citadel_module::store::org::create_agent;
use citadel_module::store::work::{create_issue, get_issue, set_issue_repos, transition_issue};
use forge_seed::*;
use serde_json::{Value, json};

struct Two {
    r: Rig,
    qa: AgentId,
    issue: IssueId,
}

/// An issue in review on a QA agent, touching repos `app` and `lib`, with both PRs open.
async fn two_open_prs() -> Two {
    let r = rig().await;
    add_forge_repo(&r.fx, r.s.project, ("lib", "acme/lib"), &r.api, SECRET).await;
    let qa = NewAgent {
        company_id: r.s.company,
        name: "QA".to_owned(),
        role: "QA".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Claude,
        model: "claude-opus".to_owned(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    let qa = create_agent(r.pool(), &qa).await.unwrap().id;
    let new = NewIssue {
        project_id: r.s.project,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Two repos".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Agent(r.s.agent)),
        points: None,
        sprint_id: None,
    };
    let issue = create_issue(r.pool(), &new).await.unwrap().id;
    transition_issue(
        r.pool(),
        issue,
        &IssueTransition::Start,
        ainkrad_core_server::api::v1::BY,
    )
    .await
    .unwrap();
    let names = ["app".to_owned(), "lib".to_owned()];
    set_issue_repos(r.pool(), issue, &names, ainkrad_core_server::api::v1::BY)
        .await
        .unwrap();
    for name in ["app", "lib"] {
        let pr = request_pr(r.pool(), issue, Some(name), r.s.agent, ("Two repos", "b"))
            .await
            .unwrap();
        let by = citadel_module::store::forge::PushReporter {
            issue,
            agent: r.s.agent,
            run: None,
        };
        let payload =
            json!({"type": "branch_pushed", "repo": name, "branch": pr.head, "sha": "dddd"});
        citadel_module::store::forge::push_reported(r.pool(), by, &payload, NOW)
            .await
            .unwrap();
    }
    citadel_module::forge::forge_sync(&r.rt).await.unwrap();
    // The developer is done: in review, waiting on the admin; the admin hands it to QA.
    let moved = submit_for_qa(r.pool(), issue, r.s.agent)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(moved.state, IssueState::InReview);
    let to_qa = IssueTransition::Reassign {
        next: NextActor::Agent(qa),
    };
    transition_issue(r.pool(), issue, &to_qa, ainkrad_core_server::api::v1::BY)
        .await
        .unwrap();
    Two { r, qa, issue }
}

async fn decide(r: &Rig, id: i64) {
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
}

async fn phases(t: &Two) -> Vec<(i64, PrPhase)> {
    issue_prs(t.r.pool(), t.issue)
        .await
        .unwrap()
        .into_iter()
        .map(|p| (p.repo_id, p.phase))
        .collect()
}

#[tokio::test]
async fn one_approval_covers_every_head_and_the_prs_merge_in_repo_order() {
    let t = two_open_prs().await;
    let all = phases(&t).await;
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|(_, p)| *p == PrPhase::Open), "{all:?}");
    let approval = qa_verdict(t.r.pool(), t.issue, t.qa, true, "looks right", NOW)
        .await
        .unwrap()
        .unwrap();
    let payload: Value = serde_json::from_str(&approval.payload).unwrap();
    let heads: Vec<_> = payload["prs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["head_sha"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        heads.len(),
        2,
        "every PR's head is in the approval: {payload}"
    );
    assert!(payload["prs"][0]["repo_id"].is_i64());
    decide(&t.r, approval.id.0).await;
    assert!(phases(&t).await.iter().all(|(_, p)| *p == PrPhase::Merging));
    t.r.sync().await;
    assert!(phases(&t).await.iter().all(|(_, p)| *p == PrPhase::Merged));
    let hub = t.r.hub.lock().unwrap();
    assert_eq!(
        hub.merges.iter().map(|m| m.0).collect::<Vec<_>>(),
        [1, 2],
        "repo order"
    );
    drop(hub);
    let i = get_issue(t.r.pool(), t.issue).await.unwrap().unwrap();
    assert_eq!(i.state, IssueState::Done, "done once every PR is merged");
}

#[tokio::test]
async fn one_moved_head_stops_the_whole_approval() {
    let t = two_open_prs().await;
    let approval = qa_verdict(t.r.pool(), t.issue, t.qa, true, "ok", NOW)
        .await
        .unwrap()
        .unwrap();
    // The second PR's branch moved after QA saw it (the poller has recorded the new head).
    sqlx::query("UPDATE citadel_issue_prs SET head_sha = 'moved' WHERE repo_id = (SELECT max(id) FROM citadel_project_repos)")
        .execute(t.r.pool())
        .await
        .unwrap();
    decide(&t.r, approval.id.0).await;
    assert!(
        phases(&t).await.iter().all(|(_, p)| *p == PrPhase::Open),
        "neither merges"
    );
    let stale = audited(t.r.pool(), "issue.pr_merge_stale").await;
    assert_eq!(stale.len(), 1);
    assert!(t.r.hub.lock().unwrap().merges.is_empty());
}

#[tokio::test]
async fn a_failed_second_merge_leaves_the_first_merged_and_asks_again_for_the_rest() {
    let t = two_open_prs().await;
    let approval = qa_verdict(t.r.pool(), t.issue, t.qa, true, "ok", NOW)
        .await
        .unwrap()
        .unwrap();
    decide(&t.r, approval.id.0).await;
    t.r.hub.lock().unwrap().unmergeable.push(2);
    t.r.sync().await;
    let all = phases(&t).await;
    assert_eq!(all[0].1, PrPhase::Merged);
    assert_eq!(all[1].1, PrPhase::Open, "the one that failed is open again");
    let again: (i64, String) = sqlx::query_as(
        "SELECT id, payload FROM citadel_approvals WHERE kind = 'pr_merge' AND status = 'pending'",
    )
    .fetch_one(t.r.pool())
    .await
    .unwrap();
    let payload: Value = serde_json::from_str(&again.1).unwrap();
    assert_eq!(payload["reopened_from"], approval.id.0);
    assert_eq!(
        payload["prs"].as_array().unwrap().len(),
        1,
        "only what is left: {payload}"
    );
    let i = get_issue(t.r.pool(), t.issue).await.unwrap().unwrap();
    assert_eq!(i.state, IssueState::InReview, "stays in review");
    // The new approval is for the head the poller saw, and merges once the forge allows it.
    t.r.hub.lock().unwrap().unmergeable.clear();
    decide(&t.r, again.0).await;
    t.r.sync().await;
    assert!(phases(&t).await.iter().all(|(_, p)| *p == PrPhase::Merged));
    let i = get_issue(t.r.pool(), t.issue).await.unwrap().unwrap();
    assert_eq!(i.state, IssueState::Done);
}
