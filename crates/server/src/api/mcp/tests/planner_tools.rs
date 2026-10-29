//! The planners' bulk and read tools (R8): `set_sprint_issues`, `close_sprint`, `get_issue`
//! across a requirement, and `get_artifact`.

use ainkrad_core::work::SprintApproval;
use base64::Engine;
use serde_json::json;

use super::plan::{DATES, ok, planning_team, refused};
use super::*;
use crate::store::work::{get_project, update_project};

/// A second issue in `a`'s project.
async fn sibling(pool: &SqlitePool, a: &Company, title: &str) -> IssueId {
    let project = crate::store::work::get_issue(pool, a.issue)
        .await
        .unwrap()
        .unwrap()
        .project_id;
    let i = NewIssue {
        project_id: project,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: title.to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(ainkrad_core::work::NextActor::Agent(a.agent)),
        points: Some(2),
        sprint_id: None,
    };
    create_issue(pool, &i).await.unwrap().id
}

async fn sprint(fx: &Fx, a: &Company, name: &str) -> i64 {
    let plan = json!({"name": name, "starts_on": DATES.0, "ends_on": DATES.1});
    ok(fx, a, "plan_sprint", plan).await["sprint_id"]
        .as_i64()
        .unwrap()
}

async fn sprint_of(fx: &Fx, issue: IssueId) -> Option<i64> {
    crate::store::work::get_issue(&fx.app.pool, issue)
        .await
        .unwrap()
        .unwrap()
        .sprint_id
        .map(|s| s.0)
}

#[tokio::test]
async fn set_sprint_issues_replaces_the_scope_all_or_nothing() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let both = json!({"sprint_id": 1, "issue_ids": [a.issue.0]});
    let why = refused(&fx, &a, "set_sprint_issues", both).await;
    assert!(
        why.contains("product owner") || why.contains("no sprint"),
        "{why}"
    );

    planning_team(pool, &a).await;
    let two = sibling(pool, &a, "Second").await;
    sibling(pool, &a, "Spare").await;
    let s = sprint(&fx, &a, "S1").await;
    let set = |ids: Vec<i64>| json!({"sprint_id": s, "issue_ids": ids});

    let out = ok(&fx, &a, "set_sprint_issues", set(vec![a.issue.0])).await;
    assert_eq!(
        (&out["added"], &out["removed"]),
        (&json!([a.issue.0]), &json!([]))
    );
    let out = ok(&fx, &a, "set_sprint_issues", set(vec![two.0])).await;
    assert_eq!(
        (&out["added"], &out["removed"]),
        (&json!([two.0]), &json!([a.issue.0]))
    );
    assert_eq!(sprint_of(&fx, a.issue).await, None);
    assert_eq!(sprint_of(&fx, two).await, Some(s));

    // One bad id: nothing moves.
    let why = refused(&fx, &a, "set_sprint_issues", set(vec![a.issue.0, 9999])).await;
    assert!(why.contains("no issue 9999"), "{why}");
    assert_eq!(sprint_of(&fx, a.issue).await, None);
    let out = ok(&fx, &a, "set_sprint_issues", set(vec![])).await;
    assert_eq!(out["removed"], json!([two.0]));
}

#[tokio::test]
async fn the_product_owner_closes_a_sprint_and_carries_its_open_issues() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let (project, _, _) = planning_team(pool, &a).await;
    let mut p = get_project(pool, project).await.unwrap().unwrap();
    p.sprint_approval = SprintApproval::ProductOwner;
    assert!(update_project(pool, &p).await.unwrap());
    sibling(pool, &a, "x").await;
    let (s1, s2) = (sprint(&fx, &a, "S1").await, sprint(&fx, &a, "S2").await);
    let add = json!({"sprint_id": s1, "issue_id": a.issue.0});
    ok(
        &fx,
        &a,
        "estimate_issue",
        json!({"issue_id": a.issue.0, "points": 2}),
    )
    .await;
    ok(&fx, &a, "sprint_add_issue", add).await;

    let close = json!({"sprint_id": s1, "carry_to_sprint_id": s2});
    let why = refused(&fx, &a, "close_sprint", close.clone()).await;
    assert!(
        why.contains("planned"),
        "only an active sprint closes: {why}"
    );
    ok(&fx, &a, "commit_sprint", json!({"sprint_id": s1})).await;
    let why = refused(
        &fx,
        &a,
        "set_sprint_issues",
        json!({"sprint_id": s1, "issue_ids": []}),
    )
    .await;
    assert!(why.contains("active"), "{why}");

    let out = ok(&fx, &a, "close_sprint", close.clone()).await;
    assert_eq!(
        (out["state"].as_str(), out["carried_to_sprint_id"].as_i64()),
        (Some("closed"), Some(s2))
    );
    assert_eq!(sprint_of(&fx, a.issue).await, Some(s2));

    // A planner who is not the team's product owner (here the CTO) may not close.
    sqlx::query("DELETE FROM team_memberships WHERE agent_id = ?")
        .bind(a.agent.0)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE agents SET org_role = 'cto' WHERE id = ?")
        .bind(a.agent.0)
        .execute(pool)
        .await
        .unwrap();
    let why = refused(&fx, &a, "close_sprint", close).await;
    assert!(why.contains("product owner"), "{why}");
}

/// `a`'s issue and a sibling on requirement 7, and a third issue on none.
async fn on_requirement(fx: &Fx, a: &Company) -> (IssueId, IssueId) {
    let pool = &fx.app.pool;
    sqlx::query(
        "INSERT INTO requirements (id, company_id, number, title, requested_by_user_id) \
         VALUES (7, ?, 3, 'Alerts', 1)",
    )
    .bind(a.company.0)
    .execute(pool)
    .await
    .unwrap();
    let (mate, other) = (
        sibling(pool, a, "Mate").await,
        sibling(pool, a, "Other").await,
    );
    for id in [a.issue, mate] {
        sqlx::query("UPDATE issues SET requirement_id = 7 WHERE id = ?")
            .bind(id.0)
            .execute(pool)
            .await
            .unwrap();
    }
    (mate, other)
}

#[tokio::test]
async fn get_issue_reads_any_issue_of_the_requirement_and_no_other() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let b = company(pool, "B", "BBB").await;
    let (mate, other) = on_requirement(&fx, &a).await;

    let got = ok(&fx, &a, "get_issue", json!({"issue_id": mate.0})).await;
    assert_eq!(got["title"], "Mate");
    let why = refused(&fx, &a, "get_issue", json!({"issue_id": other.0})).await;
    assert!(why.contains("not this run's issue"), "{why}");
    let why = refused(&fx, &b, "get_issue", json!({"issue_id": mate.0})).await;
    assert!(why.contains("not this run's issue"), "{why}");
}

#[tokio::test]
async fn get_artifact_reads_what_the_requirement_published_and_nothing_else() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let b = company(pool, "B", "BBB").await;
    on_requirement(&fx, &a).await;
    let b64 = |s: &[u8]| base64::engine::general_purpose::STANDARD.encode(s);
    let publish = |c: &'static str, body: &'static [u8]| json!({"name": c, "content": b64(body)});
    let mine = ok(
        &fx,
        &a,
        "publish_artifact",
        publish("audit.md", b"# Audit\n40 gaps"),
    )
    .await;
    let theirs = ok(&fx, &b, "publish_artifact", publish("b.md", b"secret")).await;
    let id = mine["artifact_id"].as_i64().unwrap();

    let got = ok(&fx, &a, "get_artifact", json!({"artifact_id": id})).await;
    assert_eq!(
        (got["name"].as_str(), got["content"].as_str()),
        (Some("audit.md"), Some("# Audit\n40 gaps"))
    );
    assert_eq!(got["truncated"], false);
    let list = ok(&fx, &a, "get_artifact", json!({})).await;
    assert_eq!(list["artifacts"][0]["artifact_id"], id);
    assert!(list["artifacts"][0].get("content").is_none());

    let other = json!({"artifact_id": theirs["artifact_id"]});
    let why = refused(&fx, &a, "get_artifact", other).await;
    assert!(why.contains("no artifact"), "{why}");
    let why = refused(&fx, &b, "get_artifact", json!({"artifact_id": id})).await;
    assert!(why.contains("no artifact"), "{why}");
}
