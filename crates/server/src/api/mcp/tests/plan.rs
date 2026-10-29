//! The planning tools: only a project's planners use them, never across companies, and each
//! change goes through the store's rules and audit as the run's agent.

use ainkrad_core::org::{OrgRole, TeamId, TeamMembership, TeamRole};
use ainkrad_core::work::{ProjectId, ProjectMode};
use serde_json::json;

use super::super::tools::call;
use super::*;
use crate::store::org::{create_department, create_membership, create_team};
use crate::store::work::{get_issue, get_project, update_project};

fn args(v: Value) -> rmcp::model::JsonObject {
    v.as_object().unwrap().clone()
}

pub(super) async fn ok(fx: &Fx, c: &Company, tool: &str, a: Value) -> Value {
    call(&fx.app, c.scope(), &Default::default(), tool, &args(a))
        .await
        .unwrap_or_else(|e| panic!("{tool}: {e}"))
}

pub(super) async fn refused(fx: &Fx, c: &Company, tool: &str, a: Value) -> String {
    match call(&fx.app, c.scope(), &Default::default(), tool, &args(a)).await {
        Ok(v) => panic!("{tool} was not refused: {v}"),
        Err(e) => e.to_string(),
    }
}

/// Turns `c`'s project scrum, owned by a team with `c`'s agent as product owner and a
/// developer agent as member; returns the project, team and developer.
pub(super) async fn planning_team(pool: &SqlitePool, c: &Company) -> (ProjectId, TeamId, AgentId) {
    let mut p = get_project(
        pool,
        get_issue(pool, c.issue).await.unwrap().unwrap().project_id,
    )
    .await
    .unwrap()
    .unwrap();
    let dept = create_department(pool, c.company, "Eng").await.unwrap();
    let team = create_team(pool, dept.id, "Core").await.unwrap();
    p.team_id = Some(team.id);
    p.mode = ProjectMode::Scrum;
    assert!(update_project(pool, &p).await.unwrap());
    let member = |agent_id, team_role| TeamMembership {
        team_id: team.id,
        agent_id,
        team_role,
    };
    create_membership(pool, &member(c.agent, TeamRole::ProductOwner))
        .await
        .unwrap();
    let dev = NewAgent {
        company_id: c.company,
        name: "Dev".to_owned(),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Opencode,
        model: String::new(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    let dev = create_agent(pool, &dev).await.unwrap().id;
    create_membership(pool, &member(dev, TeamRole::Member))
        .await
        .unwrap();
    (p.id, team.id, dev)
}

pub(super) const DATES: (&str, &str) = ("2026-10-21", "2026-11-03");

#[tokio::test]
async fn planners_plan_estimate_assign_and_report() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let b = company(pool, "B", "BBB").await;
    let plan = json!({"name": "S1", "goal": "Ship", "starts_on": DATES.0, "ends_on": DATES.1});
    let why = refused(&fx, &a, "plan_sprint", plan.clone()).await;
    assert!(why.contains("product owner"), "{why}");

    let (project, _, dev) = planning_team(pool, &a).await;
    let s = ok(&fx, &a, "plan_sprint", plan.clone()).await;
    assert_eq!(
        (s["state"].as_str(), s["project_id"].as_i64()),
        (Some("planned"), Some(project.0))
    );
    let sprint = s["sprint_id"].as_i64().unwrap();
    let bad = refused(
        &fx,
        &a,
        "plan_sprint",
        json!({"name": "x", "starts_on": "soon",
                                                   "ends_on": DATES.1}),
    )
    .await;
    assert!(bad.contains("bad sprint dates"), "{bad}");

    let e = ok(
        &fx,
        &a,
        "estimate_issue",
        json!({"issue_id": a.issue.0, "points": 3}),
    )
    .await;
    assert_eq!(e["points"], 3);
    let bad = refused(
        &fx,
        &a,
        "estimate_issue",
        json!({"issue_id": a.issue.0, "points": -1}),
    );
    assert!(bad.await.contains("points"));
    let added = json!({"sprint_id": sprint, "issue_id": a.issue.0});
    assert_eq!(
        ok(&fx, &a, "sprint_add_issue", added).await["sprint_id"],
        sprint
    );

    // Only a member agent of the project's team is assigned; it is woken.
    let assign = |agent: AgentId| json!({"issue_id": a.issue.0, "agent_id": agent.0});
    let why = refused(&fx, &a, "assign_issue", assign(b.agent)).await;
    assert!(why.contains("not on the project's team"), "{why}");
    let moved = ok(&fx, &a, "assign_issue", assign(dev)).await;
    assert_eq!(moved["next_actor"], json!({"agent": dev.0}));
    let woken: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM wake_requests WHERE agent_id = ? AND issue_id = ?",
    )
    .bind(dev.0)
    .bind(a.issue.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(woken, 1);

    let r = ok(&fx, &a, "sprint_report", json!({"sprint_id": sprint})).await;
    assert_eq!(
        (r["state"].as_str(), r["name"].as_str()),
        (Some("planned"), Some("S1"))
    );
    assert!(r["committed"].is_null());
    let out = ok(
        &fx,
        &a,
        "sprint_remove_issue",
        json!({"issue_id": a.issue.0}),
    )
    .await;
    assert!(out["sprint_id"].is_null());

    // B's CTO plans B, never A: A's sprint and issue look like none.
    let mut cto = crate::store::org::get_agent(pool, b.agent)
        .await
        .unwrap()
        .unwrap();
    cto.org_role = OrgRole::Cto;
    assert!(crate::store::org::update_agent(pool, &cto).await.unwrap());
    let why = refused(&fx, &b, "sprint_report", json!({"sprint_id": sprint})).await;
    assert!(why.contains("no sprint"), "{why}");
    let why = refused(&fx, &b, "estimate_issue", json!({"issue_id": a.issue.0})).await;
    assert!(why.contains("no issue"), "{why}");
    let why = refused(
        &fx,
        &b,
        "plan_sprint",
        json!({"project_id": project.0, "name": "x",
                                                     "starts_on": DATES.0, "ends_on": DATES.1}),
    );
    assert!(why.await.contains("no project"));

    // Every change is audited as A's agent.
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE actor_kind = 'agent' AND actor_id = ? \
         AND action NOT LIKE 'mcp.%' ORDER BY seq",
    )
    .bind(a.agent.0)
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "sprint.planned",
            "issue.estimated",
            "issue.sprint_set",
            "issue.todo",
            "issue.sprint_set"
        ]
    );
}

/// The product owner reads the project spec, commits over MCP, and the sprint waits on the
/// owner's approval; over capacity it must say why.
#[tokio::test]
async fn the_product_owner_commits_from_the_spec_through_the_gate() {
    use crate::store::gov::decide_approval;
    use crate::store::work::{get_sprint, set_member_capacity, set_project_spec};
    use ainkrad_core::audit::AuditActor;
    use ainkrad_core::work::{SprintId, SprintState, UserId};

    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let (project, team, dev) = planning_team(pool, &a).await;
    let spec = "Build the login page, then the dashboard.";
    let admin = AuditActor::User(UserId(1));
    assert!(set_project_spec(pool, project, spec, admin).await.unwrap());
    let ctx = ok(&fx, &a, "get_context", json!({})).await;
    assert_eq!(ctx["project"]["spec"], spec);
    assert_eq!(ctx["project"]["sprint_approval"], "owner");

    let plan = json!({"name": "S1", "starts_on": DATES.0, "ends_on": DATES.1});
    let sprint = ok(&fx, &a, "plan_sprint", plan).await["sprint_id"]
        .as_i64()
        .unwrap();
    ok(
        &fx,
        &a,
        "estimate_issue",
        json!({"issue_id": a.issue.0, "points": 8}),
    )
    .await;
    ok(
        &fx,
        &a,
        "sprint_add_issue",
        json!({"sprint_id": sprint, "issue_id": a.issue.0}),
    )
    .await;
    assert!(set_member_capacity(pool, team, dev, Some(5)).await.unwrap());
    let why = refused(&fx, &a, "commit_sprint", json!({"sprint_id": sprint})).await;
    assert!(why.contains("override_reason"), "{why}");

    let commit = json!({"sprint_id": sprint, "override_reason": "one big story"});
    let done = ok(&fx, &a, "commit_sprint", commit).await;
    assert_eq!(done["status"], "pending_approval");
    let approval = ainkrad_core::gov::ApprovalId(done["approval_id"].as_i64().unwrap());
    let s = get_sprint(pool, SprintId(sprint)).await.unwrap().unwrap();
    assert_eq!(s.state, SprintState::Planned, "no start without the gate");

    decide_approval(pool, approval, true, UserId(1), None, super::NOW)
        .await
        .unwrap();
    let r = ok(&fx, &a, "sprint_report", json!({"sprint_id": sprint})).await;
    assert_eq!(
        (r["state"].as_str(), r["committed"].as_u64()),
        (Some("active"), Some(8))
    );
}

/// After the close, the report carries the review, and the product owner proposes retro
/// items that stay proposed, linked to the sprint.
#[tokio::test]
async fn a_closed_sprint_reports_its_review_and_takes_retro_proposals() {
    use crate::store::work::close_sprint;
    use ainkrad_core::audit::AuditActor;
    use ainkrad_core::work::{SprintApproval, SprintId, UserId};

    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let (project, _, _) = planning_team(pool, &a).await;
    let mut p = get_project(pool, project).await.unwrap().unwrap();
    p.sprint_approval = SprintApproval::ProductOwner;
    assert!(update_project(pool, &p).await.unwrap());
    let plan = json!({"name": "S1", "starts_on": DATES.0, "ends_on": DATES.1});
    let sprint = ok(&fx, &a, "plan_sprint", plan).await["sprint_id"]
        .as_i64()
        .unwrap();
    ok(
        &fx,
        &a,
        "estimate_issue",
        json!({"issue_id": a.issue.0, "points": 2}),
    )
    .await;
    ok(
        &fx,
        &a,
        "sprint_add_issue",
        json!({"sprint_id": sprint, "issue_id": a.issue.0}),
    )
    .await;
    let started = ok(&fx, &a, "commit_sprint", json!({"sprint_id": sprint})).await;
    assert_eq!(started["status"], "started");
    let item = json!({"kind": "landmine", "title": "Flaky clock", "body": "Pass time in."});
    let early = json!({"sprint_id": sprint, "items": [item]});
    assert!(
        refused(&fx, &a, "propose_retro_items", early)
            .await
            .contains("active")
    );
    close_sprint(pool, SprintId(sprint), None, AuditActor::User(UserId(1)))
        .await
        .unwrap();

    let state = json!({"sprint_id": sprint, "items": [{"kind": "state", "title": "t",
                                                       "body": "b"}]});
    let why = refused(&fx, &a, "propose_retro_items", state).await;
    assert!(why.contains("kind"), "{why}");
    let none = refused(
        &fx,
        &a,
        "propose_retro_items",
        json!({"sprint_id": sprint, "items": []}),
    );
    assert!(none.await.contains("items"));
    let done = ok(
        &fx,
        &a,
        "propose_retro_items",
        json!({"sprint_id": sprint, "items": [item]}),
    );
    let done = done.await;
    assert_eq!(done["status"], "proposed");

    let r = ok(&fx, &a, "sprint_report", json!({"sprint_id": sprint})).await;
    assert_eq!(
        (
            r["review"]["committed"].as_u64(),
            r["review"]["completed"].as_u64()
        ),
        (Some(2), Some(0))
    );
    assert_eq!(r["review"]["carried"][0]["issue"], a.issue.0);
    assert_eq!(r["retro"][0]["id"], done["knowledge_entry_ids"][0]);
    assert_eq!(
        (
            r["retro"][0]["kind"].as_str(),
            r["retro"][0]["status"].as_str()
        ),
        (Some("landmine"), Some("proposed"))
    );
}
