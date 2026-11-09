//! Quest, the sprint side (API minor 9) through the Core's client gate, ported from the
//! monolith's `api/v1/tests/quest.rs`: team capacity, flow times, the owner's sprint commit, a
//! sprint's review and retro. A fixture has no run engine:
//! the monolith's `seed` also started a run, which none of these tests reads.
#![allow(dead_code, unused_imports)]

mod common;

use ainkrad_core_server::api::v1::BY;
use axum::http::{Method, StatusCode};
use citadel_module::domain::gov::KnowledgeKind;
use citadel_module::domain::org::{
    AgentId, AgentStatus, CompanyId, Harness, NewAgent, OrgRole, TeamRole,
};
use citadel_module::domain::work::{
    IssueId, IssueKind, IssueState, NewIssue, NewProject, NextActor, ProjectId, ProjectMode,
    SprintApproval, SprintId,
};
use citadel_module::store::org;
use citadel_module::store::org::{create_agent, create_company};
use citadel_module::store::work::{RetroItem, create_issue, create_project, propose_retro};
use common::*;
use serde_json::{Value, json};
use sqlx::SqlitePool;

async fn get(fx: &Fx, path: &str) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), Method::GET, path, None).await
}

async fn post(fx: &Fx, path: &str, body: Value) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), Method::POST, path, Some(body)).await
}

async fn put(fx: &Fx, path: &str, body: Value) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), Method::PUT, path, Some(body)).await
}

async fn delete(fx: &Fx, path: &str) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), Method::DELETE, path, None).await
}

/// How many audit rows `action` (the monolith's name) has.
async fn audited(fx: &Fx, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(format!("citadel.{action}"))
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

/// `get` that must answer 200.
async fn ok(fx: &Fx, path: &str) -> Value {
    let (status, body) = get(fx, path).await;
    assert_eq!(status, StatusCode::OK, "GET {path}: {body}");
    body
}

/// `post` that must answer 200.
async fn ok_post(fx: &Fx, path: &str, body: Value) -> Value {
    let (status, got) = post(fx, path, body).await;
    assert_eq!(status, StatusCode::OK, "POST {path}: {got}");
    got
}

/// A company with an active agent, a project, and an issue waiting on the agent.
struct Seed {
    company: CompanyId,
    agent: AgentId,
    project: ProjectId,
    issue: IssueId,
}

async fn seed(pool: &SqlitePool, name: &str, key: &str, mode: ProjectMode) -> Seed {
    let company = create_company(pool, name).await.unwrap().id;
    let a = NewAgent {
        company_id: company,
        name: format!("{name} dev"),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Opencode,
        model: String::new(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    let agent = create_agent(pool, &a).await.unwrap().id;
    let p = NewProject {
        company_id: company,
        team_id: None,
        name: format!("{name} project"),
        key: key.to_owned(),
        mode,
        sprint_approval: SprintApproval::Owner,
    };
    let project = create_project(pool, &p).await.unwrap().id;
    let i = NewIssue {
        project_id: project,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: format!("{name} work"),
        body: "Do the thing.".to_owned(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Agent(agent)),
        points: None,
        sprint_id: None,
    };
    let issue = create_issue(pool, &i).await.unwrap().id;
    Seed {
        company,
        agent,
        project,
        issue,
    }
}

#[tokio::test]
async fn capacity_commit_flow_and_review() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let pool = &fx.app.pool;
    let d = org::add_department(pool, a.company, "Eng", BY)
        .await
        .unwrap();
    let team = org::add_team(pool, d.id, "Core", BY).await.unwrap();
    org::seat_member(pool, team.id, a.agent, TeamRole::ProductOwner, Some(2), BY)
        .await
        .unwrap();
    let p = a.project.0;
    let (status, _) = put(
        &fx,
        &format!("/projects/{p}"),
        json!({"team_id": team.id.0}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cap = ok(&fx, &format!("/projects/{p}/capacity")).await;
    assert_eq!(
        (cap["total"].clone(), cap["members"][0]["team_role"].clone()),
        (json!(2), json!("product_owner"))
    );
    let set = format!("/projects/{p}/capacity/{}", a.agent.0);
    let (status, cap) = put(&fx, &set, json!({"capacity": 3})).await;
    assert_eq!((status, cap["total"].clone()), (StatusCode::OK, json!(3)));
    assert_eq!(audited(&fx, "member.capacity_set").await, 1);
    let (status, _) = put(&fx, &format!("/projects/{p}/capacity/9999"), json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A sprint of 5 points over a capacity of 3: the owner commits it with a reason.
    let sprint = fx
        .ok_post(
            &format!("/projects/{p}/sprints"),
            json!({"name": "S1", "starts_on": "2026-10-19", "ends_on": "2026-10-30"}),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    let i = a.issue.0;
    ok_post(&fx, &format!("/issues/{i}/estimate"), json!({"points": 5})).await;
    ok_post(
        &fx,
        &format!("/issues/{i}/sprint"),
        json!({"sprint_id": sprint}),
    )
    .await;
    let commit = format!("/sprints/{sprint}/commit");
    let (status, body) = post(&fx, &commit, json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT, "over capacity: {body}");
    let started = fx
        .ok_post(&commit, json!({"override_reason": "crunch"}))
        .await;
    assert_eq!(started["state"], "active");
    let gate: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'citadel.sprint.started'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(
        gate.contains("\"owner\"") && gate.contains("crunch"),
        "{gate}"
    );
    assert_eq!(
        post(&fx, &commit, json!({})).await.0,
        StatusCode::CONFLICT,
        "started already"
    );

    // Flow: the issue's age; done, its cycle and lead, and the project's throughput.
    let flow = ok(&fx, &format!("/issues/{i}/flow")).await;
    assert!(
        flow["age_secs"].is_i64() && flow["lead_secs"].is_null(),
        "{flow}"
    );
    for step in ["start", "review", "done"] {
        sqlx::query("UPDATE citadel_issues SET state = ? WHERE id = ?")
            .bind(match step {
                "start" => "in_progress",
                "review" => "in_review",
                _ => "done",
            })
            .bind(i)
            .execute(pool)
            .await
            .unwrap();
    }
    let flow = ok(&fx, &format!("/issues/{i}/flow")).await;
    assert!(
        flow["cycle_secs"].is_i64() && flow["lead_secs"].is_i64(),
        "{flow}"
    );
    let until = "2100-01-01T00:00:00.000Z";
    let project = fx
        .ok(&format!(
            "/projects/{p}/flow?since=2000-01-01T00:00:00.000Z&until={until}"
        ))
        .await;
    assert_eq!(project["throughput"], 1, "{project}");
    assert!(ok(&fx, &format!("/projects/{p}/flow")).await["since"].is_string());

    // Review and retro: absent before it closes, then what the PO proposed.
    let review = format!("/sprints/{sprint}/review");
    assert!(ok(&fx, &review).await["review"].is_null());
    ok_post(&fx, &format!("/sprints/{sprint}/close"), json!({})).await;
    let item = RetroItem {
        kind: KnowledgeKind::Retro,
        title: "Smaller stories".to_owned(),
        body: "Split anything over 3 points.".to_owned(),
    };
    propose_retro(pool, SprintId(sprint), &[item], a.agent)
        .await
        .unwrap();
    let got = ok(&fx, &review).await;
    assert_eq!(got["review"]["completed"], 5, "{got}");
    assert_eq!(got["retro"][0]["title"], "Smaller stories");
    assert_eq!(got["retro"][0]["status"], "proposed");
}
