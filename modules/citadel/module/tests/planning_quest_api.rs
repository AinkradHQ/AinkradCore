//! Quest (API minor 9) through the Core's client gate, ported from the monolith's
//! `api/v1/tests/quest.rs`: project settings and labels, labels on issues, and company scope on
//! every route of the quest (the sprint side is in `planning_sprint_api`). A fixture has no run engine:
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

/// Every route of this file, as company B's, refused while working in A.
#[tokio::test]
async fn another_companys_quest_data_is_refused() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Scrum).await;
    let label = fx
        .ok_post(
            &format!("/projects/{}/labels", b.project.0),
            json!({"name": "ui"}),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    let sprint = fx
        .ok_post(
            &format!("/projects/{}/sprints", b.project.0),
            json!({"name": "S", "starts_on": "2026-10-19", "ends_on": "2026-10-30"}),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    let (p, i) = (b.project.0, b.issue.0);
    for (method, uri, body) in [
        (
            Method::PUT,
            format!("/projects/{p}"),
            Some(json!({"name": "X"})),
        ),
        (Method::GET, format!("/projects/{p}/labels"), None),
        (
            Method::POST,
            format!("/projects/{p}/labels"),
            Some(json!({"name": "x"})),
        ),
        (
            Method::PUT,
            format!("/projects/{p}/labels/{label}"),
            Some(json!({"name": "y"})),
        ),
        (
            Method::DELETE,
            format!("/projects/{p}/labels/{label}"),
            None,
        ),
        (Method::PUT, format!("/issues/{i}/labels/{label}"), None),
        (Method::DELETE, format!("/issues/{i}/labels/{label}"), None),
        (Method::GET, format!("/projects/{p}/capacity"), None),
        (
            Method::PUT,
            format!("/projects/{p}/capacity/{}", b.agent.0),
            Some(json!({})),
        ),
        (Method::GET, format!("/projects/{p}/flow"), None),
        (Method::GET, format!("/issues/{i}/flow"), None),
        (
            Method::POST,
            format!("/sprints/{sprint}/commit"),
            Some(json!({})),
        ),
        (Method::GET, format!("/sprints/{sprint}/review"), None),
    ] {
        let company = a.company.0.to_string();
        let (status, _) = call_in(
            &fx,
            Some(&fx.dev),
            Some(&company),
            method.clone(),
            &uri,
            body,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
    }
}

#[tokio::test]
async fn project_settings_labels_and_epic_keys() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Scrum).await;
    let p = a.project.0;
    let uri = format!("/projects/{p}");
    let (status, got) = put(&fx, &uri, json!({"name": "Renamed", "mode": "kanban"})).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        (got["name"].clone(), got["mode"].clone()),
        (json!("Renamed"), json!("kanban"))
    );
    assert_eq!(got["key"], "AAA", "the key never changes");
    assert_eq!(audited(&fx, "project.updated").await, 1);
    let theirs = org::add_department(&fx.app.pool, b.company, "Eng", BY)
        .await
        .unwrap();
    let team = org::add_team(&fx.app.pool, theirs.id, "T", BY)
        .await
        .unwrap();
    assert_eq!(
        put(&fx, &uri, json!({"team_id": team.id.0})).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        put(&fx, &uri, json!({"name": " "})).await.0,
        StatusCode::BAD_REQUEST
    );
    // A scrum project with a planned sprint stays scrum.
    let bp = b.project.0;
    ok_post(
        &fx,
        &format!("/projects/{bp}/sprints"),
        json!({"name": "S", "starts_on": "2026-10-19", "ends_on": "2026-10-30"}),
    )
    .await;
    let (status, _) = put(&fx, &format!("/projects/{bp}"), json!({"mode": "kanban"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let labels = format!("/projects/{p}/labels");
    let ui = ok_post(&fx, &labels, json!({"name": "ui"})).await["id"]
        .as_i64()
        .unwrap();
    let api = ok_post(&fx, &labels, json!({"name": "api"})).await["id"]
        .as_i64()
        .unwrap();
    assert_eq!(
        post(&fx, &labels, json!({"name": "ui"})).await.0,
        StatusCode::BAD_REQUEST
    );
    let (status, renamed) = put(&fx, &format!("{labels}/{ui}"), json!({"name": "UI"})).await;
    assert_eq!(
        (status, renamed["name"].clone()),
        (StatusCode::OK, json!("UI"))
    );
    let i = a.issue.0;
    let (status, issue) = put(&fx, &format!("/issues/{i}/labels/{ui}"), json!(null)).await;
    assert_eq!(status, StatusCode::OK, "{issue}");
    assert_eq!(issue["labels"][0]["name"], "UI");
    put(&fx, &format!("/issues/{i}/labels/{api}"), json!(null)).await;
    let board = ok(&fx, &format!("/projects/{p}/issues")).await;
    let names: Vec<&str> = board[0]["labels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["UI", "api"], "{board}");
    let blabel = fx
        .ok_post(&format!("/projects/{bp}/labels"), json!({"name": "x"}))
        .await["id"]
        .clone();
    let (status, _) = put(&fx, &format!("/issues/{i}/labels/{blabel}"), json!(null)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "another project's label");
    let (_, issue) = delete(&fx, &format!("/issues/{i}/labels/{api}")).await;
    assert_eq!(issue["labels"].as_array().unwrap().len(), 1);
    let (status, left) = delete(&fx, &format!("{labels}/{ui}")).await;
    assert_eq!(
        (status, left.as_array().unwrap().len()),
        (StatusCode::OK, 1)
    );
    let issue = ok(&fx, &format!("/issues/{i}")).await;
    assert_eq!(
        issue["labels"],
        json!([]),
        "a deleted label leaves every issue"
    );
    for action in [
        "label.created",
        "label.renamed",
        "label.deleted",
        "issue.labeled",
    ] {
        assert!(audited(&fx, action).await > 0, "{action}");
    }

    // Epic keys: per project, never reused; the label events name their project.
    let epics = format!("/projects/{p}/epics");
    let e1 = ok_post(&fx, &epics, json!({"title": "One"})).await;
    let e2 = ok_post(&fx, &epics, json!({"title": "Two"})).await;
    assert_eq!(
        (e1["key"].clone(), e2["key"].clone()),
        (json!("AAA-E1"), json!("AAA-E2"))
    );
    sqlx::query("DELETE FROM citadel_epics WHERE id = ?")
        .bind(e2["id"].as_i64())
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let e3 = ok_post(&fx, &epics, json!({"title": "Three"})).await;
    assert_eq!(e3["key"], "AAA-E3");
    let theirs = fx
        .ok_post(&format!("/projects/{bp}/epics"), json!({"title": "B"}))
        .await;
    assert_eq!(theirs["key"], "BBB-E1");
    let unnamed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action LIKE 'citadel.issue.%' AND entity_kind = 'issue' \
         AND json_extract(details, '$.project_id') IS NULL",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(unnamed, 0, "every issue event names its project");
    // Adapted: the client event stream is the Core's, outside the module's path; the audit rows
    // it carries are read from the table.
    let events: String = sqlx::query_scalar(
        "SELECT group_concat(details) FROM audit_events WHERE action LIKE 'citadel.issue.%'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert!(events.contains("\"project_id\""), "{events}");
}
