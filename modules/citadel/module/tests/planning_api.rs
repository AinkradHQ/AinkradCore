//! Requirements (E15.10), the hub thread (E15.11) and the project profile (E15.13) through the
//! Core's client gate, ported from the monolith's `api/v1/tests/{requirements,profile}.rs`.
//! A fixture has no run engine: the monolith's `seed` also started a run, which none of these
//! tests reads.

mod common;

use ainkrad_core_server::api::v1::BY;
use axum::http::{Method, StatusCode};
use citadel_module::domain::gov::KnowledgeKind;
use citadel_module::domain::org::{AgentId, AgentStatus, CompanyId, Harness, NewAgent, OrgRole};
use citadel_module::domain::work::{
    IssueId, IssueKind, IssueState, NewIssue, NewProject, NextActor, ProjectId, ProjectMode,
    SprintApproval,
};
use citadel_module::store::gov::{Proposal, propose};
use citadel_module::store::org::{create_agent, create_company};
use citadel_module::store::work::{ask_human, create_issue, create_project, submit_intake};
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

/// A request is filed through the store (the intake route belongs to the org seam).
#[tokio::test]
async fn a_request_is_a_requirement_with_a_tree() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let asked = submit_intake(&fx.app.pool, a.company, "Phone alerts", "Buzz me", BY)
        .await
        .unwrap();
    let id = asked
        .requirement_id
        .expect("the request is a requirement")
        .0;
    let issue = ok(&fx, &format!("/issues/{}", asked.id.0)).await;
    assert_eq!(issue["requirement_id"], id);

    let all = ok(&fx, "/requirements").await;
    assert_eq!(all[0]["key"], "R-1");
    assert_eq!(all[0]["state"], "planning");
    let one = ok(&fx, &format!("/requirements/{id}")).await;
    assert_eq!(
        (one["title"].as_str(), one["plan_version"].as_i64()),
        (Some("Phone alerts"), Some(0))
    );
    let tree = ok(&fx, &format!("/requirements/{id}/tree")).await;
    assert_eq!(tree["requirement"]["id"], id);
    assert_eq!(
        (tree["points"].as_i64(), tree["percent_done"].as_i64()),
        (Some(0), Some(0))
    );
    assert_eq!(tree["epics"], json!([]));
    assert_eq!(
        tree["other"][0]["issue_id"], asked.id.0,
        "the request itself"
    );
    assert!(
        tree.get("diff").is_none() || tree["diff"].is_null(),
        "no plan approved yet"
    );
    let (status, _) = get(&fx, "/requirements/999").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The thread (E15.11): an agent's question is a card; a post answers it (auto-targeted) and
/// reaches the asker; with nothing open a post goes to the owner.
#[tokio::test]
async fn the_thread_shows_questions_and_routes_answers_to_the_asker() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Scrum).await;
    let asked = submit_intake(pool, a.company, "Alerts", "", BY)
        .await
        .unwrap();
    let r = asked.requirement_id.unwrap();
    sqlx::query("UPDATE citadel_issues SET requirement_id = ? WHERE id = ?")
        .bind(r.0)
        .bind(a.issue.0)
        .execute(pool)
        .await
        .unwrap();
    let q = ask_human(pool, a.agent, None, a.issue, "Which key?", &[])
        .await
        .unwrap();
    let uri = format!("/requirements/{}/thread", r.0);
    let thread = ok(&fx, &uri).await;
    assert_eq!(thread["to_question_id"], q.id.0);
    let card = &thread["items"][0];
    assert_eq!(card["kind"], "question", "{thread}");
    assert_eq!(card["question"]["asked_by_agent_id"], a.agent.0);
    assert_eq!(card["question"]["issue_key"], "AAA-1");

    let both = json!({"body": "x", "question_id": q.id.0, "to_owner": true});
    assert_eq!(post(&fx, &uri, both).await.0, StatusCode::BAD_REQUEST);
    let posted = ok_post(&fx, &uri, json!({"body": "The .p8"})).await;
    assert_eq!(posted["woke_agent_id"], a.agent.0);
    assert_eq!(posted["answered"]["state"], "answered");
    let thread = ok(&fx, &uri).await;
    assert!(thread.get("to_question_id").is_none() || thread["to_question_id"].is_null());
    assert_eq!(
        thread["items"][0]["question"]["answer"], "The .p8",
        "a receipt"
    );

    let posted = ok_post(&fx, &uri, json!({"body": "Status?"})).await;
    assert!(posted["comment_id"].is_i64(), "to the owner: {posted}");
    let thread = ok(&fx, &uri).await;
    assert_eq!(thread["items"][1]["kind"], "message");
    assert_eq!(thread["items"][1]["comment"]["body"], "Status?");
}

#[tokio::test]
async fn the_profile_round_trips_and_changes_only_what_is_given() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "PRO", ProjectMode::Kanban).await;
    let uri = format!("/projects/{}/profile", a.project.0);

    let empty = ok(&fx, &uri).await;
    assert_eq!(empty["profile"]["definition_of_done"], json!([]));
    assert_eq!(
        (
            empty["injected_bytes"].as_u64(),
            empty["budget_bytes"].as_u64()
        ),
        (Some(0), Some(4096))
    );
    assert_eq!(empty["permission_mode"], "ask");
    assert!(
        empty.get("updated_at").is_none_or(Value::is_null),
        "{empty}"
    );

    let (status, set) = put(
        &fx,
        &uri,
        json!({"definition_of_done": ["tests pass"],
        "environments": [{"name": "Prod", "url": "https://prod.example", "deploy": "owner"}],
        "models": [{"role": "QA", "model": "sonnet"}], "sprint_approval": "product_owner"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(set["profile"]["environments"][0]["deploy"], "owner");
    assert_eq!(set["sprint_approval"], "product_owner");
    assert!(set["injected_bytes"].as_u64().unwrap() > 0);
    assert!(
        set["updated_at"].as_str().is_some_and(|t| t.ends_with('Z')),
        "{set}"
    );

    // A partial update leaves the rest.
    let (_, set) = put(&fx, &uri, json!({"stack": "Rust"})).await;
    assert_eq!(set["profile"]["stack"], "Rust");
    assert_eq!(set["profile"]["definition_of_done"], json!(["tests pass"]));
    assert_eq!(ok(&fx, &uri).await["profile"], set["profile"]);

    for bad in [
        json!({"environments": [{"name": "Prod", "url": "https://u:p@prod.example"}]}),
        json!({"colour": "red"}),
        json!({"merge_method": "octopus"}),
        json!({"permission_mode": "sandboxed"}),
    ] {
        let (status, body) = put(&fx, &uri, bad.clone()).await;
        assert!(status.is_client_error(), "{bad}: {status} {body}");
    }
    assert_eq!(
        ok(&fx, &uri).await["profile"],
        set["profile"],
        "nothing changed"
    );
    let (status, _) = put(&fx, "/projects/999/profile", json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Adapted: the module's audit actions are `citadel.<action>`.
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'citadel.project.profile_set'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 2);
}

/// The proposal half of the monolith's profile test: it needs `store::gov::propose` to accept a
/// profile field, which S5 wires to `profile::field_patch` (S4b ships both).
#[tokio::test]
#[ignore = "S5: store::gov::propose refuses profile proposals until it calls profile::field_patch"]
async fn an_agents_profile_proposal_is_listed_not_applied() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "PRO", ProjectMode::Kanban).await;
    let uri = format!("/projects/{}/profile", a.project.0);
    let p = Proposal {
        project: a.project,
        kind: KnowledgeKind::Decision,
        title: "Format first".to_owned(),
        body: "Run cargo fmt before committing.".to_owned(),
        spec: false,
        profile_field: Some("conventions".to_owned()),
        rationale: Some("we lint on CI".to_owned()),
    };
    propose(&fx.app.pool, &p, a.agent).await.unwrap();
    let got = ok(&fx, &uri).await;
    assert_eq!(got["proposals"][0]["field"], "conventions", "{got}");
    assert_eq!(got["profile"]["conventions"], "");
}
