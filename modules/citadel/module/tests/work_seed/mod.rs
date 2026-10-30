//! Fixtures of the work gate tests (`work_api*.rs`): the monolith's `seed` without the run engine
//! (no wake, runner or run), and the monolith's `ok` / `ok_post` as plain functions.
#![allow(dead_code, unused_imports)]

use axum::http::{Method, StatusCode};
use citadel_module::domain::org::{AgentStatus, CompanyId, Harness, NewAgent, OrgRole};
use citadel_module::domain::work::{
    IssueKind, IssueState, NewIssue, NewProject, NextActor, ProjectMode, SprintApproval,
};
use citadel_module::store::{org, work};
use serde_json::Value;
use sqlx::SqlitePool;

use crate::common::*;

/// A company with an active agent, a project, and an issue waiting on the agent.
pub struct Seed {
    pub company: i64,
    pub agent: i64,
    pub project: i64,
    pub issue: i64,
}

pub async fn seed(pool: &SqlitePool, name: &str, key: &str, mode: ProjectMode) -> Seed {
    let company = org::create_company(pool, name).await.unwrap().id;
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
    let agent = org::create_agent(pool, &a).await.unwrap().id;
    let p = NewProject {
        company_id: company,
        team_id: None,
        name: format!("{name} project"),
        key: key.to_owned(),
        mode,
        sprint_approval: SprintApproval::Owner,
    };
    let project = work::create_project(pool, &p).await.unwrap().id;
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
    let issue = work::create_issue(pool, &i).await.unwrap().id;
    Seed {
        company: company.0,
        agent: agent.0,
        project: project.0,
        issue: issue.0,
    }
}

/// `GET path` that must answer 200.
pub async fn ok(fx: &Fx, path: &str) -> Value {
    let (status, body) = call(fx, Some(&fx.dev), Method::GET, path, None).await;
    assert_eq!(status, StatusCode::OK, "GET {path}: {body}");
    body
}

/// `POST path` with `body`.
pub async fn post(fx: &Fx, path: &str, body: Value) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), Method::POST, path, Some(body)).await
}

/// `POST path` that must answer 200.
pub async fn ok_post(fx: &Fx, path: &str, body: Value) -> Value {
    let (status, got) = post(fx, path, body).await;
    assert_eq!(status, StatusCode::OK, "POST {path}: {got}");
    got
}

pub async fn get(fx: &Fx, path: &str) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), Method::GET, path, None).await
}
