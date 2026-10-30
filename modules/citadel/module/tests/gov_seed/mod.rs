//! Seed rows for the governance gate tests: a company with an agent, a Kanban project and one
//! issue, written with the raw writers (no audit, no run: the run engine is a later slice).
#![allow(dead_code)]

use citadel_module::domain::org::{AgentId, AgentStatus, CompanyId, Harness, NewAgent, OrgRole};
use citadel_module::domain::work::{
    IssueId, IssueKind, IssueState, NewIssue, NewProject, NextActor, ProjectId, ProjectMode,
    SprintApproval, UserId,
};
use citadel_module::store::org::{create_agent, create_company};
use citadel_module::store::work::{create_issue, create_project};
use sqlx::SqlitePool;

pub const NOW: &str = "2026-10-22T10:00:00.000Z";

pub struct Seed {
    pub company: CompanyId,
    pub agent: AgentId,
    pub project: ProjectId,
    pub issue: IssueId,
}

pub async fn seed(pool: &SqlitePool, name: &str, key: &str) -> Seed {
    let company = create_company(pool, name).await.unwrap().id;
    let agent = NewAgent {
        company_id: company,
        name: format!("Dev {name}"),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Claude,
        model: "claude-opus".to_owned(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    let agent = create_agent(pool, &agent).await.unwrap().id;
    let project = NewProject {
        company_id: company,
        team_id: None,
        name: name.to_owned(),
        key: key.to_owned(),
        mode: ProjectMode::Kanban,
        sprint_approval: SprintApproval::Owner,
    };
    let project = create_project(pool, &project).await.unwrap().id;
    let issue = NewIssue {
        project_id: project,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Ship it".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Human(UserId(1))),
        points: None,
        sprint_id: None,
    };
    let issue = create_issue(pool, &issue).await.unwrap().id;
    Seed {
        company,
        agent,
        project,
        issue,
    }
}

/// The audit rows' details of `action` (`issue.created`, without the `citadel.` prefix).
pub async fn audited(pool: &SqlitePool, action: &str) -> Vec<serde_json::Value> {
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = ? ORDER BY seq")
            .bind(format!("citadel.{action}"))
            .fetch_all(pool)
            .await
            .unwrap();
    rows.iter()
        .map(|d| serde_json::from_str(d).unwrap())
        .collect()
}
