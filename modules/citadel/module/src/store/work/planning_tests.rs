//! Store tests of the planning half, ported from the monolith's `store/work/tests/{requirements,
//! intake,intake_existing,hub}.rs`, with the fixtures they shared with the work half. A test
//! that needs the run engine (the wake queue, a run, the dispatcher) keeps its original body in
//! an `#[ignore]`d twin named `…_wakes` / `…_engine`; the runnable one has those lines out.

use ainkrad_core::audit::AuditActor;
use sqlx::SqlitePool;

pub(crate) use crate::domain::org::{AgentId, AgentStatus, CompanyId, Harness, NewAgent, OrgRole};
pub(crate) use crate::domain::work::{
    Actor, IssueId, IssueKind, IssueState, NewIssue, NewProject, NextActor, Project, ProjectId,
    ProjectMode, SprintApproval, UserId,
};
pub(crate) use crate::store::org::{create_agent, create_company};
pub(crate) use crate::store::work::*;
pub(crate) use crate::testing::db;

mod engine;
mod hub;
mod intake;
mod intake_existing;
mod requirements;

/// The admin as the module's work domain names it.
const ADMIN: UserId = UserId(1);
/// The admin as the Core's audit names it.
const BY: AuditActor = AuditActor::User(ainkrad_core::ids::UserId(1));

fn new_project(company_id: CompanyId, key: &str) -> NewProject {
    NewProject {
        company_id,
        team_id: None,
        name: format!("Project {key}"),
        key: key.to_owned(),
        mode: ProjectMode::Scrum,
        sprint_approval: SprintApproval::Owner,
    }
}

fn new_issue(project_id: ProjectId, title: &str) -> NewIssue {
    NewIssue {
        project_id,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Story,
        title: title.to_owned(),
        body: String::new(),
        state: IssueState::Backlog,
        owner: None,
        next_actor: Some(NextActor::Human(ADMIN)),
        points: None,
        sprint_id: None,
    }
}

async fn agent(pool: &SqlitePool, company_id: CompanyId, name: &str) -> AgentId {
    let a = NewAgent {
        company_id,
        name: name.to_owned(),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Claude,
        model: "claude-opus".to_owned(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    create_agent(pool, &a).await.unwrap().id
}

async fn now(pool: &SqlitePool) -> String {
    sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_planning_tables_are_the_modules() {
    // The ported SQL names `citadel_*` tables only: a bare name would be a missing table.
    let db = db().await;
    let pool = &db.pool;
    for t in [
        "requirements",
        "requirement_plans",
        "questions",
        "plan_applies",
        "project_profiles",
    ] {
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM citadel_{t}"
        )))
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(n, 0, "{t}");
    }
}
