//! Skills for a run: who gets which skill, the latest version wins, the budget reports what
//! it drops, and another company's skills never appear.

use citadel_core::audit::AuditActor;
use citadel_core::exec::{NewRun, RunId};
use citadel_core::gov::{RunSkills, SKILL_BUDGET_BYTES, Skill};
use citadel_core::org::{Harness, TeamMembership, TeamRole};
use citadel_core::work::{IssueId, IssueKind, IssueState, NewIssue, NextActor};

use super::*;
use crate::store::exec::create_run;
use crate::store::org::{create_membership, create_team};
use crate::store::work::create_issue;

const ME: AuditActor = AuditActor::User(ADMIN);

async fn agent_as(pool: &SqlitePool, company_id: CompanyId, role: &str) -> AgentId {
    let a = NewAgent {
        company_id,
        name: role.to_owned(),
        role: role.to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Claude,
        model: "claude-opus".to_owned(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    create_agent(pool, &a).await.unwrap().id
}

async fn project(pool: &SqlitePool, company_id: CompanyId, key: &str) -> ProjectId {
    let p = NewProject {
        company_id,
        team_id: None,
        name: key.to_owned(),
        key: key.to_owned(),
        mode: ProjectMode::Scrum,
        sprint_approval: SprintApproval::Owner,
    };
    create_project(pool, &p).await.unwrap().id
}

async fn issue(pool: &SqlitePool, project_id: ProjectId) -> IssueId {
    let i = NewIssue {
        project_id,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Work".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Human(ADMIN)),
        points: None,
        sprint_id: None,
    };
    create_issue(pool, &i).await.unwrap().id
}

pub(super) async fn run(pool: &SqlitePool, agent_id: AgentId, issue_id: Option<IssueId>) -> RunId {
    let r = NewRun {
        agent_id,
        issue_id,
        wake_request_id: None,
        harness: Harness::Claude,
    };
    create_run(pool, &r).await.unwrap().id
}

async fn publish(pool: &SqlitePool, c: CompanyId, name: &str, attach: SkillAttach) -> Skill {
    let body = format!("# {name}\n");
    publish_skill(pool, c, name, &body, &attach, ME)
        .await
        .unwrap()
}

/// The names a run is given.
async fn names(pool: &SqlitePool, r: RunId) -> Vec<String> {
    let RunSkills { skills, dropped } = skills_for_run(pool, r).await.unwrap();
    assert!(dropped.is_empty(), "{dropped:?}");
    skills.into_iter().map(|s| s.name).collect()
}

#[tokio::test]
async fn a_role_skill_reaches_that_roles_runs_only() {
    let db = db().await;
    let pool = &db.pool;
    let (c, _, p) = fixture(pool, "A").await;
    let (qa, dev) = (
        agent_as(pool, c, "QA").await,
        agent_as(pool, c, "Developer").await,
    );
    publish(pool, c, "qa-checklist", SkillAttach::Role("QA".to_owned())).await;
    publish(pool, c, "house-style", SkillAttach::Company).await;
    let i = issue(pool, p.id).await;

    let qa_run = run(pool, qa, Some(i)).await;
    let dev_run = run(pool, dev, Some(i)).await;
    assert_eq!(names(pool, qa_run).await, ["qa-checklist", "house-style"]);
    assert_eq!(names(pool, dev_run).await, ["house-style"]);
    let missing = skills_for_run(pool, RunId(9999)).await.unwrap_err();
    assert!(matches!(missing, Error::RowNotFound), "{missing}");
}

#[tokio::test]
async fn a_department_skill_reaches_its_members_through_their_teams() {
    let db = db().await;
    let pool = &db.pool;
    let (c, _, _) = fixture(pool, "A").await;
    let (member, outsider) = (
        agent_as(pool, c, "Developer").await,
        agent_as(pool, c, "Developer").await,
    );
    let eng = create_department(pool, c, "Eng").await.unwrap();
    let team = create_team(pool, eng.id, "Core").await.unwrap();
    let m = TeamMembership {
        team_id: team.id,
        agent_id: member,
        team_role: TeamRole::Member,
    };
    create_membership(pool, &m).await.unwrap();
    publish(pool, c, "eng-runbook", SkillAttach::Department(eng.id)).await;

    assert_eq!(
        names(pool, run(pool, member, None).await).await,
        ["eng-runbook"]
    );
    assert!(
        names(pool, run(pool, outsider, None).await)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn a_project_skill_reaches_runs_on_that_projects_issues() {
    let db = db().await;
    let pool = &db.pool;
    let (c, dev, p) = fixture(pool, "A").await;
    let other = project(pool, c, "OPS").await;
    publish(pool, c, "citadel-layout", SkillAttach::Project(p.id)).await;

    let on_p = run(pool, dev, Some(issue(pool, p.id).await)).await;
    let on_other = run(pool, dev, Some(issue(pool, other).await)).await;
    let on_none = run(pool, dev, None).await;
    assert_eq!(names(pool, on_p).await, ["citadel-layout"]);
    assert!(names(pool, on_other).await.is_empty());
    assert!(names(pool, on_none).await.is_empty());
}

#[tokio::test]
async fn publishing_adds_a_version_and_the_latest_wins() {
    let db = db().await;
    let pool = &db.pool;
    let (c, _, p) = fixture(pool, "A").await;
    let (qa, dev) = (
        agent_as(pool, c, "QA").await,
        agent_as(pool, c, "Developer").await,
    );
    let v1 = publish(pool, c, "review", SkillAttach::Role("QA".to_owned())).await;
    let v2 = publish_skill(
        pool,
        c,
        "review",
        "# review v2\n",
        &SkillAttach::Company,
        ME,
    )
    .await
    .unwrap();
    assert_eq!((v1.version, v2.version), (1, 2));
    assert_ne!(v1.id, v2.id);
    // The old version is kept as it was.
    assert_eq!(get_skill(pool, v1.id).await.unwrap(), Some(v1.clone()));

    // v2 moved the skill to the whole company: both runs get v2, nobody gets v1.
    let i = issue(pool, p.id).await;
    for agent in [qa, dev] {
        let got = skills_for_run(pool, run(pool, agent, Some(i)).await)
            .await
            .unwrap();
        assert_eq!(got.skills, vec![v2.clone()]);
    }

    let audited: Vec<(i64, String)> = sqlx::query_as(
        "SELECT entity_id, details FROM audit_events WHERE action = 'skill.published' \
         ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        audited,
        [
            (v1.id.0, r#"{"name":"review","version":1}"#.to_owned()),
            (v2.id.0, r#"{"name":"review","version":2}"#.to_owned()),
        ]
    );
}

#[tokio::test]
async fn an_overflowing_budget_drops_the_lowest_precedence_and_says_so() {
    let db = db().await;
    let pool = &db.pool;
    let (c, dev, p) = fixture(pool, "A").await;
    let half = "x".repeat(SKILL_BUDGET_BYTES / 2 + 1);
    let company = publish_skill(pool, c, "big-company", &half, &SkillAttach::Company, ME)
        .await
        .unwrap();
    let attach = SkillAttach::Project(p.id);
    let project = publish_skill(pool, c, "big-project", &half, &attach, ME)
        .await
        .unwrap();

    let got = skills_for_run(pool, run(pool, dev, Some(issue(pool, p.id).await)).await)
        .await
        .unwrap();
    assert_eq!(got.skills, vec![project]);
    assert_eq!(got.dropped, vec![company]);
}

#[tokio::test]
async fn another_companys_skills_never_appear() {
    let db = db().await;
    let pool = &db.pool;
    let (a, _, p) = fixture(pool, "A").await;
    let (b, _, _) = fixture(pool, "B").await;
    let qa = agent_as(pool, a, "QA").await;
    publish(pool, b, "b-wide", SkillAttach::Company).await;
    publish(pool, b, "b-qa", SkillAttach::Role("QA".to_owned())).await;
    publish(pool, a, "a-wide", SkillAttach::Company).await;

    let r = run(pool, qa, Some(issue(pool, p.id).await)).await;
    assert_eq!(names(pool, r).await, ["a-wide"]);
}
