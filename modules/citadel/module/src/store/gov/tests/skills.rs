//! Skills: who gets which skill, the latest version wins, and another company's skills never
//! appear. The monolith resolved them per run (`skills_for_run`, with the budget's dropped list),
//! which reads the run table (S7): those tests are `#[ignore]`d stubs, and their resolution rules
//! are checked here per agent (`skills_for_agent`).

use super::*;
use crate::domain::org::{TeamMembership, TeamRole};
use crate::store::org::{create_membership, create_team};

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

async fn publish(pool: &SqlitePool, c: CompanyId, name: &str, attach: SkillAttach) -> Skill {
    let body = format!("# {name}\n");
    publish_skill(pool, c, name, &body, &attach, BY)
        .await
        .unwrap()
}

/// The names an agent is given.
async fn names(pool: &SqlitePool, a: AgentId) -> Vec<String> {
    let skills = skills_for_agent(pool, a).await.unwrap().unwrap();
    skills.into_iter().map(|s| s.name).collect()
}

use crate::domain::gov::Skill;

#[tokio::test]
#[ignore = "S7: skills_for_run reads the run table"]
async fn a_role_skill_reaches_that_roles_runs_only() {
    todo!("monolith store/gov/tests/skills.rs; the per-agent twin is below")
}

#[tokio::test]
#[ignore = "S7: skills_for_run reads the run table"]
async fn a_department_skill_reaches_its_members_through_their_teams() {
    todo!("monolith store/gov/tests/skills.rs; the per-agent twin is below")
}

#[tokio::test]
#[ignore = "S7: skills_for_run reads the run table"]
async fn a_project_skill_reaches_runs_on_that_projects_issues() {
    todo!("monolith store/gov/tests/skills.rs: a run on the project's issue")
}

#[tokio::test]
#[ignore = "S7: skills_for_run reads the run table"]
async fn publishing_adds_a_version_and_the_latest_wins() {
    todo!("monolith store/gov/tests/skills.rs; the per-agent twin is below")
}

#[tokio::test]
#[ignore = "S7: skills_for_run reads the run table"]
async fn an_overflowing_budget_drops_the_lowest_precedence_and_says_so() {
    todo!(
        "monolith store/gov/tests/skills.rs: fit_skills at skills_for_run (fit_skills itself is tested in domain)"
    )
}

#[tokio::test]
#[ignore = "S7: skills_for_run reads the run table"]
async fn another_companys_skills_never_appear() {
    todo!("monolith store/gov/tests/skills.rs; the per-agent twin is below")
}

#[tokio::test]
async fn a_role_skill_reaches_that_roles_agents_only() {
    let db = db().await;
    let pool = &db.pool;
    let (c, _, _) = fixture(pool, "A").await;
    let (qa, dev) = (
        agent_as(pool, c, "QA").await,
        agent_as(pool, c, "Developer").await,
    );
    publish(pool, c, "qa-checklist", SkillAttach::Role("QA".to_owned())).await;
    publish(pool, c, "house-style", SkillAttach::Company).await;
    assert_eq!(
        names(pool, qa).await,
        ["house-style", "qa-checklist"],
        "by name"
    );
    assert_eq!(names(pool, dev).await, ["house-style"]);
    assert_eq!(skills_for_agent(pool, AgentId(9999)).await.unwrap(), None);
}

#[tokio::test]
async fn a_department_skill_reaches_its_members_through_their_teams_and_a_project_skill_its_teams()
{
    let db = db().await;
    let pool = &db.pool;
    let (c, _, p) = fixture(pool, "A").await;
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
    assert_eq!(names(pool, member).await, ["eng-runbook"]);
    assert!(names(pool, outsider).await.is_empty());

    // A project owned by the team gives its skill to the team's members.
    sqlx::query("UPDATE citadel_projects SET team_id = ? WHERE id = ?")
        .bind(team.id.0)
        .bind(p.id.0)
        .execute(pool)
        .await
        .unwrap();
    publish(pool, c, "citadel-layout", SkillAttach::Project(p.id)).await;
    assert_eq!(names(pool, member).await, ["citadel-layout", "eng-runbook"]);
}

#[tokio::test]
async fn publishing_adds_a_version_and_the_latest_wins_for_an_agent() {
    let db = db().await;
    let pool = &db.pool;
    let (c, _, _) = fixture(pool, "A").await;
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
        BY,
    )
    .await
    .unwrap();
    assert_eq!((v1.version, v2.version), (1, 2));
    assert_ne!(v1.id, v2.id);
    // The old version is kept as it was.
    assert_eq!(get_skill(pool, v1.id).await.unwrap(), Some(v1.clone()));

    // v2 moved the skill to the whole company: both agents get v2, nobody gets v1.
    for agent in [qa, dev] {
        let got = skills_for_agent(pool, agent).await.unwrap().unwrap();
        assert_eq!(got, vec![v2.clone()]);
    }

    let audited: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT entity_id, json_extract(details, '$.name'), json_extract(details, '$.version') \
         FROM audit_events WHERE action = 'citadel.skill.published' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        audited,
        [
            (v1.id.0, "review".to_owned(), 1),
            (v2.id.0, "review".to_owned(), 2),
        ]
    );
}

#[tokio::test]
async fn another_companys_skills_never_appear_for_an_agent() {
    let db = db().await;
    let pool = &db.pool;
    let (a, _, _) = fixture(pool, "A").await;
    let (b, _, _) = fixture(pool, "B").await;
    let qa = agent_as(pool, a, "QA").await;
    publish(pool, b, "b-wide", SkillAttach::Company).await;
    publish(pool, b, "b-qa", SkillAttach::Role("QA".to_owned())).await;
    publish(pool, a, "a-wide", SkillAttach::Company).await;
    assert_eq!(names(pool, qa).await, ["a-wide"]);
}
