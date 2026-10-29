//! The Engineering template (E6.5): it instantiates a CTO and a team with role skills, each agent
//! hired through its approval; applying it again duplicates nothing; once the hires are approved
//! the team is routed a project and its product owner is dispatched with its skill.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::exec::{NewRunner, RunEvent};
use ainkrad_core::work::{Actor, ProjectMode, UserId};

use super::*;
use crate::store::exec::{create_runner, dispatch_next, start_run, transition_run};
use crate::store::gov::{decide_approval, list_skills, skills_for_run};
use crate::store::work::{Route, route_intake, submit_intake};

const ADMIN: UserId = UserId(1);
const BY: AuditActor = AuditActor::User(ADMIN);
const NOW: &str = "2026-10-21T10:00:00.000Z";

#[tokio::test]
async fn the_template_instantiates_a_working_team() {
    let db = db().await;
    let pool = &db.pool;
    let c = create_company(pool, "A").await.unwrap().id;
    let ceo = NewAgent {
        runner_tags: vec![],
        ..new_agent(c, "Ceo", OrgRole::Ceo)
    };
    let ceo = bootstrap_ceo(pool, &ceo, BY).await.unwrap();

    let first = apply_engineering(pool, c, BY, NOW).await.unwrap();
    assert_eq!(
        (first.department.name.as_str(), first.team.name.as_str()),
        (ENGINEERING, ENGINEERING_TEAM)
    );
    let roles: Vec<(&str, OrgRole, AgentStatus)> = first
        .agents
        .iter()
        .map(|a| (a.role.as_str(), a.org_role, a.status))
        .collect();
    let pending = AgentStatus::PendingApproval;
    assert_eq!(
        roles,
        [
            ("CTO", OrgRole::Cto, pending),
            ("Product Owner", OrgRole::None, pending),
            ("Team Lead", OrgRole::None, pending),
            ("Developer", OrgRole::None, pending),
            ("Developer", OrgRole::None, pending),
            ("QA", OrgRole::None, pending),
            ("DevOps", OrgRole::None, pending),
        ]
    );
    assert_eq!((first.hires.len(), first.skills_published), (7, 6));
    let seats: Vec<(AgentId, TeamRole)> = list_memberships(pool, first.team.id)
        .await
        .unwrap()
        .into_iter()
        .map(|m| (m.agent_id, m.team_role))
        .collect();
    let ids: Vec<AgentId> = first.agents.iter().map(|a| a.id).collect();
    assert_eq!(seats.len(), 6, "the CTO has no seat");
    assert!(seats.contains(&(ids[1], TeamRole::ProductOwner)));
    assert!(seats.contains(&(ids[2], TeamRole::TeamLead)));

    // Applying again duplicates nothing.
    let again = apply_engineering(pool, c, BY, NOW).await.unwrap();
    let again_ids: Vec<AgentId> = again.agents.iter().map(|a| a.id).collect();
    assert_eq!((again.team.id, again_ids), (first.team.id, ids.clone()));
    assert_eq!((again.hires.len(), again.skills_published), (0, 0));
    assert_eq!(list_agents(pool, c).await.unwrap().len(), 8);
    assert_eq!(list_departments(pool, c).await.unwrap().len(), 1);
    assert_eq!(
        list_teams(pool, first.department.id).await.unwrap().len(),
        1
    );
    assert_eq!(list_skills(pool, c).await.unwrap().len(), 6);

    // The CEO routes a request to Engineering; the product owner waits on its hire.
    let req = submit_intake(pool, c, "Public API", "REST", BY)
        .await
        .unwrap();
    let runner = NewRunner {
        name: "box".to_owned(),
        tags: vec![],
    };
    let runner = create_runner(pool, &runner, "box").await.unwrap().id;
    let dispatch = || dispatch_next(pool, runner, &[], &Harness::ALL, NOW);
    let ceo_run = dispatch().await.unwrap().expect("the CEO takes intake");
    assert_eq!(ceo_run.agent_id, ceo.id);
    let by = AuditActor::Runner(runner);
    start_run(pool, ceo_run.id, by, None, NOW).await.unwrap();
    let route = Route::New {
        department: first.department.id,
        team: None,
        name: "API".to_owned(),
        key: "API".to_owned(),
        mode: ProjectMode::Scrum,
    };
    let routed = route_intake(pool, req.id, Actor::Agent(ceo.id), &[route])
        .await
        .unwrap();
    assert_eq!(routed[0].product_owner, ids[1]);
    transition_run(pool, ceo_run.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap();
    assert!(
        dispatch().await.unwrap().is_none(),
        "the PO is not hired yet"
    );

    for hire in &first.hires {
        decide_approval(pool, *hire, true, ADMIN, None, NOW)
            .await
            .unwrap();
    }
    let po_run = dispatch().await.unwrap().expect("the PO takes the kickoff");
    assert_eq!(
        (po_run.agent_id, po_run.issue_id),
        (ids[1], Some(routed[0].kickoff.id))
    );
    let skills = skills_for_run(pool, po_run.id).await.unwrap();
    let names: Vec<&str> = skills.skills.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["product-owner"]);
    assert!(skills.skills[0].body.contains("kickoff issue"));
}

/// A step that fails part-way (the team already has a lead, so seating the template's is a
/// constraint error) leaves nothing behind: no agents, hires, skills or audit events.
#[tokio::test]
async fn a_failed_apply_writes_nothing() {
    let db = db().await;
    let pool = &db.pool;
    let c = create_company(pool, "A").await.unwrap().id;
    let d = add_department(pool, c, ENGINEERING, BY).await.unwrap();
    let t = add_team(pool, d.id, ENGINEERING_TEAM, BY).await.unwrap();
    let lead = create_agent(pool, &new_agent(c, "Old Lead", OrgRole::None))
        .await
        .unwrap();
    seat_member(pool, t.id, lead.id, TeamRole::TeamLead, None, BY)
        .await
        .unwrap();
    let count = |sql: &'static str| async move {
        sqlx::query_scalar::<_, i64>(sql)
            .fetch_one(pool)
            .await
            .unwrap()
    };
    let before = (
        count("SELECT count(*) FROM agents").await,
        count("SELECT count(*) FROM approvals").await,
        count("SELECT count(*) FROM skills").await,
        count("SELECT count(*) FROM audit_events").await,
    );
    let e = apply_engineering(pool, c, BY, NOW).await.unwrap_err();
    assert!(matches!(e, OrgError::Db(_)), "{e}");
    let after = (
        count("SELECT count(*) FROM agents").await,
        count("SELECT count(*) FROM approvals").await,
        count("SELECT count(*) FROM skills").await,
        count("SELECT count(*) FROM audit_events").await,
    );
    assert_eq!(before, after);
}
