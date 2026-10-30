//! The Engineering template (E6.5): it instantiates a CTO and a team with role skills, each agent
//! hired through its approval; applying it again duplicates nothing. Ported from
//! `store/org/tests/template.rs`; the second half of the first test (route an intake request,
//! approve the hires, dispatch the product owner with its skill: `submit_intake`, `route_intake`,
//! `dispatch_next`, `skills_for_run`) needs the run engine and work intake (S7/S4) and is not
//! ported.

use super::tests_util::*;
use super::*;
use crate::domain::org::{AgentStatus, Harness, OrgRole, TeamRole};

#[tokio::test]
async fn the_template_instantiates_a_working_team() {
    let db = db().await;
    let pool = &db.pool;
    let c = create_company(pool, "A").await.unwrap().id;
    let ceo = NewAgent {
        runner_tags: vec![],
        ..new_agent(c, "Ceo", OrgRole::Ceo)
    };
    bootstrap_ceo(pool, &ceo, BY).await.unwrap();

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
    assert!(first.agents.iter().all(|a| a.harness == Harness::Claude));
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
    let skills: i64 =
        sqlx::query_scalar("SELECT count(*) FROM citadel_skills WHERE company_id = ?")
            .bind(c.0)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(skills, 6);
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
        count("SELECT count(*) FROM citadel_agents").await,
        count("SELECT count(*) FROM citadel_approvals").await,
        count("SELECT count(*) FROM citadel_skills").await,
        count("SELECT count(*) FROM audit_events").await,
    );
    let e = apply_engineering(pool, c, BY, NOW).await.unwrap_err();
    assert!(matches!(e, OrgError::Db(_)), "{e}");
    let after = (
        count("SELECT count(*) FROM citadel_agents").await,
        count("SELECT count(*) FROM citadel_approvals").await,
        count("SELECT count(*) FROM citadel_skills").await,
        count("SELECT count(*) FROM audit_events").await,
    );
    assert_eq!(before, after);
}
