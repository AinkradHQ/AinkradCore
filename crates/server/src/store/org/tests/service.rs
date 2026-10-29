//! The org service and its integrity (E6.1): departments, teams and seats are audited; the org
//! and the issues pointing into it never cross companies, and reporting lines have no cycle,
//! through the service (typed reasons) or a raw write (triggers).

use ainkrad_core::audit::AuditActor;
use ainkrad_core::work::{
    Actor, IssueKind, IssueState, IssueTransition, NewIssue, NewProject, NextActor, ProjectMode,
    SprintApproval, UserId,
};

use super::*;
use crate::store::work::{
    IssueTransitionError, create_issue, create_project, transition_issue, update_issue,
};

const BY: AuditActor = AuditActor::User(UserId(1));

fn is_raised(e: &Error, message: &str) -> bool {
    matches!(e, Error::Database(d) if d.message() == message)
}

async fn actions(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar("SELECT action FROM audit_events ORDER BY seq")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn departments_teams_and_seats_are_audited_and_charted() {
    let db = db().await;
    let pool = &db.pool;
    let c = create_company(pool, "A").await.unwrap();
    let eng = add_department(pool, c.id, "Engineering", BY).await.unwrap();
    let mkt = add_department(pool, c.id, "Marketing", BY).await.unwrap();
    let dup = add_department(pool, c.id, "Engineering", BY).await;
    assert!(
        matches!(dup, Err(OrgError::Db(ref e)) if is_constraint(e)),
        "{dup:?}"
    );
    let gone = add_department(pool, CompanyId(99), "X", BY).await;
    assert!(matches!(gone, Err(OrgError::NotFound)), "{gone:?}");
    let core = add_team(pool, eng.id, "Core", BY).await.unwrap();
    let po = create_agent(pool, &new_agent(c.id, "Po", OrgRole::None))
        .await
        .unwrap();

    seat_member(pool, core.id, po.id, TeamRole::Member, Some(3), BY)
        .await
        .unwrap();
    seat_member(pool, core.id, po.id, TeamRole::ProductOwner, Some(5), BY)
        .await
        .unwrap();
    assert_eq!(
        list_memberships(pool, core.id).await.unwrap()[0].team_role,
        TeamRole::ProductOwner,
        "a second add changes the seat"
    );
    let chart = org_chart(pool, c.id).await.unwrap().unwrap();
    assert_eq!(chart["departments"][0]["name"], "Engineering");
    assert_eq!(chart["departments"][1]["id"], mkt.id.0);
    let seat = &chart["departments"][0]["teams"][0]["members"][0];
    assert_eq!(
        (seat["agent_id"].as_i64(), seat["team_role"].as_str()),
        (Some(po.id.0), Some("product_owner"))
    );
    assert_eq!(seat["capacity"], 5);
    assert_eq!(chart["agents"][0]["name"], "Po");
    assert!(org_chart(pool, CompanyId(99)).await.unwrap().is_none());

    assert!(unseat_member(pool, core.id, po.id, BY).await.unwrap());
    assert!(!unseat_member(pool, core.id, po.id, BY).await.unwrap());
    assert_eq!(
        actions(pool).await,
        [
            "department.added",
            "department.added",
            "team.added",
            "team.member_seated",
            "team.member_seated",
            "team.member_unseated"
        ]
    );
}

#[tokio::test]
async fn reporting_lines_stay_in_the_company_without_cycles() {
    let db = db().await;
    let pool = &db.pool;
    let a = create_company(pool, "A").await.unwrap();
    let b = create_company(pool, "B").await.unwrap();
    let ceo = create_agent(pool, &new_agent(a.id, "Ceo", OrgRole::Ceo))
        .await
        .unwrap();
    let lead = create_agent(pool, &new_agent(a.id, "Lead", OrgRole::None))
        .await
        .unwrap();
    let dev = create_agent(pool, &new_agent(a.id, "Dev", OrgRole::None))
        .await
        .unwrap();
    let outsider = create_agent(pool, &new_agent(b.id, "Out", OrgRole::None))
        .await
        .unwrap();
    set_manager(pool, lead.id, Some(ceo.id), BY).await.unwrap();
    let dev = set_manager(pool, dev.id, Some(lead.id), BY).await.unwrap();
    assert_eq!(dev.reports_to, Some(lead.id));

    for (agent, manager) in [(ceo.id, dev.id), (ceo.id, ceo.id)] {
        let e = set_manager(pool, agent, Some(manager), BY).await;
        assert!(matches!(e, Err(OrgError::Cycle)), "{e:?}");
    }
    let e = set_manager(pool, dev.id, Some(outsider.id), BY).await;
    assert!(matches!(e, Err(OrgError::OtherCompany)), "{e:?}");

    // Past the service, the triggers hold.
    let mut raw = get_agent(pool, ceo.id).await.unwrap().unwrap();
    raw.reports_to = Some(dev.id);
    let e = update_agent(pool, &raw).await.unwrap_err();
    assert!(is_raised(&e, "reporting cycle"), "{e}");
    raw.reports_to = Some(ceo.id);
    let e = update_agent(pool, &raw).await.unwrap_err();
    assert!(is_raised(&e, "reporting cycle"), "{e}");
    raw.reports_to = Some(outsider.id);
    let e = update_agent(pool, &raw).await.unwrap_err();
    assert!(is_raised(&e, "manager belongs to another company"), "{e}");
    let hired = NewAgent {
        reports_to: Some(outsider.id),
        ..new_agent(a.id, "New", OrgRole::None)
    };
    let e = create_agent(pool, &hired).await.unwrap_err();
    assert!(is_raised(&e, "manager belongs to another company"), "{e}");
    let e = sqlx::query("UPDATE agents SET company_id = ? WHERE id = ?")
        .bind(b.id.0)
        .bind(dev.id.0)
        .execute(pool)
        .await
        .unwrap_err();
    assert!(
        is_raised(&e, "an agent cannot move to another company"),
        "{e}"
    );
}

#[tokio::test]
async fn seats_and_teams_stay_in_their_company() {
    let db = db().await;
    let pool = &db.pool;
    let a = create_company(pool, "A").await.unwrap();
    let b = create_company(pool, "B").await.unwrap();
    let eng = add_department(pool, a.id, "Engineering", BY).await.unwrap();
    let ops = add_department(pool, a.id, "Ops", BY).await.unwrap();
    let theirs = add_department(pool, b.id, "Engineering", BY).await.unwrap();
    let core = add_team(pool, eng.id, "Core", BY).await.unwrap();
    let outsider = create_agent(pool, &new_agent(b.id, "Out", OrgRole::None))
        .await
        .unwrap();

    let e = seat_member(pool, core.id, outsider.id, TeamRole::Member, None, BY).await;
    assert!(matches!(e, Err(OrgError::OtherCompany)), "{e:?}");
    let seat = TeamMembership {
        team_id: core.id,
        agent_id: outsider.id,
        team_role: TeamRole::Member,
    };
    let e = create_membership(pool, &seat).await.unwrap_err();
    assert!(is_raised(&e, "agent belongs to another company"), "{e}");

    let mut moved = core.clone();
    moved.department_id = ops.id;
    assert!(
        update_team(pool, &moved).await.unwrap(),
        "within the company"
    );
    moved.department_id = theirs.id;
    let e = update_team(pool, &moved).await.unwrap_err();
    assert!(
        is_raised(&e, "a team cannot move to another company"),
        "{e}"
    );
    let e = sqlx::query("UPDATE departments SET company_id = ? WHERE id = ?")
        .bind(b.id.0)
        .bind(eng.id.0)
        .execute(pool)
        .await
        .unwrap_err();
    assert!(
        is_raised(&e, "a department cannot move to another company"),
        "{e}"
    );
}

#[tokio::test]
async fn issue_owners_and_next_actors_stay_in_the_projects_company() {
    let db = db().await;
    let pool = &db.pool;
    let a = create_company(pool, "A").await.unwrap();
    let b = create_company(pool, "B").await.unwrap();
    let ours = create_agent(pool, &new_agent(a.id, "Dev", OrgRole::None))
        .await
        .unwrap();
    let theirs = create_agent(pool, &new_agent(b.id, "Out", OrgRole::None))
        .await
        .unwrap();
    let p = NewProject {
        company_id: a.id,
        team_id: None,
        name: "P".to_owned(),
        key: "PRJ".to_owned(),
        mode: ProjectMode::Kanban,
        sprint_approval: SprintApproval::Owner,
    };
    let p = create_project(pool, &p).await.unwrap();
    let new = |next: AgentId, owner: Option<Actor>| NewIssue {
        project_id: p.id,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "t".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner,
        next_actor: Some(NextActor::Agent(next)),
        points: None,
        sprint_id: None,
    };
    let e = create_issue(pool, &new(theirs.id, None)).await.unwrap_err();
    assert!(
        is_raised(&e, "next actor belongs to another company"),
        "{e}"
    );
    let owner = Some(Actor::Agent(theirs.id));
    let e = create_issue(pool, &new(ours.id, owner)).await.unwrap_err();
    assert!(is_raised(&e, "owner belongs to another company"), "{e}");

    let mut i = create_issue(pool, &new(ours.id, None)).await.unwrap();
    i.owner = owner;
    let e = update_issue(pool, &i).await.unwrap_err();
    assert!(is_raised(&e, "owner belongs to another company"), "{e}");
    let to = IssueTransition::Reassign {
        next: NextActor::Agent(theirs.id),
    };
    let e = transition_issue(pool, i.id, &to, BY).await.unwrap_err();
    assert!(
        matches!(&e, IssueTransitionError::Db(e) if is_raised(e, "next actor belongs to another company")),
        "{e}"
    );
}
