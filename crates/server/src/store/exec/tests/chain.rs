//! The escalation chain (E6.3): a failing run hands its issue up the issue's team, developer
//! → team lead → product owner → the admin, waking each in turn, and never the CEO or CTO;
//! a cross-department issue reaches the CEO (the CTO without one) before the admin.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::exec::RunEvent;
use ainkrad_core::org::TeamRole;
use ainkrad_core::work::IssueTransition;

use super::wake::{dispatch, runner};
use super::*;
use crate::store::org::{add_department, add_team, seat_member, set_cross_department};
use crate::store::work::{get_issue, transition_issue};

const NOW: &str = "2026-10-21T10:00:00.000Z";
const BY: AuditActor = AuditActor::System;

struct Org {
    ceo: AgentId,
    cto: AgentId,
    po: AgentId,
    lead: AgentId,
    dev: AgentId,
    project: ainkrad_core::work::ProjectId,
}

async fn org(pool: &SqlitePool) -> Org {
    let c = create_company(pool, "A").await.unwrap().id;
    let mut ids = vec![];
    for (name, org_role) in [
        ("Ceo", OrgRole::Ceo),
        ("Cto", OrgRole::Cto),
        ("Po", OrgRole::None),
        ("Lead", OrgRole::None),
        ("Dev", OrgRole::None),
    ] {
        let a = NewAgent {
            company_id: c,
            name: name.to_owned(),
            role: name.to_owned(),
            org_role,
            reports_to: None,
            harness: Harness::Claude,
            model: "opus".to_owned(),
            runner_tags: vec![],
            status: AgentStatus::Active,
        };
        ids.push(create_agent(pool, &a).await.unwrap().id);
    }
    let d = add_department(pool, c, "Engineering", BY).await.unwrap();
    let t = add_team(pool, d.id, "Core", BY).await.unwrap();
    for (agent, role) in [
        (ids[2], TeamRole::ProductOwner),
        (ids[3], TeamRole::TeamLead),
        (ids[4], TeamRole::Member),
    ] {
        seat_member(pool, t.id, agent, role, None, BY)
            .await
            .unwrap();
    }
    // Reporting lines up to the CEO are the org chart's; escalation does not follow them.
    for (agent, manager) in [(ids[4], ids[3]), (ids[3], ids[1]), (ids[2], ids[0])] {
        crate::store::org::set_manager(pool, agent, Some(manager), BY)
            .await
            .unwrap();
    }
    let first = issue(pool, c).await;
    let project = get_issue(pool, first).await.unwrap().unwrap().project_id;
    sqlx::query("UPDATE projects SET team_id = ? WHERE id = ?")
        .bind(t.id.0)
        .bind(project.0)
        .execute(pool)
        .await
        .unwrap();
    Org {
        ceo: ids[0],
        cto: ids[1],
        po: ids[2],
        lead: ids[3],
        dev: ids[4],
        project,
    }
}

/// A new issue of the team's project handed to `to`, which wakes it.
async fn handed(pool: &SqlitePool, o: &Org, to: AgentId) -> IssueId {
    let new = NewIssue {
        project_id: o.project,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Work".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Human(UserId(1))),
        points: None,
        sprint_id: None,
    };
    let i = create_issue(pool, &new).await.unwrap().id;
    let reassign = IssueTransition::Reassign {
        next: NextActor::Agent(to),
    };
    transition_issue(pool, i, &reassign, BY).await.unwrap();
    i
}

/// Dispatches the next wake, checks whose it is, and ends its run at its token cap (no retry
/// left: it escalates); returns who the issue went to.
async fn fail(pool: &SqlitePool, mac: RunnerId, who: AgentId, i: IssueId) -> Option<NextActor> {
    let run = dispatch(pool, mac, NOW).await.expect("a wake is due");
    assert_eq!((run.agent_id, run.issue_id), (who, Some(i)));
    let by = AuditActor::Runner(mac);
    start_run(pool, run.id, by, None, NOW).await.unwrap();
    transition_run(pool, run.id, by, &RunEvent::TokenCap, NOW)
        .await
        .unwrap();
    get_issue(pool, i).await.unwrap().unwrap().next_actor
}

async fn woken(pool: &SqlitePool, agent: AgentId) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM wake_requests WHERE agent_id = ?")
        .bind(agent.0)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn escalation_climbs_the_team_to_the_admin_without_the_ceo() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let mac = runner(pool, "mac").await;
    let i = handed(pool, &o, o.dev).await;
    let agent = |a| Some(NextActor::Agent(a));
    assert_eq!(fail(pool, mac, o.dev, i).await, agent(o.lead), "dev → lead");
    assert_eq!(fail(pool, mac, o.lead, i).await, agent(o.po), "lead → PO");
    assert_eq!(
        fail(pool, mac, o.po, i).await,
        Some(NextActor::Human(ESCALATION_USER)),
        "PO → Ahmed"
    );
    assert!(
        dispatch(pool, mac, NOW).await.is_none(),
        "nothing left to run"
    );
    assert_eq!((woken(pool, o.ceo).await, woken(pool, o.cto).await), (0, 0));
    let sources: Vec<String> =
        sqlx::query_scalar("SELECT source FROM wake_requests WHERE issue_id = ? ORDER BY id")
            .bind(i.0)
            .fetch_all(pool)
            .await
            .unwrap();
    assert_eq!(sources, ["assignment", "escalation", "escalation"]);

    // A seat whose agent cannot run is skipped: with the lead paused, dev goes to the PO.
    sqlx::query("UPDATE agents SET status = 'paused' WHERE id = ?")
        .bind(o.lead.0)
        .execute(pool)
        .await
        .unwrap();
    let j = handed(pool, &o, o.dev).await;
    assert_eq!(fail(pool, mac, o.dev, j).await, agent(o.po));
}

#[tokio::test]
async fn a_cross_department_issue_reaches_the_ceo_then_the_cto() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let mac = runner(pool, "mac").await;
    let i = handed(pool, &o, o.po).await;
    assert!(set_cross_department(pool, i, true, BY).await.unwrap());
    assert_eq!(
        fail(pool, mac, o.po, i).await,
        Some(NextActor::Agent(o.ceo))
    );
    assert_eq!(
        fail(pool, mac, o.ceo, i).await,
        Some(NextActor::Human(ESCALATION_USER)),
        "past the CEO, Ahmed"
    );

    sqlx::query("UPDATE agents SET status = 'paused' WHERE id = ?")
        .bind(o.ceo.0)
        .execute(pool)
        .await
        .unwrap();
    let j = handed(pool, &o, o.po).await;
    set_cross_department(pool, j, true, BY).await.unwrap();
    assert_eq!(
        fail(pool, mac, o.po, j).await,
        Some(NextActor::Agent(o.cto))
    );
}

/// An issue of a project with no team (an intake request) goes straight to the admin.
#[tokio::test]
async fn without_a_team_escalation_goes_to_the_admin() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    sqlx::query("UPDATE projects SET team_id = NULL")
        .execute(pool)
        .await
        .unwrap();
    let mac = runner(pool, "mac").await;
    let i = handed(pool, &o, o.dev).await;
    assert_eq!(
        fail(pool, mac, o.dev, i).await,
        Some(NextActor::Human(ESCALATION_USER))
    );
}
