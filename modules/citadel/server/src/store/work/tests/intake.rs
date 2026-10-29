//! CEO intake (E6.2): a request waits on the CEO (or the admin without one), is routed to
//! departments as projects kicked off by each team's product owner, and after that the work
//! flows inside the teams: the CEO is not woken again.

use citadel_core::org::{DepartmentId, TeamRole};
use citadel_core::work::IssueTransition;

use super::*;
use crate::store::org::{add_department, add_team, get_team, is_cross_department, seat_member};

const BY: AuditActor = AuditActor::User(ADMIN);

pub(super) struct Org {
    pub(super) company: CompanyId,
    pub(super) ceo: AgentId,
    pub(super) eng: DepartmentId,
    pub(super) mkt: DepartmentId,
    pub(super) eng_po: AgentId,
    pub(super) mkt_po: AgentId,
    pub(super) dev: AgentId,
}

/// A company with a CEO, Engineering (a team with a product owner and a developer) and
/// Marketing (a team with a product owner and a writer).
pub(super) async fn org(pool: &SqlitePool) -> Org {
    let company = create_company(pool, "A").await.unwrap().id;
    let ceo = NewAgent {
        company_id: company,
        name: "Ceo".to_owned(),
        role: "CEO".to_owned(),
        org_role: OrgRole::Ceo,
        reports_to: None,
        harness: Harness::Claude,
        model: "opus".to_owned(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    let ceo = create_agent(pool, &ceo).await.unwrap().id;
    let mut seats = vec![];
    for (dept, team, people) in [
        ("Engineering", "Core", ["Eng PO", "Dev"]),
        ("Marketing", "Brand", ["Mkt PO", "Writer"]),
    ] {
        let d = add_department(pool, company, dept, BY).await.unwrap();
        let t = add_team(pool, d.id, team, BY).await.unwrap();
        let (po, member) = (
            agent(pool, company, people[0]).await,
            agent(pool, company, people[1]).await,
        );
        seat_member(pool, t.id, po, TeamRole::ProductOwner, None, BY)
            .await
            .unwrap();
        seat_member(pool, t.id, member, TeamRole::Member, None, BY)
            .await
            .unwrap();
        seats.push((d.id, po, member));
    }
    Org {
        company,
        ceo,
        eng: seats[0].0,
        mkt: seats[1].0,
        eng_po: seats[0].1,
        mkt_po: seats[1].1,
        dev: seats[0].2,
    }
}

pub(super) fn route(department: DepartmentId, key: &str, mode: ProjectMode) -> Route {
    Route::New {
        department,
        team: None,
        name: format!("Project {key}"),
        key: key.to_owned(),
        mode,
    }
}

/// (issue, source) of each wake of the agent, oldest first.
async fn wakes(pool: &SqlitePool, agent: AgentId) -> Vec<(Option<i64>, String)> {
    sqlx::query_as("SELECT issue_id, source FROM wake_requests WHERE agent_id = ? ORDER BY id")
        .bind(agent.0)
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn department_of(pool: &SqlitePool, p: &Project) -> DepartmentId {
    let team = get_team(pool, p.team_id.unwrap()).await.unwrap().unwrap();
    team.department_id
}

#[tokio::test]
async fn non_tech_and_engineering_requests_land_in_different_departments() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let campaign = submit_intake(pool, o.company, "Launch campaign", "For v1", BY)
        .await
        .unwrap();
    let api = submit_intake(pool, o.company, "Public API", "REST", BY)
        .await
        .unwrap();
    assert_eq!(campaign.project_id, api.project_id, "one intake project");
    assert_eq!(
        get_project(pool, campaign.project_id)
            .await
            .unwrap()
            .unwrap()
            .key,
        INTAKE_KEY
    );
    assert_eq!(campaign.next_actor, Some(NextActor::Agent(o.ceo)));
    let ceo_wakes = vec![
        (Some(campaign.id.0), "assignment".to_owned()),
        (Some(api.id.0), "assignment".to_owned()),
    ];
    assert_eq!(wakes(pool, o.ceo).await, ceo_wakes);

    let as_ceo = Actor::Agent(o.ceo);
    let mkt = route_intake(
        pool,
        campaign.id,
        as_ceo,
        &[route(o.mkt, "MKT", ProjectMode::Kanban)],
    )
    .await
    .unwrap();
    let eng = route_intake(
        pool,
        api.id,
        as_ceo,
        &[route(o.eng, "API", ProjectMode::Scrum)],
    )
    .await
    .unwrap();
    let (mkt, eng) = (&mkt[0], &eng[0]);
    assert_eq!(department_of(pool, &mkt.project).await, o.mkt);
    assert_eq!(department_of(pool, &eng.project).await, o.eng);
    assert_eq!((mkt.product_owner, eng.product_owner), (o.mkt_po, o.eng_po));
    assert_eq!(mkt.kickoff.next_actor, Some(NextActor::Agent(o.mkt_po)));
    assert_eq!(
        is_cross_department(pool, mkt.kickoff.id).await.unwrap(),
        Some(false)
    );
    assert_eq!(
        project_spec(pool, eng.project.id).await.unwrap().unwrap(),
        "Public API\n\nREST"
    );
    assert_eq!(
        wakes(pool, o.eng_po).await,
        [(Some(eng.kickoff.id.0), "assignment".to_owned())]
    );
    for i in [campaign.id, api.id] {
        let closed = get_issue(pool, i).await.unwrap().unwrap();
        assert_eq!((closed.state, closed.next_actor), (IssueState::Done, None));
    }
    let again = route_intake(
        pool,
        api.id,
        as_ceo,
        &[route(o.eng, "X", ProjectMode::Scrum)],
    )
    .await;
    assert!(matches!(again, Err(IntakeError::Closed)), "{again:?}");
    let routed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'intake.routed'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(routed, 2);

    // Downstream work flows inside the team; the CEO is not woken again.
    let k = eng.kickoff.id;
    let to_dev = IssueTransition::Reassign {
        next: NextActor::Agent(o.dev),
    };
    for t in [to_dev, IssueTransition::Start, IssueTransition::Done] {
        transition_issue(pool, k, &t, AuditActor::Agent(o.dev))
            .await
            .unwrap();
    }
    assert_eq!(wakes(pool, o.ceo).await, ceo_wakes);
}

#[tokio::test]
async fn routing_is_checked() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let other = create_company(pool, "B").await.unwrap().id;
    let theirs = add_department(pool, other, "Engineering", BY)
        .await
        .unwrap()
        .id;
    let empty = add_department(pool, o.company, "Ops", BY).await.unwrap();
    let headless = add_team(pool, o.eng, "Headless", BY).await.unwrap();
    let req = submit_intake(pool, o.company, "Thing", "", BY)
        .await
        .unwrap();
    let ceo = Actor::Agent(o.ceo);
    let check = |r: Result<Vec<Routed>, IntakeError>| match r {
        Err(e) => e,
        Ok(_) => panic!("routed"),
    };
    let ok = route(o.eng, "ENG", ProjectMode::Scrum);
    let e = check(
        route_intake(
            pool,
            req.id,
            Actor::Agent(o.eng_po),
            std::slice::from_ref(&ok),
        )
        .await,
    );
    assert!(matches!(e, IntakeError::NotYours), "{e}");
    assert!(matches!(
        check(route_intake(pool, req.id, ceo, &[]).await),
        IntakeError::Routes(0)
    ));
    let e = check(route_intake(pool, req.id, ceo, &[route(theirs, "T", ProjectMode::Scrum)]).await);
    assert!(matches!(e, IntakeError::Elsewhere), "{e}");
    let e = check(
        route_intake(
            pool,
            req.id,
            ceo,
            &[route(empty.id, "O", ProjectMode::Scrum)],
        )
        .await,
    );
    assert!(matches!(e, IntakeError::NoTeam(d) if d == empty.id), "{e}");
    let pick = Route::New {
        department: o.eng,
        team: Some(headless.id),
        name: "Project ENG".to_owned(),
        key: "ENG".to_owned(),
        mode: ProjectMode::Scrum,
    };
    let e = check(route_intake(pool, req.id, ceo, &[pick]).await);
    assert!(
        matches!(e, IntakeError::NoProductOwner(t) if t == headless.id),
        "{e}"
    );
    // A failed route leaves nothing behind: the request is still open.
    let e = check(
        route_intake(
            pool,
            req.id,
            ceo,
            &[ok.clone(), route(empty.id, "O", ProjectMode::Scrum)],
        )
        .await,
    );
    assert!(matches!(e, IntakeError::NoTeam(_)), "{e}");
    assert_eq!(
        list_projects(pool, o.company).await.unwrap().len(),
        1,
        "only intake"
    );

    let p = create_project(pool, &new_project(o.company, "CIT"))
        .await
        .unwrap();
    let plain = NewIssue {
        next_actor: Some(NextActor::Agent(o.ceo)),
        ..new_issue(p.id, "plain")
    };
    let plain = create_issue(pool, &plain).await.unwrap();
    let e = check(route_intake(pool, plain.id, ceo, &[ok]).await);
    assert!(matches!(e, IntakeError::NotIntake), "{e}");
}

/// With no active CEO a request waits on the admin, who routes it; both departments of one
/// request get a project.
#[tokio::test]
async fn without_a_ceo_the_admin_routes() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    sqlx::query("UPDATE agents SET status = 'paused' WHERE id = ?")
        .bind(o.ceo.0)
        .execute(pool)
        .await
        .unwrap();
    let req = submit_intake(pool, o.company, "Launch", "", BY)
        .await
        .unwrap();
    assert_eq!(req.next_actor, Some(NextActor::Human(INTAKE_FALLBACK_USER)));
    assert!(wakes(pool, o.ceo).await.is_empty());
    let both = [
        route(o.eng, "ENG", ProjectMode::Scrum),
        route(o.mkt, "MKT", ProjectMode::Kanban),
    ];
    let routed = route_intake(pool, req.id, Actor::Human(ADMIN), &both)
        .await
        .unwrap();
    assert_eq!(routed.len(), 2);
    for r in &routed {
        let cross = is_cross_department(pool, r.kickoff.id).await.unwrap();
        assert_eq!(
            cross,
            Some(true),
            "a request for two departments crosses them"
        );
    }
    assert_eq!(
        (routed[0].product_owner, routed[1].product_owner),
        (o.eng_po, o.mkt_po)
    );
}

/// A user project already keyed `INTAKE` keeps its key: the intake project takes the next free
/// one. Route keys are checked up front, with typed reasons and nothing written.
#[tokio::test]
async fn intake_and_route_keys_never_collide() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    for key in [INTAKE_KEY, "INTAKE2"] {
        create_project(pool, &new_project(o.company, key))
            .await
            .unwrap();
    }
    let req = submit_intake(pool, o.company, "Launch", "", BY)
        .await
        .unwrap();
    let intake = get_project(pool, req.project_id).await.unwrap().unwrap();
    assert_eq!(intake.key, "INTAKE3");

    let ceo = Actor::Agent(o.ceo);
    let mode = ProjectMode::Scrum;
    for (routes, want) in [
        (vec![route(o.eng, "lower", mode)], "BadKey"),
        (vec![route(o.eng, "9LIVES", mode)], "BadKey"),
        (vec![route(o.eng, "WAYTOOLONGKEY", mode)], "BadKey"),
        (vec![route(o.eng, INTAKE_KEY, mode)], "KeyTaken"),
        (vec![route(o.eng, "INTAKE3", mode)], "KeyTaken"),
        (
            vec![route(o.eng, "DUP", mode), route(o.mkt, "DUP", mode)],
            "KeyTaken",
        ),
    ] {
        let e = route_intake(pool, req.id, ceo, &routes).await.unwrap_err();
        assert!(format!("{e:?}").starts_with(want), "{e:?}");
    }
    assert_eq!(list_projects(pool, o.company).await.unwrap().len(), 3);
    route_intake(pool, req.id, ceo, &[route(o.eng, "API", mode)])
        .await
        .unwrap();
}
