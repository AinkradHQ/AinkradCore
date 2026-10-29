//! Routing a request to an existing project: no project is made, the kickoff lands in it
//! waiting on its team's product owner and carries the request's requirement, so plan-first and
//! the requirement's planners work as for a new project; the project's spec, profile and own
//! requirement are left alone.

use citadel_core::work::RequirementState;

use super::intake::{Org, org, route};
use super::*;
use crate::store::org::{add_team, is_cross_department};

const BY: AuditActor = AuditActor::User(ADMIN);

/// R-1 routed to Engineering as project WRK: the project a later request goes to.
async fn existing(pool: &SqlitePool, o: &Org) -> Project {
    let first = submit_intake(pool, o.company, "Workan", "The product", BY)
        .await
        .unwrap();
    route_intake(
        pool,
        first.id,
        Actor::Agent(o.ceo),
        &[route(o.eng, "WRK", ProjectMode::Scrum)],
    )
    .await
    .unwrap()
    .remove(0)
    .project
}

async fn project_requirement(pool: &SqlitePool, p: ProjectId) -> Option<i64> {
    sqlx::query_scalar("SELECT requirement_id FROM projects WHERE id = ?")
        .bind(p.0)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_request_about_an_existing_project_is_kicked_off_there() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let wrk = existing(pool, &o).await;
    let (spec, profile) = (
        project_spec(pool, wrk.id).await.unwrap(),
        project_profile(pool, wrk.id).await.unwrap(),
    );
    let own = project_requirement(pool, wrk.id).await;
    let projects = list_projects(pool, o.company).await.unwrap().len();

    let req = submit_intake(pool, o.company, "Invoices", "PDF export", BY)
        .await
        .unwrap();
    let r = req.requirement_id.unwrap();
    let routed = route_intake(
        pool,
        req.id,
        Actor::Agent(o.ceo),
        &[Route::Existing(wrk.id)],
    )
    .await
    .unwrap();
    let [one] = &routed[..] else {
        panic!("one route")
    };
    assert!(!one.created);
    assert_eq!((one.project.id, one.product_owner), (wrk.id, o.eng_po));
    assert_eq!(
        list_projects(pool, o.company).await.unwrap().len(),
        projects
    );
    let kickoff = get_issue(pool, one.kickoff.id).await.unwrap().unwrap();
    assert_eq!(kickoff.project_id, wrk.id);
    assert_eq!(kickoff.title, "Kick off Invoices");
    assert_eq!(kickoff.next_actor, Some(NextActor::Agent(o.eng_po)));
    assert_eq!(kickoff.requirement_id, Some(r));
    assert_eq!(
        is_cross_department(pool, kickoff.id).await.unwrap(),
        Some(false)
    );
    let in_wrk: i64 = sqlx::query_scalar("SELECT count(*) FROM issues WHERE requirement_id = ?")
        .bind(r.0)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(in_wrk, 2, "the request and exactly one kickoff");
    let woken: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM wake_requests WHERE agent_id = ? AND issue_id = ?",
    )
    .bind(o.eng_po.0)
    .bind(kickoff.id.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(woken, 1);
    // The requirement is handed to the product owner; the project keeps what it had.
    let q = get_requirement(pool, r).await.unwrap().unwrap();
    assert_eq!(
        (q.owner_agent_id, q.owner_issue_id, q.state),
        (Some(o.eng_po), Some(kickoff.id), RequirementState::Planning)
    );
    assert_eq!(project_spec(pool, wrk.id).await.unwrap(), spec);
    assert_eq!(project_profile(pool, wrk.id).await.unwrap(), profile);
    assert_eq!(project_requirement(pool, wrk.id).await, own);
    assert_ne!(own, Some(r.0));

    // Plan-first: the product owner plans it in the project; the dev's task waits.
    let task = PlannedTask {
        epic: None,
        title: "PDF renderer",
        body: "",
        points: Some(3),
        assignee: Some(o.dev),
    };
    let epic = NewPlanEpic {
        project: wrk.id,
        title: "Export",
        tasks: vec![task],
    };
    let planned = plan_requirement(pool, r, o.eng_po, &[epic], &[])
        .await
        .unwrap();
    assert!(planned.problems.is_empty(), "{:?}", planned.problems);
    let t = planned.tasks[0];
    assert_eq!(
        get_issue(pool, t).await.unwrap().unwrap().requirement_id,
        Some(r)
    );
    let held = plan_hold(pool, t, o.dev).await.unwrap().unwrap();
    assert!(held.contains("R-2"), "{held}");
    assert_eq!(plan_hold(pool, kickoff.id, o.eng_po).await.unwrap(), None);
    let now: String = sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')")
        .fetch_one(pool)
        .await
        .unwrap();
    // WRK asks the owner: the plan waits on a person, as for a new project.
    let s = submit_plan(pool, r, o.eng_po, Some(kickoff.id), &now)
        .await
        .unwrap();
    assert!(matches!(s, Submitted::Pending(_)), "{s:?}");
    let e = submit_plan(pool, r, o.dev, None, &now).await;
    assert!(matches!(e, Err(RequirementError::NotPlanner)), "{e:?}");
}

#[tokio::test]
async fn under_the_product_owner_policy_an_existing_projects_plan_is_approved_at_once() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let mut wrk = existing(pool, &o).await;
    wrk.sprint_approval = SprintApproval::ProductOwner;
    update_project(pool, &wrk).await.unwrap();
    let req = submit_intake(pool, o.company, "Invoices", "", BY)
        .await
        .unwrap();
    let r = req.requirement_id.unwrap();
    route_intake(
        pool,
        req.id,
        Actor::Agent(o.ceo),
        &[Route::Existing(wrk.id)],
    )
    .await
    .unwrap();
    let epic = NewPlanEpic {
        project: wrk.id,
        title: "Export",
        tasks: vec![PlannedTask {
            epic: None,
            title: "PDF",
            body: "",
            points: Some(1),
            assignee: Some(o.dev),
        }],
    };
    plan_requirement(pool, r, o.eng_po, &[epic], &[])
        .await
        .unwrap();
    let now: String = sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')")
        .fetch_one(pool)
        .await
        .unwrap();
    let done = submit_plan(pool, r, o.eng_po, None, &now).await.unwrap();
    assert!(
        matches!(done, Submitted::Approved(1)),
        "the intake project's owner policy does not count: {done:?}"
    );
}

#[tokio::test]
async fn mixed_routes_make_only_the_new_projects() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let wrk = existing(pool, &o).await;
    let req = submit_intake(pool, o.company, "Launch", "", BY)
        .await
        .unwrap();
    let routes = [
        Route::Existing(wrk.id),
        route(o.mkt, "LCH", ProjectMode::Kanban),
    ];
    let routed = route_intake(pool, req.id, Actor::Agent(o.ceo), &routes)
        .await
        .unwrap();
    let made: Vec<_> = routed
        .iter()
        .map(|r| (r.project.key.as_str(), r.created, r.product_owner))
        .collect();
    assert_eq!(made, [("WRK", false, o.eng_po), ("LCH", true, o.mkt_po)]);
    for r in &routed {
        assert_eq!(r.kickoff.requirement_id, req.requirement_id);
        assert_eq!(
            is_cross_department(pool, r.kickoff.id).await.unwrap(),
            Some(true)
        );
    }
    // The first route's product owner owns the requirement.
    let q = get_requirement(pool, req.requirement_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(q.owner_agent_id, Some(o.eng_po));
    // A new route's key is still checked; an existing project's is not.
    let next = submit_intake(pool, o.company, "More", "", BY)
        .await
        .unwrap();
    let e = route_intake(
        pool,
        next.id,
        Actor::Agent(o.ceo),
        &[
            Route::Existing(wrk.id),
            route(o.eng, "WRK", ProjectMode::Scrum),
        ],
    )
    .await;
    assert!(matches!(e, Err(IntakeError::KeyTaken(_))), "{e:?}");
}

#[tokio::test]
async fn routing_to_an_existing_project_is_checked() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let wrk = existing(pool, &o).await;
    let req = submit_intake(pool, o.company, "Thing", "", BY)
        .await
        .unwrap();
    let ceo = Actor::Agent(o.ceo);
    let refused = |r: Result<Vec<Routed>, IntakeError>| match r {
        Err(e) => e,
        Ok(_) => panic!("routed"),
    };
    // Another company's project, the intake project, a missing one, or one named twice.
    let other = create_company(pool, "B").await.unwrap().id;
    let theirs = create_project(pool, &new_project(other, "THR"))
        .await
        .unwrap();
    for p in [theirs.id, req.project_id, ProjectId(999)] {
        let e = refused(route_intake(pool, req.id, ceo, &[Route::Existing(p)]).await);
        assert!(matches!(e, IntakeError::NotRoutable(q) if q == p), "{e}");
    }
    let twice = [Route::Existing(wrk.id), Route::Existing(wrk.id)];
    let e = refused(route_intake(pool, req.id, ceo, &twice).await);
    assert!(matches!(e, IntakeError::NotRoutable(_)), "{e}");
    // No team, or a team without a product owner.
    let loose = create_project(pool, &new_project(o.company, "LOO"))
        .await
        .unwrap();
    let e = refused(route_intake(pool, req.id, ceo, &[Route::Existing(loose.id)]).await);
    assert!(
        matches!(e, IntakeError::ProjectNoTeam(p) if p == loose.id),
        "{e}"
    );
    let headless = add_team(pool, o.eng, "Headless", BY).await.unwrap();
    let orphan = NewProject {
        team_id: Some(headless.id),
        ..new_project(o.company, "ORP")
    };
    let orphan = create_project(pool, &orphan).await.unwrap();
    let e = refused(route_intake(pool, req.id, ceo, &[Route::Existing(orphan.id)]).await);
    assert!(
        matches!(e, IntakeError::NoProductOwner(t) if t == headless.id),
        "{e}"
    );
    // Nothing was routed: the request is still open, then routes once.
    let open = get_issue(pool, req.id).await.unwrap().unwrap();
    assert!(!open.state.is_terminal());
    route_intake(pool, req.id, ceo, &[Route::Existing(wrk.id)])
        .await
        .unwrap();
    let e = refused(route_intake(pool, req.id, ceo, &[Route::Existing(wrk.id)]).await);
    assert!(matches!(e, IntakeError::Closed), "{e}");
}
