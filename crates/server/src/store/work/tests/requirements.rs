//! Requirements and plan-first (E15.10): an intake is a requirement whose projects, epics,
//! issues and subtasks carry it; dev work waits for its approved plan under either sprint
//! policy; the tree's numbers; scope changed after approval shows in the diff.

use ainkrad_core::exec::{NewRunner, NewWakeRequest, WakeSource};
use ainkrad_core::gov::ApprovalKind;
use ainkrad_core::org::Harness;
use ainkrad_core::work::{Issue, IssueTransition, RequirementState};

use super::intake::{Org, org, route};
use super::*;
use crate::store::exec::{create_runner, dispatch_next, enqueue_wake};
use crate::store::gov::{decide_approval, list_approvals};

const BY: AuditActor = AuditActor::User(ADMIN);

async fn now(pool: &SqlitePool) -> String {
    sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// R-1 routed to Engineering: its project, its kickoff (waiting on the product owner) and the
/// requirement.
async fn routed(pool: &SqlitePool, o: &Org) -> (Requirement, Project, Issue) {
    let intake = submit_intake(pool, o.company, "Phone alerts", "Buzz me", BY)
        .await
        .unwrap();
    let as_ceo = Actor::Agent(o.ceo);
    let r = &route_intake(
        pool,
        intake.id,
        as_ceo,
        &[route(o.eng, "ALR", ProjectMode::Scrum)],
    )
    .await
    .unwrap()[0];
    let req = get_issue(pool, r.kickoff.id).await.unwrap().unwrap();
    let req = get_requirement(pool, req.requirement_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    (req, r.project.clone(), r.kickoff.clone())
}

fn task<'a>(title: &'a str, points: Option<u32>, dev: AgentId) -> PlannedTask<'a> {
    PlannedTask {
        epic: None,
        title,
        body: "",
        points,
        assignee: Some(dev),
    }
}

/// One epic of `tasks` in `p`, filed by the product owner.
async fn plan_one(
    pool: &SqlitePool,
    r: &Requirement,
    p: &Project,
    po: AgentId,
    tasks: Vec<PlannedTask<'_>>,
) -> Planned {
    let epic = NewPlanEpic {
        project: p.id,
        title: "APNs delivery",
        tasks,
    };
    plan_requirement(pool, r.id, po, &[epic], &[])
        .await
        .unwrap()
}

#[tokio::test]
async fn an_intake_is_a_requirement_that_everything_routed_from_it_carries() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let (r, p, kickoff) = routed(pool, &o).await;
    assert_eq!((r.number, r.key()), (1, "R-1".to_owned()));
    assert_eq!(r.state, RequirementState::Planning);
    assert_eq!(r.requested_by, ADMIN);
    let intake = get_issue(pool, r.intake_issue_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(intake.requirement_id, Some(r.id));
    // Handed off: the product owner owns the thread now (#45), woken on its kickoff.
    assert_eq!(r.owner_agent_id, Some(o.eng_po));
    assert_eq!(r.owner_issue_id, Some(kickoff.id));
    assert_eq!(kickoff.requirement_id, Some(r.id));

    // An epic, an issue in it, a loose issue and a subtask all carry it.
    let epic = create_epic(pool, p.id, "E").await.unwrap();
    let mut new = new_issue(p.id, "In the epic");
    new.epic_id = Some(epic.id);
    let in_epic = create_issue(pool, &new).await.unwrap();
    let loose = create_issue(pool, &new_issue(p.id, "Loose")).await.unwrap();
    let sub = NewIssue {
        parent_id: Some(in_epic.id),
        kind: IssueKind::Subtask,
        ..new_issue(p.id, "Sub")
    };
    let sub = create_issue(pool, &sub).await.unwrap();
    for i in [&in_epic, &loose, &sub] {
        assert_eq!(i.requirement_id, Some(r.id), "{}", i.title);
    }
    // A second request is R-2; another company's start again at R-1.
    submit_intake(pool, o.company, "Audit log", "", BY)
        .await
        .unwrap();
    let all = list_requirements(pool, Some(o.company)).await.unwrap();
    assert_eq!(all.iter().map(|r| r.number).collect::<Vec<_>>(), [2, 1]);
    let other = create_company(pool, "B").await.unwrap().id;
    let b = submit_intake(pool, other, "Theirs", "", BY).await.unwrap();
    assert_eq!(
        get_requirement(pool, b.requirement_id.unwrap())
            .await
            .unwrap()
            .unwrap()
            .number,
        1
    );
}

/// A dev's wake on a task of the requirement before its plan is approved, and the planner's.
async fn wakes(pool: &SqlitePool, o: &Org, task: IssueId, kickoff: IssueId) {
    for (agent, issue, key) in [(o.dev, task, "dev"), (o.eng_po, kickoff, "po")] {
        let w = NewWakeRequest {
            agent_id: agent,
            issue_id: Some(issue),
            source: WakeSource::Assignment,
            reason: "go".to_owned(),
            idempotency_key: key.to_owned(),
            not_before: None,
        };
        enqueue_wake(pool, &w).await.unwrap();
    }
}

async fn runner(pool: &SqlitePool) -> ainkrad_core::exec::RunnerId {
    let r = NewRunner {
        name: "box".to_owned(),
        tags: vec![],
    };
    create_runner(pool, &r, "box").await.unwrap().id
}

#[tokio::test]
async fn dev_work_waits_for_the_owners_approval_of_the_complete_plan() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let (r, p, kickoff) = routed(pool, &o).await;
    let planned = plan_one(pool, &r, &p, o.eng_po, vec![task("Sender", None, o.dev)]).await;
    assert_eq!(planned.problems, ["ALR-2 has no estimate"]);
    let t = planned.tasks[0];
    let now = now(pool).await;

    // Incomplete, or not a planner: refused.
    let e = submit_plan(pool, r.id, o.eng_po, Some(kickoff.id), &now).await;
    assert!(matches!(e, Err(RequirementError::Incomplete(_))), "{e:?}");
    let e = submit_plan(pool, r.id, o.dev, None, &now).await;
    assert!(matches!(e, Err(RequirementError::NotPlanner)), "{e:?}");

    // Held: the dev's wake is skipped, the product owner's is not; start is refused.
    wakes(pool, &o, t, kickoff.id).await;
    let box_ = runner(pool).await;
    let mut served = vec![];
    while let Some(run) = dispatch_next(pool, box_, &[], &Harness::ALL, &now)
        .await
        .unwrap()
    {
        served.push(run.agent_id);
    }
    assert!(served.contains(&o.eng_po), "the planner works the plan");
    assert!(!served.contains(&o.dev), "the dev's wake waits: {served:?}");
    let why = plan_hold(pool, t, o.dev).await.unwrap().unwrap();
    assert!(why.contains("R-1") && why.contains("not approved"), "{why}");
    assert_eq!(plan_hold(pool, kickoff.id, o.eng_po).await.unwrap(), None);

    // Complete and submitted under the owner policy: one plan approval, about the kickoff.
    estimate_issue(pool, t, Some(3), BY).await.unwrap();
    let Submitted::Pending(a) = submit_plan(pool, r.id, o.eng_po, Some(kickoff.id), &now)
        .await
        .unwrap()
    else {
        panic!("the owner decides")
    };
    assert_eq!(
        (a.kind, a.issue_id),
        (ApprovalKind::PlanApproval, Some(kickoff.id))
    );
    let r1 = get_requirement(pool, r.id).await.unwrap().unwrap();
    assert_eq!(r1.state, RequirementState::PlanReview);
    // Nothing is added while it is reviewed.
    let e = plan_requirement(pool, r.id, o.eng_po, &[], &[]).await;
    assert!(matches!(e, Err(RequirementError::State(_))), "{e:?}");

    // Rejected: back to planning, the reply goes to the product owner.
    decide_approval(pool, a.id, false, ADMIN, Some("split it"), &now)
        .await
        .unwrap();
    let r2 = get_requirement(pool, r.id).await.unwrap().unwrap();
    assert_eq!(r2.state, RequirementState::Planning);
    let replied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM wake_requests WHERE agent_id = ? AND source = 'approval'",
    )
    .bind(o.eng_po.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(replied, 1);

    // Approved: version 1, in progress, and the dev's wake goes out.
    let Submitted::Pending(a) = submit_plan(pool, r.id, o.eng_po, Some(kickoff.id), &now)
        .await
        .unwrap()
    else {
        panic!("the owner decides")
    };
    decide_approval(pool, a.id, true, ADMIN, None, &now)
        .await
        .unwrap();
    let r3 = get_requirement(pool, r.id).await.unwrap().unwrap();
    assert_eq!(
        (r3.state, r3.plan_version),
        (RequirementState::InProgress, 1)
    );
    assert_eq!(plan_hold(pool, t, o.dev).await.unwrap(), None);
    let run = dispatch_next(pool, box_, &[], &Harness::ALL, &now)
        .await
        .unwrap();
    assert_eq!(run.unwrap().agent_id, o.dev);
}

#[tokio::test]
async fn under_the_product_owner_policy_a_complete_plan_is_approved_at_once() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let (r, mut p, _) = routed(pool, &o).await;
    p.sprint_approval = SprintApproval::ProductOwner;
    update_project(pool, &p).await.unwrap();
    plan_one(pool, &r, &p, o.eng_po, vec![task("Sender", Some(2), o.dev)]).await;
    let now = now(pool).await;
    let done = submit_plan(pool, r.id, o.eng_po, None, &now).await.unwrap();
    assert!(matches!(done, Submitted::Approved(1)), "{done:?}");
    let r = get_requirement(pool, r.id).await.unwrap().unwrap();
    assert_eq!(r.state, RequirementState::InProgress);
    assert!(list_approvals(pool, o.company).await.unwrap().is_empty());
    let e = submit_plan(pool, r.id, o.eng_po, None, &now).await;
    assert!(
        matches!(e, Err(RequirementError::State(_))),
        "once only: {e:?}"
    );
}

/// Approves the plan under the product owner policy, as of `days` ago.
async fn approve(pool: &SqlitePool, o: &Org, r: &Requirement, p: &Project, days: i64) {
    let mut p = p.clone();
    p.sprint_approval = SprintApproval::ProductOwner;
    update_project(pool, &p).await.unwrap();
    let now = now(pool).await;
    submit_plan(pool, r.id, o.eng_po, None, &now).await.unwrap();
    sqlx::query(
        "UPDATE requirement_plans SET approved_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)",
    )
    .bind(format!("-{days} days"))
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn the_tree_numbers_are_exact() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let (r, p, _) = routed(pool, &o).await;
    let a = plan_one(
        pool,
        &r,
        &p,
        o.eng_po,
        vec![
            task("Events", Some(3), o.dev),
            task("Sender", Some(5), o.dev),
        ],
    )
    .await;
    let b = NewPlanEpic {
        project: p.id,
        title: "Mac alerts",
        tasks: vec![task("Settings pane", Some(2), o.dev)],
    };
    plan_requirement(pool, r.id, o.eng_po, &[b], &[])
        .await
        .unwrap();
    approve(pool, &o, &r, &p, 2).await;
    // Events was filed and done yesterday, after a 90-second run of 1200 tokens.
    let events = a.tasks[0];
    for t in [IssueTransition::Start, IssueTransition::Done] {
        transition_issue(pool, events, &t, AuditActor::Agent(o.dev))
            .await
            .unwrap();
    }
    sqlx::query(
        "UPDATE issue_state_history SET at = strftime('%Y-%m-%dT%H:%M:%fZ', at, '-1 day') \
         WHERE issue_id = ?",
    )
    .bind(events.0)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO runs (agent_id, issue_id, harness, state, terminal_reason, started_at, \
         ended_at, input_tokens, output_tokens) VALUES (?, ?, 'claude', 'succeeded', 'done', \
         '2026-10-20T10:00:00.000Z', '2026-10-20T10:01:30.000Z', 1000, 200)",
    )
    .bind(o.dev.0)
    .bind(events.0)
    .execute(pool)
    .await
    .unwrap();

    // All of it was filed when the plan was approved, two days ago.
    sqlx::query("UPDATE issues SET created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-2 days')")
        .execute(pool)
        .await
        .unwrap();
    let now = now(pool).await;
    let t = requirement_tree(pool, r.id, &now).await.unwrap().unwrap();
    assert_eq!((t.points, t.done_points, t.percent_done), (10, 3, 30));
    assert_eq!((t.tasks, t.done_tasks), (3, 1));
    assert_eq!(t.epics.len(), 2);
    assert_eq!((t.epics[0].points, t.epics[0].done_points), (8, 3));
    assert_eq!((t.epics[1].points, t.epics[1].done_points), (2, 0));
    let first = &t.epics[0].tasks[0];
    assert_eq!(
        (first.state, first.time_secs, first.tokens),
        (IssueState::Done, 90, 1200)
    );
    assert_eq!(first.assignee, Some(Actor::Agent(o.dev)));
    let left: Vec<u32> = t.burndown.iter().map(|(_, l, _)| *l).collect();
    assert_eq!(left, [10, 7, 7], "{:?}", t.burndown);
    // 3 points in 2 days: a pace, but too little data for an ETA.
    assert!(
        (t.points_per_day - 1.5).abs() < 0.01,
        "{}",
        t.points_per_day
    );
    assert_eq!(t.eta, None);
    // The kickoff and the intake request are outside the plan.
    assert_eq!(t.other.len(), 2);
    let diff = t.diff.unwrap();
    assert!(diff.added.is_empty() && diff.removed.is_empty());
    assert_eq!(
        (diff.version, diff.points_approved, diff.points_now),
        (1, 10, 10)
    );
}

#[tokio::test]
async fn scope_changed_after_approval_shows_in_the_diff() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let (r, p, _) = routed(pool, &o).await;
    let a = plan_one(
        pool,
        &r,
        &p,
        o.eng_po,
        vec![
            task("Events", Some(3), o.dev),
            task("Sender", Some(5), o.dev),
        ],
    )
    .await;
    approve(pool, &o, &r, &p, 0).await;
    let added = PlannedTask {
        epic: Some(a.epics[0]),
        ..task("Push for blocked work", Some(3), o.dev)
    };
    let more = plan_requirement(pool, r.id, o.eng_po, &[], &[added])
        .await
        .unwrap();
    transition_issue(pool, a.tasks[1], &IssueTransition::Cancel, BY)
        .await
        .unwrap();

    let r = get_requirement(pool, r.id).await.unwrap().unwrap();
    let diff = plan_diff(pool, &r).await.unwrap().unwrap();
    let ids = |v: &[PlannedTaskRef]| v.iter().map(|t| t.id).collect::<Vec<_>>();
    assert_eq!(ids(&diff.added), [more.tasks[0].0]);
    assert_eq!(diff.added[0].points, Some(3));
    assert_eq!(ids(&diff.removed), [a.tasks[1].0]);
    assert_eq!((diff.points_approved, diff.points_now), (8, 6));
    let audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'requirement.plan_approved'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(audit, 1);
}

#[tokio::test]
async fn aggregates_count_leaf_product_tasks_and_keep_each_days_scope() {
    let db = db().await;
    let pool = &db.pool;
    let o = org(pool).await;
    let (r, p, _) = routed(pool, &o).await;
    let a = plan_one(
        pool,
        &r,
        &p,
        o.eng_po,
        vec![
            task("Events", Some(3), o.dev),
            task("Sender", Some(5), o.dev),
            task("Write the guide", Some(2), o.dev),
        ],
    )
    .await;
    approve(pool, &o, &r, &p, 3).await;
    // Sender is split into subtasks of 2 and 3: they count, it does not.
    for (title, points) in [("Sender A", 2), ("Sender B", 3)] {
        let sub = NewIssue {
            kind: IssueKind::Subtask,
            parent_id: Some(a.tasks[1]),
            points: Some(points),
            ..new_issue(p.id, title)
        };
        create_issue(pool, &sub).await.unwrap();
    }
    // The guide is documentation.
    let label = add_label(pool, p.id, "docs", BY).await.unwrap();
    sqlx::query("INSERT INTO issue_labels (issue_id, label_id) VALUES (?, ?)")
        .bind(a.tasks[2].0)
        .bind(label.id.0)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE issues SET created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-3 days')")
        .execute(pool)
        .await
        .unwrap();
    for t in [IssueTransition::Start, IssueTransition::Done] {
        transition_issue(pool, a.tasks[0], &t, AuditActor::Agent(o.dev))
            .await
            .unwrap();
    }
    // Scope grows today.
    let late = NewPlanEpic {
        project: p.id,
        title: "Late",
        tasks: vec![task("Extra", Some(2), o.dev)],
    };
    plan_requirement(pool, r.id, o.eng_po, &[late], &[])
        .await
        .unwrap();

    let now = now(pool).await;
    let t = requirement_tree(pool, r.id, &now).await.unwrap().unwrap();
    assert_eq!(
        (t.points, t.done_points, t.tasks, t.done_tasks),
        (10, 3, 4, 1)
    );
    assert_eq!(t.percent_done, 30);
    let days: Vec<(u32, u32)> = t.burndown.iter().map(|(_, l, s)| (*l, *s)).collect();
    // Earlier days keep the scope they had; today's carries the added work.
    assert_eq!(days, [(8, 8), (8, 8), (8, 8), (7, 10)], "{:?}", t.burndown);
    assert!(t.eta.is_some(), "three days of data is enough");
}
