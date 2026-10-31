//! The requirement tests that need the run engine (S7): the wake queue, and a run's time and
//! tokens. The dispatcher's half (a held wake is skipped, a released one is served) is
//! `tests/detectors.rs`. Their runnable halves are in `requirements`.

use crate::domain::gov::ApprovalKind;
use crate::domain::work::{IssueTransition, RequirementState};
use crate::store::gov::decide_approval;

use super::intake::org;
use super::requirements::{approve, plan_one, routed, task};
use super::*;

#[tokio::test]
async fn dev_work_waits_for_the_owners_approval_of_the_complete_plan_engine() {
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
    for (agent, key) in [(o.dev, "dev"), (o.eng_po, "po")] {
        let wake = crate::store::exec::NewWakeRequest {
            agent_id: agent,
            issue_id: Some(t),
            source: crate::domain::work::WakeSource::Assignment,
            reason: "start".to_owned(),
            idempotency_key: key.to_owned(),
            not_before: None,
        };
        crate::store::exec::enqueue_wake(pool, &wake).await.unwrap();
    }
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
    let approval_wakes: Vec<i64> =
        sqlx::query_scalar("SELECT agent_id FROM citadel_wake_requests WHERE source = 'approval'")
            .fetch_all(pool)
            .await
            .unwrap();
    assert_eq!(
        approval_wakes,
        [o.eng_po.0],
        "the reply wakes the product owner once"
    );

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
}

#[tokio::test]
#[ignore = "S7: a run's time and tokens come from the runs table"]
async fn the_tree_numbers_are_exact_engine() {
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
        transition_issue(pool, events, &t, AuditActor::System)
            .await
            .unwrap();
    }
    sqlx::query(
        "UPDATE citadel_issue_state_history SET at = strftime('%Y-%m-%dT%H:%M:%fZ', at, '-1 day') \
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
    sqlx::query(
        "UPDATE citadel_issues SET created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-2 days')",
    )
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
