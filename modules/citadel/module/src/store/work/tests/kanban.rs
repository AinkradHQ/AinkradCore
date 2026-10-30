//! Kanban (E5.3): WIP limits enforced by the engine, cycle and lead times with exact numbers
//! on fixed fixtures, and the scrum / kanban mode guards.

use crate::domain::work::{Issue, IssueTransition, Project};

use super::*;

const BY: AuditActor = core_user(ADMIN);

async fn kanban(pool: &SqlitePool) -> (CompanyId, Project) {
    let c = create_company(pool, "A").await.unwrap();
    let p = NewProject {
        mode: ProjectMode::Kanban,
        ..new_project(c.id, "FLO")
    };
    (c.id, create_project(pool, &p).await.unwrap())
}

async fn step(pool: &SqlitePool, i: IssueId, t: IssueTransition) -> Issue {
    transition_issue(pool, i, &t, BY).await.unwrap()
}

/// Dates the issue's move into `state` at `at`.
async fn dated(pool: &SqlitePool, i: IssueId, state: &str, at: &str) {
    sqlx::query(
        "UPDATE citadel_issue_state_history SET at = ? WHERE issue_id = ? AND to_state = ?",
    )
    .bind(at)
    .bind(i.0)
    .bind(state)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn a_transition_into_a_full_column_is_refused() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = kanban(pool).await;
    set_wip_limit(pool, p.id, IssueState::InProgress, Some(1), BY)
        .await
        .unwrap();
    assert_eq!(
        wip_limits(pool, p.id).await.unwrap(),
        [(IssueState::InProgress, 1)]
    );
    let a = create_issue(pool, &new_issue(p.id, "a")).await.unwrap();
    let b = create_issue(pool, &new_issue(p.id, "b")).await.unwrap();
    step(pool, a.id, IssueTransition::Start).await;

    let full = transition_issue(pool, b.id, &IssueTransition::Start, BY).await;
    assert!(
        matches!(
            full,
            Err(IssueTransitionError::WipLimit {
                state: IssueState::InProgress,
                limit: 1
            })
        ),
        "{full:?}"
    );
    assert_eq!(get_issue(pool, b.id).await.unwrap(), Some(b.clone()));
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE entity_kind = 'issue' AND entity_id = ?",
    )
    .bind(b.id.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(audited, 0);

    // Subtasks neither count nor are limited.
    let sub = NewIssue {
        kind: IssueKind::Subtask,
        parent_id: Some(a.id),
        ..new_issue(p.id, "sub")
    };
    let sub = create_issue(pool, &sub).await.unwrap();
    step(pool, sub.id, IssueTransition::Start).await;

    // Room again once a moves on; removing the limit lifts it.
    step(pool, a.id, IssueTransition::Done).await;
    step(pool, b.id, IssueTransition::Start).await;
    let c_ = create_issue(pool, &new_issue(p.id, "c")).await.unwrap();
    assert!(
        transition_issue(pool, c_.id, &IssueTransition::Start, BY)
            .await
            .is_err()
    );
    set_wip_limit(pool, p.id, IssueState::InProgress, None, BY)
        .await
        .unwrap();
    step(pool, c_.id, IssueTransition::Start).await;
    assert!(wip_limits(pool, p.id).await.unwrap().is_empty());
}

/// `(agent, issue, key)` of every wake for a freed kanban slot, oldest first.
async fn freed_wakes(pool: &SqlitePool) -> Vec<(i64, i64, String)> {
    sqlx::query_as(
        "SELECT agent_id, issue_id, idempotency_key FROM wake_requests \
         WHERE idempotency_key LIKE 'wip:%' ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// A full `in_progress` column that frees up wakes the agent of the oldest `todo` issue it
/// held back, once per freed slot, whether an issue moved on or was deleted; a column that
/// was not full wakes nobody.
#[tokio::test]
#[ignore = "S7: needs the wake queue (wake_requests); wake_freed_in comes with it"]
async fn a_freed_column_wakes_the_oldest_held_back_issue() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = kanban(pool).await;
    let (dev, qa) = (agent(pool, c, "Dev").await, agent(pool, c, "QA").await);
    set_wip_limit(pool, p.id, IssueState::InProgress, Some(1), BY)
        .await
        .unwrap();
    let a = create_issue(pool, &new_issue(p.id, "a")).await.unwrap();
    let waiting = |title, who| NewIssue {
        state: IssueState::Todo,
        next_actor: Some(NextActor::Agent(who)),
        ..new_issue(p.id, title)
    };
    let human = NewIssue {
        state: IssueState::Todo,
        ..new_issue(p.id, "human")
    };
    create_issue(pool, &human).await.unwrap();
    let b = create_issue(pool, &waiting("b", dev)).await.unwrap();
    let c_ = create_issue(pool, &waiting("c", qa)).await.unwrap();
    step(pool, a.id, IssueTransition::Start).await;
    assert!(freed_wakes(pool).await.is_empty());

    step(pool, a.id, IssueTransition::Done).await;
    let woken = freed_wakes(pool).await;
    assert_eq!(woken.len(), 1, "{woken:?}");
    assert_eq!((woken[0].0, woken[0].1), (dev.0, b.id.0), "not the human's");
    assert!(
        woken[0]
            .2
            .starts_with(&format!("wip:issue:{}:audit:", a.id.0))
    );

    // b starts and is deleted: the slot frees again, for c now.
    step(pool, b.id, IssueTransition::Start).await;
    assert!(delete_issue(pool, b.id, BY).await.unwrap());
    let woken = freed_wakes(pool).await;
    assert_eq!(woken.len(), 2, "{woken:?}");
    assert_eq!((woken[1].0, woken[1].1), (qa.0, c_.id.0));
    assert_eq!(woken[1].2, format!("wip:issue:{}:deleted", b.id.0));

    // With room to spare, leaving the column wakes nobody.
    set_wip_limit(pool, p.id, IssueState::InProgress, Some(3), BY)
        .await
        .unwrap();
    step(pool, c_.id, IssueTransition::Start).await;
    step(pool, c_.id, IssueTransition::Done).await;
    assert_eq!(freed_wakes(pool).await.len(), 2);
}

/// An unblock returns an issue to `todo` even past the limit: refusing it would refuse the
/// close of its blocker.
#[tokio::test]
async fn an_unblock_is_exempt_and_the_ready_column_is_limited_too() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = kanban(pool).await;
    set_wip_limit(pool, p.id, IssueState::Todo, Some(1), BY)
        .await
        .unwrap();
    let parked = create_issue(pool, &new_issue(p.id, "parked"))
        .await
        .unwrap();
    let blocker = create_issue(pool, &new_issue(p.id, "blocker"))
        .await
        .unwrap();
    let link = BlockerLink {
        blocker: blocker.id,
        blocked: parked.id,
    };
    add_blocker(pool, link).await.unwrap();
    step(pool, parked.id, IssueTransition::Block).await;
    let ready = create_issue(pool, &new_issue(p.id, "ready")).await.unwrap();
    step(pool, ready.id, IssueTransition::Ready).await;
    let more = create_issue(pool, &new_issue(p.id, "more")).await.unwrap();
    let full = transition_issue(pool, more.id, &IssueTransition::Ready, BY).await;
    assert!(
        matches!(full, Err(IssueTransitionError::WipLimit { .. })),
        "{full:?}"
    );

    step(pool, blocker.id, IssueTransition::Start).await;
    step(pool, blocker.id, IssueTransition::Done).await;
    let back = get_issue(pool, parked.id).await.unwrap().unwrap();
    assert_eq!(back.state, IssueState::Todo, "unblocked past the limit");
}

/// A scrum project has no WIP limits (and limits left from a kanban past are ignored); a
/// kanban project has no sprints.
#[tokio::test]
async fn scrum_and_kanban_operations_stay_in_their_mode() {
    let db = db().await;
    let pool = &db.pool;
    let (c, mut p) = kanban(pool).await;
    let invalid = |r: Result<(), Error>| matches!(r, Err(Error::InvalidArgument(_)));
    let limit = |s, n| set_wip_limit(pool, p.id, s, n, BY);
    assert!(invalid(limit(IssueState::Done, Some(1)).await));
    assert!(invalid(limit(IssueState::Todo, Some(0)).await));
    let gone = set_wip_limit(pool, ProjectId(999), IssueState::Todo, Some(1), BY).await;
    assert!(matches!(gone, Err(Error::RowNotFound)), "{gone:?}");
    limit(IssueState::InProgress, Some(1)).await.unwrap();

    let wrong = |e: SprintError| matches!(e, SprintError::WrongMode(ProjectMode::Kanban));
    let s = NewSprint {
        starts_on: Some("2020-03-02".to_owned()),
        ends_on: Some("2020-03-06".to_owned()),
        ..new_sprint(p.id, "S1", SprintState::Planned)
    };
    assert!(wrong(plan_sprint(pool, &s, BY).await.unwrap_err()));
    let raw = create_sprint(pool, &s).await.unwrap();
    let i = create_issue(pool, &new_issue(p.id, "a")).await.unwrap();
    assert!(wrong(
        add_to_sprint(pool, raw.id, i.id, BY).await.unwrap_err()
    ));
    assert!(wrong(start_sprint(pool, raw.id, BY).await.unwrap_err()));
    assert!(wrong(
        close_sprint(pool, raw.id, None, BY).await.unwrap_err()
    ));
    let sprinted = NewIssue {
        sprint_id: Some(raw.id),
        ..new_issue(p.id, "in it")
    };
    let sprinted = create_issue(pool, &sprinted).await.unwrap();
    assert!(wrong(
        remove_from_sprint(pool, sprinted.id, BY).await.unwrap_err()
    ));

    // Turned scrum: no new limits, and the old one no longer holds anything back.
    p.mode = ProjectMode::Scrum;
    assert!(update_project(pool, &p).await.unwrap());
    assert!(invalid(limit(IssueState::Todo, Some(1)).await));
    step(pool, i.id, IssueTransition::Start).await;
    step(pool, sprinted.id, IssueTransition::Start).await;
    let scrum = create_project(pool, &new_project(c, "SCR")).await.unwrap();
    let s = NewSprint {
        project_id: scrum.id,
        ..s
    };
    plan_sprint(pool, &s, BY).await.unwrap();
}

/// a: created day 0, started +12 h, done +2 d. b: created day -1, started day 1, reviewed,
/// done day 3 +6 h. d: created done on day 1. c: done after the window. Window [day -1,
/// day 4). Cycle a 129600 s, b 194400 s; lead d 0, a 172800, b 367200.
#[tokio::test]
async fn cycle_and_lead_times_on_fixtures() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = kanban(pool).await;
    let mut ids = vec![];
    for t in ["a", "b", "c"] {
        ids.push(create_issue(pool, &new_issue(p.id, t)).await.unwrap().id);
    }
    let [a, b, c_] = ids.try_into().unwrap();
    let d = NewIssue {
        state: IssueState::Done,
        next_actor: None,
        ..new_issue(p.id, "d")
    };
    let d = create_issue(pool, &d).await.unwrap().id;
    for i in [a, c_] {
        step(pool, i, IssueTransition::Start).await;
        step(pool, i, IssueTransition::Done).await;
    }
    step(pool, b, IssueTransition::Start).await;
    let reviewer = Actor::Human(ADMIN);
    step(pool, b, IssueTransition::SubmitForReview { reviewer }).await;
    step(pool, b, IssueTransition::Approve).await;

    for (i, state, at) in [
        (a, "backlog", "2020-03-02T00:00:00.000Z"),
        (a, "in_progress", "2020-03-02T12:00:00.000Z"),
        (a, "done", "2020-03-04T00:00:00.000Z"),
        (b, "backlog", "2020-03-01T00:00:00.000Z"),
        (b, "in_progress", "2020-03-03T00:00:00.000Z"),
        (b, "done", "2020-03-05T06:00:00.000Z"),
        (c_, "backlog", "2020-03-01T00:00:00.000Z"),
        (c_, "done", "2020-03-10T00:00:00.000Z"),
        (d, "done", "2020-03-03T00:00:00.000Z"),
    ] {
        dated(pool, i, state, at).await;
    }
    let m = flow_metrics(pool, p.id, "2020-03-01T00:00:00Z", "2020-03-06T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(
        m.issues,
        [
            (d, None, 0),
            (a, Some(129_600), 172_800),
            (b, Some(194_400), 367_200)
        ]
    );
    assert_eq!(m.mean_cycle_secs, Some(162_000.0));
    assert_eq!(m.mean_lead_secs, Some(180_000.0));
    let empty = flow_metrics(pool, p.id, "2021-01-01T00:00:00Z", "2021-02-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!((empty.issues.len(), empty.mean_cycle_secs), (0, None));
}
