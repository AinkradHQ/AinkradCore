//! Sprints (E5.2): plan, fill, start, close; capacity, velocity and the burndown, with exact
//! numbers on fixed fixtures.

use ainkrad_core::org::{TeamMembership, TeamRole};
use ainkrad_core::work::{Issue, IssueTransition, SprintReport};

use super::*;
use crate::store::org::create_membership;

const BY: AuditActor = AuditActor::User(ADMIN);

pub(super) fn planned(p: ProjectId, name: &str) -> NewSprint {
    NewSprint {
        starts_on: Some("2020-03-02".to_owned()),
        ends_on: Some("2020-03-06".to_owned()),
        goal: format!("{name} goal"),
        ..new_sprint(p, name, SprintState::Planned)
    }
}

pub(super) async fn pointed(pool: &SqlitePool, p: ProjectId, title: &str, points: u32) -> Issue {
    let i = NewIssue {
        points: Some(points),
        ..new_issue(p, title)
    };
    create_issue(pool, &i).await.unwrap()
}

/// Starts the issue and finishes it.
pub(super) async fn finish(pool: &SqlitePool, i: IssueId) {
    for t in [IssueTransition::Start, IssueTransition::Done] {
        transition_issue(pool, i, &t, BY).await.unwrap();
    }
}

/// Dates the issue's last move into `state` at `at`.
async fn dated(pool: &SqlitePool, i: IssueId, state: &str, at: &str) {
    sqlx::query(
        "UPDATE issue_state_history SET at = ? WHERE id = (SELECT max(id) \
         FROM issue_state_history WHERE issue_id = ? AND to_state = ?)",
    )
    .bind(at)
    .bind(i.0)
    .bind(state)
    .execute(pool)
    .await
    .unwrap();
}

pub(super) async fn sprint_actions(pool: &SqlitePool, s: SprintId) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE entity_kind = 'sprint' AND entity_id = ? \
         ORDER BY seq",
    )
    .bind(s.0)
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn plan_fill_start_and_close() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let bad = NewSprint {
        ends_on: Some("2020-02-30".to_owned()),
        ..planned(p.id, "S0")
    };
    let err = plan_sprint(pool, &bad, BY).await.unwrap_err();
    assert!(
        matches!(err, SprintError::Db(Error::InvalidArgument(_))),
        "{err}"
    );
    let undated = NewSprint {
        ends_on: None,
        ..planned(p.id, "S0")
    };
    assert!(plan_sprint(pool, &undated, BY).await.is_err());
    let active = new_sprint(p.id, "S0", SprintState::Active);
    let err = plan_sprint(pool, &active, BY).await.unwrap_err();
    assert!(
        matches!(err, SprintError::State(SprintState::Active)),
        "{err}"
    );

    let s1 = plan_sprint(pool, &planned(p.id, "S1"), BY).await.unwrap();
    assert_eq!(
        (s1.state, s1.goal.as_str()),
        (SprintState::Planned, "S1 goal")
    );
    let s2 = plan_sprint(pool, &planned(p.id, "S2"), BY).await.unwrap();
    let a = pointed(pool, p.id, "a", 3).await;
    let b = create_issue(pool, &new_issue(p.id, "b")).await.unwrap();
    let done = NewIssue {
        state: IssueState::Done,
        next_actor: None,
        ..new_issue(p.id, "closed")
    };
    let done = create_issue(pool, &done).await.unwrap();
    let sub = NewIssue {
        kind: IssueKind::Subtask,
        parent_id: Some(a.id),
        ..new_issue(p.id, "sub")
    };
    let sub = create_issue(pool, &sub).await.unwrap();
    let other = create_project(pool, &new_project(c, "WEB")).await.unwrap();
    let foreign = create_issue(pool, &new_issue(other.id, "x")).await.unwrap();

    for i in [a.id, b.id] {
        let added = add_to_sprint(pool, s1.id, i, BY).await.unwrap();
        assert_eq!(added.sprint_id, Some(s1.id));
    }
    let refused = |r: Result<Issue, SprintError>| r.unwrap_err();
    let e = refused(add_to_sprint(pool, s1.id, done.id, BY).await);
    assert!(
        matches!(e, SprintError::IssueClosed(IssueState::Done)),
        "{e}"
    );
    let e = refused(add_to_sprint(pool, s1.id, sub.id, BY).await);
    assert!(matches!(e, SprintError::Subtask), "{e}");
    let e = refused(add_to_sprint(pool, s1.id, foreign.id, BY).await);
    assert!(matches!(e, SprintError::OtherProject), "{e}");
    let e = refused(add_to_sprint(pool, SprintId(999), a.id, BY).await);
    assert!(matches!(e, SprintError::NotFound), "{e}");

    // Scrum: every issue needs points before the sprint starts.
    let e = start_sprint(pool, s1.id, BY).await.unwrap_err();
    assert!(
        matches!(&e, SprintError::Unpointed(ids) if *ids == vec![b.id]),
        "{e}"
    );
    let b = Issue {
        points: Some(5),
        ..b
    };
    assert!(update_issue(pool, &b).await.unwrap());
    let started = start_sprint(pool, s1.id, BY).await.unwrap();
    assert_eq!(started.state, SprintState::Active);
    let again = start_sprint(pool, s2.id, BY).await.unwrap_err();
    assert!(
        matches!(again, SprintError::ActiveExists(id) if id == s1.id),
        "{again}"
    );

    // Scope is frozen for agents once active (the admin may: `sprint_scope`).
    let agent = AuditActor::Agent(AgentId(1));
    let c_ = pointed(pool, p.id, "c", 1).await;
    let e = refused(add_to_sprint(pool, s1.id, c_.id, agent).await);
    assert!(matches!(e, SprintError::State(SprintState::Active)), "{e}");
    let e = refused(remove_from_sprint(pool, a.id, agent).await);
    assert!(matches!(e, SprintError::State(SprintState::Active)), "{e}");
    let e = refused(add_to_sprint(pool, s2.id, a.id, agent).await);
    assert!(matches!(e, SprintError::State(SprintState::Active)), "{e}");

    // Close: a is done and stays; b carries to S2. Only a planned sprint of the project
    // takes carried issues.
    finish(pool, a.id).await;
    let foreign_sprint = plan_sprint(pool, &planned(other.id, "W1"), BY)
        .await
        .unwrap();
    let e = close_sprint(pool, s1.id, Some(foreign_sprint.id), BY)
        .await
        .unwrap_err();
    assert!(matches!(e, SprintError::OtherProject), "{e}");
    let closed = close_sprint(pool, s1.id, Some(s2.id), BY).await.unwrap();
    assert_eq!(closed.state, SprintState::Closed);
    let e = close_sprint(pool, s1.id, None, BY).await.unwrap_err();
    assert!(matches!(e, SprintError::State(SprintState::Closed)), "{e}");
    assert_eq!(
        get_issue(pool, a.id).await.unwrap().unwrap().sprint_id,
        Some(s1.id)
    );
    assert_eq!(
        get_issue(pool, b.id).await.unwrap().unwrap().sprint_id,
        Some(s2.id)
    );
    let report = sprint_report(pool, s1.id, "2020-03-09T00:00:00Z")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((report.committed, report.completed), (Some(8), 3));
    assert_eq!(
        sprint_actions(pool, s1.id).await,
        ["sprint.planned", "sprint.started", "sprint.closed"]
    );

    // Out of a planned sprint, back to the backlog.
    let back = remove_from_sprint(pool, b.id, BY).await.unwrap();
    assert_eq!(back.sprint_id, None);
    let issue_moves: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'issue.sprint_set' AND entity_id = ?",
    )
    .bind(b.id.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(issue_moves, 3, "added, carried, removed");
}

#[tokio::test]
async fn closing_to_the_backlog_and_a_carry_target_must_be_planned() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let s1 = plan_sprint(pool, &planned(p.id, "S1"), BY).await.unwrap();
    let a = pointed(pool, p.id, "a", 2).await;
    add_to_sprint(pool, s1.id, a.id, BY).await.unwrap();
    start_sprint(pool, s1.id, BY).await.unwrap();
    let old = raw_sprint(pool, p.id, "S0", SprintState::Closed).await;
    let e = close_sprint(pool, s1.id, Some(old.id), BY)
        .await
        .unwrap_err();
    assert!(matches!(e, SprintError::State(SprintState::Closed)), "{e}");
    close_sprint(pool, s1.id, None, BY).await.unwrap();
    assert_eq!(
        get_issue(pool, a.id).await.unwrap().unwrap().sprint_id,
        None
    );
    let report = sprint_report(pool, s1.id, "2020-03-09T00:00:00Z")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((report.committed, report.completed), (Some(2), 0));
}

/// Committed 18 (3 + 5 + 8 + 2); a done on day 2; b and c on day 3; c reopened on day 4.
/// Capacity 5 + 8 (one member unset). Burndown 18, 15, 2, 10 to "today" (day 4), then the
/// close carries c and d out: as never done in this sprint, so day 3 reads 10.
#[tokio::test]
async fn burndown_capacity_and_velocity_on_fixtures() {
    let db = db().await;
    let pool = &db.pool;
    let (c, mut p) = project_fixture(pool).await;
    let d_ = create_department(pool, c, "Eng").await.unwrap();
    let team = create_team(pool, d_.id, "Core").await.unwrap();
    p.team_id = Some(team.id);
    assert!(update_project(pool, &p).await.unwrap());
    for (name, capacity) in [("x", Some(5)), ("y", Some(8)), ("z", None)] {
        let m = TeamMembership {
            team_id: team.id,
            agent_id: agent(pool, c, name).await,
            team_role: TeamRole::Member,
        };
        create_membership(pool, &m).await.unwrap();
        assert!(
            set_member_capacity(pool, team.id, m.agent_id, capacity)
                .await
                .unwrap()
        );
    }

    let s = plan_sprint(pool, &planned(p.id, "S1"), BY).await.unwrap();
    let mut issues = vec![];
    for (title, points) in [("a", 3), ("b", 5), ("c", 8), ("d", 2)] {
        let i = pointed(pool, p.id, title, points).await;
        add_to_sprint(pool, s.id, i.id, BY).await.unwrap();
        issues.push(i.id);
    }
    let [a, b, c_, d] = issues.try_into().unwrap();
    let planned_report = sprint_report(pool, s.id, "2020-03-04T12:00:00Z")
        .await
        .unwrap();
    assert_eq!(
        planned_report,
        Some(SprintReport {
            sprint_id: s.id,
            state: SprintState::Planned,
            committed: None,
            completed: 0,
            capacity: Some(13),
            burndown: vec![],
        })
    );
    start_sprint(pool, s.id, BY).await.unwrap();
    for i in [a, b, c_] {
        finish(pool, i).await;
    }
    dated(pool, a, "done", "2020-03-03T09:00:00.000Z").await;
    dated(pool, b, "done", "2020-03-04T23:59:59.999Z").await;
    dated(pool, c_, "done", "2020-03-04T08:00:00.000Z").await;
    let next = NextActor::Human(ADMIN);
    transition_issue(pool, c_, &IssueTransition::Reopen { next }, BY)
        .await
        .unwrap();
    dated(pool, c_, "todo", "2020-03-05T10:00:00.000Z").await;

    let day = |d: &str, left: u32| (d.to_owned(), left);
    let report = sprint_report(pool, s.id, "2020-03-05T12:00:00.000Z")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        report,
        SprintReport {
            sprint_id: s.id,
            state: SprintState::Active,
            committed: Some(18),
            completed: 8,
            capacity: Some(13),
            burndown: vec![
                day("2020-03-02", 18),
                day("2020-03-03", 15),
                day("2020-03-04", 2),
                day("2020-03-05", 10),
            ],
        }
    );

    close_sprint(pool, s.id, None, BY).await.unwrap();
    let report = sprint_report(pool, s.id, "2020-04-01T00:00:00.000Z")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((report.committed, report.completed), (Some(18), 8));
    let left: Vec<u32> = report.burndown.iter().map(|d| d.1).collect();
    assert_eq!(left, [18, 15, 10, 10, 10]);
    assert_eq!(get_issue(pool, d).await.unwrap().unwrap().sprint_id, None);

    // Two more sprints: completed 5 of 7, then 0 of 4. Velocity over the last 2 and 3.
    for (done, open) in [(&[5][..], &[2][..]), (&[][..], &[4][..])] {
        let s = plan_sprint(pool, &planned(p.id, "next"), BY).await.unwrap();
        let mut to_finish = vec![];
        for (n, points) in done.iter().chain(open).enumerate() {
            let i = pointed(pool, p.id, "n", *points).await;
            add_to_sprint(pool, s.id, i.id, BY).await.unwrap();
            if n < done.len() {
                to_finish.push(i.id);
            }
        }
        start_sprint(pool, s.id, BY).await.unwrap();
        for i in to_finish {
            finish(pool, i).await;
        }
        close_sprint(pool, s.id, None, BY).await.unwrap();
    }
    let v = velocity(pool, p.id, 2).await.unwrap();
    let numbers: Vec<(u32, u32)> = v.sprints.iter().map(|s| (s.1, s.2)).collect();
    assert_eq!(numbers, [(4, 0), (7, 5)]);
    assert_eq!(v.average, 2.5);
    let v = velocity(pool, p.id, 3).await.unwrap();
    assert_eq!(v.sprints.last().unwrap().0, s.id);
    assert_eq!(v.average, 13.0 / 3.0);
    let none = create_project(pool, &new_project(c, "WEB")).await.unwrap();
    assert_eq!(velocity(pool, none.id, 3).await.unwrap().average, 0.0);
}

/// Every state change lands in the history, the checkout's included.
#[tokio::test]
async fn state_history_records_every_change() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let i = create_issue(pool, &new_issue(p.id, "a")).await.unwrap();
    transition_issue(pool, i.id, &IssueTransition::Ready, BY)
        .await
        .unwrap();
    finish(pool, i.id).await;
    let rows: Vec<(Option<String>, String)> = sqlx::query_as(
        "SELECT from_state, to_state FROM issue_state_history WHERE issue_id = ? ORDER BY id",
    )
    .bind(i.id.0)
    .fetch_all(pool)
    .await
    .unwrap();
    let s = |x: &str| x.to_owned();
    assert_eq!(
        rows,
        [
            (None, s("backlog")),
            (Some(s("backlog")), s("todo")),
            (Some(s("todo")), s("in_progress")),
            (Some(s("in_progress")), s("done")),
        ]
    );
}

/// `create_issue` cannot put a top-level issue in an active (or closed) sprint, nor a
/// subtask in a sprint other than its parent's; `create_sprint` only plans.
#[tokio::test]
async fn creating_cannot_bypass_the_sprint_rules() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let s1 = plan_sprint(pool, &planned(p.id, "S1"), BY).await.unwrap();
    let s2 = plan_sprint(pool, &planned(p.id, "S2"), BY).await.unwrap();
    let into = |sprint: SprintId, title| NewIssue {
        sprint_id: Some(sprint),
        points: Some(1),
        ..new_issue(p.id, title)
    };
    let parent = create_issue(pool, &into(s1.id, "planned")).await.unwrap();
    start_sprint(pool, s1.id, BY).await.unwrap();
    let late = create_issue(pool, &into(s1.id, "late")).await;
    assert!(matches!(late, Err(Error::InvalidArgument(_))), "{late:?}");

    let sub = |sprint| NewIssue {
        kind: IssueKind::Subtask,
        parent_id: Some(parent.id),
        sprint_id: sprint,
        ..new_issue(p.id, "sub")
    };
    let with_parent = create_issue(pool, &sub(Some(s1.id))).await.unwrap();
    assert_eq!(
        with_parent.sprint_id,
        Some(s1.id),
        "a subtask goes with its parent"
    );
    let elsewhere = create_issue(pool, &sub(Some(s2.id))).await;
    assert!(
        matches!(elsewhere, Err(Error::InvalidArgument(_))),
        "{elsewhere:?}"
    );

    let report = sprint_report(pool, s1.id, "2020-03-02T12:00:00Z")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        report.committed,
        Some(1),
        "nothing slipped in after the start"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM issues WHERE sprint_id = ?")
        .bind(s1.id.0)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(count, 2, "the parent and its subtask");
}
