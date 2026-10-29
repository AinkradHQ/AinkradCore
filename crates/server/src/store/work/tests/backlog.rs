//! The backlog (E5.1): ordering, epic and label assignment, the filtered listing, `ready`,
//! and who may read it.

use ainkrad_core::org::{TeamMembership, TeamRole};
use ainkrad_core::work::{BacklogFilter, Issue, IssueTransition, Position};

use super::*;
use crate::store::org::{create_membership, update_agent};

/// The audit actions about `issue`, oldest first.
async fn actions(pool: &SqlitePool, issue: IssueId) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE entity_kind = 'issue' AND entity_id = ? \
         ORDER BY seq",
    )
    .bind(issue.0)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn page(pool: &SqlitePool, p: ProjectId, f: &BacklogFilter) -> Vec<String> {
    let issues = backlog_page(pool, p, f, 0, 50).await.unwrap();
    issues.into_iter().map(|i| i.title).collect()
}

async fn issues(pool: &SqlitePool, p: ProjectId, titles: &[&str]) -> Vec<Issue> {
    let mut out = vec![];
    for t in titles {
        out.push(create_issue(pool, &new_issue(p, t)).await.unwrap());
    }
    out
}

#[tokio::test]
async fn backlog_is_open_unsprinted_top_level_issues_by_rank() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let s = create_sprint(pool, &new_sprint(p.id, "S1", SprintState::Planned))
        .await
        .unwrap();
    let [a, b, _c] = issues(pool, p.id, &["a", "b", "c"])
        .await
        .try_into()
        .unwrap();
    assert!(a.rank < b.rank);
    let sprinted = NewIssue {
        sprint_id: Some(s.id),
        ..new_issue(p.id, "in sprint")
    };
    create_issue(pool, &sprinted).await.unwrap();
    let done = NewIssue {
        state: IssueState::Done,
        next_actor: None,
        ..new_issue(p.id, "done")
    };
    create_issue(pool, &done).await.unwrap();
    let sub = NewIssue {
        kind: IssueKind::Subtask,
        parent_id: Some(a.id),
        ..new_issue(p.id, "sub")
    };
    create_issue(pool, &sub).await.unwrap();

    move_issue(pool, b.id, Position::Top, AuditActor::System)
        .await
        .unwrap();
    let all = BacklogFilter::default();
    assert_eq!(page(pool, p.id, &all).await, ["b", "a", "c"]);
}

#[tokio::test]
async fn moves_to_top_bottom_before_and_after_and_audits() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let [a, b, c_, d] = issues(pool, p.id, &["a", "b", "c", "d"])
        .await
        .try_into()
        .unwrap();
    let all = BacklogFilter::default();
    let by = AuditActor::User(ADMIN);

    move_issue(pool, d.id, Position::Top, by).await.unwrap();
    assert_eq!(page(pool, p.id, &all).await, ["d", "a", "b", "c"]);
    move_issue(pool, d.id, Position::Bottom, by).await.unwrap();
    assert_eq!(page(pool, p.id, &all).await, ["a", "b", "c", "d"]);
    move_issue(pool, a.id, Position::After(c_.id), by)
        .await
        .unwrap();
    assert_eq!(page(pool, p.id, &all).await, ["b", "c", "a", "d"]);
    let moved = move_issue(pool, d.id, Position::Before(b.id), by)
        .await
        .unwrap();
    assert_eq!(page(pool, p.id, &all).await, ["d", "b", "c", "a"]);
    assert_eq!(get_issue(pool, d.id).await.unwrap(), Some(moved));
    assert_eq!(actions(pool, d.id).await, ["issue.moved"; 3]);

    // Next to itself, next to another project's issue, or a missing one: refused.
    let own = move_issue(pool, a.id, Position::After(a.id), by).await;
    assert!(matches!(own, Err(Error::InvalidArgument(_))), "{own:?}");
    let other = create_project(pool, &new_project(c, "WEB")).await.unwrap();
    let foreign = create_issue(pool, &new_issue(other.id, "x")).await.unwrap();
    let cross = move_issue(pool, a.id, Position::Before(foreign.id), by).await;
    assert!(matches!(cross, Err(Error::InvalidArgument(_))), "{cross:?}");
    let gone = move_issue(pool, a.id, Position::Before(IssueId(999)), by).await;
    assert!(matches!(gone, Err(Error::RowNotFound)), "{gone:?}");
    let gone = move_issue(pool, IssueId(999), Position::Top, by).await;
    assert!(matches!(gone, Err(Error::RowNotFound)), "{gone:?}");
    assert_eq!(page(pool, p.id, &all).await, ["d", "b", "c", "a"]);
}

/// 1000 random moves against a plain list: the stored order matches it after every move, and
/// ranks stay strictly increasing, renumbering when halving runs out of room.
#[tokio::test]
async fn a_thousand_random_moves_keep_a_total_order() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let titles: Vec<String> = (0..12).map(|n| format!("i{n}")).collect();
    let titles: Vec<&str> = titles.iter().map(String::as_str).collect();
    let mut model: Vec<IssueId> = issues(pool, p.id, &titles)
        .await
        .iter()
        .map(|i| i.id)
        .collect();
    // A fixed LCG: the same moves every run.
    let mut seed: u64 = 0x5eed;
    let mut next = |n: usize| {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize % n
    };
    for _ in 0..1000 {
        let id = model[next(model.len())];
        let anchor = model[next(model.len())];
        let to = match next(4) {
            // Mostly between the same two neighbours, so halving runs out and renumbers.
            _ if anchor == id => Position::Top,
            0 => Position::Top,
            1 => Position::Bottom,
            2 => Position::Before(anchor),
            _ => Position::After(anchor),
        };
        move_issue(pool, id, to, AuditActor::System).await.unwrap();
        model.retain(|i| *i != id);
        let at = match to {
            Position::Top => 0,
            Position::Bottom => model.len(),
            Position::Before(a) => model.iter().position(|i| *i == a).unwrap(),
            Position::After(a) => model.iter().position(|i| *i == a).unwrap() + 1,
        };
        model.insert(at, id);
        let stored = list_issues(pool, p.id).await.unwrap();
        let mut stored: Vec<(f64, IssueId)> = stored.iter().map(|i| (i.rank, i.id)).collect();
        stored.sort_by(|x, y| x.0.total_cmp(&y.0).then(x.1.0.cmp(&y.1.0)));
        assert!(
            stored.windows(2).all(|w| w[0].0 < w[1].0),
            "ties: {stored:?}"
        );
        let order: Vec<IssueId> = stored.into_iter().map(|(_, id)| id).collect();
        assert_eq!(order, model);
    }
}

/// Two issues leapfrogging just after a third halve the gap below it every move; past what an
/// f64 can split, the project is renumbered and the order still holds.
#[tokio::test]
async fn halving_without_room_renumbers_the_project() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let [a, b, c] = issues(pool, p.id, &["a", "b", "c"])
        .await
        .try_into()
        .unwrap();
    let by = AuditActor::System;
    let mut renumbered = false;
    for n in 0..200 {
        let (mover, anchor) = if n % 2 == 0 {
            (c.id, b.id)
        } else {
            (b.id, c.id)
        };
        move_issue(pool, mover, Position::Before(anchor), by)
            .await
            .unwrap();
        let ranks: Vec<f64> = list_issues(pool, p.id)
            .await
            .unwrap()
            .iter()
            .map(|i| i.rank)
            .collect();
        renumbered |= n > 0 && ranks.contains(&2.0);
        let expect = if n % 2 == 0 {
            ["a", "c", "b"]
        } else {
            ["a", "b", "c"]
        };
        assert_eq!(page(pool, p.id, &BacklogFilter::default()).await, expect);
    }
    assert!(renumbered);
    assert_eq!(get_issue(pool, a.id).await.unwrap().unwrap().rank, 1.0);
}

#[tokio::test]
async fn epic_and_labels_are_assigned_with_an_audit() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let i = create_issue(pool, &new_issue(p.id, "One")).await.unwrap();
    let e = create_epic(pool, p.id, "Engine").await.unwrap();
    let by = AuditActor::User(ADMIN);

    assert!(set_issue_epic(pool, i.id, Some(e.id), by).await.unwrap());
    assert_eq!(
        get_issue(pool, i.id).await.unwrap().unwrap().epic_id,
        Some(e.id)
    );
    assert!(set_issue_epic(pool, i.id, None, by).await.unwrap());
    assert_eq!(get_issue(pool, i.id).await.unwrap().unwrap().epic_id, None);
    assert!(!set_issue_epic(pool, IssueId(999), None, by).await.unwrap());
    let other = create_project(pool, &new_project(c, "WEB")).await.unwrap();
    let foreign = create_epic(pool, other.id, "Elsewhere").await.unwrap();
    let err = set_issue_epic(pool, i.id, Some(foreign.id), by)
        .await
        .unwrap_err();
    assert!(is_raised(&err, "epic belongs to another project"), "{err}");

    let l = create_label(pool, p.id, "infra").await.unwrap();
    add_issue_label(pool, i.id, l.id, by).await.unwrap();
    add_issue_label(pool, i.id, l.id, by).await.unwrap();
    assert_eq!(
        list_issue_labels(pool, i.id).await.unwrap(),
        vec![l.clone()]
    );
    assert!(remove_issue_label(pool, i.id, l.id, by).await.unwrap());
    assert!(!remove_issue_label(pool, i.id, l.id, by).await.unwrap());
    let gone = add_issue_label(pool, IssueId(999), l.id, by).await;
    assert!(matches!(gone, Err(Error::RowNotFound)), "{gone:?}");
    assert_eq!(
        actions(pool, i.id).await,
        [
            "issue.epic_set",
            "issue.epic_set",
            "issue.labeled",
            "issue.unlabeled"
        ]
    );
}

#[tokio::test]
async fn backlog_filters_and_pages() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let dev = agent(pool, c, "Dev").await;
    let e = create_epic(pool, p.id, "Engine").await.unwrap();
    let l = create_label(pool, p.id, "infra").await.unwrap();
    let new = |title: &str| new_issue(p.id, title);
    create_issue(
        pool,
        &NewIssue {
            epic_id: Some(e.id),
            ..new("story")
        },
    )
    .await
    .unwrap();
    let bug = NewIssue {
        kind: IssueKind::Bug,
        owner: Some(Actor::Agent(dev)),
        ..new("bug")
    };
    let bug = create_issue(pool, &bug).await.unwrap();
    let todo = NewIssue {
        kind: IssueKind::Task,
        state: IssueState::Todo,
        owner: Some(Actor::Human(ADMIN)),
        ..new("todo")
    };
    create_issue(pool, &todo).await.unwrap();
    add_issue_label(pool, bug.id, l.id, AuditActor::System)
        .await
        .unwrap();

    let all = BacklogFilter::default();
    assert_eq!(page(pool, p.id, &all).await, ["story", "bug", "todo"]);
    let epic = BacklogFilter {
        epic_id: Some(e.id),
        ..all.clone()
    };
    assert_eq!(page(pool, p.id, &epic).await, ["story"]);
    let label = BacklogFilter {
        label_id: Some(l.id),
        ..all.clone()
    };
    assert_eq!(page(pool, p.id, &label).await, ["bug"]);
    let kind = BacklogFilter {
        kind: Some(IssueKind::Task),
        ..all.clone()
    };
    assert_eq!(page(pool, p.id, &kind).await, ["todo"]);
    let state = BacklogFilter {
        state: Some(IssueState::Backlog),
        ..all.clone()
    };
    assert_eq!(page(pool, p.id, &state).await, ["story", "bug"]);
    let mine = BacklogFilter {
        assignee: Some(Actor::Agent(dev)),
        ..all.clone()
    };
    assert_eq!(page(pool, p.id, &mine).await, ["bug"]);
    let admin = BacklogFilter {
        assignee: Some(Actor::Human(ADMIN)),
        ..all.clone()
    };
    assert_eq!(page(pool, p.id, &admin).await, ["todo"]);
    let both = BacklogFilter {
        epic_id: Some(e.id),
        kind: Some(IssueKind::Bug),
        ..all.clone()
    };
    assert!(page(pool, p.id, &both).await.is_empty());

    let titles = |v: Vec<Issue>| v.into_iter().map(|i| i.title).collect::<Vec<_>>();
    let second = backlog_page(pool, p.id, &all, 1, 1).await.unwrap();
    assert_eq!(titles(second), ["bug"]);
    let past = backlog_page(pool, p.id, &all, 3, 10).await.unwrap();
    assert!(past.is_empty());

    // A page holds at most MAX_BACKLOG_PAGE issues, whatever is asked.
    for n in 0..MAX_BACKLOG_PAGE {
        create_issue(pool, &new(&format!("n{n}"))).await.unwrap();
    }
    let big = backlog_page(pool, p.id, &all, 0, u32::MAX).await.unwrap();
    assert_eq!(big.len(), MAX_BACKLOG_PAGE as usize);
}

/// `ready` moves a backlog issue to `todo` through the engine: audited, nobody woken.
#[tokio::test]
async fn ready_moves_backlog_to_todo_without_a_wake() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let dev = agent(pool, c, "Dev").await;
    let i = NewIssue {
        next_actor: Some(NextActor::Agent(dev)),
        ..new_issue(p.id, "One")
    };
    let i = create_issue(pool, &i).await.unwrap();
    let by = AuditActor::User(ADMIN);
    let ready = transition_issue(pool, i.id, &IssueTransition::Ready, by)
        .await
        .unwrap();
    assert_eq!(ready.state, IssueState::Todo);
    assert_eq!(ready.next_actor, Some(NextActor::Agent(dev)));
    assert_eq!(actions(pool, i.id).await, ["issue.todo"]);
    let wakes: i64 = sqlx::query_scalar("SELECT count(*) FROM wake_requests")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(wakes, 0);
    let again = transition_issue(pool, i.id, &IssueTransition::Ready, by).await;
    assert!(
        matches!(again, Err(IssueTransitionError::Illegal(_))),
        "{again:?}"
    );
}

/// The product owner and team lead of the project's team, and the company's CEO and CTO,
/// may read the backlog; a member, a stranger and another company's CEO may not.
#[tokio::test]
async fn who_may_read_the_backlog() {
    let db = db().await;
    let pool = &db.pool;
    let (c, mut p) = project_fixture(pool).await;
    let d = create_department(pool, c, "Engineering").await.unwrap();
    let team = create_team(pool, d.id, "Core").await.unwrap();
    p.team_id = Some(team.id);
    assert!(update_project(pool, &p).await.unwrap());
    let mut may = vec![];
    for (name, role) in [
        ("po", Some(TeamRole::ProductOwner)),
        ("lead", Some(TeamRole::TeamLead)),
        ("member", Some(TeamRole::Member)),
        ("stranger", None),
    ] {
        let a = agent(pool, c, name).await;
        if let Some(team_role) = role {
            let m = TeamMembership {
                team_id: team.id,
                agent_id: a,
                team_role,
            };
            create_membership(pool, &m).await.unwrap();
        }
        may.push(may_read_backlog(pool, a, p.id).await.unwrap());
    }
    assert_eq!(may, [true, true, false, false]);

    let other = create_company(pool, "B").await.unwrap().id;
    for (company, role, expected) in [
        (c, OrgRole::Ceo, true),
        (c, OrgRole::Cto, true),
        (other, OrgRole::Ceo, false),
    ] {
        let id = agent(pool, company, "exec").await;
        let mut a = crate::store::org::get_agent(pool, id)
            .await
            .unwrap()
            .unwrap();
        a.org_role = role;
        assert!(update_agent(pool, &a).await.unwrap());
        assert_eq!(
            may_read_backlog(pool, id, p.id).await.unwrap(),
            expected,
            "{role:?}"
        );
    }
}

/// An estimate is audited with its old and new points; a closed issue is not estimated.
#[tokio::test]
async fn estimates_are_audited_and_only_for_open_issues() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let i = create_issue(pool, &new_issue(p.id, "a")).await.unwrap();
    let by = AuditActor::User(ADMIN);
    assert_eq!(
        estimate_issue(pool, i.id, Some(3), by)
            .await
            .unwrap()
            .points,
        Some(3)
    );
    assert_eq!(
        estimate_issue(pool, i.id, None, by).await.unwrap().points,
        None
    );
    let details: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'issue.estimated' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        details,
        [
            r#"{"from":null,"to":3,"project_id":1}"#,
            r#"{"from":3,"to":null,"project_id":1}"#
        ]
    );
    let done = NewIssue {
        state: IssueState::Done,
        next_actor: None,
        ..new_issue(p.id, "done")
    };
    let done = create_issue(pool, &done).await.unwrap();
    let e = estimate_issue(pool, done.id, Some(1), by).await;
    assert!(
        matches!(e, Err(SprintError::IssueClosed(IssueState::Done))),
        "{e:?}"
    );
    let gone = estimate_issue(pool, IssueId(999), Some(1), by).await;
    assert!(matches!(gone, Err(SprintError::NotFound)), "{gone:?}");
}
