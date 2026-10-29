//! Issues, blocker links and comments.

use citadel_core::exec::RunId;
use citadel_core::work::Issue;

use super::*;

#[tokio::test]
async fn issue_crud() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let dev = agent(pool, c, "Dev").await;
    let mut i = create_issue(
        pool,
        &NewIssue {
            body: "Details".to_owned(),
            owner: Some(Actor::Agent(dev)),
            next_actor: Some(NextActor::Agent(dev)),
            points: Some(3),
            ..new_issue(p.id, "One")
        },
    )
    .await
    .unwrap();
    assert_eq!(get_issue(pool, i.id).await.unwrap(), Some(i.clone()));

    i.title = "Renamed".to_owned();
    i.kind = IssueKind::Bug;
    i.owner = Some(Actor::Human(ADMIN));
    i.points = None;
    i.rank = 0.5;
    assert!(update_issue(pool, &i).await.unwrap());
    assert_eq!(list_issues(pool, p.id).await.unwrap(), vec![i.clone()]);
    assert!(delete_issue(pool, i.id, AuditActor::System).await.unwrap());
    assert!(!delete_issue(pool, i.id, AuditActor::System).await.unwrap());
}

/// State, next actor, checkout and sprint move only through the engine: an edit that sets
/// them changes nothing but its other fields.
#[tokio::test]
async fn update_issue_cannot_change_state_next_actor_checkout_or_sprint() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let dev = agent(pool, c, "Dev").await;
    let stored = create_issue(pool, &new_issue(p.id, "One")).await.unwrap();
    let s = create_sprint(pool, &new_sprint(p.id, "S1", SprintState::Planned))
        .await
        .unwrap();
    let edit = Issue {
        title: "Renamed".to_owned(),
        state: IssueState::Done,
        next_actor: Some(NextActor::Agent(dev)),
        checkout_run_id: Some(RunId(7)),
        sprint_id: Some(s.id),
        ..stored.clone()
    };
    assert!(update_issue(pool, &edit).await.unwrap());
    let after = get_issue(pool, stored.id).await.unwrap().unwrap();
    assert_eq!(
        after,
        Issue {
            title: "Renamed".to_owned(),
            ..stored
        }
    );
}

#[tokio::test]
async fn no_issue_without_a_project() {
    let db = db().await;
    let err = create_issue(&db.pool, &new_issue(ProjectId(999), "Orphan"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::RowNotFound), "{err}");
    let direct = sqlx::query(
        "INSERT INTO issues (project_id, number, kind, title, state, next_user_id, rank) \
         VALUES (999, 1, 'task', 'Orphan', 'todo', 1, 1)",
    )
    .execute(&db.pool)
    .await
    .unwrap_err();
    assert!(is_constraint(&direct), "{direct}");
}

#[tokio::test]
async fn numbers_are_sequential_per_project_and_never_reused() {
    let db = db().await;
    let pool = &db.pool;
    let (c, a) = project_fixture(pool).await;
    let b = create_project(pool, &new_project(c, "WEB")).await.unwrap();
    let mut numbers = Vec::new();
    for (project, title) in [(a.id, "a1"), (b.id, "b1"), (a.id, "a2"), (a.id, "a3")] {
        numbers.push(
            create_issue(pool, &new_issue(project, title))
                .await
                .unwrap()
                .number,
        );
    }
    assert_eq!(numbers, vec![1, 1, 2, 3]);

    let last = list_issues(pool, a.id).await.unwrap().pop().unwrap();
    assert!(
        delete_issue(pool, last.id, AuditActor::System)
            .await
            .unwrap()
    );
    assert_eq!(
        create_issue(pool, &new_issue(a.id, "a4"))
            .await
            .unwrap()
            .number,
        4
    );

    // A rejected insert rolls the counter back with it.
    let bad = NewIssue {
        next_actor: None,
        ..new_issue(a.id, "rejected")
    };
    assert!(is_constraint(&create_issue(pool, &bad).await.unwrap_err()));
    assert_eq!(
        create_issue(pool, &new_issue(a.id, "a5"))
            .await
            .unwrap()
            .number,
        5
    );
}

#[tokio::test]
async fn non_terminal_issues_need_a_next_actor() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    for state in [IssueState::Backlog, IssueState::Todo] {
        let issue = NewIssue {
            state,
            next_actor: None,
            ..new_issue(p.id, "x")
        };
        let err = create_issue(pool, &issue).await.unwrap_err();
        assert!(is_constraint(&err), "{state:?}: {err}");
    }
    // The states only a transition reaches are refused outright, next actor or not.
    for state in [
        IssueState::InProgress,
        IssueState::InReview,
        IssueState::Blocked,
    ] {
        let issue = NewIssue {
            state,
            ..new_issue(p.id, "x")
        };
        let err = create_issue(pool, &issue).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{state:?}: {err}");
    }
    let done = create_issue(
        pool,
        &NewIssue {
            state: IssueState::Done,
            next_actor: None,
            ..new_issue(p.id, "done")
        },
    )
    .await
    .unwrap();
    assert_eq!(done.next_actor, None);

    // Reopening without naming a next actor is rejected.
    let reopened = sqlx::query("UPDATE issues SET state = 'todo' WHERE id = ?")
        .bind(done.id.0)
        .execute(pool)
        .await
        .unwrap_err();
    assert!(is_constraint(&reopened), "{reopened}");

    // Two next actors at once is rejected.
    let both = sqlx::query(
        "UPDATE issues SET next_user_id = 1, next_at = '2026-10-22T09:00:00Z' WHERE id = ?",
    )
    .bind(done.id.0)
    .execute(pool)
    .await
    .unwrap_err();
    assert!(is_constraint(&both), "{both}");
    // As are two owners and a negative estimate.
    let dev = agent(pool, c, "Dev").await;
    for (sql, value) in [
        (
            "UPDATE issues SET owner_agent_id = ?, owner_user_id = 1",
            dev.0,
        ),
        ("UPDATE issues SET points = ?", -1),
    ] {
        let err = sqlx::query(sql)
            .bind(value)
            .execute(pool)
            .await
            .unwrap_err();
        assert!(is_constraint(&err), "{sql}: {err}");
    }
}

#[tokio::test]
async fn subtask_iff_parent_within_the_project() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let story = create_issue(pool, &new_issue(p.id, "Story")).await.unwrap();
    let sub = NewIssue {
        kind: IssueKind::Subtask,
        parent_id: Some(story.id),
        ..new_issue(p.id, "Sub")
    };
    let sub = create_issue(pool, &sub).await.unwrap();

    let parentless = NewIssue {
        kind: IssueKind::Subtask,
        ..new_issue(p.id, "x")
    };
    assert!(is_constraint(
        &create_issue(pool, &parentless).await.unwrap_err()
    ));
    let task_with_parent = NewIssue {
        kind: IssueKind::Task,
        parent_id: Some(story.id),
        ..new_issue(p.id, "x")
    };
    assert!(is_constraint(
        &create_issue(pool, &task_with_parent).await.unwrap_err()
    ));

    let nested = NewIssue {
        kind: IssueKind::Subtask,
        parent_id: Some(sub.id),
        ..new_issue(p.id, "x")
    };
    let err = create_issue(pool, &nested).await.unwrap_err();
    assert!(is_raised(&err, "a subtask cannot have subtasks"), "{err}");

    let other = create_project(pool, &new_project(c, "WEB")).await.unwrap();
    let foreign = NewIssue {
        kind: IssueKind::Subtask,
        parent_id: Some(story.id),
        ..new_issue(other.id, "x")
    };
    let err = create_issue(pool, &foreign).await.unwrap_err();
    assert!(
        is_raised(&err, "parent belongs to another project"),
        "{err}"
    );

    // The parent story cannot itself become a subtask.
    let other_story = create_issue(pool, &new_issue(p.id, "Other")).await.unwrap();
    let mut demoted = story.clone();
    demoted.kind = IssueKind::Subtask;
    demoted.parent_id = Some(other_story.id);
    let err = update_issue(pool, &demoted).await.unwrap_err();
    assert!(
        is_raised(&err, "an issue with subtasks cannot become a subtask"),
        "{err}"
    );
}

#[tokio::test]
async fn epic_sprint_and_label_must_share_the_issue_project() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let other = create_project(pool, &new_project(c, "WEB")).await.unwrap();
    let foreign_epic = create_epic(pool, other.id, "Theirs").await.unwrap();
    let foreign_sprint = create_sprint(pool, &new_sprint(other.id, "S1", SprintState::Planned))
        .await
        .unwrap();
    let foreign_label = create_label(pool, other.id, "theirs").await.unwrap();

    let err = create_issue(
        pool,
        &NewIssue {
            epic_id: Some(foreign_epic.id),
            ..new_issue(p.id, "x")
        },
    )
    .await
    .unwrap_err();
    assert!(is_raised(&err, "epic belongs to another project"), "{err}");

    let foreign = NewIssue {
        sprint_id: Some(foreign_sprint.id),
        ..new_issue(p.id, "x")
    };
    let err = create_issue(pool, &foreign).await.unwrap_err();
    assert!(
        is_raised(&err, "sprint belongs to another project"),
        "{err}"
    );
    let mut i = create_issue(pool, &new_issue(p.id, "Mine")).await.unwrap();

    let err = add_issue_label(pool, i.id, foreign_label.id, AuditActor::System)
        .await
        .unwrap_err();
    assert!(is_raised(&err, "label belongs to another project"), "{err}");

    // A dangling epic id is a foreign-key error, not a cross-project one.
    i.epic_id = Some(EpicId(999));
    let err = update_issue(pool, &i).await.unwrap_err();
    assert!(is_constraint(&err), "{err}");
}

#[tokio::test]
async fn blocker_links_reject_self_duplicates_and_cycles() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let mut ids = Vec::new();
    for t in ["a", "b", "c", "d"] {
        ids.push(create_issue(pool, &new_issue(p.id, t)).await.unwrap().id);
    }
    let link = |blocker: IssueId, blocked: IssueId| BlockerLink { blocker, blocked };
    let (a, b, c, d) = (ids[0], ids[1], ids[2], ids[3]);

    add_blocker(pool, link(a, b)).await.unwrap();
    add_blocker(pool, link(b, c)).await.unwrap();
    add_blocker(pool, link(a, c)).await.unwrap(); // diamond, not a cycle

    assert!(matches!(
        add_blocker(pool, link(c, a)).await,
        Err(BlockerError::Cycle)
    ));
    assert!(matches!(
        add_blocker(pool, link(b, a)).await,
        Err(BlockerError::Cycle)
    ));
    assert!(
        matches!(add_blocker(pool, link(a, a)).await, Err(BlockerError::Db(e)) if is_constraint(&e))
    );
    assert!(
        matches!(add_blocker(pool, link(a, b)).await, Err(BlockerError::Db(e)) if is_constraint(&e))
    );

    assert_eq!(list_blockers(pool, c).await.unwrap(), vec![a, b]);
    assert_eq!(list_dependants(pool, a).await.unwrap(), vec![b, c]);

    // Removing the path frees the reverse link.
    assert!(
        remove_blocker(pool, link(b, c), AuditActor::System)
            .await
            .unwrap()
    );
    assert!(
        remove_blocker(pool, link(a, c), AuditActor::System)
            .await
            .unwrap()
    );
    add_blocker(pool, link(c, a)).await.unwrap();
    add_blocker(pool, link(d, c)).await.unwrap();
    assert!(matches!(
        add_blocker(pool, link(b, d)).await,
        Err(BlockerError::Cycle)
    ));
}

#[tokio::test]
async fn comments_dedupe_on_idempotency_key() {
    let db = db().await;
    let pool = &db.pool;
    let (c, p) = project_fixture(pool).await;
    let dev = agent(pool, c, "Dev").await;
    let i = create_issue(pool, &new_issue(p.id, "One")).await.unwrap();
    let j = create_issue(pool, &new_issue(p.id, "Two")).await.unwrap();
    let posted = |issue_id, body: &str, key: Option<&str>| NewComment {
        issue_id,
        author: Actor::Agent(dev),
        body: body.to_owned(),
        run_id: None,
        idempotency_key: key.map(str::to_owned),
    };

    let first = create_comment(pool, &posted(i.id, "Done", Some("k1")))
        .await
        .unwrap();
    let again = create_comment(pool, &posted(i.id, "Done (retry)", Some("k1")))
        .await
        .unwrap();
    assert_eq!(again, first);
    // Same key on another issue, and comments without a key, are distinct.
    create_comment(pool, &posted(j.id, "Done", Some("k1")))
        .await
        .unwrap();
    create_comment(pool, &posted(i.id, "x", None))
        .await
        .unwrap();
    create_comment(pool, &posted(i.id, "x", None))
        .await
        .unwrap();
    assert_eq!(list_comments(pool, i.id).await.unwrap().len(), 3);

    let mut human = create_comment(
        pool,
        &NewComment {
            author: Actor::Human(ADMIN),
            run_id: None,
            ..posted(i.id, "LGTM", Some("k2"))
        },
    )
    .await
    .unwrap();
    human.body = "LGTM!".to_owned();
    assert!(update_comment(pool, &human).await.unwrap());
    assert_eq!(
        get_comment(pool, human.id).await.unwrap(),
        Some(human.clone())
    );
    assert!(delete_comment(pool, human.id).await.unwrap());

    let no_author = sqlx::query("INSERT INTO comments (issue_id, body) VALUES (?, 'x')")
        .bind(i.id.0)
        .execute(pool)
        .await
        .unwrap_err();
    assert!(is_constraint(&no_author), "{no_author}");
    let two_authors = sqlx::query(
        "INSERT INTO comments (issue_id, author_agent_id, author_user_id, body) \
         VALUES (?, ?, 1, 'x')",
    )
    .bind(i.id.0)
    .bind(dev.0)
    .execute(pool)
    .await
    .unwrap_err();
    assert!(is_constraint(&two_authors), "{two_authors}");
}
