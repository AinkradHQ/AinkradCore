//! Issue transitions: the next-actor invariant against the schema, and the wake that
//! commits with each agent next-actor change.

use citadel_core::audit::AuditActor;
use citadel_core::work::{
    BlockerLink, IllegalIssueTransition, IssueTransition, apply as apply_issue,
};

use citadel_core::exec::WakeRequest;

use super::*;
use crate::store::work::{IssueTransitionError, add_blocker, get_issue, transition_issue};

const STATES: [IssueState; 7] = [
    IssueState::Backlog,
    IssueState::Todo,
    IssueState::InProgress,
    IssueState::InReview,
    IssueState::Blocked,
    IssueState::Done,
    IssueState::Cancelled,
];

const TIMER: &str = "2026-10-22T09:00:00.000Z";

/// Another issue in `of`'s project, `todo` and waiting on a human.
pub(super) async fn sibling(pool: &SqlitePool, of: IssueId) -> IssueId {
    let p = get_issue(pool, of).await.unwrap().unwrap().project_id;
    let i = NewIssue {
        project_id: p,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Other".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Human(UserId(1))),
        points: None,
        sprint_id: None,
    };
    create_issue(pool, &i).await.unwrap().id
}

pub(super) async fn wakes_for(pool: &SqlitePool, i: IssueId) -> Vec<WakeRequest> {
    let agents: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT agent_id FROM wake_requests")
        .fetch_all(pool)
        .await
        .unwrap();
    let mut all = vec![];
    for a in agents {
        all.extend(list_wake_requests(pool, AgentId(a)).await.unwrap());
    }
    all.retain(|w| w.issue_id == Some(i));
    all.sort_by_key(|w| w.id);
    all
}

/// Test-only: forces the issue's state and next actor with raw SQL, past the engine, to set
/// up a case. Production code moves issues only with `transition_issue`.
pub(super) async fn set(pool: &SqlitePool, i: IssueId, state: IssueState, next: Option<NextActor>) {
    let (agent, user, at) = match next {
        Some(NextActor::Agent(a)) => (Some(a.0), None, None),
        Some(NextActor::Human(u)) => (None, Some(u.0), None),
        Some(NextActor::Timer(t)) => (None, None, Some(t)),
        None => (None, None, None),
    };
    sqlx::query(
        "UPDATE issues SET state = ?, next_agent_id = ?, next_user_id = ?, next_at = ? \
         WHERE id = ?",
    )
    .bind(state.as_str())
    .bind(agent)
    .bind(user)
    .bind(at)
    .bind(i.0)
    .execute(pool)
    .await
    .unwrap();
}

fn transitions(dev: AgentId, other: AgentId) -> Vec<IssueTransition> {
    use IssueTransition as T;
    let mut all = vec![
        T::Start,
        T::Approve,
        T::Block,
        T::Unblock,
        T::Done,
        T::Cancel,
    ];
    for a in [
        Actor::Agent(dev),
        Actor::Agent(other),
        Actor::Human(UserId(1)),
    ] {
        all.push(T::SubmitForReview { reviewer: a });
        all.push(T::RequestChanges { assignee: a });
        all.push(T::Reassign { next: a.into() });
        all.push(T::Reopen { next: a.into() });
    }
    all.push(T::Reassign {
        next: NextActor::Timer(TIMER.to_owned()),
    });
    all
}

/// Every state × transition, with and without an open blocker: the schema's CHECKs never
/// fire, every stored result keeps the invariant, and the wakes stored match the rules.
#[tokio::test]
async fn every_transition_keeps_the_schema_and_wakes_by_the_rules() {
    let db = db().await;
    let pool = &db.pool;
    let c = create_company(pool, "A").await.unwrap().id;
    let (dev, other) = (agent(pool, c).await, agent(pool, c).await);
    let i = issue(pool, c).await;
    let blocker = sibling(pool, i).await;
    let mut legal = 0;
    for with_blocker in [false, true] {
        if with_blocker {
            add_blocker(
                pool,
                BlockerLink {
                    blocker,
                    blocked: i,
                },
            )
            .await
            .unwrap();
        }
        for state in STATES {
            for start_next in [NextActor::Agent(dev), NextActor::Human(UserId(1))] {
                for t in transitions(dev, other) {
                    set(pool, i, state, Some(start_next.clone())).await;
                    let wakes = wakes_for(pool, i).await.len();
                    let expected = apply_issue(state, Some(&start_next), &t, with_blocker as usize);
                    let case = format!("{state:?} {start_next:?} {t:?} blocker={with_blocker}");
                    match transition_issue(pool, i, &t, AuditActor::System).await {
                        Ok(stored) => {
                            legal += 1;
                            let step = expected.expect(&case);
                            assert_eq!(
                                (stored.state, &stored.next_actor),
                                (step.state, &step.next_actor),
                                "{case}"
                            );
                            let new = wakes_for(pool, i).await;
                            assert_eq!(new.len() - wakes, step.wake.is_some() as usize, "{case}");
                            if let Some(a) = step.wake {
                                assert_eq!(new.last().unwrap().agent_id, a, "{case}");
                            }
                        }
                        Err(IssueTransitionError::Illegal(e)) => {
                            assert_eq!(Err(e), expected, "{case}");
                            assert_eq!(wakes_for(pool, i).await.len(), wakes, "{case}");
                        }
                        Err(e) => panic!("{case}: {e}"),
                    }
                }
            }
        }
    }
    assert!(legal > 50, "{legal}");
}

#[tokio::test]
async fn in_review_without_a_reviewer_is_rejected_and_nothing_changes() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    set(pool, i, IssueState::InReview, Some(NextActor::Agent(dev))).await;
    let before = get_issue(pool, i).await.unwrap();
    let timer = IssueTransition::Reassign {
        next: NextActor::Timer(TIMER.to_owned()),
    };
    assert!(matches!(
        transition_issue(pool, i, &timer, AuditActor::System).await,
        Err(IssueTransitionError::Illegal(
            IllegalIssueTransition::ReviewerRequired
        ))
    ));
    assert_eq!(get_issue(pool, i).await.unwrap(), before);
    // A bad timer timestamp is refused too, outside review.
    set(pool, i, IssueState::Todo, Some(NextActor::Agent(dev))).await;
    let bad = IssueTransition::Reassign {
        next: NextActor::Timer("soon".to_owned()),
    };
    assert!(matches!(
        transition_issue(pool, i, &bad, AuditActor::System).await,
        Err(IssueTransitionError::Db(Error::InvalidArgument(_)))
    ));
}

#[tokio::test]
async fn an_agent_next_actor_change_stores_exactly_one_wake() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let to_dev = IssueTransition::Reassign {
        next: NextActor::Agent(dev),
    };
    let by = AuditActor::User(UserId(1));
    let stored = transition_issue(pool, i, &to_dev, by).await.unwrap();
    assert_eq!(
        (stored.state, stored.next_actor),
        (IssueState::Todo, Some(NextActor::Agent(dev)))
    );
    let wakes = wakes_for(pool, i).await;
    assert_eq!(wakes.len(), 1);
    let seq: i64 = sqlx::query_scalar(
        "SELECT seq FROM audit_events WHERE entity_kind = 'issue' AND entity_id = ? \
         AND action = 'issue.todo'",
    )
    .bind(i.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        wakes[0].idempotency_key,
        format!("issue:{}:audit:{seq}", i.0)
    );
    assert_eq!(
        (wakes[0].source, wakes[0].agent_id),
        (WakeSource::Assignment, dev)
    );
    // Reassigning to the same agent, or the agent starting, wakes nobody.
    transition_issue(pool, i, &to_dev, by).await.unwrap();
    transition_issue(pool, i, &IssueTransition::Start, AuditActor::Agent(dev))
        .await
        .unwrap();
    assert_eq!(wakes_for(pool, i).await.len(), 1);
}

/// A wake that cannot be stored rolls back the transition and its audit, and an audit
/// that cannot be stored rolls back the transition and its wake.
#[tokio::test]
async fn a_failed_wake_or_audit_rolls_everything_back() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let before = get_issue(pool, i).await.unwrap();
    let to_dev = IssueTransition::Reassign {
        next: NextActor::Agent(dev),
    };
    for (trigger, create, drop) in [
        (
            "wake_down",
            "CREATE TRIGGER wake_down BEFORE INSERT ON wake_requests \
             BEGIN SELECT RAISE(ABORT, 'wake_down'); END",
            "DROP TRIGGER wake_down",
        ),
        (
            "audit_down",
            "CREATE TRIGGER audit_down BEFORE INSERT ON audit_events \
             BEGIN SELECT RAISE(ABORT, 'audit_down'); END",
            "DROP TRIGGER audit_down",
        ),
    ] {
        sqlx::query(create).execute(pool).await.unwrap();
        let err = transition_issue(pool, i, &to_dev, AuditActor::System)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, IssueTransitionError::Db(e) if is_raised(e, trigger)),
            "{err}"
        );
        assert_eq!(get_issue(pool, i).await.unwrap(), before);
        assert!(wakes_for(pool, i).await.is_empty());
        let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(audited, 0);
        sqlx::query(drop).execute(pool).await.unwrap();
    }
    transition_issue(pool, i, &to_dev, AuditActor::System)
        .await
        .unwrap();
    assert_eq!(wakes_for(pool, i).await.len(), 1);
}
