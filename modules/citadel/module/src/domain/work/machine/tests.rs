use super::*;
use crate::domain::work::UserId;

const STATES: [IssueState; 7] = [
    IssueState::Backlog,
    IssueState::Todo,
    IssueState::InProgress,
    IssueState::InReview,
    IssueState::Blocked,
    IssueState::Done,
    IssueState::Cancelled,
];

fn agent(n: i64) -> NextActor {
    NextActor::Agent(AgentId(n))
}

fn timer() -> NextActor {
    NextActor::Timer("2026-10-22T09:00:00Z".to_owned())
}

/// Every next actor an issue can arrive with, including none.
fn next_actors() -> Vec<Option<NextActor>> {
    vec![
        None,
        Some(agent(1)),
        Some(agent(2)),
        Some(NextActor::Human(UserId(1))),
        Some(timer()),
    ]
}

/// Every transition shape, over every kind of actor.
fn transitions() -> Vec<IssueTransition> {
    use IssueTransition as T;
    let actors = [
        Actor::Agent(AgentId(1)),
        Actor::Agent(AgentId(2)),
        Actor::Human(UserId(1)),
    ];
    let mut all = vec![
        T::Start,
        T::Ready,
        T::Approve,
        T::Block,
        T::Unblock,
        T::Done,
        T::Cancel,
    ];
    for a in actors {
        all.push(T::SubmitForReview { reviewer: a });
        all.push(T::RequestChanges { assignee: a });
    }
    for n in next_actors().into_iter().flatten() {
        all.push(T::Reassign { next: n.clone() });
        all.push(T::Reopen { next: n.clone() });
        all.push(T::Shelve { next: n });
    }
    all
}

#[test]
fn no_transition_ever_leaves_an_open_issue_without_a_next_actor() {
    let (mut checked, mut legal) = (0, 0);
    for state in STATES {
        for next in next_actors() {
            for t in transitions() {
                for open_blockers in 0..3 {
                    checked += 1;
                    let Ok(step) = apply(state, next.as_ref(), &t, open_blockers) else {
                        continue;
                    };
                    legal += 1;
                    let case = format!("{state:?} {next:?} {t:?} {open_blockers}");
                    // An open issue that arrives with no next actor is never accepted.
                    assert!(state.is_terminal() || next.is_some(), "{case}");
                    // Mirrors the DB CHECK: a next actor exactly when open.
                    assert_eq!(
                        step.next_actor.is_some(),
                        !step.state.is_terminal(),
                        "{case}"
                    );
                    if step.state == IssueState::InReview {
                        assert!(
                            matches!(
                                step.next_actor,
                                Some(NextActor::Agent(_) | NextActor::Human(_))
                            ),
                            "{case}"
                        );
                    }
                    if step.state == IssueState::Blocked {
                        assert!(open_blockers > 0, "{case}");
                    }
                    // A wake goes to the new next actor, and only when it is an agent.
                    match (&step.next_actor, step.wake) {
                        (Some(NextActor::Agent(a)), Some(w)) => assert_eq!(*a, w, "{case}"),
                        (_, Some(_)) => panic!("woke a non-agent: {case}"),
                        _ => {}
                    }
                    // Every change to an agent next actor wakes it exactly once.
                    if let Some(NextActor::Agent(a)) = &step.next_actor
                        && step.next_actor.as_ref() != next.as_ref()
                    {
                        assert_eq!(step.wake, Some(*a), "{case}");
                    }
                }
            }
        }
    }
    assert_eq!(checked, 7 * 5 * transitions().len() * 3);
    assert!(legal > 100, "{legal}");
}

#[test]
fn an_open_issue_with_no_next_actor_is_an_engine_error() {
    for state in STATES.into_iter().filter(|s| !s.is_terminal()) {
        for t in transitions() {
            assert_eq!(
                apply(state, None, &t, 0),
                Err(IllegalIssueTransition::NoNextActor { state })
            );
        }
    }
}

#[test]
fn review_needs_an_agent_or_human() {
    let reviewer = NextActor::Human(UserId(1));
    let t = IssueTransition::Reassign { next: timer() };
    assert_eq!(
        apply(IssueState::InReview, Some(&reviewer), &t, 0),
        Err(IllegalIssueTransition::ReviewerRequired)
    );
    let submit = IssueTransition::SubmitForReview {
        reviewer: Actor::Agent(AgentId(2)),
    };
    let step = apply(IssueState::InProgress, Some(&agent(1)), &submit, 0).unwrap();
    assert_eq!(
        step,
        IssueStep {
            state: IssueState::InReview,
            next_actor: Some(agent(2)),
            wake: Some(AgentId(2)),
        }
    );
}

#[test]
fn blocking_needs_an_open_blocker_and_unblocking_none() {
    let worker = agent(1);
    assert_eq!(
        apply(
            IssueState::InProgress,
            Some(&worker),
            &IssueTransition::Block,
            0
        ),
        Err(IllegalIssueTransition::NoOpenBlocker)
    );
    let parked = apply(
        IssueState::InProgress,
        Some(&worker),
        &IssueTransition::Block,
        1,
    )
    .unwrap();
    assert_eq!(
        (parked.state, parked.next_actor.as_ref(), parked.wake),
        (IssueState::Blocked, Some(&worker), None)
    );
    assert_eq!(
        apply(
            IssueState::Blocked,
            Some(&worker),
            &IssueTransition::Unblock,
            2
        ),
        Err(IllegalIssueTransition::BlockersOpen { open: 2 })
    );
    // The worker is handed the issue back and woken, though it was already next actor.
    let resumed = apply(
        IssueState::Blocked,
        Some(&worker),
        &IssueTransition::Unblock,
        0,
    )
    .unwrap();
    assert_eq!(
        resumed,
        IssueStep {
            state: IssueState::Todo,
            next_actor: Some(worker),
            wake: Some(AgentId(1)),
        }
    );
}

#[test]
fn starting_your_own_issue_wakes_nobody() {
    let step = apply(
        IssueState::Todo,
        Some(&agent(1)),
        &IssueTransition::Start,
        0,
    )
    .unwrap();
    assert_eq!((step.state, step.wake), (IssueState::InProgress, None));
    assert!(matches!(
        apply(IssueState::Done, None, &IssueTransition::Start, 0),
        Err(IllegalIssueTransition::Forbidden { .. })
    ));
}

#[test]
fn ready_moves_backlog_to_todo_without_waking() {
    let worker = agent(1);
    let step = apply(
        IssueState::Backlog,
        Some(&worker),
        &IssueTransition::Ready,
        0,
    )
    .unwrap();
    assert_eq!(
        step,
        IssueStep {
            state: IssueState::Todo,
            next_actor: Some(worker.clone()),
            wake: None,
        }
    );
    for from in STATES.into_iter().filter(|s| *s != IssueState::Backlog) {
        assert!(
            apply(from, Some(&worker), &IssueTransition::Ready, 0).is_err(),
            "{from:?}"
        );
    }
}
