//! Issue transitions and the next-actor invariant (brainstorm §5–§6, decision #4): pure,
//! no I/O.
//!
//! Every open (non-terminal) issue names its next actor; a transition that would leave
//! none is unrepresentable, and an open issue that arrives with none is an engine error,
//! never a silent stall. `in_review` always waits on an agent or human reviewer, never a
//! timer. `blocked` needs at least one open blocker and keeps the next actor it had: the
//! one who resumes it once its blockers close, whom closing the last blocker wakes (E2.5).
//! A terminal issue has no next actor.

use std::fmt;

use super::{Actor, IssueState, NextActor};
use crate::domain::org::AgentId;

/// Something done to an issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueTransition {
    /// `backlog` | `todo` → `in_progress`; the next actor stays (normally the worker).
    Start,
    /// `backlog` → `todo`: ready to be picked up, without starting work; the next actor
    /// stays and is not woken.
    Ready,
    /// `in_progress` → `in_review`, waiting on `reviewer`.
    SubmitForReview { reviewer: Actor },
    /// `in_review` → `done`.
    Approve,
    /// `in_review` → `in_progress`, back to `assignee`.
    RequestChanges { assignee: Actor },
    /// `backlog` | `todo` | `in_progress` → `blocked`; needs an open blocker. Link the
    /// blockers first; the next actor stays.
    Block,
    /// `blocked` → `todo` once no blocker is open; the next actor stays and is woken.
    Unblock,
    /// `in_progress` → `done`.
    Done,
    /// Any open state → `cancelled`.
    Cancel,
    /// Same state, new next actor; an `in_review` issue only to an agent or human.
    Reassign { next: NextActor },
    /// `done` | `cancelled` → `todo`, with `next`.
    Reopen { next: NextActor },
    /// `todo` | `in_progress` | `blocked` → `backlog`, with `next` (normally a person, so
    /// nobody is woken; a new agent next actor is woken, as with any hand-over).
    Shelve { next: NextActor },
}

impl IssueTransition {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Ready => "ready",
            Self::SubmitForReview { .. } => "submit_for_review",
            Self::Approve => "approve",
            Self::RequestChanges { .. } => "request_changes",
            Self::Block => "block",
            Self::Unblock => "unblock",
            Self::Done => "done",
            Self::Cancel => "cancel",
            Self::Reassign { .. } => "reassign",
            Self::Reopen { .. } => "reopen",
            Self::Shelve { .. } => "shelve",
        }
    }
}

/// The outcome of a legal transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueStep {
    pub state: IssueState,
    /// `Some` exactly when `state` is open.
    pub next_actor: Option<NextActor>,
    /// The agent to wake: set when the next actor is an agent and either changed or is
    /// being handed the issue back (unblock, reopen). Never set for a human or a timer.
    pub wake: Option<AgentId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IllegalIssueTransition {
    /// The transition is not allowed from this state.
    Forbidden {
        from: IssueState,
        transition: &'static str,
    },
    /// The issue is open but names no next actor: an engine error (#4), not a stall.
    NoNextActor { state: IssueState },
    /// `in_review` must wait on an agent or human, not a timer.
    ReviewerRequired,
    /// A `blocked` issue needs at least one open blocker, whether it is being blocked or
    /// staying blocked.
    NoOpenBlocker,
    /// Unblocking needs every blocker closed.
    BlockersOpen { open: usize },
}

impl fmt::Display for IllegalIssueTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forbidden { from, transition } => {
                write!(f, "cannot {transition} a {} issue", from.as_str())
            }
            Self::NoNextActor { state } => {
                write!(
                    f,
                    "engine error: {} issue has no next actor",
                    state.as_str()
                )
            }
            Self::ReviewerRequired => f.write_str("in_review needs an agent or human reviewer"),
            Self::NoOpenBlocker => f.write_str("a blocked issue needs an open blocker"),
            Self::BlockersOpen { open } => write!(f, "{open} blocker(s) still open"),
        }
    }
}

impl std::error::Error for IllegalIssueTransition {}

/// The state and next actor `transition` moves an issue to, from `state` with `next`;
/// `open_blockers` is how many of its blockers are not done or cancelled.
pub fn apply(
    state: IssueState,
    next: Option<&NextActor>,
    transition: &IssueTransition,
    open_blockers: usize,
) -> Result<IssueStep, IllegalIssueTransition> {
    use IllegalIssueTransition as E;
    use IssueState as S;
    use IssueTransition as T;

    if !state.is_terminal() && next.is_none() {
        return Err(E::NoNextActor { state });
    }
    let (to, next_after) = match (state, transition) {
        (S::Backlog | S::Todo, T::Start) => (S::InProgress, next.cloned()),
        (S::Backlog, T::Ready) => (S::Todo, next.cloned()),
        (S::InProgress, T::SubmitForReview { reviewer }) => (S::InReview, Some((*reviewer).into())),
        (S::InReview, T::Approve) => (S::Done, None),
        (S::InReview, T::RequestChanges { assignee }) => (S::InProgress, Some((*assignee).into())),
        (S::Backlog | S::Todo | S::InProgress, T::Block) => (S::Blocked, next.cloned()),
        (S::Blocked, T::Unblock) if open_blockers > 0 => {
            return Err(E::BlockersOpen {
                open: open_blockers,
            });
        }
        (S::Blocked, T::Unblock) => (S::Todo, next.cloned()),
        (S::InProgress, T::Done) => (S::Done, None),
        (s, T::Cancel) if !s.is_terminal() => (S::Cancelled, None),
        (
            S::InReview,
            T::Reassign {
                next: NextActor::Timer(_),
            },
        ) => {
            return Err(E::ReviewerRequired);
        }
        (s, T::Reassign { next }) if !s.is_terminal() => (s, Some(next.clone())),
        (S::Done | S::Cancelled, T::Reopen { next }) => (S::Todo, Some(next.clone())),
        (S::Todo | S::InProgress | S::Blocked, T::Shelve { next }) => {
            (S::Backlog, Some(next.clone()))
        }
        _ => {
            return Err(E::Forbidden {
                from: state,
                transition: transition.name(),
            });
        }
    };
    if to == S::Blocked && open_blockers == 0 {
        return Err(E::NoOpenBlocker);
    }
    let handed_back = matches!(transition, T::Unblock | T::Reopen { .. });
    let wake = match &next_after {
        Some(NextActor::Agent(a)) if handed_back || next_after.as_ref() != next => Some(*a),
        _ => None,
    };
    Ok(IssueStep {
        state: to,
        next_actor: next_after,
        wake,
    })
}

#[cfg(test)]
mod tests;
