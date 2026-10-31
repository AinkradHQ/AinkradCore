//! The stuck detector's rules (E2.8, brainstorm §6): the Paperclip watchdog's checks as
//! pure functions over what the store read. Each finding says why, in words, what would
//! unstick it, and the repair the scheduler applies by itself (E15.8, `RepairAction`): wake
//! the next actor again, hand the issue to its lead or up the chain, unblock it, release a dead
//! checkout, requeue a lost run, or drop a wake nothing can serve.
//!
//! The engine already forbids several of these states (an open issue with no next actor, a
//! `blocked` issue with no open blocker, a timer reviewer); they are still checked, so a
//! bug or a raw write shows up here instead of as a silent stall.

use std::str::FromStr;

use crate::domain::org::{AgentId, AgentStatus, UnknownVariant, text_enum};
use crate::domain::work::{IssueId, IssueState, NextActor, RunId};

text_enum!(StuckKind {
    NoNextActor => "no_next_actor",
    BlockedNoBlocker => "blocked_no_blocker",
    BlockedBlockersClosed => "blocked_blockers_closed",
    AgentPausedByBreaker => "agent_paused_by_breaker",
    ReviewerInactive => "reviewer_inactive",
    NextActorInactive => "next_actor_inactive",
    ReviewNoReviewer => "review_no_reviewer",
    InProgressIdle => "in_progress_idle",
    TodoIdle => "todo_idle",
    WakeNoRunner => "wake_no_runner",
    RunQueuedNoLease => "run_queued_no_lease",
    CheckoutDead => "checkout_dead",
});

// What the scheduler does about a stuck finding (E15.8): wake the next actor again; hand
// the issue to its team's lead (no agent to start the chain from) or up the chain from the agent
// it waits on; unblock it (its next actor is woken); clear a checkout held by an ended run;
// cancel a run nothing will claim and wake its agent again; drop a wake for no issue that no
// runner can serve, with the reason; or only tell the admin (a full disk needs a person).
text_enum!(RepairAction {
    Rewake => "rewake",
    ReassignToLead => "reassign_to_lead",
    Escalate => "escalate",
    Unblock => "unblock",
    ReleaseCheckout => "release_checkout",
    Requeue => "requeue",
    DropWake => "drop_wake",
    Notify => "notify",
});

/// The repair for a finding of `kind`, waiting on `agent` (when there is one) about `issue`.
pub fn repair_for(kind: StuckKind, agent: Option<AgentId>, issue: Option<IssueId>) -> RepairAction {
    use RepairAction as R;
    use StuckKind as K;
    match kind {
        K::NoNextActor => R::ReassignToLead,
        K::BlockedNoBlocker | K::BlockedBlockersClosed => R::Unblock,
        K::AgentPausedByBreaker | K::ReviewerInactive | K::NextActorInactive => R::Escalate,
        K::ReviewNoReviewer if agent.is_none() => R::ReassignToLead,
        K::ReviewNoReviewer | K::InProgressIdle | K::TodoIdle => R::Rewake,
        K::WakeNoRunner if issue.is_some() => R::Escalate,
        K::WakeNoRunner => R::DropWake,
        K::RunQueuedNoLease => R::Requeue,
        K::CheckoutDead => R::ReleaseCheckout,
    }
}

/// The last repair applied to an issue (E15.8): its action and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastRepair {
    pub action: String,
    pub at: String,
}

/// One stuck thing: an issue, a wake that no runner can serve, or a run nothing will claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StuckIssue {
    pub kind: StuckKind,
    pub issue_id: Option<IssueId>,
    /// The agent it waits on, when there is one.
    pub agent_id: Option<AgentId>,
    /// Why it is stuck, for people.
    pub reason: String,
    /// What would unstick it.
    pub action: String,
    /// The wake no runner can serve, or the run nothing claims (or that holds a dead checkout).
    pub wake_id: Option<i64>,
    pub run_id: Option<RunId>,
    /// What the scheduler does about it (E15.8).
    pub repair: RepairAction,
    /// The issue's last repair, when the report is read with it.
    pub last_repair: Option<LastRepair>,
    /// How long it has been stuck, in seconds as of the report: an issue's idle time, a wake's
    /// or run's wait; `None` when unknown (a full disk).
    pub stuck_secs: Option<i64>,
}

/// What the store knows about one open issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueFacts {
    pub id: IssueId,
    pub state: IssueState,
    pub next_actor: Option<NextActor>,
    /// The next-actor agent's status, when the next actor is an agent.
    pub agent_status: Option<AgentStatus>,
    /// The loop breaker has paused that agent (E2.7).
    pub paused_by_breaker: bool,
    pub blockers: i64,
    pub open_blockers: i64,
    /// A pending wake for the next-actor agent on this issue.
    pub pending_wake: bool,
    /// A queued, claimed or running run on this issue.
    pub live_run: bool,
    /// A `todo` issue of a kanban project whose `in_progress` column is at its WIP limit
    /// (E5.3): it waits on the flow, not on its agent.
    pub wip_held: bool,
    /// Seconds since anything happened to it: created, audited, or a run on it ended.
    pub idle_secs: i64,
    /// The run that holds its checkout although it has ended (an engine error, E15.8).
    pub dead_checkout: Option<RunId>,
}

/// Why the issue is stuck, or `None` when something will move it: a human or a timer is
/// next, an open blocker holds it, its agent has a wake or a live run, or a full WIP column
/// holds it back, or it has been idle no more than `after` seconds. The first rule that
/// matches wins, most specific first.
pub fn issue_stuck(f: &IssueFacts, after: i64) -> Option<StuckIssue> {
    use IssueState as S;
    use StuckKind as K;

    let found = |kind, agent_id, reason: String, action: String| {
        Some(StuckIssue {
            kind,
            issue_id: Some(f.id),
            agent_id,
            reason,
            action,
            wake_id: None,
            run_id: f.dead_checkout,
            repair: repair_for(kind, agent_id, Some(f.id)),
            last_repair: None,
            stuck_secs: Some(f.idle_secs),
        })
    };
    let state = f.state.as_str();
    if let Some(run) = f.dead_checkout {
        return found(
            K::CheckoutDead,
            None,
            format!(
                "{state}, checked out by run {}, which has ended (engine error)",
                run.0
            ),
            "release the checkout, and report the bug".to_owned(),
        );
    }
    let Some(next) = &f.next_actor else {
        return found(
            K::NoNextActor,
            None,
            format!("{state} with no next actor: nothing will ever pick it up (engine error)"),
            "reassign it to an agent or a human, and report the bug".to_owned(),
        );
    };
    if f.state == S::Blocked {
        return match (f.blockers, f.open_blockers) {
            (0, _) => found(
                K::BlockedNoBlocker,
                None,
                "blocked with no linked blocker: nothing it waits on can close".to_owned(),
                "link the issue it waits on, or unblock it".to_owned(),
            ),
            (n, 0) => found(
                K::BlockedBlockersClosed,
                None,
                format!("blocked, but all {n} of its blockers are closed"),
                "unblock it; its next actor is woken".to_owned(),
            ),
            _ => None,
        };
    }
    let NextActor::Agent(agent) = next else {
        if let (S::InReview, NextActor::Timer(at)) = (f.state, next) {
            return found(
                K::ReviewNoReviewer,
                None,
                format!("in review waiting on a timer ({at}), not a reviewer"),
                "reassign the review to an agent or a human".to_owned(),
            );
        }
        return None;
    };
    let a = agent.0;
    let status = f.agent_status.unwrap_or(AgentStatus::Active);
    if status != AgentStatus::Active {
        let by_breaker = f.paused_by_breaker && status == AgentStatus::Paused;
        let status = status.as_str();
        return if by_breaker {
            found(
                K::AgentPausedByBreaker,
                Some(*agent),
                format!("{state}, waiting on agent {a}, which the loop breaker paused"),
                format!(
                    "read the breaker's trips, fix the cause, then resume agent {a} or reassign"
                ),
            )
        } else if f.state == S::InReview {
            found(
                K::ReviewerInactive,
                Some(*agent),
                format!("in review by agent {a}, which is {status}"),
                format!("resume agent {a}, or reassign the review"),
            )
        } else {
            found(
                K::NextActorInactive,
                Some(*agent),
                format!("{state}, waiting on agent {a}, which is {status}"),
                format!("resume agent {a}, or reassign the issue"),
            )
        };
    }
    if f.pending_wake || f.live_run || f.wip_held || f.idle_secs <= after {
        return None;
    }
    let mins = f.idle_secs / 60;
    let (kind, doing) = match f.state {
        S::Todo => (K::TodoIdle, "start it"),
        S::InProgress => (K::InProgressIdle, "finish it"),
        S::InReview => (K::ReviewNoReviewer, "review it"),
        _ => return None,
    };
    found(
        kind,
        Some(*agent),
        format!("{state} for agent {a} with no live run and no pending wake for {mins} min"),
        format!("wake agent {a} to {doing}, or reassign it"),
    )
}

/// A pending wake no online runner can serve: `None` until it has waited `after` seconds.
/// `runner_known` says a runner that offers the agent's harness is registered, only offline: an
/// issue's wake then waits for it to come back (`Notify`) rather than escalating to a person.
/// (The monolith's runner tags are not ported: a Core runner is a device and carries none.)
pub fn wake_stuck(
    wake: i64,
    agent: AgentId,
    issue: Option<IssueId>,
    harness: &str,
    runner_known: bool,
    waiting_secs: i64,
    after: i64,
) -> Option<StuckIssue> {
    if waiting_secs <= after {
        return None;
    }
    let (w, a, mins) = (wake, agent.0, waiting_secs / 60);
    let repair = match issue {
        Some(_) if runner_known => RepairAction::Notify,
        _ => repair_for(StuckKind::WakeNoRunner, Some(agent), issue),
    };
    Some(StuckIssue {
        wake_id: Some(wake),
        run_id: None,
        repair,
        last_repair: None,
        stuck_secs: Some(waiting_secs),
        kind: StuckKind::WakeNoRunner,
        issue_id: issue,
        agent_id: Some(agent),
        reason: format!(
            "wake {w} for agent {a} pending {mins} min: no online runner offers {harness}"
        ),
        action: format!("bring a runner with {harness} online, or change agent {a}'s harness"),
    })
}

/// A `queued` run with no lease: `None` until it has waited `after` seconds. Dispatch
/// inserts and claims a run in one transaction, so a run left queued came from outside the
/// engine; nothing claims or reaps it, and it holds back every wake for its agent and issue.
pub fn run_stuck(
    run: RunId,
    agent: AgentId,
    issue: Option<IssueId>,
    queued_secs: i64,
    after: i64,
) -> Option<StuckIssue> {
    if queued_secs <= after {
        return None;
    }
    let (r, a, mins) = (run.0, agent.0, queued_secs / 60);
    Some(StuckIssue {
        wake_id: None,
        run_id: Some(run),
        repair: repair_for(StuckKind::RunQueuedNoLease, Some(agent), issue),
        last_repair: None,
        stuck_secs: Some(queued_secs),
        kind: StuckKind::RunQueuedNoLease,
        issue_id: issue,
        agent_id: Some(agent),
        reason: format!(
            "run {r} for agent {a} queued {mins} min with no lease: nothing will claim it, \
             and it holds back agent {a}'s wakes for the issue (engine error)"
        ),
        action: format!("cancel run {r}; the held-back wakes then dispatch, and report the bug"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wake_for_an_issue_waits_on_an_offline_runner_instead_of_escalating() {
        let (w, a, i) = (1, AgentId(2), Some(IssueId(3)));
        let tags = "claude";
        let known = wake_stuck(w, a, i, tags, true, 600, 60).unwrap();
        assert_eq!(known.repair, RepairAction::Notify);
        let gone = wake_stuck(w, a, i, tags, false, 600, 60).unwrap();
        assert_eq!(gone.repair, RepairAction::Escalate);
        // An issue-less wake keeps its drop, whether or not a runner is known.
        let dropped = wake_stuck(w, a, None, tags, true, 600, 60).unwrap();
        assert_eq!(dropped.repair, RepairAction::DropWake);
        assert!(wake_stuck(w, a, i, tags, false, 30, 60).is_none());
    }
}
