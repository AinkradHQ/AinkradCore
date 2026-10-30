//! The run model of the engine (S7): states, wake sources and statuses, and the run state
//! machine. Pure, no I/O. Runners are Core devices and a run's harness is an agent session of
//! the platform (`ainkrad_core_server::agents`), so the monolith's runner and lease records are
//! gone: a session's own supervisor is the lease.

use crate::domain::org::{UnknownVariant, text_enum};
use std::fmt;
use std::str::FromStr;

text_enum!(RunState {
    Queued => "queued",
    Claimed => "claimed",
    Running => "running",
    Succeeded => "succeeded",
    Failed => "failed",
    Cancelled => "cancelled",
    TimedOut => "timed_out",
    RunnerLost => "runner_lost",
});

impl RunState {
    /// A terminal run carries a reason; a non-terminal one never does.
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Claimed | Self::Running)
    }
}

text_enum!(WakeStatus {
    Pending => "pending",
    Dispatched => "dispatched",
    Coalesced => "coalesced",
    Dropped => "dropped",
});

/// Attempts a wake gets before a failure stops retrying and escalates.
pub const MAX_WAKE_ATTEMPTS: i64 = 3;

/// Longest retry backoff, in seconds.
pub const MAX_RETRY_BACKOFF_SECS: i64 = 600;

/// Seconds to wait before retrying after `attempt` failed: 30, 60, 120, ... capped at `max`.
pub fn retry_backoff_secs(attempt: i64, max: i64) -> i64 {
    let doublings = attempt.clamp(1, 16) - 1;
    (30 << doublings).min(max)
}

// --- the state machine (brainstorm §6, decision #4) ---

/// Something that happened to a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEvent {
    /// A runner (a Core device, `d_...`) took the run.
    Claim {
        runner: String,
    },
    /// The harness started; `session` is its resumable session id when it has one.
    Start {
        session: Option<String>,
    },
    /// The runner is still alive; the state does not change.
    Heartbeat,
    Succeed,
    /// `fingerprint` is the error class + step, for the loop breaker (E2.7).
    Fail {
        reason: String,
        fingerprint: Option<String>,
    },
    Cancel {
        reason: String,
    },
    Timeout,
    RunnerLost,
    /// Usage reached the run's token cap (#15, E3.8); ends `failed: token_cap`.
    TokenCap,
    /// No progress for the project's stall limit (E15.7); ends `failed: stalled`.
    Stall,
}

impl RunEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Claim { .. } => "claim",
            Self::Start { .. } => "start",
            Self::Heartbeat => "heartbeat",
            Self::Succeed => "succeed",
            Self::Fail { .. } => "fail",
            Self::Cancel { .. } => "cancel",
            Self::Timeout => "timeout",
            Self::RunnerLost => "runner_lost",
            Self::TokenCap => "token_cap",
            Self::Stall => "stall",
        }
    }
}

/// Why a run ended. Renders to the stored `terminal_reason` text, never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalReason {
    Succeeded,
    Failed(String),
    Cancelled(String),
    TimedOut,
    RunnerLost,
    TokenCap,
    Stalled,
}

impl fmt::Display for TerminalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Succeeded => "succeeded",
            Self::Failed(why) | Self::Cancelled(why) => why,
            Self::TimedOut => "timed_out",
            Self::RunnerLost => "runner_lost",
            Self::TokenCap => "token_cap",
            Self::Stalled => "stalled",
        })
    }
}

/// The outcome of a legal event. `reason` is set exactly when `state` is terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub state: RunState,
    pub reason: Option<TerminalReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IllegalTransition {
    /// The event is not allowed in this state.
    Forbidden { from: RunState, event: &'static str },
    /// A fail or cancel without a reason (blank text).
    BlankReason { event: &'static str },
}

impl fmt::Display for IllegalTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forbidden { from, event } => write!(f, "cannot {event} a {} run", from.as_str()),
            Self::BlankReason { event } => write!(f, "{event} needs a reason"),
        }
    }
}

impl std::error::Error for IllegalTransition {}

/// The state `event` moves a run in `state` to, or why it may not.
pub fn apply(state: RunState, event: &RunEvent) -> Result<Transition, IllegalTransition> {
    use RunEvent as E;
    use RunState as S;

    let live = |state| {
        Ok(Transition {
            state,
            reason: None,
        })
    };
    let end = |state, reason| {
        Ok(Transition {
            state,
            reason: Some(reason),
        })
    };
    let reason = |why: &str| {
        if why.trim().is_empty() {
            Err(IllegalTransition::BlankReason {
                event: event.name(),
            })
        } else {
            Ok(why.to_owned())
        }
    };

    match (state, event) {
        (S::Queued, E::Claim { .. }) => live(S::Claimed),
        (S::Claimed, E::Start { .. }) => live(S::Running),
        (S::Claimed | S::Running, E::Heartbeat) => live(state),
        (S::Running, E::Succeed) => end(S::Succeeded, TerminalReason::Succeeded),
        (S::Claimed | S::Running, E::Fail { reason: why, .. }) => {
            end(S::Failed, TerminalReason::Failed(reason(why)?))
        }
        (S::Running, E::TokenCap) => end(S::Failed, TerminalReason::TokenCap),
        (S::Running, E::Stall) => end(S::Failed, TerminalReason::Stalled),
        (S::Queued | S::Claimed | S::Running, E::Cancel { reason: why }) => {
            end(S::Cancelled, TerminalReason::Cancelled(reason(why)?))
        }
        (S::Claimed | S::Running, E::Timeout) => end(S::TimedOut, TerminalReason::TimedOut),
        (S::Claimed | S::Running, E::RunnerLost) => end(S::RunnerLost, TerminalReason::RunnerLost),
        _ => Err(IllegalTransition::Forbidden {
            from: state,
            event: event.name(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every event shape, including blank reasons.
    fn alphabet() -> Vec<RunEvent> {
        vec![
            RunEvent::Claim {
                runner: "d_1".to_owned(),
            },
            RunEvent::Start { session: None },
            RunEvent::Start {
                session: Some("s".to_owned()),
            },
            RunEvent::Heartbeat,
            RunEvent::Succeed,
            RunEvent::Fail {
                reason: "build broke".to_owned(),
                fingerprint: Some("E0308@build".to_owned()),
            },
            RunEvent::Fail {
                reason: " ".to_owned(),
                fingerprint: None,
            },
            RunEvent::Cancel {
                reason: "user".to_owned(),
            },
            RunEvent::Cancel {
                reason: String::new(),
            },
            RunEvent::Timeout,
            RunEvent::RunnerLost,
            RunEvent::TokenCap,
            RunEvent::Stall,
        ]
    }

    /// Walks every event sequence up to `depth` from `state`, checking each step.
    fn walk(state: RunState, depth: usize, events: &[RunEvent], visited: &mut usize) {
        if depth == 0 {
            return;
        }
        // Every live run can still be ended with a reason.
        if !state.is_terminal() {
            let cancel = RunEvent::Cancel {
                reason: "stop".to_owned(),
            };
            assert!(apply(state, &cancel).unwrap().state.is_terminal());
        }
        for e in events {
            *visited += 1;
            match apply(state, e) {
                Ok(t) => {
                    // Once terminal, stays terminal: a terminal state never gets here.
                    assert!(!state.is_terminal(), "{state:?} accepted {e:?}");
                    // Mirrors the DB CHECK: reason exactly when terminal, never empty.
                    assert_eq!(t.state.is_terminal(), t.reason.is_some(), "{e:?}");
                    if let Some(r) = &t.reason {
                        assert!(!r.to_string().trim().is_empty(), "{e:?}");
                    }
                    walk(t.state, depth - 1, events, visited);
                }
                Err(_) => walk(state, depth - 1, events, visited),
            }
        }
    }

    #[test]
    fn every_sequence_up_to_six_events_holds_the_invariants() {
        let events = alphabet();
        let mut visited = 0;
        walk(RunState::Queued, 6, &events, &mut visited);
        // 13 + 13² + … + 13⁶ steps: the whole space was walked.
        assert_eq!(visited, (1..=6).map(|k| 13usize.pow(k)).sum::<usize>());
    }

    #[test]
    fn happy_path_and_reasons_render_to_text() {
        let mut s = RunState::Queued;
        for e in [
            RunEvent::Claim {
                runner: "d_1".to_owned(),
            },
            RunEvent::Start { session: None },
            RunEvent::Heartbeat,
        ] {
            s = apply(s, &e).unwrap().state;
        }
        assert_eq!(s, RunState::Running);
        let t = apply(s, &RunEvent::TokenCap).unwrap();
        assert_eq!(t.state, RunState::Failed);
        assert_eq!(t.reason.unwrap().to_string(), "token_cap");
        let t = apply(s, &RunEvent::Stall).unwrap();
        assert_eq!(t.state, RunState::Failed);
        assert_eq!(t.reason.unwrap().to_string(), "stalled");
        let t = apply(
            RunState::Running,
            &RunEvent::Fail {
                reason: "tests red".to_owned(),
                fingerprint: None,
            },
        )
        .unwrap();
        assert_eq!(t.reason.unwrap().to_string(), "tests red");
    }

    #[test]
    fn setup_failure_after_claim_is_terminal() {
        let t = apply(
            RunState::Claimed,
            &RunEvent::Fail {
                reason: "setup_failed: worktree lock".to_owned(),
                fingerprint: None,
            },
        )
        .unwrap();
        assert_eq!(t.state, RunState::Failed);
    }

    #[test]
    fn cancel_before_dispatch_is_terminal() {
        let t = apply(
            RunState::Queued,
            &RunEvent::Cancel {
                reason: "issue closed".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(t.state, RunState::Cancelled);
        assert_eq!(
            t.reason,
            Some(TerminalReason::Cancelled("issue closed".to_owned()))
        );
    }

    #[test]
    fn illegal_events_are_rejected_with_a_cause() {
        let forbidden = |from, e: &RunEvent| apply(from, e).unwrap_err();
        assert_eq!(
            forbidden(RunState::Queued, &RunEvent::Start { session: None }),
            IllegalTransition::Forbidden {
                from: RunState::Queued,
                event: "start"
            }
        );
        // A queued run has no runner to lose or time out.
        for e in [RunEvent::Timeout, RunEvent::RunnerLost, RunEvent::Heartbeat] {
            assert!(apply(RunState::Queued, &e).is_err(), "{e:?}");
        }
        for e in alphabet() {
            assert!(apply(RunState::Succeeded, &e).is_err(), "{e:?}");
        }
        assert_eq!(
            forbidden(
                RunState::Running,
                &RunEvent::Cancel {
                    reason: "  ".to_owned()
                }
            ),
            IllegalTransition::BlankReason { event: "cancel" }
        );
    }
}
