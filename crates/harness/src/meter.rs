//! A run's tokens counted from its events, one way for every harness (E3.8). The adapters
//! normalise what each harness reports into a turn's `UsageSoFar` (Claude: per assistant
//! message, deduplicated; Codex: running thread totals minus the turn's start; OpenCode:
//! per step, deduplicated; agy: per step) and its closing `Usage`. A turn counts the larger
//! of the two, field by field, so a turn that reports less than it spent still counts what
//! was seen of it.
//!
//! The gap: an interrupted Claude turn reports zero, so it counts only its assistant
//! messages, whose output tokens are those at the message's start; the output streamed
//! after that, and the call in flight, are not counted. Claude's cumulative cost does not
//! move either. OpenCode's aborted step reports nothing; Codex repeats its last total.
//!
//! Cost (E7.3): a closing `Usage` carries the session's cost so far where the harness reports
//! one (Claude, OpenCode); the latest is the session's. A run that moves to another session
//! (a fallback, E15.3) adds them up (`new_session`).

use crate::{HarnessEvent, Usage, sum_tokens};

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Meter {
    /// Completed turns.
    done: Usage,
    /// The running turn, so far.
    turn: Usage,
    /// The session's cost so far, as the harness last reported it.
    cost_usd: Option<f64>,
    /// What earlier sessions of the run cost (`new_session`, E15.3).
    cost_before: Option<f64>,
}

/// Every token in `u`: what a cap counts.
pub fn tokens(u: &Usage) -> u64 {
    u.input + u.output + u.cache_read + u.cache_write
}

/// The tokens of `u` with its cache reads and writes at `1 / divisor` (1.27, `run.token_cap`):
/// the fresh work a run did, not the context it re-read. A divisor of 1 is `tokens`.
pub fn weighted_tokens(u: &Usage, divisor: u64) -> u64 {
    u.input + u.output + (u.cache_read + u.cache_write) / divisor.max(1)
}

impl Meter {
    /// Counts `event`; whether the total changed.
    pub fn see(&mut self, event: &HarnessEvent) -> bool {
        let before = self.total();
        match event {
            HarnessEvent::UsageSoFar(u) => self.turn = *u,
            HarnessEvent::Usage(u) => {
                let t = self.turn;
                let turn = Usage {
                    input: u.input.max(t.input),
                    output: u.output.max(t.output),
                    cache_read: u.cache_read.max(t.cache_read),
                    cache_write: u.cache_write.max(t.cache_write),
                    cost_usd: None,
                };
                self.done = sum_tokens([&self.done, &turn]);
                self.turn = Usage::default();
                self.cost_usd = u.cost_usd.or(self.cost_usd);
            }
            _ => return false,
        }
        self.total() != before
    }

    /// Completed turns plus the running one so far; no cost.
    pub fn total(&self) -> Usage {
        sum_tokens([&self.done, &self.turn])
    }

    /// The run's cost so far in US dollars (every session's), if a harness reported one.
    pub fn cost_usd(&self) -> Option<f64> {
        match (self.cost_before, self.cost_usd) {
            (None, None) => None,
            (before, now) => Some(before.unwrap_or(0.0) + now.unwrap_or(0.0)),
        }
    }

    /// Closes the running turn, counting what was seen of it (a turn that never reported its
    /// end, e.g. a dropped connection).
    pub fn close_turn(&mut self) {
        self.see(&HarnessEvent::Usage(Usage::default()));
    }

    /// The run moves to a new session (another harness or model, E15.3): its tokens keep
    /// adding up, and the next session's cost, which starts again from zero, adds to this one's.
    pub fn new_session(&mut self) {
        self.close_turn();
        self.cost_before = self.cost_usd();
        self.cost_usd = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(input: u64, output: u64) -> Usage {
        Usage {
            input,
            output,
            ..Usage::default()
        }
    }

    #[test]
    fn a_turn_counts_the_larger_of_its_progress_and_its_close() {
        let mut m = Meter::default();
        assert!(m.see(&HarnessEvent::UsageSoFar(u(10, 1))));
        assert!(m.see(&HarnessEvent::UsageSoFar(u(30, 2))));
        assert_eq!(m.total(), u(30, 2), "progress replaces, not adds");
        // The close reports more output, less input (an undercounting harness).
        assert!(m.see(&HarnessEvent::Usage(u(25, 9))));
        assert_eq!(m.total(), u(30, 9));
        // An interrupted turn closing at zero keeps what was seen of it.
        m.see(&HarnessEvent::UsageSoFar(u(5, 5)));
        assert!(!m.see(&HarnessEvent::Usage(Usage::default())));
        assert_eq!(m.total(), u(35, 14));
        assert_eq!(tokens(&m.total()), 49);
        assert!(!m.see(&HarnessEvent::AssistantText { text: "hi".into() }));
    }

    #[test]
    fn the_latest_reported_cost_is_the_runs() {
        let mut m = Meter::default();
        assert_eq!(m.cost_usd(), None);
        let costing = |c: Option<f64>| {
            HarnessEvent::Usage(Usage {
                cost_usd: c,
                ..u(1, 1)
            })
        };
        m.see(&costing(Some(0.25)));
        m.see(&costing(None));
        assert_eq!(
            m.cost_usd(),
            Some(0.25),
            "a turn without a cost keeps the last"
        );
        m.see(&costing(Some(0.5)));
        assert_eq!(m.cost_usd(), Some(0.5), "cumulative: replaced, not added");
        // A fallback's new session starts from zero; the run's cost adds both, and its
        // tokens keep the old session's unclosed turn.
        m.see(&HarnessEvent::UsageSoFar(u(7, 0)));
        m.new_session();
        assert_eq!(m.cost_usd(), Some(0.5));
        assert_eq!(m.total(), u(10, 3));
        m.see(&costing(Some(0.25)));
        assert_eq!(m.cost_usd(), Some(0.75));
    }
}
