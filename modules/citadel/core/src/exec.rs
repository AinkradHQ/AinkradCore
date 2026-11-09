//! Execution model: runners, runs, wake requests, leases and cost events (brainstorm §6).
//! Records, the run state machine in `machine` (E2.1), the retry policy (E2.2), the loop
//! breaker's fingerprint in `breaker` (E2.7) and the stuck detector's rules in `stuck`
//! (E2.8); wake dispatch builds on these.
//!
//! Timestamps are ISO-8601 text, as stored. Runner keys are never held here: the store
//! keeps only their SHA-256.

use std::str::FromStr;

use crate::org::{AgentId, Harness, UnknownVariant, id, text_enum};
use crate::work::IssueId;

mod breaker;
mod machine;
mod stuck;
pub use breaker::*;
pub use machine::*;
pub use stuck::*;

id!(RunnerId, RunId, WakeRequestId, CostEventId);

text_enum!(RunnerStatus {
    Online => "online",
    Offline => "offline",
    Unhealthy => "unhealthy",
});

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

text_enum!(WakeSource {
    Assignment => "assignment",
    Comment => "comment",
    BlockerClosed => "blocker_closed",
    Timer => "timer",
    Manual => "manual",
    Approval => "approval",
    Escalation => "escalation",
    Retry => "retry",
});

text_enum!(WakeStatus {
    Pending => "pending",
    Dispatched => "dispatched",
    Coalesced => "coalesced",
    Dropped => "dropped",
});

/// Token counts and cost. `cost_usd_micros` is `None` when the price is unknown
/// (subscription harnesses, unpriced models) — never zero (#15, E7.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    pub cost_usd_micros: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRunner {
    pub name: String,
    /// Capabilities it offers, e.g. `macos`, `xcode`.
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runner {
    pub id: RunnerId,
    pub name: String,
    pub tags: Vec<String>,
    pub status: RunnerStatus,
    pub last_seen_at: Option<String>,
    /// Set exactly when `status` is `Unhealthy`.
    pub health_reason: Option<String>,
    /// When the admin asked to wake it (a sleeping Mac); cleared when it next connects.
    pub wake_requested_at: Option<String>,
    /// How: `now` (pushed to wake it) or `when_back` (its work waits for it).
    pub wake_mode: Option<String>,
    /// When the admin drained it: it takes no new run; its runs finish.
    pub drained_at: Option<String>,
    /// The admin's Power Nap preference for it (a Mac), pushed to it; `None`, none set.
    pub power_nap: Option<bool>,
}

/// A run before it is stored; it starts `queued` with zero usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRun {
    pub agent_id: AgentId,
    pub issue_id: Option<IssueId>,
    pub wake_request_id: Option<WakeRequestId>,
    pub harness: Harness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub id: RunId,
    pub agent_id: AgentId,
    pub issue_id: Option<IssueId>,
    pub wake_request_id: Option<WakeRequestId>,
    pub runner_id: Option<RunnerId>,
    pub state: RunState,
    /// Required in a terminal state, forbidden otherwise.
    pub terminal_reason: Option<String>,
    pub harness: Harness,
    pub harness_version: Option<String>,
    pub session_id: Option<String>,
    pub usage: Usage,
    pub queued_at: String,
    pub claimed_at: Option<String>,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    /// Error class + step, for the loop breaker (E2.7).
    pub failure_fingerprint: Option<String>,
    /// The provider account it works as (E15.1).
    pub account_id: Option<crate::gov::AccountId>,
    /// The model it works with (E15.3); `None` on runs from before.
    pub model_used: Option<String>,
    /// Why it is not on its agent's first (harness, model), every reason in order (E15.3).
    pub fallback_reason: Option<String>,
    /// The tier its task was routed to (E15.5); `None` on runs from before.
    pub tier: Option<crate::org::Tier>,
    /// Its first turn's input tokens, cache included: the context it started with (E15.5).
    pub context_tokens: Option<i64>,
    /// When its wake was due (E15.6): enqueued, or its retry backoff over.
    pub woken_at: Option<String>,
    /// When its harness first reported (E15.6); `started_at` is when its workspace was ready.
    pub harness_started_at: Option<String>,
    /// When its model first answered: text, a tool call or usage (E15.6).
    pub first_token_at: Option<String>,
    /// When its runner last saw it progress (E15.7): a tool call, a file change, a new
    /// message or more tokens. The lease heartbeat only says the process is alive.
    pub last_progress_at: Option<String>,
    /// Files its worktree differs from the base in, as its runner last measured (E15.7).
    pub diff_files: Option<i64>,
    /// Each repo's diff, as its runner last measured (protocol 1.18): a JSON array of
    /// `{repo, files, insertions, deletions}`.
    pub diff_repos: Option<String>,
    /// When its transcript was pruned under `transcript.retention_secs`.
    pub transcript_pruned_at: Option<String>,
}

/// A wake request before it is stored. Posting twice with the same key yields the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWakeRequest {
    pub agent_id: AgentId,
    pub issue_id: Option<IssueId>,
    pub source: WakeSource,
    pub reason: String,
    pub idempotency_key: String,
    /// Not dispatched before this timestamp (retry backoff).
    pub not_before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeRequest {
    pub id: WakeRequestId,
    pub agent_id: AgentId,
    pub issue_id: Option<IssueId>,
    pub source: WakeSource,
    pub reason: String,
    pub idempotency_key: String,
    /// How many later wakes were folded into this one.
    pub coalesced_count: i64,
    pub status: WakeStatus,
    pub not_before: Option<String>,
    /// 1 on the first try.
    pub attempt: i64,
    /// The pending request it was folded into; set exactly when `status` is `Coalesced`.
    pub coalesced_into: Option<WakeRequestId>,
    /// Why it was dropped; set exactly when `status` is `Dropped` (no silent drops).
    pub dropped_reason: Option<String>,
}

/// Attempts a wake gets before a failure stops retrying and escalates: the default of the
/// `wake.max_attempts` setting (E15.17).
pub const MAX_WAKE_ATTEMPTS: i64 = 3;

/// Longest retry backoff, in seconds: the default of `wake.retry_backoff_max_secs`.
pub const MAX_RETRY_BACKOFF_SECS: i64 = 600;

/// Seconds to wait before retrying after `attempt` failed: 30, 60, 120, … capped at `max`.
pub fn retry_backoff_secs(attempt: i64, max: i64) -> i64 {
    let doublings = attempt.clamp(1, 16) - 1;
    (30 << doublings).min(max)
}

/// How long a lease lasts without renewal, in seconds; a runner renews well inside it. The
/// default of the `lease.ttl_secs` setting.
pub const LEASE_TTL_SECS: i64 = 90;

/// How long a lapsed lease waits for its runner to come back before the run is lost, in
/// seconds: a runner back inside it re-claims its run. The default of `lease.grace_secs`.
pub const LEASE_GRACE_SECS: i64 = 300;

/// A runner's hold on a run; at most one per run, and only while the run is claimed or
/// running (E2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub run_id: RunId,
    pub runner_id: RunnerId,
    pub expires_at: String,
    pub heartbeat_at: String,
}

/// A usage record before it is stored. Recording twice with the same key yields the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCostEvent {
    pub run_id: RunId,
    /// Must be the run's agent and issue.
    pub agent_id: AgentId,
    pub issue_id: Option<IssueId>,
    pub usage: Usage,
    pub idempotency_key: String,
}

/// Immutable once recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostEvent {
    pub id: CostEventId,
    pub run_id: RunId,
    pub agent_id: AgentId,
    pub issue_id: Option<IssueId>,
    pub usage: Usage,
    pub idempotency_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enums_round_trip_through_text() {
        for s in [RunState::TimedOut, RunState::RunnerLost, RunState::Claimed] {
            assert_eq!(s.as_str().parse::<RunState>(), Ok(s));
        }
        assert_eq!(
            "blocker_closed".parse::<WakeSource>(),
            Ok(WakeSource::BlockerClosed)
        );
        assert_eq!("coalesced".parse::<WakeStatus>(), Ok(WakeStatus::Coalesced));
        assert_eq!(
            "unhealthy".parse::<RunnerStatus>(),
            Ok(RunnerStatus::Unhealthy)
        );
        assert!("lost".parse::<RunState>().is_err());
    }

    #[test]
    fn retry_backoff_doubles_from_30s_and_caps() {
        let max = MAX_RETRY_BACKOFF_SECS;
        let delays: Vec<_> = (1..=7).map(|a| retry_backoff_secs(a, max)).collect();
        assert_eq!(delays, vec![30, 60, 120, 240, 480, 600, 600]);
        assert_eq!(retry_backoff_secs(i64::MAX, max), max);
        assert_eq!(retry_backoff_secs(0, max), 30);
        assert_eq!(retry_backoff_secs(3, 90), 90);
    }

    #[test]
    fn only_queued_claimed_running_are_live() {
        let live: Vec<_> = [
            RunState::Queued,
            RunState::Claimed,
            RunState::Running,
            RunState::Succeeded,
            RunState::Failed,
            RunState::Cancelled,
            RunState::TimedOut,
            RunState::RunnerLost,
        ]
        .into_iter()
        .filter(|s| !s.is_terminal())
        .collect();
        assert_eq!(
            live,
            vec![RunState::Queued, RunState::Claimed, RunState::Running]
        );
    }
}
