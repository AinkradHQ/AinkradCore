//! The request and response bodies of the agent routes that carry nothing of the scheduler.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

/// Tokens used, as the harness reported them.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentUsage {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    /// Millionths of a US dollar, when the harness says.
    pub cost_usd_micros: Option<u64>,
}

#[derive(Deserialize, ToSchema)]
pub struct AgentMessage {
    pub text: String,
}

#[derive(Deserialize, ToSchema)]
pub struct AgentDecision {
    pub approved: bool,
    /// Told to the agent; a denial's reason.
    pub reply: Option<String>,
}

/// A wake for an idle session.
#[derive(Deserialize, ToSchema)]
pub struct AgentWakeRequest {
    /// Makes the wake idempotent: asking again with the same key queues nothing (it is kept for
    /// 30 days). 1 to 128 of `A-Za-z0-9_.:-`; absent, the Core makes one up.
    pub key: Option<String>,
    /// The next turn, 1 byte to 16 KiB; absent, the session just continues.
    pub text: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AgentWake {
    /// The session, `as_…`.
    pub session: String,
    /// The wake's key.
    pub key: String,
    /// `false` when this key was already used: nothing was queued.
    pub queued: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AgentTranscriptEntry {
    /// From 1, by one: replay from any `seq` with `after`.
    pub seq: u64,
    /// Unix milliseconds, on the runner.
    pub at_ms: i64,
    /// A harness event, or the session's own (`started`, `message`, `approval_request`,
    /// `approval_decided`, `interrupted`, `gap`, `ended`), redacted.
    #[schema(value_type = Object)]
    pub body: Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AgentTranscript {
    pub session: String,
    pub state: String,
    pub last_seq: i64,
    pub entries: Vec<AgentTranscriptEntry>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct Before {
    /// Sessions with an `index` below this; absent, from the newest.
    pub before: Option<i64>,
    pub limit: Option<u32>,
}
