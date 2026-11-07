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
    /// Only the attempts of this run (its first attempt's id, `as_…`).
    pub run: Option<String>,
}

/// A secret for the session: the broker's secret `name`, delivered under `var`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AgentSecret {
    pub name: String,
    /// `[A-Z_][A-Z0-9_]*`, not `PATH`, `HOME` or a loader's: the value (`env` delivery), the
    /// path of a 0600 file holding it (`file`), or of an askpass helper (`askpass`).
    pub var: String,
}

/// A session to start. No `Debug`: the prompt is the caller's.
#[derive(Deserialize, ToSchema)]
pub struct NewAgentSession {
    /// The runner's device id, `d_…`.
    pub runner: String,
    /// `claude`, `codex`, `opencode`, `agy` (what the runner's `agent` driver takes). Omit it
    /// (and `model`) when the session draws from a chain: the account the allocator picks sets them.
    #[serde(default)]
    #[schema(required = false)]
    pub harness: String,
    /// The model id as the provider names it. For a session served by the auth gateway it must be
    /// one of the ids priced for its provider, exactly: the gateway resolves no alias.
    pub model: Option<String>,
    pub prompt: Option<String>,
    /// The repo and worktree to work in (`{"repo_url", "base_branch", "branch", …}`); absent, a
    /// scratch dir.
    #[schema(value_type = Option<Object>)]
    pub workspace: Option<Value>,
    /// `{"mode": "ask" | "accept_edits" | "sandboxed", "allow": […]}`; default `ask`.
    #[schema(value_type = Option<Object>)]
    pub policy: Option<Value>,
    /// At most 16. Each is leased to the runner at each start (secrets broker, gate G-SEC).
    pub secrets: Option<Vec<AgentSecret>>,
    /// A fallback chain's id: the session draws its account from it, one at a time. Needs
    /// `admin`. It must not come with a harness, a model or an `acct.*` secret.
    pub chain: Option<i64>,
    /// An opaque agent id (1 to 64 of `[A-Za-z0-9._:-]`): its bound chain, else the user's
    /// default chain, serves the session. Needs `admin`. With no chain either way the session
    /// runs as a plain one and names its harness.
    pub agent: Option<String>,
}
