//! Agent sessions on runners (E2-08, P2.7): the `agent` driver's ops.
//!
//! A session is owned by the runner's agent driver, keyed by the Core's session id, not by a
//! command stream: a stream is only one request about it. So a Core restart, or a runner
//! reconnect, never touches a running harness.
//!
//! - `agent.start` starts (or, for a session it already holds, confirms) a harness in a session,
//!   with the leases of the secrets it gets (E2-07.2): the runner redeems each itself, once.
//!   `resume` names the harness's own session to continue (after a runner restart).
//! - `agent.read` is a long poll on the session's transcript: entries after `after`, waiting up
//!   to `wait_ms` for the first one. Every entry has its own per-session `seq`, assigned by the
//!   runner, so the Core persists each once and asks again from where its store ends: no gap,
//!   whatever frames or connections were lost. `after` also acknowledges what the Core holds.
//! - `agent.send` (a message), `agent.decide` (a tool approval) and `agent.stop` (cancel, or
//!   kill) are short commands.
//!
//! Capacity: the driver's `capacity` is how many sessions run at once, `slots` splits it per
//! harness, and `streams` is how many of its commands may be in flight (reads included), which
//! the hub counts per driver.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::runner::{Outcome, Policy, Tokens, Workspace};

pub const AGENT_DRIVER: &str = "agent";
pub const OP_AGENT_START: &str = "agent.start";
pub const OP_AGENT_READ: &str = "agent.read";
pub const OP_AGENT_SEND: &str = "agent.send";
pub const OP_AGENT_DECIDE: &str = "agent.decide";
pub const OP_AGENT_STOP: &str = "agent.stop";

/// Every op of the `agent` driver.
pub const AGENT_OPS: [&str; 5] = [
    OP_AGENT_START,
    OP_AGENT_READ,
    OP_AGENT_SEND,
    OP_AGENT_DECIDE,
    OP_AGENT_STOP,
];

/// Variables a secret may not take: the ones that steer how programs are found and loaded.
const RESERVED_VARS: &[&str] = &["PATH", "HOME", "SHELL", "USER", "LOGNAME", "TMPDIR", "IFS"];

/// The variable a module's run token is delivered under; a client session may not name it.
pub const RUN_TOKEN_VAR: &str = "CITADEL_RUN_TOKEN";

/// A variable a secret may be delivered under: `[A-Z_][A-Z0-9_]{0,63}`, not one the runner
/// sets itself, not a loader's (`LD_*`, `DYLD_*`).
pub fn valid_secret_var(var: &str) -> bool {
    let b = var.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
        && !RESERVED_VARS.contains(&var)
        && !var.starts_with("AINKRAD_")
        && !matches!(var, "BASH_ENV" | "ENV" | "NODE_OPTIONS" | "PYTHONPATH")
        && !var.starts_with("LD_")
        && !var.starts_with("DYLD_")
}

/// A session id: `as_` and a lowercase alphanumeric tail, at most 64 bytes in all.
pub fn valid_session_id(id: &str) -> bool {
    id.len() <= 64
        && id.strip_prefix("as_").is_some_and(|t| {
            !t.is_empty()
                && t.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// What a runner answers for a session it does not hold (`invalid_args`).
pub const NO_SESSION: &str = "no such session on this runner";

/// Core to runner: run `harness` in session `session`.
#[derive(Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentStart {
    /// The Core's id, `as_…`.
    pub session: String,
    pub harness: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// The repo and worktree to work in; absent, a scratch dir of the session's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<Workspace>,
    #[serde(default)]
    pub policy: Policy,
    /// The harness's own session to continue (`AgentEvents::harness_session`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume: Option<String>,
    /// Leases the runner redeems for this session, once each. Never logged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretGrant>,
    /// Which resume this is, 0 for the first start. A session that has ended is started again
    /// (a wake) only by a `resume` whose `epoch` is newer than the one it last ran under; the
    /// same one again is a resent start and is answered, never run twice.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub epoch: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// No `Debug` on anything carrying a lease (secrets review L4).
impl std::fmt::Debug for AgentStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentStart")
            .field("session", &self.session)
            .field("harness", &self.harness)
            .field("secrets", &self.secrets.len())
            .finish_non_exhaustive()
    }
}

/// One secret for a session: its lease, and the variable it is delivered under.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SecretGrant {
    /// `l_…`, redeemable once, by this runner only.
    pub lease: String,
    /// The environment variable: the value itself (`env`), the file's path (`file`), or the
    /// askpass helper's path (`askpass`, also set as `GIT_ASKPASS`). `[A-Z_][A-Z0-9_]*`.
    pub var: String,
}

/// Core to runner: the transcript after `after`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentRead {
    pub session: String,
    /// The last `seq` the Core holds (0 for none): entries above it are sent, those at or below
    /// it may be dropped by the runner.
    pub after: u64,
    /// How long to wait for a first entry; absent or 0 answers at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentSend {
    pub session: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentDecide {
    pub session: String,
    /// The `id` of the transcript's `approval_request`.
    pub request: String,
    pub approved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentStop {
    pub session: String,
    /// Kill the harness now; otherwise let its tool call in flight finish, then end it.
    #[serde(default)]
    pub kill: bool,
}

/// Where a session is, as its runner sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    Running,
    /// Its harness ended (`outcome`).
    Ended,
    /// Its harness went with a runner restart; the transcript is kept. The Core resumes it.
    Interrupted,
    /// A state from a newer runner. Never sent.
    #[serde(other)]
    Unknown,
}

/// One transcript entry: redacted by the runner before it is kept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscriptEntry {
    /// From 1, by one, per session.
    pub seq: u64,
    /// Unix milliseconds.
    pub at: i64,
    /// The harness event, or the driver's own (`approval_request`, `gap`, `ended`, …).
    #[schemars(with = "Value")]
    pub body: Value,
}

/// Runner to Core: a session's state, and (for `agent.read`) its entries after `after`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentEvents {
    pub session: String,
    pub state: AgentState,
    /// The newest `seq` the session has.
    pub last_seq: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<TranscriptEntry>,
    /// The harness's own session id, once known: what a resume continues.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Tokens>,
    /// Once `ended`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
}
