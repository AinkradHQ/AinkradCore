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

/// A Code Mode write the Core holds until a person decides (plan E6).
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentApproval {
    /// `cm_…`: the request id for `decideAgentApproval`.
    pub id: String,
    /// `ainkrad.<operation>`.
    pub tool: String,
    /// The operation in plain words.
    pub summary: String,
    /// The arguments the AI session passed, with secrets redacted and long texts cut.
    pub args: Value,
    /// `{summary, args, reason}` as one object, the shape of a harness approval's `input`, so a card
    /// shows it without guessing.
    pub input: Value,
    /// `risky`: the only class that waits for a person.
    pub risk: String,
    /// Why it needs a person, in a sentence.
    pub reason: String,
    pub requested_at: super::super::types::Timestamp,
    /// After this the call is refused `approval_timeout`.
    pub expires_at: super::super::types::Timestamp,
}

/// The approvals one session waits on, newest last.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentApprovals {
    pub approvals: Vec<AgentApproval>,
}

/// A new title for a session.
#[derive(Deserialize, ToSchema)]
pub struct AgentTitle {
    /// At most 60 characters; empty clears it (the list then shows the session's harness).
    pub title: String,
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
    /// The first message. Absent or empty: the session starts with no message, like opening the
    /// CLI: its harness is up, the state is `waiting`, and the first message comes through
    /// `sendAgentMessage`. A message gives the session its `title` (its first 60 characters).
    pub prompt: Option<String>,
    /// One live conversation (default `true`): the harness stays up after each answer, the state
    /// is `waiting` until the next `sendAgentMessage`, and the session ends only on `cancel`,
    /// `kill`, the idle end (`agents.idle_end_secs`) or when the CLI exits by itself. `false`, or
    /// a runner that does not offer it (the answer's `live` says), runs one answer and ends.
    pub live: Option<bool>,
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
    /// Capability names the session may call through its connections (`read_repo`,
    /// `issues_write`, `read_issues`, ...; see `listConnectionKinds`). Needs `admin`. Absent: the
    /// default, read-class capabilities only (write is an explicit grant); an agent's session
    /// with none has no connection tools. An empty list is refused (400 `empty_allowlist`), and
    /// so are operation names and `*` (400).
    pub connection_access: Option<Vec<String>>,
}
