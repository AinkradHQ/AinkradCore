//! Connection tools (C4; design `2026-11-06-core-connections-design` §5): typed tools a session's
//! harness calls (`github.get_issue`, `jira.create_issue`) that the Core makes upstream with a
//! credential the runner never sees.
//!
//! One op, `agent.tools`, in both directions, so no existing message changes:
//!
//! - The Core polls it. `after` acknowledges the calls it holds (the runner drops those); `results`
//!   answer calls the Core has finished; `tools`, when present, is the whole current tool list
//!   (sent at the first poll and again whenever the session's grants change).
//! - The runner answers with the calls the harness made after `after`, each numbered per session
//!   (`tc_seq`, from 1, by one) so the Core stores a cursor and runs every call at most once.
//!
//! A call names a tool and gives its arguments, nothing else: who the user is, which agent, which
//! connection and what it may do all come from the Core's own session row. A result is plain data
//! or a plain refusal code; it carries no credential and no upstream text. A runner lists
//! [`CAP_TOOLS`] among its agent driver's commands when it serves the op.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const OP_AGENT_TOOLS: &str = "agent.tools";

/// The command an agent driver lists when its runner serves `agent.tools`.
pub const CAP_TOOLS: &str = "connection-tools";

/// The most bytes of a call's arguments (as JSON text) a runner forwards and the Core accepts.
pub const MAX_ARGS_BYTES: usize = 384 * 1024;
/// The most bytes of a result's JSON text the Core returns.
pub const MAX_RESULT_BYTES: usize = 256 * 1024;
/// The most calls one poll answer carries, and the most tools one list holds.
pub const MAX_BATCH: usize = 32;
/// The most bytes of one tool's input schema (as JSON text) a runner lists to a harness.
pub const MAX_SCHEMA_BYTES: usize = 16 * 1024;
/// The most calls a runner keeps waiting on the Core for one session.
pub const MAX_PENDING: usize = 64;

/// A tool or call id's shape: `[a-z0-9_.]`, 1 to 64 bytes (an operation name, `github.get_issue`).
pub fn valid_tool_name(s: &str) -> bool {
    (3..=64).contains(&s.len())
        && s.contains('.')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

/// A call id: made by the runner, `[A-Za-z0-9_-]`, 1 to 64 bytes.
pub fn valid_call_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// One tool the harness may see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnTool {
    /// The operation, `github.get_issue`.
    pub name: String,
    /// What it does and the arguments it takes, for the model.
    pub description: String,
    /// It changes something upstream.
    #[serde(default)]
    pub write: bool,
    /// The JSON Schema (an object schema) of its arguments, for the harness's tool list. Absent
    /// from an older Core: the runner then lists an open object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<Value>")]
    pub input_schema: Option<Value>,
}

/// Runner to Core: the harness called `tool`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ToolCall {
    /// Per session, from 1, by one: the Core's cursor over it.
    pub tc_seq: u64,
    /// Made by the runner; the result names it.
    pub id: String,
    pub tool: String,
    /// The harness's arguments, as given.
    #[schemars(with = "Value")]
    pub args: Value,
}

/// Core to runner: how call `id` ended. Either `result`, or a plain `code` and a fixed `message`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ToolResult {
    pub id: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<Value>")]
    pub result: Option<Value>,
    /// A refusal or upstream class (`not_granted`, `rate_limited`, `not_found`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// `ainkrad.call` only: the request id (`cm_…`) of the person's approval the call waited for,
    /// whatever its answer (E6.5: a script's result says which calls were approved or denied).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
}

/// Core to runner: the poll.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ToolsPoll {
    pub session: String,
    /// The last `tc_seq` the Core holds (0 for none).
    pub after: u64,
    /// How long to wait for a first call; absent or 0 answers at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<ToolResult>,
    /// The whole tool list now; absent: unchanged. An empty list takes every tool away.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ConnTool>>,
}

/// Runner to Core: the calls after `ToolsPoll::after`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ToolBatch {
    pub session: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<ToolCall>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_ids_are_plain() {
        assert!(valid_tool_name("github.get_issue"));
        assert!(!valid_tool_name("get_issue"));
        assert!(!valid_tool_name("Github.get"));
        assert!(!valid_tool_name("a.b c"));
        assert!(valid_call_id("c-1_x"));
        assert!(!valid_call_id(""));
        assert!(!valid_call_id("a/b"));
    }
}
