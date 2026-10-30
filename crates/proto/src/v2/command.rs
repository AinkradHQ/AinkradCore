//! `command` and `result` payloads, tagged by `op`. A command's op belongs to the driver
//! that lists it in `RunnerHello::drivers`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The ops of the `exec` driver.
pub const OP_NOOP: &str = "noop";
pub const OP_EXEC_RUN: &str = "exec.run";

/// Core to runner, the first frame of a command stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op")]
pub enum Command {
    /// Answers `result` at once: proves the path end to end.
    #[serde(rename = "noop")]
    Noop,
    #[serde(rename = "exec.run")]
    ExecRun(ExecRun),
    #[serde(rename = "agent.start")]
    AgentStart(super::AgentStart),
    #[serde(rename = "agent.read")]
    AgentRead(super::AgentRead),
    #[serde(rename = "agent.send")]
    AgentSend(super::AgentSend),
    #[serde(rename = "agent.decide")]
    AgentDecide(super::AgentDecide),
    #[serde(rename = "agent.stop")]
    AgentStop(super::AgentStop),
    /// An op from a newer Core: answered `unsupported_command`. Never sent.
    #[serde(other)]
    Unknown,
}

impl Command {
    /// The op on the wire, as drivers list it.
    pub fn op(&self) -> &'static str {
        match self {
            Self::Noop => OP_NOOP,
            Self::ExecRun(_) => OP_EXEC_RUN,
            Self::AgentStart(_) => super::OP_AGENT_START,
            Self::AgentRead(_) => super::OP_AGENT_READ,
            Self::AgentSend(_) => super::OP_AGENT_SEND,
            Self::AgentDecide(_) => super::OP_AGENT_DECIDE,
            Self::AgentStop(_) => super::OP_AGENT_STOP,
            Self::Unknown => "unknown",
        }
    }
}

/// Runs `program args…` to its end, bounded, and answers with its exit and output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExecRun {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// An absolute directory; absent, the runner's own working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Variables set in the child as given.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Names of the runner's own variables to pass on. Only those also on the runner's
    /// allow-list are; the child's environment starts empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_pass: Vec<String>,
    #[serde(default)]
    pub limits: ExecLimits,
}

/// What the Core asks for; the runner clamps each to its own ceiling and uses its default
/// for an absent one.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct ExecLimits {
    /// Wall clock until the process group gets TERM, then KILL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// The most of stdout, and of stderr, kept; the rest is dropped and marked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<u64>,
}

/// Runner to Core, a command's last frame when it ran.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op")]
pub enum Reply {
    #[serde(rename = "noop")]
    Noop,
    #[serde(rename = "exec.run")]
    ExecRun(ExecResult),
    /// Every `agent.*` op answers with the session's state (`agent.read` with its entries).
    #[serde(rename = "agent.start")]
    AgentStart(super::AgentEvents),
    #[serde(rename = "agent.read")]
    AgentRead(super::AgentEvents),
    #[serde(rename = "agent.send")]
    AgentSend(super::AgentEvents),
    #[serde(rename = "agent.decide")]
    AgentDecide(super::AgentEvents),
    #[serde(rename = "agent.stop")]
    AgentStop(super::AgentEvents),
    /// An op from a newer runner. Never sent.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExecResult {
    /// Absent when it was ended by a signal (its timeout included).
    pub exit_code: Option<i32>,
    /// It ran past its timeout and was killed.
    pub timed_out: bool,
    pub duration_ms: u64,
    pub stdout: Captured,
    pub stderr: Captured,
}

/// One output pipe: redacted UTF-8 (lossy), cut at the limit with a marker.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Captured {
    pub text: String,
    /// How many bytes the process wrote, kept or not.
    pub bytes: u64,
    /// `text` was cut at the limit and ends in `TRUNCATED_MARKER`.
    pub truncated: bool,
}

/// What ends a cut `Captured::text`.
pub const TRUNCATED_MARKER: &str = "\n[output truncated]";
