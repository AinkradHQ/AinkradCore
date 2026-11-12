//! Runner control ops: the runner policy and the install of a tool on the runner host.
//!
//! The three ops belong to a `control` driver that every runner of this version lists (a runner
//! without it answers nothing and the Core reports `unsupported_command`). They travel on the
//! connection the runner and the Core proved to each other, like every command.
//!
//! - `runner.policy` sets what this runner offers (terminals, agents, how many agent sessions at
//!   once). The runner keeps it in its state directory, answers, and restarts itself (exit status
//!   75, which its supervisor restarts) so the drivers come up as the policy says.
//! - `tools.install` starts the install of one allow-listed tool and answers at once with the
//!   operation's status; `tools.status` reads it. The Core polls; the runner never pushes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const OP_RUNNER_POLICY: &str = "runner.policy";
pub const OP_TOOLS_INSTALL: &str = "tools.install";
pub const OP_TOOLS_STATUS: &str = "tools.status";

/// The driver that lists the three ops.
pub const DRIVER_CONTROL: &str = "control";

/// The most agent sessions at once a policy may ask for.
pub const MAX_AGENT_CAPACITY: u32 = 8;

/// What a runner offers. The same shape is the command, the answer and the runner's report of
/// what is active (`RunnerFacts::policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerPolicy {
    /// Terminals (`pty`) are offered.
    pub terminals: bool,
    /// Agent sessions are offered.
    pub agents: bool,
    /// How many agent sessions run at once, 1 to [`MAX_AGENT_CAPACITY`].
    pub agent_capacity: u32,
    /// The runner answers `history.read` (the Brain reads its Claude Code history): `--share-history`.
    /// Off by default; an older Core's policy without it reads as off.
    #[serde(default)]
    pub share_history: bool,
}

impl RunnerPolicy {
    pub fn valid(&self) -> bool {
        (1..=MAX_AGENT_CAPACITY).contains(&self.agent_capacity)
    }
}

/// The answer to `runner.policy`: the policy was saved and the runner is restarting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyApplied {
    pub policy: RunnerPolicy,
    /// The runner restarts a moment after this answer; it reconnects with the new policy.
    pub restarting: bool,
}

/// A tool the runner host can install. A fixed list: the runner and its root helper refuse any
/// other name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Tool {
    Claude,
    Codex,
    Node,
    Git,
    Python,
    Go,
    Rust,
    Docker,
}

impl Tool {
    pub const ALL: [Tool; 8] = [
        Tool::Claude,
        Tool::Codex,
        Tool::Node,
        Tool::Git,
        Tool::Python,
        Tool::Go,
        Tool::Rust,
        Tool::Docker,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Tool::Claude => "claude",
            Tool::Codex => "codex",
            Tool::Node => "node",
            Tool::Git => "git",
            Tool::Python => "python",
            Tool::Go => "go",
            Tool::Rust => "rust",
            Tool::Docker => "docker",
        }
    }
}

/// Core to runner: install `tool`. `operation` is the Core's id for the operation (`tools.status`
/// names it); not `op`, which is the command's tag on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ToolsInstall {
    pub operation: String,
    pub tool: Tool,
}

/// Core to runner: how is operation `op`?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ToolsStatusReq {
    pub operation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolOpState {
    Running,
    Done,
    Failed,
}

/// The answer to `tools.install` and `tools.status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ToolsStatus {
    pub operation: String,
    pub tool: Tool,
    pub state: ToolOpState,
    /// 0 to 100.
    pub percent: u8,
    /// What it is doing, a short sentence: `Downloading Node 22.22.1`.
    pub step: String,
    /// Why it failed (`state` `failed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When `done`: the tools the runner found on its host after the install (what `RunnerFacts::tools` holds).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tools: BTreeMap<String, String>,
}
