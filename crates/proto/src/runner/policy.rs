//! A project's harness permission policy (1.3), as `Assign` carries it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::isolation::{
    DISK_MB, Egress, Isolation, MEMORY_MB, VCPUS, WALL_SECS, WorkspaceMode, digest_problem,
};

/// A project's harness permission policy (1.3). Never full-auto by default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Policy {
    pub mode: PermissionMode,
    /// Tools the harness may use without asking: a tool name (`Edit`, `fileChange`), or
    /// `<tool>:<command prefix>` (`Bash:cargo test`) for a command with no shell operators, or a
    /// chain of commands each of which it covers.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Runs must work in a disposable sandbox: only a sandboxed runner may take them.
    #[serde(default)]
    pub sandboxed: bool,
    /// The weakest isolation the session may run in (E8a-08). Absent: any runner. A runner that
    /// cannot offer it is never given the session, and refuses it if it is (E8a-09).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_isolation: Option<Isolation>,
    /// The guest image, by digest (`sha256:` + 64 hex). Only a tier that boots an image takes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Virtual CPUs, 1 to 32. Only a VM tier has them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcpus: Option<u32>,
    /// Memory cap in MiB, 64 to 262144. It can only lower the runner's own cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u32>,
    /// Disk cap in MiB, 16 to 1048576. It can only lower the runner's own cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_mb: Option<u32>,
    /// A hard wall-clock cap in seconds, 1 to 86400: the host kills the sandbox at the deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_secs: Option<u32>,
    /// Destinations the session may reach, narrowing the runner's own allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<Egress>,
    /// How the workspace reaches the sandbox. Absent: `bind`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<WorkspaceMode>,
}

impl Policy {
    /// Why this policy must not be run, if it must not: a resource out of bounds, a malformed
    /// digest, an egress rule that is not an IP or CIDR. Checked where a policy enters (the Core,
    /// the runner), so no side relies on the other.
    pub fn problem(&self) -> Option<String> {
        let bounded = |name: &str, v: Option<u32>, r: &std::ops::RangeInclusive<u32>| {
            v.filter(|v| !r.contains(v))
                .map(|_| format!("{name} is {} to {}", r.start(), r.end()))
        };
        bounded("vcpus", self.vcpus, &VCPUS)
            .or_else(|| bounded("memory_mb", self.memory_mb, &MEMORY_MB))
            .or_else(|| bounded("disk_mb", self.disk_mb, &DISK_MB))
            .or_else(|| bounded("wall_secs", self.wall_secs, &WALL_SECS))
            .or_else(|| {
                self.image
                    .as_deref()
                    .and_then(digest_problem)
                    .map(str::to_owned)
            })
            .or_else(|| self.egress.as_ref().and_then(Egress::problem))
    }

    /// Whether any isolation field is set: a runner with no sandbox honours none of them.
    pub fn asks_for_isolation(&self) -> bool {
        self.min_isolation.is_some_and(|m| m != Isolation::None)
            || self.image.is_some()
            || self.vcpus.is_some()
            || self.memory_mb.is_some()
            || self.disk_mb.is_some()
            || self.wall_secs.is_some()
            || self.egress.is_some()
            || self.workspace.is_some()
    }
}

/// Caller-selected approval bypasses authorize code execution, including aliases and
/// command prefixes. The API requires admin for every such exception, not a shell denylist.
pub fn has_destructive_allow(policy: &Policy) -> bool {
    !policy.allow.is_empty() || policy.mode == PermissionMode::Sandboxed
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    #[test]
    fn approval_bypasses_cannot_hide_behind_tool_aliases_or_prefixes() {
        for tool in [
            "Bash",
            "Bash:curl",
            "commandExecution",
            "unknown-alias",
            "Edit",
        ] {
            let p = Policy {
                allow: vec![tool.into()],
                ..Policy::default()
            };
            assert!(has_destructive_allow(&p));
        }
        assert!(!has_destructive_allow(&Policy::default()));
        assert!(has_destructive_allow(&Policy {
            mode: PermissionMode::Sandboxed,
            ..Policy::default()
        }));
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PermissionMode {
    /// Everything outside the allowlist asks.
    #[default]
    Ask,
    /// File edits inside the run's directory go ahead; the rest asks.
    AcceptEdits,
    /// The harness acts without asking. Only with `sandboxed`.
    Sandboxed,
}

impl PermissionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::AcceptEdits => "accept_edits",
            Self::Sandboxed => "sandboxed",
        }
    }
}

impl std::str::FromStr for PermissionMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        [Self::Ask, Self::AcceptEdits, Self::Sandboxed]
            .into_iter()
            .find(|m| m.as_str() == s)
            .ok_or_else(|| format!("unknown permission mode {s:?}"))
    }
}

/// The command a tool call runs, when it runs one: Claude's `Bash` and Codex give `command` (a
/// string or argv), OpenCode's `bash` its `patterns`.
pub fn command_of(input: &Value) -> Option<String> {
    match (&input["command"], &input["patterns"][0]) {
        (Value::String(c), _) | (_, Value::String(c)) => Some(c.clone()),
        (Value::Array(argv), _) => Some(
            argv.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        _ => None,
    }
}

/// Whether allowlist `entry` covers the call: a tool name, or `<tool>:<prefix>` for a command
/// that starts with the prefix's words and has no shell operators (which could chain anything
/// on; the runner checks a chain part by part).
pub fn allows(entry: &str, tool: &str, input: &Value) -> bool {
    let Some((name, prefix)) = entry.split_once(':') else {
        return entry == tool;
    };
    let Some(command) = command_of(input) else {
        return false;
    };
    let chained = command.contains(|c: char| ";&|`$<>()\n\r".contains(c));
    // Word for word: `npm run` covers `npm run x`, never `npm runx`.
    let whole = |rest: &str| {
        rest.is_empty() || rest.starts_with(char::is_whitespace) || prefix.ends_with(' ')
    };
    name == tool
        && !prefix.is_empty()
        && !chained
        && command.trim_start().strip_prefix(prefix).is_some_and(whole)
}
