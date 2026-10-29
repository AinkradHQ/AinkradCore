//! A project's harness permission policy (1.3), as `Assign` carries it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A project's harness permission policy (1.3). Never full-auto by default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
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
