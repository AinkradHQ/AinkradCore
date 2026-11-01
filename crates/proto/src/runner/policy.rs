//! A project's harness permission policy (1.3), as `Assign` carries it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shell;

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
            // An argv word is data, not shell, but a control character is still refused.
            if bad.contains(|c: char| c.is_control() && c != '\n') {
                assert!(!yes(json!({"command": ["cargo", "test", bad]})), "{bad:?}");
            }
        }
        // Quotes make one word; a wrapper is looked through to what really runs.
        assert!(yes(json!({"command": "cargo test 'a;b' \"c d\""})));
        assert!(allows(
            "commandExecution:cargo test",
            "commandExecution",
            &json!({"command": ["bash", "-lc", "cargo test -p x"]})
        ));
        assert!(allows(
            "commandExecution:cargo test",
            "commandExecution",
            &json!({"command": "bash -lc 'cargo test'"})
        ));
        for bad in [
            "bash -lc 'cargo test; rm -rf x'",
            "bash -lc 'cargo test && curl x'",
            "bash -lc 'rm -rf ~/w'",
            "bash -lc 'cargo test | sh'",
            "bash -lc \"cargo test $(id)\"",
            "bash -lc 'bash -lc \"cargo test; id\"'",
        ] {
            assert!(
                !allows(
                    "commandExecution:cargo test",
                    "commandExecution",
                    &json!({"command": bad})
                ),
                "{bad}"
            );
        }
        assert!(!allows(
            "Bash:bash -lc",
            "Bash",
            &json!({"command": "bash -lc 'rm -rf ~/w'"})
        ));
        // `sh -c 'cargo test'` really is `cargo test`.
        assert!(allows(
            "commandExecution:cargo test",
            "commandExecution",
            &json!({"command": "sh -c 'cargo test'"})
        ));
    }

    #[test]
    fn destructive_commands_are_never_covered_by_a_rule() {
        use serde_json::json;
        let no = |rule: &str, c: &str| !allows(rule, "Bash", &json!({"command": c}));
        assert!(allows(
            "Bash:git push",
            "Bash",
            &json!({"command": "git push origin main"})
        ));
        assert!(allows(
            "Bash:git push",
            "Bash",
            &json!({"command": "git push -u origin feat"})
        ));
        for c in [
            "git push --force",
            "git push -f origin main",
            "git push --force-with-lease",
            "git push --delete origin x",
            "git push -d origin x",
            "git push origin +main",
            "git push origin :main",
            "git push --mirror",
            "git push -fu origin x",
            "git push --receive-pack=evil",
            "git -c core.sshCommand=x push",
            "git -C / push",
            "git --exec-path=/x push",
        ] {
            assert!(no("Bash:git", c), "{c}");
            assert!(no("Bash:git push", c), "{c}");
        }
        assert!(no("Bash:git", "git config alias.x '!id'"));
        assert!(no("Bash:rm", "rm -rf /"));
        assert!(no("Bash:rm", "rm -r x"));
        assert!(no("Bash:rm", "rm -fr x"));
        assert!(no("Bash:rm", "rm --recursive x"));
        assert!(allows("Bash:rm", "Bash", &json!({"command": "rm x.txt"})));
        for (rule, c) in [
            ("Bash:sudo", "sudo ls"),
            ("Bash:su", "su root"),
            ("Bash:chmod", "chmod -R 777 ."),
            ("Bash:dd", "dd if=/dev/zero of=x"),
            ("Bash:mkfs.ext4", "mkfs.ext4 /dev/x"),
            ("Bash:cargo", "cargo --config build.rustc='x' build"),
            ("Bash:cargo", "cargo -C x build"),
            ("Bash:cargo", "cargo build --config=x"),
        ] {
            assert!(no(rule, c), "{c}");
        }
        assert!(allows(
            "Bash:cargo",
            "Bash",
            &json!({"command": "cargo build --release"})
        ));
        // The same through the Codex wrapper.
        assert!(!allows(
            "commandExecution:git",
            "commandExecution",
            &json!({"command": "bash -lc 'git push --force'"})
        ));
    }

    #[test]
    fn a_stored_rule_names_a_tool_or_a_plain_command_never_a_shell_or_wrapper() {
        for ok in [
            "Edit",
            "Bash:cargo test",
            "bash:git status",
            "Bash:git push",
            "Bash:python3 tool.py",
            "Bash:cargo",
        ] {
            assert_eq!(rule_problem(ok), None, "{ok}");
        }
        for bad in [
            "",
            "Bash",
            "bash",
            "commandExecution",
            "Bash:",
            "Bash: ",
            ":cargo",
            " Edit",
            "Bash:cargo\ntest",
            "Bash:cargo\0",
            &format!("Bash:{}", "a".repeat(300)),
            "Bash:sh -c",
            "Bash:bash -lc",
            "commandExecution:bash -lc",
            "Bash:/bin/sh",
            "Bash:env",
            "Bash:xargs",
            "Bash:sudo",
            "Bash:nohup",
            "Bash:time",
            "Bash:command",
            "Bash:exec",
            "Bash:nice",
            "Bash:timeout",
            "Bash:eval",
            "Bash:find",
            "Bash:python3 -c",
            "Bash:python3",
            "Bash:node -e",
            "Bash:node",
            "Bash:perl -e",
            "Bash:ruby -e",
            "Bash:python3 -m http.server",
            "Bash:git push --force",
            "Bash:git -c x",
            "Bash:rm -rf",
            "Bash:cargo test; id",
            "Bash:cargo $(id)",
            "Bash:cargo test | sh",
            "Bash:cargo >x",
        ] {
            assert!(rule_problem(bad).is_some(), "{bad:?}");
        }
        // A wrapper rule that exists anyway (stored before, or inserted directly) covers nothing.
        let call = serde_json::json!({"command": "bash -lc 'rm -rf ~/w'"});
        assert!(!allows(
            "commandExecution:bash -lc",
            "commandExecution",
            &call
        ));
    }

    #[test]
    fn the_default_rule_names_the_command_that_really_runs() {
        use serde_json::json;
        let rule = |t: &str, i: Value| default_rule(t, &i);
        assert_eq!(
            rule("Bash", json!({"command": "cargo test -p x"})),
            "Bash:cargo test"
        );
        assert_eq!(
            rule(
                "commandExecution",
                json!({"command": ["bash", "-lc", "cargo test -p x"]})
            ),
            "commandExecution:cargo test"
        );
        assert_eq!(
            rule(
                "commandExecution",
                json!({"command": "bash -lc 'cargo build --release'"})
            ),
            "commandExecution:cargo build"
        );
        // Not one simple command, or not plain: the bare tool, which a shell then refuses.
        for i in [
            json!({"command": "cargo test; rm x"}),
            json!({"command": "a | b"}),
            json!({}),
            json!({"command": "$(id) x"}),
        ] {
            assert_eq!(rule("Bash", i), "Bash");
        }
        assert_eq!(rule("Bash", json!({"command": "git 'a b'"})), "Bash:git");
        // A wrapper inside the script gives a wrapper rule, which is refused.
        let wrapped = rule(
            "commandExecution",
            json!({"command": "bash -lc 'env FOO=1 rm x'"}),
        );
        assert_eq!(wrapped, "commandExecution:env FOO=1");
        assert!(rule_problem(&wrapped).is_some());
        // The escalated call's input arrives as the JSON text it was stored as.
        let stored = json!(r#"{"command":["bash","-lc","cargo test -p x"]}"#);
        assert_eq!(
            rule("commandExecution", stored),
            "commandExecution:cargo test"
        );
    }

    #[test]
    fn a_bare_tool_entry_is_exactly_that_tool() {
        use serde_json::json;
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

/// The first command a tool call runs, for DISPLAY and the parked Citadel copy only: it reads one
/// `patterns` entry, so it must never decide anything. Decisions use [`commands_of`].
pub fn command_of(input: &Value) -> Option<String> {
    commands_of(input).and_then(|all| all.into_iter().next())
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
        // An argv is exec'd, not parsed: each word stays one word (quoted when it has to be), so
        // `["bash", "-lc", "cargo test"]` reads as the shell command it is. A word with a quote
        // in it cannot be quoted here, so the call is not read at all.
        Value::Array(argv) => out.push(
            argv.iter()
                .map(|w| w.as_str().and_then(quote_word))
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

/// `word` as one shell word: itself when plain, else in single quotes; `None` when it holds a
/// single quote (which cannot be written inside them).
fn quote_word(word: &str) -> Option<String> {
    let plain = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    match (
        word.contains('\''),
        !word.is_empty() && word.chars().all(plain),
    ) {
        (true, _) => None,
        (false, true) => Some(word.to_owned()),
        (false, false) => Some(format!("'{word}'")),
    }
}

/// The most `patterns` one call may carry, and the longest command, for a rule to cover it.
const MAX_PATTERNS: usize = 16;
const MAX_COMMAND: usize = 4096;

/// The shell tools, as each harness names them: Claude's `Bash`, Codex's `commandExecution`,
/// OpenCode's `bash`. A bare rule for one would allow every command.
pub const SHELL_TOOLS: [&str; 3] = ["Bash", "commandExecution", "bash"];

/// The words of the one simple command `command` runs, or `None` when it is anything else: a
/// list, a pipe, a redirection, an expansion, a control character, or what [`shell::tokens`]
/// cannot read. Codex's `bash -lc '<script>'` wrapper is looked through, so a rule is matched on
/// what really runs.
pub fn call_words(command: &str) -> Option<Vec<String>> {
    if command.contains(|c: char| c.is_control() && c != '\t' && c != '\n') {
        return None;
    }
    match shell::pipelines(command)?.as_mut_slice() {
        [pipeline] => match pipeline.as_mut_slice() {
            [stage] if !stage.is_empty() => Some(std::mem::take(stage)),
            _ => None,
        },
        _ => None,
    }
}

/// Whether `words` (one simple command) is destructive enough that no allowlist entry may cover
/// it: it goes to a reviewer every time. A short fixed list, not a shell denylist: privilege
/// changes, forced or deleting pushes, git and cargo options that load configuration from the
/// command line, recursive removal and ownership changes, raw disk tools.
pub fn hard_escalate(words: &[String]) -> bool {
    let Some(name) = words.first() else {
        return true;
    };
    let name = name.rsplit('/').next().unwrap_or("");
    let args = &words[1..];
    let cluster = |a: &String, letters: &str| {
        a.len() > 1
            && a.starts_with('-')
            && !a.starts_with("--")
            && a[1..].chars().any(|c| letters.contains(c))
    };
    match name {
        "sudo" | "su" | "doas" | "dd" | "shred" | "mkfs" | "fdisk" | "mount" | "umount" => true,
        n if n.starts_with("mkfs.") => true,
        "rm" => args
            .iter()
            .any(|a| cluster(a, "rR") || a == "--recursive" || a == "--no-preserve-root"),
        "chmod" | "chown" | "chgrp" => args.iter().any(|a| cluster(a, "R") || a == "--recursive"),
        "cargo" => args
            .iter()
            .any(|a| a == "--config" || a.starts_with("--config=") || a == "-C" || a == "-Z"),
        "git" => {
            // A global option before the subcommand (`-c`, `-C`, `--exec-path`, ...) can load
            // configuration or run another program.
            let Some(sub) = args.iter().position(|a| !a.starts_with('-')) else {
                return true;
            };
            sub > 0
                || (args[sub] == "push"
                    && args[sub + 1..].iter().any(|a| {
                        cluster(a, "fd")
                            || a.starts_with("--force")
                            || a.starts_with("--delete")
                            || a.starts_with("--mirror")
                            || a.starts_with("--prune")
                            || a.starts_with("--receive-pack")
                            || a.starts_with("--exec")
                            || a.starts_with('+')
                            || a.starts_with(':')
                    }))
                || matches!(
                    args[sub].as_str(),
                    "filter-branch" | "config" | "submodule" | "daemon"
                )
        }
        _ => false,
    }
}

/// Programs whose first word makes a rule cover anything: shells, wrappers that run another
/// command, and programs that execute their arguments.
const WRAPPERS: [&str; 33] = [
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "env", "xargs", "sudo", "su",
    "doas", "nohup", "time", "command", "exec", "nice", "timeout", "ionice", "setsid", "stdbuf",
    "watch", "busybox", "builtin", "eval", "source", ".", "find", "awk", "gawk", "npx", "chroot",
];
/// Interpreters: a rule for one must name a script, never reach `-c`, `-e` or `-m`.
const INTERPRETERS: [&str; 10] = [
    "python",
    "python3",
    "node",
    "ruby",
    "perl",
    "php",
    "lua",
    "deno",
    "bun",
    "osascript",
];

/// Why an allow rule (`<tool>` or `<tool>:<command prefix>`, as "allow for this issue" stores
/// it) must not exist, if it must not: it is not short printable text, it names a whole shell,
/// its prefix is not plain words, or it would cover a wrapper, an interpreter's inline code or
/// something [`hard_escalate`]s.
pub fn rule_problem(rule: &str) -> Option<&'static str> {
    if rule.len() > 256 || rule.chars().any(char::is_control) {
        return Some("a rule is short printable text");
    }
    let Some((tool, prefix)) = rule.split_once(':') else {
        let bare_shell = SHELL_TOOLS.contains(&rule);
        return match (rule.is_empty() || rule.trim() != rule, bare_shell) {
            (true, _) => Some("a rule is <tool> or <tool>:<command prefix>"),
            (_, true) => Some("a shell needs a command prefix, not the whole tool"),
            _ => None,
        };
    };
    if tool.is_empty() || tool.trim() != tool {
        return Some("a rule is <tool> or <tool>:<command prefix>");
    }
    let words = match shell::tokens(prefix) {
        Some(t) if !t.is_empty() => t
            .into_iter()
            .map(|t| match t {
                shell::Token::Word(w) => Some(w),
                shell::Token::Op(_) => None,
            })
            .collect::<Option<Vec<_>>>(),
        _ => None,
    };
    let Some(words) = words else {
        return Some("a rule's command prefix is plain words");
    };
    let first = words[0].rsplit('/').next().unwrap_or("");
    if WRAPPERS.contains(&first) {
        Some("a rule cannot start with a shell or a wrapper that runs another command")
    } else if INTERPRETERS.contains(&first)
        && (words.len() < 2 || words[1].starts_with('-') || words[1].contains('='))
    {
        Some("an interpreter's rule must name a script, not inline code")
    } else if hard_escalate(&words) {
        Some("that command always goes to a reviewer")
    } else {
        None
    }
}

/// The rule an "allow for this issue" of this call stores when none is given: `<tool>:<the first
/// two plain words of the command that really runs>`, else the bare tool.
pub fn default_rule(tool: &str, input: &Value) -> String {
    let parsed;
    let input = match input {
        Value::String(text) => match serde_json::from_str::<Value>(text) {
            Ok(v) => {
                parsed = v;
                &parsed
            }
            Err(_) => input,
        },
        v => v,
    };
    let words = commands_of(input)
        .and_then(|all| all.into_iter().next())
        .and_then(|c| call_words(&c))
        .unwrap_or_default();
    let plain = |w: &String| {
        !w.is_empty()
            && w.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._/=:@%+,-".contains(c) && c != ':')
    };
    let kept: Vec<&str> = words
        .iter()
        .take(2)
        .take_while(|w| plain(w))
        .map(String::as_str)
        .collect();
    match kept.is_empty() {
        true => tool.to_owned(),
        false => format!("{tool}:{}", kept.join(" ")),
    }
}

/// Whether allowlist `entry` covers the call: a tool name, or `<tool>:<prefix>` for a call whose
/// every command (see [`commands_of`]) is ONE simple command (see [`call_words`]) that starts
/// with the prefix's words, word for word (`npm run` covers `npm run x`, never `npm runx`), and is
/// not [`hard_escalate`]d. Quoted words are single words. Anything unclear is not covered.
pub fn allows(entry: &str, tool: &str, input: &Value) -> bool {
    let Some((name, prefix)) = entry.split_once(':') else {
        return entry == tool;
    };
    let rule: Option<Vec<String>> = shell::tokens(prefix).and_then(|t| {
        t.into_iter()
            .map(|t| match t {
                shell::Token::Word(w) => Some(w),
                shell::Token::Op(_) => None,
            })
            .collect()
    });
    let Some(rule) = rule.filter(|r| !r.is_empty()) else {
        return false;
    };
    name == tool
        && commands_of(input).is_some_and(|all| {
            all.iter()
                .all(|c| call_words(c).is_some_and(|w| w.starts_with(&rule) && !hard_escalate(&w)))
        })
}
