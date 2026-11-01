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
    use serde_json::json;

    fn call(c: &str) -> Value {
        json!({"command": c})
    }
    fn covered(rule: &str, c: &str) -> bool {
        allows(rule, "Bash", &call(c))
    }

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

    /// The allowlist is the gate: a rule exists only for a listed program (and subcommand), and
    /// covers only a call to it.
    #[test]
    fn a_rule_exists_only_for_the_listed_programs() {
        for ok in [
            "Edit",
            "Bash:cargo test",
            "bash:git status",
            "Bash:git push",
            "Bash:ls",
            "Bash:grep",
            "Bash:python3 tool.py",
            "Bash:php artisan route:list",
            "Bash:node a.js",
            "Bash:echo",
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
            "Bash:cargo",
            "Bash:cargo run",
            "Bash:cargo install",
            "Bash:git",
            "Bash:git clone",
            "Bash:git grep",
            "Bash:git config",
            "Bash:git pull",
            "Bash:git rebase",
            "Bash:git ls-remote",
            "Bash:python3",
            "Bash:python3 -c",
            "Bash:python3 -X importtime -c",
            "Bash:python3 -m x",
            "Bash:node -e",
            "Bash:node18 a.js",
            "Bash:python3.12 x.py",
            "Bash:tsx a.ts",
            "Bash:php -r x",
            "Bash:perl a.pl",
            "Bash:ruby a.rb",
            "Bash:make",
            "Bash:make test",
            "Bash:npm run build",
            "Bash:npm exec rm",
            "Bash:npx x",
            "Bash:bundle exec x",
            "Bash:docker run x",
            "Bash:fd -x x",
            "Bash:rm",
            "Bash:rm -rf",
            "Bash:RM -r",
            "Bash:sudo",
            "Bash:SUDO",
            "Bash:sh -c",
            "Bash:bash -lc",
            "commandExecution:bash -lc",
            "Bash:/bin/sh",
            "Bash:/bin/ls",
            "Bash:env",
            "Bash:xargs",
            "Bash:nohup",
            "Bash:time",
            "Bash:command",
            "Bash:builtin",
            "Bash:exec",
            "Bash:noglob",
            "Bash:nocorrect",
            "Bash:then",
            "Bash:do",
            "Bash:if",
            "Bash:eval",
            "Bash:ssh host",
            "Bash:=bash",
            "Bash:- rm",
            "Bash:-",
            "Bash:FOO=1 git",
            "Bash:\u{17f}udo",
            "Bash:LS",
            "Bash:rg --pre x",
            "Bash:find -exec x",
            "Bash:sed -i x",
            "Bash:sort -o x",
            "Bash:git push --force",
            "Bash:git -c x",
            "Bash:cargo -Zfoo build",
            "Bash:cargo --conf x",
            "Bash:git branch -D",
            "Bash:cargo\ntest",
            "Bash:cargo\0",
            "Bash:cargo test; id",
            "Bash:cargo $(id)",
            "Bash:cargo test | sh",
            "Bash:cargo >x",
            &format!("Bash:{}", "a".repeat(300)),
        ] {
            assert!(rule_problem(bad).is_some(), "{bad:?}");
        }
    }

    #[test]
    fn a_rule_covers_only_a_call_it_covers_in_full() {
        let rule = "Bash:cargo test";
        let yes = |input: Value| allows(rule, "Bash", &input);
        assert!(yes(call("cargo test")));
        assert!(yes(call("  cargo test -p x")));
        assert!(yes(json!({"command": ["cargo", "test"]})));
        assert!(yes(json!({"patterns": ["cargo test", "cargo test -p x"]})));
        assert!(yes(call("cargo test 'a;b' \"c d\"")));
        assert!(
            !allows(rule, "bash", &call("cargo test")),
            "tool name is exact"
        );
        assert!(!allows("Bash:", "Bash", &call("cargo test")));
        // One covered pattern never carries the others.
        for bad in [
            json!({"patterns": ["cargo test", "curl evil.sh"]}),
            json!({"patterns": ["curl evil.sh", "cargo test"]}),
            json!({"command": "cargo test", "patterns": ["cargo test", "rm -rf x"]}),
            json!({"command": "rm -rf x", "patterns": ["cargo test"]}),
            json!({"patterns": ["cargo test", 5]}),
            json!({"patterns": "cargo test"}),
            json!({"command": ["cargo", "test", 5]}),
            json!({"command": 5, "patterns": ["cargo test"]}),
            json!({"command": {"a": "cargo test"}}),
            json!({}),
            json!({"patterns": []}),
            json!({"patterns": (0..17).map(|_| "cargo test").collect::<Vec<_>>()}),
            json!({"command": format!("cargo test {}", "a".repeat(5000))}),
            json!({"command": ["cargo", "test", "a'b"]}),
        ] {
            assert!(!yes(bad.clone()), "{bad}");
        }
        for bad in [
            "cargo testx",
            "cargo\u{a0}test",
            "cargo test\u{85}x",
            "cargo test\u{2028}x",
            "xcargo test",
            "./cargo test",
            "FOO=1 cargo test",
            "CARGO test",
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
            assert!(!yes(call(bad)), "{bad:?}");
            assert!(!yes(json!({"patterns": [bad]})), "{bad:?}");
        }
        // A control character in a stage is refused by the shell reader itself.
        for c in ["cargo test\u{1}", "cargo\u{7f}test", "ls\0"] {
            assert!(
                shell::tokens(c).is_none() && shell::pipelines(c).is_none(),
                "{c:?}"
            );
        }
        assert!(allows("Edit", "Edit", &json!({})) && !allows("Edit", "Write", &json!({})));
    }

    /// Every spelling of "run something else" in the review is simply not on the list.
    #[test]
    fn what_is_not_listed_never_matches_a_rule() {
        let rules = [
            "Bash:ls",
            "Bash:cargo test",
            "Bash:git status",
            "Bash:git push",
            "Bash:grep",
            "Bash:echo",
            "Bash:python3 tool.py",
            "Bash:node a.js",
            "Bash:php artisan",
            "Bash:find",
            "Bash:rg",
            "Bash:sed",
            "Bash:sort",
            "Bash:cat",
        ];
        for c in [
            "=bash -c ls",
            "=ls",
            "- rm -rf x",
            "-rm",
            "noglob rm x",
            "nocorrect rm x",
            "command rm x",
            "builtin rm x",
            "exec rm x",
            "then rm -rf x",
            "do rm x",
            "else rm x",
            "if rm x",
            "{ rm x",
            "npm exec rm",
            "npm run build",
            "npx rm",
            "bundle exec rm",
            "docker run x",
            "make x",
            "rg --pre rm x",
            "rg --pre=rm x",
            "rg --pr=rm x",
            "fd -x rm",
            "fd -X rm",
            "git grep -O rm x",
            "git clone --template=x u",
            "git clone -u x y",
            "git pull --rebase",
            "python3 -X importtime -c x",
            "python3 -c x",
            "python3 -m x",
            "python3 -W error a.py",
            "python3 -",
            "python3 /abs/a.py",
            "python3 ../a.py",
            "python3 a.py",
            "node -e x",
            "node --eval x",
            "node -r x a.js",
            "node a.js",
            "php -r x",
            "perl -e x",
            "ruby -e x",
            "python3.12 a.py",
            "node18 a.js",
            "\u{17f}udo ls",
            "\u{212a}it status",
            "\u{ff4c}s",
            "LS",
            "Ls",
            "CARGO test",
            "GIT status",
            "RM -rf x",
            "SUDO ls",
            "/bin/ls",
            "./ls",
            "~/ls",
            "FOO=1 ls",
            "GIT_SSH_COMMAND=x git push",
            "RUSTC_WRAPPER=x cargo build",
            "PATH=/tmp ls",
            "A=b",
        ] {
            for rule in rules {
                // The rules are fine; only a call that matches both rule and table can pass.
                let listed_call = covered(rule, c);
                let expected = matches!(
                    (rule, c),
                    ("Bash:python3 tool.py", "python3 tool.py") | ("Bash:node a.js", "node a.js")
                );
                assert_eq!(listed_call, expected, "{rule} vs {c}");
            }
        }
        // The same words as an entry never become a rule.
        assert!(rule_problem("Bash:=bash").is_some() && rule_problem("Bash:noglob rm").is_some());
    }

    /// The listed programs keep their guards (a second layer, including abbreviations).
    #[test]
    fn listed_programs_keep_their_dangerous_options_out() {
        for (rule, c) in [
            ("Bash:git push", "git push --force"),
            ("Bash:git push", "git push -f origin main"),
            ("Bash:git push", "git push --force-with-lease"),
            ("Bash:git push", "git push --del origin x"),
            ("Bash:git push", "git push -d origin x"),
            ("Bash:git push", "git push origin +main"),
            ("Bash:git push", "git push origin :main"),
            ("Bash:git push", "git push --mirr"),
            ("Bash:git push", "git push --forc"),
            ("Bash:git push", "git push --f"),
            ("Bash:git push", "git push --receive-pack=x"),
            ("Bash:git push", "git push --repo=x"),
            ("Bash:git push", "git push -fu origin x"),
            ("Bash:git fetch", "git fetch --upload-pack=x"),
            ("Bash:git fetch", "git fetch --upl=x"),
            ("Bash:git fetch", "git fetch --prune"),
            ("Bash:git log", "git log --output=x"),
            ("Bash:git diff", "git diff --ext-diff"),
            ("Bash:git diff", "git diff -O x"),
            ("Bash:git show", "git show --textc"),
            ("Bash:git branch", "git branch -D x"),
            ("Bash:git branch", "git branch --delete x"),
            ("Bash:git branch", "git branch -m a b"),
            ("Bash:git status", "git -c core.pager=x status"),
            ("Bash:git status", "git -C / status"),
            ("Bash:cargo test", "cargo -Zunstable-options test"),
            ("Bash:cargo test", "cargo test --conf x=y"),
            ("Bash:cargo build", "cargo build --config=x"),
            ("Bash:find", "find . -exec rm {} ;"),
            ("Bash:find", "find . -delete"),
            ("Bash:find", "find . -ok x"),
            ("Bash:find", "find . -fprint x"),
            ("Bash:rg", "rg --pre rm x"),
            ("Bash:rg", "rg --pr=rm x"),
            ("Bash:rg", "rg -z x"),
            ("Bash:sort", "sort -o out in"),
            ("Bash:sort", "sort --compress-program=x a"),
            ("Bash:sed", "sed -i s/a/b/ f"),
            ("Bash:sed", "sed -e 1e f"),
            ("Bash:sed", "sed s/a/b/e f"),
            ("Bash:sed", "sed s/a/b/w;x f"),
            ("Bash:sed", "sed 1e f"),
            ("Bash:sed", "sed -f s f"),
            ("Bash:sed", "sed --expression=1e f"),
            ("Bash:sed", "sed -n 1w x f"),
            ("Bash:uniq", "uniq in out"),
            ("Bash:php artisan", "php -r x artisan"),
        ] {
            assert!(!covered(rule, c), "{rule} vs {c}");
        }
        for (rule, c) in [
            ("Bash:git push", "git push -u origin feat"),
            ("Bash:git push", "git push origin main"),
            ("Bash:git status", "git status -sb"),
            ("Bash:git log", "git log --oneline -5"),
            ("Bash:find", "find . -name x -type f"),
            ("Bash:rg", "rg foo src"),
            ("Bash:sed", "sed -n 5p f"),
            ("Bash:sed", "sed s/a/b/g f"),
            ("Bash:sed", "sed -n 2,4p f"),
            ("Bash:sort", "sort -u f"),
            ("Bash:uniq", "uniq -c f"),
            ("Bash:php artisan", "php artisan migrate -n -r"),
            ("Bash:python3 tool.py", "python3 tool.py -c x"),
        ] {
            assert!(covered(rule, c), "{rule} vs {c}");
        }
    }

    #[test]
    fn wrapped_scripts_are_matched_on_what_runs() {
        let rule = "commandExecution:cargo test";
        let wrapped = |c: &str| allows(rule, "commandExecution", &call(c));
        assert!(wrapped("bash -lc 'cargo test' x y"));
        assert!(wrapped("BASH -c 'cargo test'"));
        assert!(wrapped("/bin/zsh -l -c 'cargo test -p x'"));
        assert!(wrapped("sh -ic 'cargo test'"));
        assert!(wrapped("sh -c 'cargo test'"));
        assert!(allows(
            rule,
            "commandExecution",
            &json!({"command": ["bash", "-lc", "cargo test -p x"]})
        ));
        for bad in [
            "bash -lc 'cargo test; rm -rf x'",
            "bash -lc 'cargo test && curl x'",
            "bash -lc 'rm -rf ~'",
            "bash -lc 'rm -rf ~' x",
            "bash -lc 'cargo test | sh'",
            "bash -lc \"cargo test $(id)\"",
            "bash -lc 'bash -lc \"cargo test; id\"'",
            "bash --login -c 'cargo test'",
            "bash -lc 'cargo test' ; id",
            "/tmp/bash -lc 'cargo test'",
            "bash -lc",
            "bash -x 'cargo test'",
            "dash -c 'curl x | sh'",
            "bash -lc 'cargo test' $(id)",
        ] {
            assert!(!wrapped(bad), "{bad}");
        }
    }

    /// A rule stored before the allowlist existed matches nothing.
    #[test]
    fn legacy_stored_rules_outside_the_list_match_nothing() {
        for (rule, c) in [
            ("commandExecution:bash -lc", "bash -lc 'rm -rf ~' x"),
            ("commandExecution:bash -lc", "bash -lc ls"),
            ("Bash:sh -c", "sh -c ls"),
            ("Bash:env", "env ls"),
            ("Bash:sudo", "sudo ls"),
            ("Bash:FOO=1 git", "FOO=1 git status"),
            ("Bash:git push --force", "git push --force"),
            ("Bash:python3 -c", "python3 -c x"),
            ("Bash:rm -rf", "rm -rf x"),
            ("Bash:rm", "rm x"),
            ("Bash:cargo", "cargo build"),
            ("Bash:git", "git status"),
            ("Bash:npm run", "npm run build"),
            ("Bash:make", "make test"),
            ("Bash:python3", "python3 a.py"),
            ("Bash:node18 a.js", "node18 a.js"),
        ] {
            let tool = rule.split(':').next().unwrap();
            assert!(!allows(rule, tool, &call(c)), "{rule} {c}");
            assert_eq!(rule_prefix(rule, tool), None, "{rule}");
        }
        assert!(rule_prefix("Bash:cargo test", "Bash").is_some());
        assert_eq!(rule_prefix("Bash:cargo test", "bash"), None);
    }

    #[test]
    fn the_default_rule_is_offered_only_when_the_list_accepts_it() {
        let rule = |t: &str, i: Value| default_rule(t, &i);
        assert_eq!(rule("Bash", call("cargo test -p x")), "Bash:cargo test");
        assert_eq!(rule("Bash", call("ls -la src")), "Bash:ls -la");
        assert_eq!(rule("Bash", call("ls")), "Bash:ls");
        assert_eq!(
            rule(
                "commandExecution",
                json!({"command": ["bash", "-lc", "cargo test -p x"]})
            ),
            "commandExecution:cargo test"
        );
        assert_eq!(
            rule("commandExecution", call("bash -lc 'cargo build --release'")),
            "commandExecution:cargo build"
        );
        assert_eq!(
            rule(
                "commandExecution",
                json!(r#"{"command":["bash","-lc","cargo test -p x"]}"#)
            ),
            "commandExecution:cargo test"
        );
        // Not listed, not one simple command, or not plain: the bare tool, so "approve once".
        for c in [
            "cargo test; rm x",
            "a | b",
            "$(id) x",
            "FOO=1 git push",
            "rm -rf x",
            "make test",
            "npm run build",
            "python3 -c x",
            "=ls",
            "bash -lc 'env FOO=1 rm x'",
            "docker run x",
            "git clone u",
        ] {
            assert_eq!(rule("Bash", call(c)), "Bash", "{c}");
        }
        assert_eq!(rule("Bash", json!({})), "Bash");
        assert!(rule_problem("Bash").is_some());
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

/// A program's name as the system will look it up: its last path part, lower-cased (macOS file
/// lookup ignores case), without a trailing version (`python3.12` is `python`, `node18` is `node`).
fn program(word: &str) -> String {
    let base = word.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    match base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.') {
        "" => base,
        trimmed => trimmed.to_owned(),
    }
}

/// Whether `word` is a `NAME=value` environment assignment, which the shell runs the command under.
fn is_assignment(word: &str) -> bool {
    let name = word.split('=').next().unwrap_or("");
    word.contains('=')
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `arg` is `--option` or an unambiguous abbreviation of one of `full` (GNU tools and git
/// take any unique prefix of a long option), with or without `=value`.
fn long(arg: &str, full: &[&str]) -> bool {
    let name = arg.split('=').next().unwrap_or("");
    name.len() > 2 && name.starts_with("--") && full.iter().any(|f| f.starts_with(name))
}

/// Whether the short-option cluster `arg` (`-rf`, not `--x`) holds one of `letters`.
fn cluster(arg: &str, letters: &str) -> bool {
    arg.len() > 1
        && arg.starts_with('-')
        && !arg.starts_with("--")
        && arg[1..].chars().any(|c| letters.contains(c))
}

/// Programs that run another command (shells, wrappers, remote and scheduling tools, programs
/// that execute their arguments). A call to one is never covered by a rule: what runs is in its
/// arguments.
const RUNNERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "csh",
    "tcsh",
    "env",
    "xargs",
    "sudo",
    "su",
    "doas",
    "nohup",
    "time",
    "command",
    "exec",
    "nice",
    "timeout",
    "ionice",
    "setsid",
    "stdbuf",
    "watch",
    "busybox",
    "builtin",
    "eval",
    "source",
    ".",
    "awk",
    "gawk",
    "npx",
    "chroot",
    "arch",
    "script",
    "flock",
    "caffeinate",
    "sandbox-exec",
    "ssh",
    "scp",
    "sftp",
    "uv",
    "bunx",
    "swift",
    "at",
    "batch",
    "crontab",
    "open",
];

/// Interpreters: a rule may name one only with the script or subcommand it runs, and a call is
/// escalated when the interpreter's own options (those before the script) run inline code, load
/// code, or read the program from stdin or a prompt.
const INTERPRETERS: &[&str] = &[
    "python",
    "pythonw",
    "node",
    "ruby",
    "perl",
    "php",
    "lua",
    "deno",
    "bun",
    "tsx",
    "ts-node",
    "osascript",
];

/// Whether `args` of the interpreter `name` make it run something other than a named script.
fn runs_inline_code(name: &str, args: &[String]) -> bool {
    let Some(script) = args.iter().position(|a| !a.starts_with('-') || a == "-") else {
        return true;
    };
    let long = |a: &String| {
        long(
            a,
            &[
                "--eval",
                "--print",
                "--exec",
                "--command",
                "--require",
                "--import",
                "--loader",
                "--interactive",
                "--preload",
                "--run",
                "--input-type",
            ],
        )
    };
    args[script] == "-"
        || args[..script]
            .iter()
            .any(|a| cluster(a, "cemprxEMRBFnilaCIs") || long(a))
        || (["deno", "bun"].contains(&name)
            && ["eval", "repl", "x"].contains(&args[script].as_str()))
}

/// Whether `words` (one simple command) must go to a reviewer whatever an allowlist says: it
/// starts with an environment assignment (`GIT_SSH_COMMAND=x git ...`), it runs another program
/// ([`RUNNERS`]), or it is destructive: privilege changes, forced or deleting pushes, git and
/// cargo options that load configuration or run a program, recursive removal and ownership
/// changes, raw disk tools, and the options of `tar` and `rsync` that run a command. Names are
/// compared lower-cased and without a version, long options by unique prefix.
pub fn hard_escalate(words: &[String]) -> bool {
    let Some(first) = words.first() else {
        return true;
    };
    if is_assignment(first) {
        return true;
    }
    let name = program(first);
    let args = &words[1..];
    if RUNNERS.contains(&name.as_str()) {
        return true;
    }
    if INTERPRETERS.contains(&name.as_str()) {
        return runs_inline_code(&name, args);
    }
    match name.as_str() {
        "dd" | "shred" | "fdisk" | "mount" | "umount" | "mkfs" | "diskutil" | "launchctl" => true,
        n if n.starts_with("mkfs.") => true,
        "rm" => args
            .iter()
            .any(|a| cluster(a, "rR") || long(a, &["--recursive", "--no-preserve-root"])),
        "chmod" | "chown" | "chgrp" => args
            .iter()
            .any(|a| cluster(a, "R") || long(a, &["--recursive"])),
        "cargo" => args
            .iter()
            .any(|a| a == "-C" || a.starts_with("-Z") || long(a, &["--config"])),
        "tar" => args.iter().any(|a| {
            cluster(a, "I")
                || long(
                    a,
                    &[
                        "--to-command",
                        "--checkpoint-action",
                        "--use-compress-program",
                        "--rsh-command",
                        "--info-script",
                        "--new-volume-script",
                    ],
                )
        }),
        "rsync" => args
            .iter()
            .any(|a| cluster(a, "e") || long(a, &["--rsh", "--rsync-path", "--daemon"])),
        "git" => {
            // A global option before the subcommand (`-c`, `-C`, `--exec-path`, ...) can load
            // configuration or run another program.
            let Some(sub) = args.iter().position(|a| !a.starts_with('-')) else {
                return true;
            };
            let rest = &args[sub + 1..];
            let dangerous = |a: &String| {
                long(
                    a,
                    &[
                        "--force",
                        "--force-with-lease",
                        "--force-if-includes",
                        "--delete",
                        "--mirror",
                        "--prune",
                        "--receive-pack",
                        "--upload-pack",
                        "--exec",
                        "--exec-path",
                        "--config",
                        "--repo",
                    ],
                )
            };
            sub > 0
                || rest.iter().any(dangerous)
                || (args[sub] == "push"
                    && rest
                        .iter()
                        .any(|a| cluster(a, "fd") || a.starts_with('+') || a.starts_with(':')))
                || (args[sub] == "rebase" && rest.iter().any(|a| cluster(a, "x")))
                || (args[sub] == "clone" && rest.iter().any(|a| cluster(a, "uc")))
                || matches!(
                    args[sub].as_str(),
                    "filter-branch" | "config" | "submodule" | "daemon" | "difftool" | "mergetool"
                )
        }
        _ => false,
    }
}

/// What an allow rule may name. THE allowlist: a rule exists, and covers a call, only for a program
/// listed here, with a subcommand from its list when it has one. Everything else (shells,
/// wrappers, runners, reserved words, `noglob`, package managers, `docker`, `make`, unknown tools)
/// is simply absent, so it can only be approved once. The deny logic in [`hard_escalate`] is a second
/// layer over the listed programs, not the gate.
enum Safe {
    /// The first argument must be one of these subcommands.
    Sub(&'static [&'static str]),
    /// Any arguments, except those [`guard`] refuses.
    Any,
    /// Runs a script FILE: the first argument must be a plain relative file path, so no option of
    /// the interpreter (`-c`, `-e`, `-m`, `-r`, `-X`, ...) can come before it.
    Script,
}

const SAFE: &[(&str, Safe)] = &[
    (
        "cargo",
        Safe::Sub(&[
            "build", "check", "test", "clippy", "fmt", "doc", "metadata", "tree",
        ]),
    ),
    (
        "git",
        Safe::Sub(&[
            "status",
            "diff",
            "log",
            "show",
            "branch",
            "rev-parse",
            "add",
            "commit",
            "fetch",
            "push",
        ]),
    ),
    ("ls", Safe::Any),
    ("cat", Safe::Any),
    ("head", Safe::Any),
    ("tail", Safe::Any),
    ("wc", Safe::Any),
    ("grep", Safe::Any),
    ("rg", Safe::Any),
    ("find", Safe::Any),
    ("sed", Safe::Any),
    ("sort", Safe::Any),
    ("uniq", Safe::Any),
    ("diff", Safe::Any),
    ("jq", Safe::Any),
    ("tree", Safe::Any),
    ("pwd", Safe::Any),
    ("echo", Safe::Any),
    ("test", Safe::Any),
    ("true", Safe::Any),
    ("false", Safe::Any),
    ("node", Safe::Script),
    ("python3", Safe::Script),
    ("python", Safe::Script),
    ("php", Safe::Script),
];

/// A program word the table can match at all: lower-case ASCII letters, digits and `._+-`, not
/// starting with a symbol. No case folding, no path, no `=cmd`, `- cmd`, `NAME=value` or non-ASCII.
fn plain_program(word: &str) -> bool {
    word.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && word
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._+-".contains(c))
}

/// A relative file path of plain characters, with no `..`: `tool.py`, `src/a.js`, `artisan`.
fn plain_file(word: &str) -> bool {
    word.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./-".contains(c))
        && !word.split('/').any(|p| p.is_empty() || p == "..")
}

/// The options of a listed program that write, run or delete something.
fn guard(name: &str, args: &[String]) -> bool {
    match name {
        "find" => args.iter().any(|a| {
            [
                "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf",
                "-fls",
            ]
            .contains(&a.as_str())
        }),
        "rg" => args
            .iter()
            .any(|a| long(a, &["--pre", "--hostname-bin", "--search-zip"]) || cluster(a, "z")),
        "sort" => args.iter().any(|a| {
            cluster(a, "o") || long(a, &["--output", "--compress-program", "--files0-from"])
        }),
        "tree" => args
            .iter()
            .any(|a| cluster(a, "o") || long(a, &["--output"])),
        // `uniq in out` writes `out`.
        "uniq" => args.iter().filter(|a| !a.starts_with('-')).count() > 1,
        "sed" => {
            // Only `-n`/`-E`/`-r` and one script of the form `Np`, `N,Md` or `s/a/b/flags`.
            let (opts, rest): (Vec<_>, Vec<_>) = args.iter().partition(|a| a.starts_with('-'));
            let script_ok = |s: &str| {
                let print_or_delete = !s.is_empty()
                    && s.trim_end_matches(['p', 'd'])
                        .chars()
                        .all(|c| c.is_ascii_digit() || c == ',' || c == '$')
                    && s.len() > s.trim_end_matches(['p', 'd']).len()
                    && s.len() - s.trim_end_matches(['p', 'd']).len() == 1;
                let substitute = s.strip_prefix("s/").is_some_and(|r| {
                    let parts: Vec<&str> = r.split('/').collect();
                    parts.len() == 3
                        && parts[..2].iter().all(|p| !p.contains(['\\', ';', '\n']))
                        && parts[2].chars().all(|c| "gpiI0123456789".contains(c))
                });
                print_or_delete || substitute
            };
            // No script yet (a rule's bare prefix) is nothing to refuse.
            !args.is_empty()
                && !(opts
                    .iter()
                    .all(|o| ["-n", "-E", "-r"].contains(&o.as_str()))
                    && rest.first().is_some_and(|s| script_ok(s)))
        }
        "git" => {
            let sub = args.first().map(String::as_str).unwrap_or("");
            let rest = args.get(1..).unwrap_or(&[]);
            match sub {
                "diff" | "log" | "show" => rest
                    .iter()
                    .any(|a| long(a, &["--output", "--ext-diff", "--textconv"]) || cluster(a, "O")),
                "branch" => rest.iter().any(|a| {
                    cluster(a, "dDmMcCfu")
                        || long(
                            a,
                            &[
                                "--delete",
                                "--move",
                                "--copy",
                                "--force",
                                "--set-upstream-to",
                                "--edit-description",
                            ],
                        )
                }),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Whether `words` (one simple command) is on the allowlist: a listed program, spelled exactly,
/// with a listed subcommand or a plain script file where the table says so, and none of its
/// guarded options. Everything not listed is `false`: the call escalates.
pub fn safe_call(words: &[String]) -> bool {
    let Some(first) = words.first() else {
        return false;
    };
    if !plain_program(first) {
        return false;
    }
    let args = &words[1..];
    let Some((_, kind)) = SAFE.iter().find(|(n, _)| n == first) else {
        return false;
    };
    let shape = match kind {
        Safe::Sub(subs) => args.first().is_some_and(|a| subs.contains(&a.as_str())),
        Safe::Any => true,
        Safe::Script => args.first().is_some_and(|a| plain_file(a)),
    };
    shape && !guard(first, args)
}

/// Whether a stored rule's `prefix` words cover the stage `words` of a call: the stage starts with
/// them, word for word, is on the allowlist ([`safe_call`]) and is not [`hard_escalate`]d. The ONE place a rule meets a command: both
/// [`allows`] and the runner's chain check go through it, so they cannot drift.
pub fn covers(prefix: &[String], words: &[String]) -> bool {
    !prefix.is_empty() && words.starts_with(prefix) && safe_call(words) && !hard_escalate(words)
}

/// A rule entry's prefix as words, or `None` when the entry is not a usable `<tool>:<prefix>`
/// rule for `tool`: another tool, an empty prefix, a prefix that is not plain words, or an entry
/// [`rule_problem`] finds fault with. Stored rules are checked again here, at USE time: an entry
/// stored or inserted before a check existed covers nothing.
pub fn rule_prefix(entry: &str, tool: &str) -> Option<Vec<String>> {
    let (name, prefix) = entry.split_once(':')?;
    if name != tool || rule_problem(entry).is_some() {
        return None;
    }
    let words = shell::tokens(prefix)?
        .into_iter()
        .map(|t| match t {
            shell::Token::Word(w) => Some(w),
            shell::Token::Op(_) => None,
        })
        .collect::<Option<Vec<_>>>()?;
    (!words.is_empty()).then_some(words)
}

/// Why an allow rule (`<tool>` or `<tool>:<command prefix>`, as "allow for this issue" stores
/// it) must not exist, if it must not: it is not short printable text, it names a whole shell,
/// its prefix is not plain words, or it starts with a setting, a program that runs another
/// ([`RUNNERS`]), an interpreter without a script, or something [`hard_escalate`]s.
pub fn rule_problem(rule: &str) -> Option<&'static str> {
    if rule.len() > 256 || rule.chars().any(char::is_control) {
        return Some("a rule is short printable text");
    }
    let Some((tool, prefix)) = rule.split_once(':') else {
        let bare_shell = SHELL_TOOLS.contains(&rule);
        return match (rule.is_empty() || rule.trim() != rule, bare_shell) {
            (true, _) => Some("a rule is <tool> or <tool>:<command prefix>"),
            (_, true) => Some(
                "a shell needs a safe command prefix, not the whole tool; approve this call once instead",
            ),
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
    if is_assignment(&words[0]) {
        Some("a rule cannot start with a setting")
    } else if RUNNERS.contains(&program(&words[0]).as_str()) {
        Some("a rule cannot start with a shell, wrapper or interpreter that runs another command")
    } else if hard_escalate(&words) {
        Some("that command always goes to a reviewer")
    } else if !safe_call(&words) {
        Some(
            "only the listed safe commands can be allowed for an issue; approve this call once instead",
        )
    } else {
        None
    }
}

/// The rule an "allow for this issue" of this call stores when none is given: `<tool>:<the first
/// two (or one) plain words of the command that really runs>` when the allowlist accepts it, else
/// the bare tool (which a shell refuses).
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
    // Only a rule the allowlist accepts is offered (two words, then one); otherwise the bare tool,
    // which a shell refuses: the call can only be approved once.
    for n in [2, 1] {
        let kept: Vec<&str> = words
            .iter()
            .take(n)
            .take_while(|w| plain(w))
            .map(String::as_str)
            .collect();
        let rule = format!("{tool}:{}", kept.join(" "));
        if kept.len() == n && rule_problem(&rule).is_none() {
            return rule;
        }
    }
    tool.to_owned()
}

/// Whether allowlist `entry` covers the call: a tool name, or `<tool>:<prefix>` for a call whose
/// every command (see [`commands_of`]) is ONE simple command (see [`call_words`]) that starts
/// with the prefix's words, word for word (`npm run` covers `npm run x`, never `npm runx`), and is
/// not [`hard_escalate`]d. Quoted words are single words. Anything unclear is not covered.
pub fn allows(entry: &str, tool: &str, input: &Value) -> bool {
    if !entry.contains(':') {
        return entry == tool;
    }
    let Some(rule) = rule_prefix(entry, tool) else {
        return false;
    };
    commands_of(input).is_some_and(|all| {
        all.iter()
            .all(|c| call_words(c).is_some_and(|w| covers(&rule, &w)))
    })
}
