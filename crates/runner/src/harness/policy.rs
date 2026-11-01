//! The project's permission policy applied to a harness's approval requests (E3.10).

use std::path::{Component, Path};
use std::time::Duration;

use ainkrad_harness::Decision;
use ainkrad_proto::runner::shell::pipelines;
use ainkrad_proto::runner::{PermissionMode, Policy, allows, commands_of, covers, rule_prefix};
use serde_json::Value;
use tokio::sync::mpsc;

use super::HarnessExecutor;
use crate::{Answer, Reply, Report};

impl HarnessExecutor {
    /// Whether `policy` lets the tool call go ahead, or why it needs a reviewer.
    pub(super) fn decide(
        &self,
        policy: &Policy,
        tool: &str,
        input: &Value,
        cwd: &Path,
    ) -> Result<(), String> {
        if policy.mode == PermissionMode::Sandboxed && self.sandboxed {
            return Ok(());
        }
        // The Citadel MCP tools (E4.2) and CLI (E15.18) are scoped by the run token, not by
        // the policy.
        if citadel_call(tool, input) {
            return Ok(());
        }
        // The usable rules for this tool: an entry that `rule_problem` finds fault with (a shell,
        // a wrapper, a destructive command, stored before the check existed) covers nothing.
        for entry in policy.allow.iter() {
            if SHELLS.contains(&entry.as_str()) {
                // An admin-authored bare shell entry is a deliberate full-auto mode for that shell.
                warn_once(entry, "the project policy allows every command of a shell");
            } else if entry.starts_with(tool)
                && entry[tool.len()..].starts_with(':')
                && rule_prefix(entry, tool).is_none()
            {
                warn_unusable_rule(entry);
            }
        }
        let rules: Vec<Vec<String>> = (policy.allow.iter())
            .filter_map(|entry| rule_prefix(entry, tool))
            .collect();
        // A shell's harmless waits (`sleep`, `date`) need no rule; another tool's need one.
        let chain = !rules.is_empty() || SHELLS.contains(&tool);
        let listed = policy.allow.iter().any(|entry| allows(entry, tool, input))
            || (chain
                && commands_of(input)
                    .is_some_and(|all| all.iter().all(|c| chain_allowed(&rules, c))));
        let edit =
            policy.mode == PermissionMode::AcceptEdits && self.edit_tools.iter().any(|t| t == tool);
        if !listed && !edit {
            return Err(format!("{tool} is outside the project's permission policy"));
        }
        // A listed read-only tool may look outside the run's directory when the policy already
        // allows a whole shell, which could read the same file anyway.
        if listed
            && READ_TOOLS.contains(&tool)
            && policy.allow.iter().any(|e| SHELLS.contains(&e.as_str()))
        {
            return Ok(());
        }
        // Claude names a path per key (OpenCode: `filepath`); Codex lists `changes[].path`.
        let changes = input["changes"].as_array().into_iter().flatten();
        let paths = ["file_path", "notebook_path", "path", "filepath"]
            .iter()
            .map(|key| &input[key])
            .chain(changes.map(|c| &c["path"]))
            .filter_map(Value::as_str);
        for path in paths {
            let path = Path::new(path);
            let inside = (path.is_relative() || path.starts_with(cwd))
                && !path.components().any(|c| c == Component::ParentDir);
            if !inside {
                return Err(format!("{} is outside the run's directory", path.display()));
            }
        }
        Ok(())
    }

    /// Asks a reviewer through the server and waits for the answer, or denies on timeout.
    pub(super) async fn escalate(
        &self,
        id: &str,
        tool: &str,
        input: &Value,
        reports: &mpsc::Sender<Report>,
        timeout: Duration,
    ) -> Decision {
        let (reply, answer) = Reply::new();
        let ask = Report::Approval {
            id: id.to_owned(),
            tool: tool.to_owned(),
            input: input.clone(),
            // Rounded up, so the server never expires it before the runner gives up.
            timeout_secs: timeout.as_millis().div_ceil(1000) as u64,
            reply,
        };
        if reports.send(ask).await.is_err() {
            return Decision::Deny {
                reason: "the runner is shutting down".to_owned(),
            };
        }
        match tokio::time::timeout(timeout, answer).await {
            Ok(Ok(Answer { approved: true, .. })) => Decision::Allow,
            Ok(Ok(Answer { reply, .. })) => Decision::Deny {
                reason: reply
                    .filter(|r| !r.trim().is_empty())
                    .unwrap_or_else(|| format!("a reviewer denied {tool}")),
            },
            _ => Decision::Deny {
                reason: format!("{tool} needs a reviewer, and none answered within {timeout:?}"),
            },
        }
    }
}

/// Whether the call only reaches Citadel: one of its MCP tools, as each harness names them
/// (Claude `mcp__citadel__<tool>`, OpenCode `citadel_<tool>`), or a shell command made only
/// of run-scoped `citadel` CLI calls (Claude `Bash`, Codex `commandExecution`, OpenCode `bash`).
pub(super) fn citadel_call(tool: &str, input: &Value) -> bool {
    tool.starts_with("mcp__citadel__")
        || tool.starts_with("citadel_")
        || (SHELLS.contains(&tool) && citadel_shell(input))
}

/// A shell call made only of `citadel` CLI calls. EVERY command it carries is read (`commands_of`):
/// the `command`, when there is one, must be a citadel call as a whole; each OpenCode pattern is a
/// pipeline stage (`citadel ...` or a read-only filter like `jq .title`), so a call whose second
/// pattern is anything else is left to the policy.
fn citadel_shell(input: &Value) -> bool {
    let Some(all) = commands_of(input) else {
        return false;
    };
    let stage_filter = |c: &str| {
        pipelines(c).is_some_and(|ps| matches!(&ps[..], [p] if matches!(&p[..], [s] if filter(s))))
    };
    let whole = input["command"].is_null() || citadel_cli(&all[0]);
    whole
        && all.iter().all(|c| citadel_cli(c) || stage_filter(c))
        && all.iter().any(|c| citadel_cli(c))
}

/// The shell tools: Claude's `Bash`, Codex's `commandExecution`, OpenCode's `bash`.
const SHELLS: [&str; 3] = ["Bash", "commandExecution", "bash"];

/// The read-only file tools: Claude's and OpenCode's.
const READ_TOOLS: [&str; 8] = ["Read", "Glob", "Grep", "LS", "read", "glob", "grep", "list"];

/// The longest `sleep` that goes ahead without a rule: an agent polling a background job.
const MAX_SLEEP_SECS: f64 = 300.0;

/// Whether `command` only runs the run-scoped `citadel` CLI (E15.18): pipelines joined by `;`,
/// `&&` or `||`, each a bare `citadel` call piped into nothing but read-only filters, or a lone
/// `echo` between them. Anything else, or anything it cannot tell, is left to the policy.
pub(super) fn citadel_cli(command: &str) -> bool {
    pipelines(command).is_some_and(|ps| {
        let calls: Option<Vec<bool>> = ps.iter().map(|p| pipeline(p)).collect();
        calls.is_some_and(|c| c.contains(&true))
    })
}

/// Whether every simple command in `command` would go ahead on its own: it starts with the
/// words of one of `rules` (allowlist prefixes, `covers`) or is [`harmless`], it is a bare `echo`, or it
/// is piped into as a read-only filter; a run-scoped `citadel` pipeline goes ahead whole. The
/// condition and body of an `until`/`while … do … done` loop are checked the same way. One that
/// would not, or a command [`pipelines`] or [`unlooped`] refuses, leaves the whole command to a
/// reviewer.
pub(super) fn chain_allowed(rules: &[Vec<String>], command: &str) -> bool {
    let listed = |stage: &[String]| rules.iter().any(|r| covers(r, stage));
    pipelines(command).and_then(unlooped).is_some_and(|ps| {
        !ps.is_empty()
            && ps.iter().all(|p| {
                pipeline(p).is_some_and(|call| call || p == &[vec!["echo".to_owned()]])
                    || ((listed(&p[0]) || harmless(&p[0]))
                        && p[1..].iter().all(|s| listed(s) || filter(s)))
            })
    })
}

/// `pipelines` with each `until`/`while <condition>; do <body>; done` loop opened up into the
/// pipelines of its condition and body, or `None` for a nested, unclosed or piped loop, or a
/// stray `do` or `done`.
fn unlooped(ps: Vec<Vec<Vec<String>>>) -> Option<Vec<Vec<Vec<String>>>> {
    #[derive(PartialEq)]
    enum In {
        Nothing,
        Condition,
        Body,
    }
    let (mut at, mut out) = (In::Nothing, vec![]);
    for mut p in ps {
        match (&at, p[0][0].as_str()) {
            (In::Nothing, "until" | "while") => at = In::Condition,
            (In::Condition, "do") => at = In::Body,
            (In::Body, "done") if p == [vec!["done".to_owned()]] => at = In::Nothing,
            (_, "until" | "while" | "do" | "done") => return None,
            _ => {
                out.push(p);
                continue;
            }
        }
        p[0].remove(0);
        match (p[0].is_empty(), p.len()) {
            // `do` or `until` alone on its line.
            (true, 1) => {}
            (true, _) => return None,
            (false, _) => out.push(p),
        }
    }
    (at == In::Nothing).then_some(out)
}

/// Whether `stage` is harmless on its own: `true`, `date` printing the time (`+<format>`, `-u`),
/// or `sleep` of at most [`MAX_SLEEP_SECS`] (seconds, or with an `s` or `m` suffix).
fn harmless(stage: &[String]) -> bool {
    let Some((name, args)) = stage.split_first() else {
        return false;
    };
    match (name.as_str(), args) {
        ("true", []) => true,
        ("date", _) => args.iter().all(|a| a.starts_with('+') || a == "-u"),
        ("sleep", [secs]) => {
            let (n, unit) = match secs.strip_suffix('m') {
                Some(n) => (n, 60.0),
                None => (secs.strip_suffix('s').unwrap_or(secs), 1.0),
            };
            let digits = !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit() || b == b'.');
            digits && n.parse::<f64>().is_ok_and(|n| n * unit <= MAX_SLEEP_SECS)
        }
        _ => false,
    }
}

/// Whether `stages` is a `citadel` call (`Some(true)`) piped only into read-only filters, or a
/// lone `echo` (`Some(false)`).
fn pipeline(stages: &[Vec<String>]) -> Option<bool> {
    let (first, rest) = stages.split_first()?;
    match first.first().map(String::as_str) {
        Some("echo") if rest.is_empty() => return Some(false),
        Some("citadel") => {}
        _ => return None,
    }
    rest.iter().all(|s| filter(s)).then_some(true)
}

/// Whether `stage` is a read-only filter of its input: flags that read a file or a directory
/// (or write one) are refused, and so is a file operand.
fn filter(stage: &[String]) -> bool {
    let flag = |w: &str, banned: &str| {
        (!w.is_empty() && w.bytes().all(|b| b.is_ascii_digit()))
            || (w.len() > 1
                && w.starts_with('-')
                && w[1..].bytes().all(|b| b.is_ascii_alphanumeric())
                && !w.contains(|c| banned.contains(c)))
    };
    let Some((name, args)) = stage.split_first() else {
        return false;
    };
    // `operands` that are not files: grep's pattern, jq's filter, tr's sets.
    let (banned, operands) = match name.as_str() {
        "head" | "tail" | "wc" | "uniq" => ("", 0),
        "sort" => ("oT", 0),
        "tr" => ("", 2),
        "grep" => ("fdrDR", 1),
        "jq" => ("fL", 1),
        _ => return false,
    };
    let others = args.iter().filter(|a| !flag(a, banned)).count();
    let refused = args.iter().any(|a| a.starts_with('-') && !flag(a, banned));
    others <= operands && !refused
}

/// Logs `what` once per distinct `entry`; `true` the first time.
pub(super) fn warn_once(entry: &str, what: &str) -> bool {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let key: String = entry.chars().take(256).collect();
    let first = SEEN
        .get_or_init(Default::default)
        .lock()
        .is_ok_and(|mut seen| seen.insert(format!("{what}\0{key}")));
    if first {
        tracing::warn!(entry = %key, "{what}");
    }
    first
}

/// A `<tool>:<prefix>` entry that is not on the allowlist matches nothing: its calls escalate and a
/// reviewer can approve them once.
pub(super) fn warn_unusable_rule(entry: &str) -> bool {
    warn_once(
        entry,
        "an allow rule is not on the safe-command list and matches nothing",
    )
}
