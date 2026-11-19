//! "Always for this project" (Core 0.10, E14): an allow rule made when a person approves one tool
//! call, and the auto-approval of later calls that match it in any session of that project.
//!
//! The design is the runner's positive allowlist, not a deny-list (every deny-list round of the
//! allow-rule work found a new bypass): a shell rule exists, and covers a call, only when
//! `ainkrad_proto::runner::{default_rule, rule_problem, allows}` accept it, which is the `SAFE`
//! table plus `hard_escalate`; the same check runs again at USE, so a stored row can never allow
//! more than the table does today. On top of it: no network egress (`git push`/`fetch`), nothing
//! that names a secret. A file edit rule is a path prefix of plain names inside the session's
//! folder: no hidden file or folder (`.git`, `.env`, `.github`), nothing named like a secret.
//! Anything else is `rule_not_allowed`: it can only be approved once.

use std::collections::HashSet;

use ainkrad_proto::runner::{
    SHELL_TOOLS, allows, call_words, commands_of, default_rule, rule_problem,
};
use ainkrad_proto::v2::{TranscriptEntry, folder_relative};
use serde_json::{Value, json};

use super::*;

/// The file-edit tools a path rule may name (Claude Code's).
pub const EDIT_TOOLS: [&str; 3] = ["Edit", "Write", "MultiEdit"];

const SECRETISH: [&str; 12] = [
    ".env",
    "secret",
    "credential",
    "token",
    "password",
    "passwd",
    ".pem",
    ".key",
    "id_rsa",
    "id_ed25519",
    ".p12",
    ".ssh",
];

fn secretish(word: &str) -> bool {
    let w = word.to_ascii_lowercase();
    SECRETISH.iter().any(|s| w.contains(s))
}

/// A command that reaches the network, or names a secret: never made a rule, never auto-approved.
fn blocked(words: &[String]) -> bool {
    let first = words.first().map_or("", String::as_str);
    let sub = words.get(1).map_or("", String::as_str);
    let net = matches!(
        first,
        "curl" | "wget" | "ssh" | "scp" | "sftp" | "rsync" | "nc" | "ncat" | "telnet" | "ftp"
    ) || (first == "git"
        && matches!(sub, "push" | "fetch" | "pull" | "clone" | "remote"));
    net || words.iter().any(|w| secretish(w))
}

/// Every command of the call as words, `None` when one cannot be read or is [`blocked`].
fn clean_commands(input: &Value) -> Option<Vec<Vec<String>>> {
    let all = commands_of(input)?
        .iter()
        .map(|c| call_words(c))
        .collect::<Option<Vec<_>>>()?;
    all.iter().all(|w| !blocked(w)).then_some(all)
}

/// The input of an approval request as a value (some harnesses carry it as JSON text).
fn input_of(input: &Value) -> Value {
    match input {
        Value::String(t) => serde_json::from_str(t).unwrap_or_else(|_| input.clone()),
        v => v.clone(),
    }
}

/// The edited file of a call, relative to the session folder, when it is a plain path.
fn edit_path(input: &Value, folder: Option<&str>) -> Option<String> {
    let path = ["file_path", "path"]
        .iter()
        .find_map(|k| input[*k].as_str())?;
    let rel = folder_relative(folder?, path)?;
    let plain = |p: &str| {
        !p.starts_with('.')
            && !secretish(p)
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    };
    (!rel.is_empty() && rel.split('/').all(plain)).then_some(rel)
}

/// The rule `(tool, pattern)` an "always" for this call stores, or why there is none.
pub fn derive(
    tool: &str,
    input: &Value,
    folder: Option<&str>,
) -> Result<(String, String), &'static str> {
    let input = input_of(input);
    if SHELL_TOOLS.contains(&tool) {
        let rule = default_rule(tool, &input);
        let Some(pattern) = rule.strip_prefix(&format!("{tool}:")) else {
            return Err("only the listed safe commands can be allowed for a project");
        };
        let words: Vec<String> = pattern.split_whitespace().map(str::to_owned).collect();
        if rule_problem(&rule).is_some() || blocked(&words) {
            return Err("that command always asks: approve it once instead");
        }
        // Every command of the call must be covered: `cargo test && rm x` is no `cargo test` rule.
        if clean_commands(&input).is_none() || !allows(&rule, tool, &input) {
            return Err("that call is not covered by one safe command");
        }
        return Ok((tool.to_owned(), pattern.to_owned()));
    }
    if EDIT_TOOLS.contains(&tool) {
        let Some(rel) = edit_path(&input, folder) else {
            return Err("only a plain file inside the project folder can be allowed");
        };
        let pattern = match rel.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/"),
            None => rel,
        };
        return Ok((tool.to_owned(), pattern));
    }
    Err("only the safe shell commands and file edits can be allowed for a project")
}

/// Whether the stored rule `(rule_tool, pattern)` covers the request `tool`/`input`. The allowlist
/// is applied again here, whatever was stored.
pub fn covers(
    rule_tool: &str,
    pattern: &str,
    tool: &str,
    input: &Value,
    folder: Option<&str>,
) -> bool {
    if rule_tool != tool {
        return false;
    }
    let input = input_of(input);
    if SHELL_TOOLS.contains(&tool) {
        return clean_commands(&input).is_some()
            && allows(&format!("{tool}:{pattern}"), tool, &input);
    }
    if EDIT_TOOLS.contains(&tool) {
        return edit_path(&input, folder).is_some_and(|rel| match pattern.ends_with('/') {
            true => rel.starts_with(pattern),
            false => rel == pattern,
        });
    }
    false
}

/// The label a transcript note shows for a rule: `Bash cargo test`, `Edit src/api/`.
pub fn label(tool: &str, pattern: &str) -> String {
    format!("{tool} {pattern}")
}

/// The approval requests among `entries` that a rule of `s`'s project covers: `(request id,
/// label)`. Empty for a session of no project, or entries with no request: no query then.
pub async fn matching(
    app: &App,
    s: &Session,
    entries: &[TranscriptEntry],
) -> Vec<(String, String)> {
    let Some(project) = s.project_id else {
        return vec![];
    };
    let asked: Vec<&TranscriptEntry> = entries
        .iter()
        .filter(|e| e.body["type"] == "approval_request")
        .collect();
    if asked.is_empty() {
        return vec![];
    }
    let rules = match crate::store::approval_rules::list(&app.pool, project).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(session = s.id, error = %e, "reading project approval rules failed");
            return vec![];
        }
    };
    let mut out = vec![];
    for e in asked {
        let (Some(id), Some(tool)) = (e.body["id"].as_str(), e.body["tool"].as_str()) else {
            continue;
        };
        let hit = rules.iter().find(|r| {
            covers(
                &r.tool,
                &r.pattern,
                tool,
                &e.body["input"],
                s.folder.as_deref(),
            )
        });
        if let Some(r) = hit {
            out.push((id.to_owned(), label(&r.tool, &r.pattern)));
        }
    }
    out
}

/// The ids of `hits`, for `store::apply_quiet`.
pub fn quiet(hits: &[(String, String)]) -> HashSet<String> {
    hits.iter().map(|(id, _)| id.clone()).collect()
}

/// Approves each of `hits` on the runner, noting the rule in the transcript (`approval_decided`'s
/// `rule`) and the audit (`agent.approval_auto`). One that fails stays for the person: it is
/// raised as the approval request it is.
pub async fn decide(app: &App, s: &Session, hits: Vec<(String, String)>) {
    for (request, rule) in hits {
        let cmd = Command::AgentDecide(ainkrad_proto::v2::AgentDecide {
            session: s.id.clone(),
            request: request.clone(),
            approved: true,
            // The runner keeps an approving `reply` as the entry's `note`: the transcript says why.
            reply: Some(format!("Approved by the project's always rule: {rule}.")),
        });
        let proof = app.agents.elevated.lock().unwrap().get(&s.id).copied();
        let done = match ask(app, &s.runner, cmd, app.agents.config.answer, proof).await {
            Ok(ev) => store::apply(&app.pool, &s.id, &ev, &app.clock.now())
                .await
                .map(drop),
            Err(e) => {
                tracing::warn!(
                    session = s.id,
                    why = e.message,
                    "auto-approving a request failed"
                );
                let tool = rule.split(' ').next().unwrap_or_default();
                let payload = json!({"session": s.id, "request": request, "tool": tool});
                let _ = crate::store::agents::raise_request(&app.pool, payload).await;
                continue;
            }
        };
        if let Err(e) = done {
            tracing::warn!(session = s.id, error = %e, "storing an auto-approval failed");
        }
        let details = json!({"request": request, "rule": rule});
        let by = s.created_by.clone();
        let sys = ainkrad_core::audit::AuditActor::System;
        if let Err(e) =
            store::action(&app.pool, s, sys, "agent.approval_auto", None, details, &by).await
        {
            tracing::warn!(session = s.id, error = %e, "auditing an auto-approval failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const DIR: Option<&str> = Some("/w/s");

    fn bash(c: &str) -> Value {
        json!({"command": c})
    }

    #[test]
    fn a_safe_command_makes_a_rule_of_its_first_words() {
        let got = derive("Bash", &bash("cargo test --workspace"), DIR);
        assert_eq!(got, Ok(("Bash".to_owned(), "cargo test".to_owned())));
        let got = derive("Bash", &bash("ls -la src"), DIR);
        assert_eq!(got, Ok(("Bash".to_owned(), "ls -la".to_owned())));
    }

    #[test]
    fn nothing_unsafe_secret_or_networked_makes_a_rule() {
        for c in [
            "rm -rf target",
            "sudo cargo test",
            "curl https://example.com",
            "git push origin main",
            "git fetch",
            "cat .env",
            "cat id_rsa",
            "cargo test && rm x",
            "npm install",
            "docker run x",
            "make",
        ] {
            assert!(derive("Bash", &bash(c), DIR).is_err(), "{c}");
        }
        assert!(derive("WebFetch", &json!({"url": "https://x"}), DIR).is_err());
    }

    #[test]
    fn a_stored_rule_covers_only_what_the_allowlist_still_accepts() {
        assert!(covers(
            "Bash",
            "cargo test",
            "Bash",
            &bash("cargo test -p a"),
            DIR
        ));
        assert!(!covers(
            "Bash",
            "cargo test",
            "Bash",
            &bash("cargo testx"),
            DIR
        ));
        assert!(!covers(
            "Bash",
            "cargo test",
            "Bash",
            &bash("cargo test && rm x"),
            DIR
        ));
        assert!(!covers(
            "Bash",
            "cargo test",
            "Edit",
            &bash("cargo test"),
            DIR
        ));
        // A row stored before a check existed covers nothing.
        assert!(!covers("Bash", "rm", "Bash", &bash("rm x"), DIR));
        assert!(!covers("Bash", "git push", "Bash", &bash("git push"), DIR));
        assert!(!covers("Bash", "cat", "Bash", &bash("cat .env"), DIR));
    }

    #[test]
    fn an_edit_rule_is_a_path_prefix_of_plain_names_inside_the_folder() {
        let edit = |p: &str| json!({"file_path": p});
        let got = derive("Edit", &edit("/w/s/src/api/mod.rs"), DIR);
        assert_eq!(got, Ok(("Edit".to_owned(), "src/api/".to_owned())));
        let top = derive("Write", &edit("README.md"), DIR);
        assert_eq!(top, Ok(("Write".to_owned(), "README.md".to_owned())));
        for bad in [
            "/w/other/a.rs",
            "../a.rs",
            ".env",
            "src/.git/config",
            ".github/ci.yml",
            "src/secrets.json",
        ] {
            assert!(derive("Edit", &edit(bad), DIR).is_err(), "{bad}");
        }
        assert!(covers(
            "Edit",
            "src/api/",
            "Edit",
            &edit("/w/s/src/api/x.rs"),
            DIR
        ));
        assert!(!covers(
            "Edit",
            "src/api/",
            "Edit",
            &edit("/w/s/src/apix/x.rs"),
            DIR
        ));
        assert!(!covers(
            "Edit",
            "src/api/",
            "Edit",
            &edit("/w/s/src/api/.env"),
            DIR
        ));
        assert!(covers(
            "Write",
            "README.md",
            "Write",
            &edit("README.md"),
            DIR
        ));
        assert!(!covers(
            "Write",
            "README.md",
            "Write",
            &edit("README.md.bak"),
            DIR
        ));
    }
}
