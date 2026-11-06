//! What `agent show` says of the scheduler's fields on a session, after the one-line row:
//! the agent, the chain and where the run sits on it, the account, why it waits, how many picks
//! a launch refused, and the gateway's last status class. A field the Core did not send (a
//! plain session has none of them) prints no line.

use serde_json::Value;

use crate::chains::entry_lines;
use crate::devices::s;

/// The lines for `v` (an `AgentSession`), none when it carries no scheduler field.
pub fn detail(v: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    let present = |k: &str| !v[k].is_null();
    if present("agent") {
        lines.push(format!("agent {}", s(&v["agent"])));
    }
    if present("chain_id") {
        let pos = v["chain_pos"]
            .as_i64()
            .map_or_else(|| "position -".to_owned(), |p| format!("position {p}"));
        lines.push(format!("chain {} {pos}", v["chain_id"]));
        // The snapshot the run walks, in fallback order; an edit to the chain never shows here.
        let at = v["chain_pos"].as_u64().map(|p| p as usize);
        for (i, l) in entry_lines(&v["chain"]).into_iter().enumerate() {
            lines.push(format!("{}{l}", if Some(i) == at { ">" } else { " " }));
        }
    }
    if present("account") {
        lines.push(format!("account {}", v["account"]));
    }
    let w = &v["waiting"];
    if w.is_object() {
        let since = w["since"]
            .as_str()
            .map(|t| format!(" since {t}"))
            .unwrap_or_default();
        lines.push(format!(
            "waiting until {}{since}: {}",
            s(&w["until"]),
            s(&w["why"])
        ));
    }
    if present("repicked") {
        lines.push(format!("repicked {}", v["repicked"]));
    }
    if present("upstream_class") {
        lines.push(format!("upstream_class {}", s(&v["upstream_class"])));
    }
    // S6 (#144, failover) adds its own lines here: run, attempt, failover_of, failed_over_to.
    // They do not exist in the contract yet; nothing is read for them.
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_plain_session_prints_nothing_extra() {
        let v = json!({"id": "as_x", "agent": null, "chain_id": null, "account": null,
            "waiting": null, "repicked": null, "upstream_class": null});
        assert!(detail(&v).is_empty());
        assert!(detail(&json!({"id": "as_x"})).is_empty());
    }

    #[test]
    fn a_chain_session_prints_every_scheduler_field() {
        let v = json!({"agent": "bot", "chain_id": 3, "chain_pos": 1, "account": 9,
            "chain": [
              {"pool": 2, "provider": "anthropic", "harness": "claude", "model": null},
              {"pool": 5, "provider": "openai", "harness": "codex", "model": "m"}],
            "waiting": {"until": "U", "since": "S", "why": "every account is cooling"},
            "repicked": 1, "upstream_class": "rate_limited"});
        assert_eq!(
            detail(&v),
            [
                "agent bot",
                "chain 3 position 1",
                "   [0]\tpool 2\tanthropic\tclaude\tdefault",
                ">  [1]\tpool 5\topenai\tcodex\tm",
                "account 9",
                "waiting until U since S: every account is cooling",
                "repicked 1",
                "upstream_class rate_limited",
            ]
        );
    }
}
