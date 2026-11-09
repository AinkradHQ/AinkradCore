//! `account ls | show <id>`: the provider accounts (`/api/v1/accounts`, scope `admin`) with what
//! the scheduler keeps of them: the sessions holding a slot now (`live`, against the cap) and
//! the health counters. Reads only; state, caps and keys stay with the apps.

use std::io::Write;

use serde_json::Value;

use crate::Error;
use crate::client::Client;
use crate::devices::s;

fn print(out: &mut impl Write, text: impl std::fmt::Display) -> Result<(), Error> {
    writeln!(out, "{text}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
}

fn count(v: &Value) -> String {
    v.as_u64().map_or_else(|| "-".to_owned(), |n| n.to_string())
}

/// `id  provider  label  state  live N/cap  fail N auth N`; a cap of 0 is no cap (`-`).
pub fn row(a: &Value) -> String {
    let cap = match a["cap"].as_u64() {
        Some(0) | None => "-".to_owned(),
        Some(n) => n.to_string(),
    };
    format!(
        "{}\t{}\t{}\t{}\tlive {}/{cap}\tfail {} auth {}",
        a["id"],
        s(&a["provider"]),
        s(&a["label"]),
        s(&a["state"]),
        count(&a["live"]),
        count(&a["health"]["fail_streak"]),
        count(&a["health"]["auth_streak"]),
    )
}

/// What `show` adds under the row: why it is not active, and the rest of its health.
pub fn detail(a: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(r) = a["state_reason"].as_str() {
        let until = a["state_until"]
            .as_str()
            .map(|t| format!(" until {t}"))
            .unwrap_or_default();
        lines.push(format!("state_reason {r}{until}"));
    }
    let h = &a["health"];
    if let Some(t) = h["last_success_at"].as_str() {
        lines.push(format!("last_success {t}"));
    }
    if let Some(c) = h["upstream_class"].as_str() {
        lines.push(format!("upstream_class {c}"));
    }
    // A subscription's plan-limit snapshot (S6), as its harness last said it.
    let pl = &h["plan_limit"];
    if pl.is_object() {
        lines.push(format!(
            "plan_limit {} at {}",
            s(&pl["status"]),
            s(&pl["at"])
        ));
        for w in pl["windows"].as_array().into_iter().flatten() {
            let used = w["utilization"]
                .as_f64()
                .map_or_else(|| "-".to_owned(), |u| format!("{:.0}%", u * 100.0));
            let resets = w["resets_at"]
                .as_str()
                .map(|t| format!(" resets {t}"))
                .unwrap_or_default();
            lines.push(format!("  window {} {used}{resets}", s(&w["name"])));
        }
    }
    lines
}

fn aid(id: &str) -> Result<i64, Error> {
    id.parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::Usage(format!("{id:?} is not an account id (a number)")))
}

/// `account …` (`accounts` too).
pub async fn account(
    c: &mut Client,
    words: &[&str],
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["ls" | "list"] => {
            let v: Value = c.get("/api/v1/accounts", "").await?;
            if json {
                return print(out, v);
            }
            v.as_array()
                .into_iter()
                .flatten()
                .try_for_each(|a| print(out, row(a)))
        }
        ["show", id] => {
            let a: Value = c.get(&format!("/api/v1/accounts/{}", aid(id)?), "").await?;
            if json {
                return print(out, a);
            }
            print(out, row(&a))?;
            detail(&a).into_iter().try_for_each(|l| print(out, l))
        }
        _ => Err(Error::Usage("account ls | show <id>".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_row_has_the_live_count_against_the_cap_and_the_streaks() {
        let a = json!({"id": 7, "provider": "anthropic", "label": "work", "state": "active",
            "cap": 3, "live": 2, "health": {"fail_streak": 1, "auth_streak": 0}});
        assert_eq!(
            row(&a),
            "7\tanthropic\twork\tactive\tlive 2/3\tfail 1 auth 0"
        );
        // No cap, and an answer without the scheduler fields (an older Core).
        let b = json!({"id": 8, "provider": "openai", "label": "x", "state": "active", "cap": 0});
        assert_eq!(row(&b), "8\topenai\tx\tactive\tlive -/-\tfail - auth -");
    }

    #[test]
    fn detail_says_why_it_is_cooling() {
        let a = json!({"state_reason": "rate_limited", "state_until": "U",
            "health": {"last_success_at": "L", "upstream_class": "rate_limited",
              "plan_limit": {"status": "allowed_warning", "at": "P", "windows": [
                {"name": "five_hour", "utilization": 0.834, "resets_at": "R"},
                {"name": "seven_day", "utilization": 1.2}]}}});
        assert_eq!(
            detail(&a),
            [
                "state_reason rate_limited until U",
                "last_success L",
                "upstream_class rate_limited",
                "plan_limit allowed_warning at P",
                "  window five_hour 83% resets R",
                "  window seven_day 120%"
            ]
        );
        assert!(detail(&json!({"state": "active"})).is_empty());
    }
}
