//! Operations settings (parity API B2): chain presets, roles and notification preferences.
//! Plain values and their validation; the store keeps them, the API shows them.

use crate::domain::org::Harness;

/// One entry of a chain: a harness and model, optionally pinned to an account of the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEntry {
    pub harness: Harness,
    pub model: String,
    pub account_id: Option<i64>,
}

/// The most entries a chain has.
pub const MAX_CHAIN: usize = 20;

/// Why `entries` is not a chain: too long, or an empty or over-long model.
pub fn invalid_chain(entries: &[ChainEntry]) -> Option<String> {
    if entries.len() > MAX_CHAIN {
        return Some(format!("a chain has at most {MAX_CHAIN} entries"));
    }
    let bad = |e: &&ChainEntry| e.model.trim().is_empty() || e.model.len() > 200;
    entries
        .iter()
        .find(bad)
        .map(|_| "a chain entry needs a model of 1-200 characters".to_owned())
}

/// A named, coloured chain a company's agents can share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPreset {
    pub id: i64,
    pub company_id: i64,
    pub name: String,
    /// `#rrggbb`.
    pub color: Option<String>,
    pub description: String,
    /// The chain agents with no chain of their own use.
    pub is_default: bool,
    pub entries: Vec<ChainEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewChainPreset {
    pub name: String,
    pub color: Option<String>,
    pub description: String,
    pub is_default: bool,
    pub entries: Vec<ChainEntry>,
}

/// Whether `c` is `#rrggbb`.
pub fn is_color(c: &str) -> bool {
    c.len() == 7 && c.starts_with('#') && c[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

impl NewChainPreset {
    /// Why it is refused, if it is.
    pub fn invalid(&self) -> Option<String> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            return Some("a preset needs a name of 1-100 characters".to_owned());
        }
        if self.color.as_deref().is_some_and(|c| !is_color(c)) {
            return Some("a colour is #rrggbb".to_owned());
        }
        if self.description.chars().count() > 2000 {
            return Some("a description is at most 2000 characters".to_owned());
        }
        invalid_chain(&self.entries)
    }
}

/// A job a company hires for, with the defaults a new agent of that role starts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: i64,
    pub company_id: i64,
    pub name: String,
    pub purpose: String,
    pub icon: String,
    pub harness: Option<Harness>,
    pub model: Option<String>,
    pub budget_tokens: Option<i64>,
    /// Skill names.
    pub skills: Vec<String>,
    pub instructions: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRole {
    pub name: String,
    pub purpose: String,
    pub icon: String,
    pub harness: Option<Harness>,
    pub model: Option<String>,
    pub budget_tokens: Option<i64>,
    pub skills: Vec<String>,
    pub instructions: String,
}

impl NewRole {
    /// Why it is refused, if it is.
    pub fn invalid(&self) -> Option<String> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            return Some("a role needs a name of 1-100 characters".to_owned());
        }
        if self.purpose.chars().count() > 500 || self.icon.chars().count() > 40 {
            return Some("a purpose is at most 500 characters and an icon 40".to_owned());
        }
        if self
            .model
            .as_deref()
            .is_some_and(|m| m.trim().is_empty() || m.len() > 200)
        {
            return Some("a model is 1-200 characters".to_owned());
        }
        if self.budget_tokens.is_some_and(|b| b < 0) {
            return Some("a budget is 0 or more tokens".to_owned());
        }
        if self.skills.len() > 50 || self.skills.iter().any(|s| s.trim().is_empty()) {
            return Some("a role has at most 50 skills, each named".to_owned());
        }
        if self.instructions.chars().count() > 20_000 {
            return Some("instructions are at most 20000 characters".to_owned());
        }
        None
    }
}

/// What a notification can be about.
pub const NOTIFY_EVENTS: [&str; 8] = [
    "approval_waiting",
    "run_waiting_permission",
    "agent_question",
    "issue_stuck",
    "budget_warning",
    "account_limit",
    "run_finished",
    "requirement_done",
];

/// Where a notification can go.
pub const NOTIFY_CHANNELS: [&str; 3] = ["push", "signal", "email"];

/// Whether `event` goes to `channel` before anyone chooses: pushes for what needs a human.
pub fn notify_default(event: &str, channel: &str) -> bool {
    channel == "push" && !matches!(event, "run_finished" | "requirement_done")
}

/// What still gets through quiet hours.
pub const BREAKTHROUGHS: [&str; 2] = ["stalled", "nothing"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_and_roles_are_validated() {
        let entry = ChainEntry {
            harness: Harness::Claude,
            model: "opus".to_owned(),
            account_id: None,
        };
        let preset = NewChainPreset {
            name: "Fast".to_owned(),
            color: Some("#3b82f6".to_owned()),
            description: String::new(),
            is_default: false,
            entries: vec![entry.clone()],
        };
        assert_eq!(preset.invalid(), None);
        let bad = |f: fn(&mut NewChainPreset)| {
            let mut p = preset.clone();
            f(&mut p);
            p.invalid().is_some()
        };
        assert!(bad(|p| p.name = " ".to_owned()));
        assert!(bad(|p| p.color = Some("blue".to_owned())));
        assert!(bad(|p| p.entries[0].model = " ".to_owned()));
        assert!(bad(
            |p| p.entries = vec![p.entries[0].clone(); MAX_CHAIN + 1]
        ));
        let role = NewRole {
            name: "QA".to_owned(),
            purpose: String::new(),
            icon: "check".to_owned(),
            harness: None,
            model: None,
            budget_tokens: Some(0),
            skills: vec![],
            instructions: String::new(),
        };
        assert_eq!(role.invalid(), None);
        let negative = NewRole {
            budget_tokens: Some(-1),
            ..role
        };
        assert!(negative.invalid().is_some());
        assert!(notify_default("approval_waiting", "push"));
        assert!(!notify_default("run_finished", "push"));
        assert!(!notify_default("approval_waiting", "email"));
    }
}
