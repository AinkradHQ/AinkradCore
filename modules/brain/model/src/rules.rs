//! Refusal and routing rules (plan §4.2, E1-4), matched against an item and its signals.

use crate::item::Item;
use crate::signals::Signals;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Project,
    Path,
    Org,
    Tracker,
    Source,
    ItemHash,
}

impl RuleKind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "project" => Self::Project,
            "path" => Self::Path,
            "org" => Self::Org,
            "tracker" => Self::Tracker,
            "source" => Self::Source,
            "item_hash" => Self::ItemHash,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: i64,
    pub kind: RuleKind,
    pub pattern: String,
    pub enabled: bool,
}

/// Case-insensitive match of a path component, so `GitScope` hits `/a/GitScope/b` but not
/// `/a/GitScopeX/b`.
fn has_component(path: &str, name: &str) -> bool {
    path.split(['/', '\\'])
        .any(|c| c.eq_ignore_ascii_case(name))
}

pub fn matches(rule: &Rule, item: &Item, s: &Signals) -> bool {
    if !rule.enabled {
        return false;
    }
    let p = rule.pattern.as_str();
    let hint = item.project_hint.as_deref().unwrap_or("");
    match rule.kind {
        RuleKind::Project => {
            s.project
                .as_deref()
                .is_some_and(|x| x.eq_ignore_ascii_case(p))
                || has_component(hint, p)
                || has_component(&item.origin.path, p)
        }
        RuleKind::Path => {
            let p = p.to_lowercase();
            item.origin.path.to_lowercase().contains(&p) || hint.to_lowercase().contains(&p)
        }
        RuleKind::Org => s.org.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(p)),
        RuleKind::Tracker => s.trackers.iter().any(|t| t.eq_ignore_ascii_case(p)),
        RuleKind::Source => item.source_kind.as_str() == p,
        RuleKind::ItemHash => item.content_hash == p,
    }
}

/// The first enabled rule that refuses `item`, if any.
pub fn first_match<'a>(rules: &'a [Rule], item: &Item, s: &Signals) -> Option<&'a Rule> {
    rules.iter().find(|r| matches(r, item, s))
}

/// Files whose content is never read or kept (Q-18): keys, certificates, `.env`, key stores,
/// contract folders. Collectors check this before opening a file; the Core checks it again and
/// keeps a pointer instead of text.
pub fn restricted_path(path: &str) -> bool {
    const EXT: &[&str] = &[
        "pem", "p8", "p12", "pfx", "key", "crt", "cer", "jks", "keystore", "kdbx", "ppk",
    ];
    const NAMES: &[&str] = &[
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        ".npmrc",
        ".netrc",
        "credentials",
    ];
    const DIRS: &[&str] = &["contracts", "contract", "agreements", "nda"];
    let lower = path.to_lowercase();
    let parts: Vec<&str> = lower.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    let Some(file) = parts.last() else {
        return false;
    };
    file == &".env"
        || file.starts_with(".env.")
        || NAMES.contains(file)
        || file.rsplit_once('.').is_some_and(|(_, e)| EXT.contains(&e))
        || parts[..parts.len() - 1].iter().any(|d| DIRS.contains(d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::fixture;
    use crate::signals::extract;

    fn rule(kind: RuleKind, pattern: &str) -> Rule {
        Rule {
            id: 1,
            kind,
            pattern: pattern.to_owned(),
            enabled: true,
        }
    }

    #[test]
    fn deprecated_project_matches_by_component_not_substring() {
        let mut i = fixture("x");
        i.project_hint = Some("/Users/x/Home/Projects/GitScope/Repos/app".into());
        let r = rule(RuleKind::Project, "GitScope");
        assert!(matches(&r, &i, &extract(&i)));
        i.project_hint = Some("/Users/x/Home/Projects/GitScopeX/app".into());
        i.origin.path = "/p/other/s.jsonl".into();
        assert!(!matches(&r, &i, &extract(&i)));
    }

    #[test]
    fn restricted_paths() {
        for p in [
            "/a/.env",
            "/a/.env.local",
            "/a/server.pem",
            "/a/AuthKey.p8",
            "/h/.ssh/id_rsa",
            "/w/Contracts/x.md",
            "/a/store.keystore",
        ] {
            assert!(restricted_path(p), "{p}");
        }
        for p in [
            "/a/env.md",
            "/a/README.md",
            "/a/keys.md",
            "/a/envelope.txt",
            "/a/monkey.rs",
        ] {
            assert!(!restricted_path(p), "{p}");
        }
    }

    #[test]
    fn disabled_rule_never_matches() {
        let i = fixture("x");
        let mut r = rule(RuleKind::Source, "claude_code");
        assert!(matches(&r, &i, &extract(&i)));
        r.enabled = false;
        assert!(!matches(&r, &i, &extract(&i)));
    }
}
