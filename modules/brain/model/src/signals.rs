//! The deterministic signals of an item (plan §2 B1, E2-1): the project folder of the session's
//! working directory, the repo's GitHub org, tracker keys and a known company. No model, no
//! statistics: a signal is a string found in text the collector sent.

use serde::{Deserialize, Serialize};

use crate::item::Item;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RoomKind {
    Personal,
    Product,
    Employer,
    Client,
    General,
    GlobalSafe,
}

impl RoomKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Product => "product",
            Self::Employer => "employer",
            Self::Client => "client",
            Self::General => "general",
            Self::GlobalSafe => "global-safe",
        }
    }
}

/// A company Ahmed's work is known to touch. ponytail: a built-in seed list; a user-editable list
/// (rules of kind `org`) is the upgrade. The kinds are guesses the review screen lets the user fix.
pub const COMPANIES: &[(&str, &str, RoomKind)] = &[
    ("automotiveai", "AutomotiveAi", RoomKind::Employer),
    ("optimus", "Optimus", RoomKind::Employer),
    ("dvxmotive", "dvxmotive", RoomKind::Employer),
    ("ainkrad", "Ainkrad", RoomKind::Product),
    ("workan", "Workan.Space", RoomKind::Product),
    ("voutra", "Voutra", RoomKind::Product),
    ("ulynk", "ULYNK", RoomKind::Product),
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signals {
    /// The project folder name, as written.
    pub project: Option<String>,
    /// The GitHub org of a repo remote named in the hint.
    pub org: Option<String>,
    /// Tracker key prefixes (`KAN` of `KAN-476`), sorted, unique.
    pub trackers: Vec<String>,
    pub company: Option<(&'static str, RoomKind)>,
}

/// Tokens that look like a tracker key and are not one.
const NOT_TRACKERS: &[&str] = &[
    "UTF", "SHA", "ISO", "HTTP", "TLS", "AES", "RFC", "MD", "CVE", "TCP", "UDP", "IPV", "X", "GPT",
];

fn path_project(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    // `~/Home/Projects/<Project>/...` is the layout the rooms follow: the folder after `Projects`.
    if let Some(i) = parts
        .iter()
        .position(|p| p.eq_ignore_ascii_case("projects"))
        && let Some(p) = parts.get(i + 1)
    {
        return Some((*p).to_owned());
    }
    parts.last().map(|p| (*p).to_owned())
}

/// `github.com/<org>/<repo>` or `git@github.com:<org>/<repo>` anywhere in `s`.
fn github(s: &str) -> Option<(String, String)> {
    let at = s.find("github.com")? + "github.com".len();
    let rest = s[at..].trim_start_matches([':', '/']);
    let mut it = rest.split(['/', ' ', '\n']);
    let org = it.next()?;
    let repo = it.next()?.trim_end_matches(".git");
    (!org.is_empty() && !repo.is_empty()).then(|| (org.to_owned(), repo.to_owned()))
}

fn tracker_prefixes(s: &str, out: &mut Vec<String>) {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_uppercase() && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            let mut j = i;
            while j < b.len() && (b[j].is_ascii_uppercase() || b[j].is_ascii_digit()) {
                j += 1;
            }
            let word = &s[i..j];
            if (2..=10).contains(&word.len())
                && j < b.len()
                && b[j] == b'-'
                && b.get(j + 1).is_some_and(u8::is_ascii_digit)
                && !NOT_TRACKERS.contains(&word)
            {
                out.push(word.to_owned());
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
}

pub fn extract(item: &Item) -> Signals {
    let hint = item.project_hint.as_deref().unwrap_or("");
    let mut s = Signals::default();
    if let Some((org, repo)) = github(hint) {
        s.org = Some(org);
        s.project = Some(repo);
    } else if hint.contains(['/', '\\']) {
        s.project = path_project(hint);
    } else if !hint.trim().is_empty() {
        s.project = Some(hint.trim().to_owned());
    }
    let head: String = item.text.chars().take(2000).collect();
    for t in [hint, &item.title, &head] {
        tracker_prefixes(t, &mut s.trackers);
    }
    s.trackers.sort();
    s.trackers.dedup();
    let hay = format!(
        "{hint} {} {} {}",
        item.origin.path,
        s.org.as_deref().unwrap_or(""),
        item.title
    )
    .to_lowercase();
    s.company = COMPANIES
        .iter()
        .find(|(needle, _, _)| hay.contains(needle))
        .map(|(_, name, kind)| (*name, *kind));
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::fixture;

    fn item(hint: &str, title: &str, text: &str) -> Item {
        let mut i = fixture(text);
        i.project_hint = Some(hint.to_owned());
        i.title = title.to_owned();
        i
    }

    #[test]
    fn project_folder_from_the_working_directory() {
        let s = extract(&item(
            "/Users/x/Home/Projects/Alpha/Repositories/Core",
            "t",
            "x",
        ));
        assert_eq!(s.project.as_deref(), Some("Alpha"));
        let s = extract(&item("/work/beta-app", "t", "x"));
        assert_eq!(s.project.as_deref(), Some("beta-app"));
    }

    #[test]
    fn repo_remote_gives_org_and_project() {
        let s = extract(&item("git@github.com:SomeOrg/some-repo.git", "t", "x"));
        assert_eq!(
            (s.org.as_deref(), s.project.as_deref()),
            (Some("SomeOrg"), Some("some-repo"))
        );
    }

    #[test]
    fn tracker_keys_and_false_friends() {
        let s = extract(&item(
            "/w/a",
            "Fix KAN-12",
            "see ABC-7 and UTF-8 and SHA-256, KAN-99",
        ));
        assert_eq!(s.trackers, vec!["ABC", "KAN"]);
    }

    #[test]
    fn known_company() {
        let s = extract(&item("/Users/x/Home/Projects/Optimus/api", "t", "x"));
        assert_eq!(s.company, Some(("Optimus", RoomKind::Employer)));
        assert_eq!(extract(&item("/w/none", "t", "x")).company, None);
    }
}
