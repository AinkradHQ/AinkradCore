//! The deterministic signals of an item (plan §2 B1, E2-1): the project folder of the session's
//! working directory, the repo's GitHub org, tracker keys and a known company. No model, no
//! statistics: a signal is a string found in text the collector sent.

use serde::{Deserialize, Serialize};

use crate::item::{Item, SourceKind};

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
    /// The project came from a `Projects/<P>` folder (a stronger spelling than a bare folder).
    pub under_projects: bool,
    /// The repo folder under `Projects/<P>/Repositories/<R>`.
    pub repo: Option<String>,
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

/// Names that are never a project: generic folders, hidden folders, temp dirs, ids and hashes.
const GENERIC: &[&str] = &[
    "src",
    "app",
    "lib",
    "test",
    "tests",
    "desktop",
    "downloads",
    "documents",
    "developer",
    "code",
    "work",
    "repos",
    "projects",
    "git",
    "home",
    "users",
    "repositories",
    "worktrees",
];
const TEMP: &[&str] = &["tmp", "temp", "scratchpad"];

/// A UUID, a truncated UUID or a hex hash: 8+ hex digits (dashes ignored) with at least one digit.
fn id_like(name: &str) -> bool {
    let h: String = name.chars().filter(|c| *c != '-').collect();
    h.len() >= 8
        && h.chars().all(|c| c.is_ascii_hexdigit())
        && h.chars().any(|c| c.is_ascii_digit())
}

pub fn is_junk(name: &str) -> bool {
    let l = name.to_lowercase();
    name.trim().is_empty()
        || name.starts_with('.')
        || name == "~"
        || GENERIC.contains(&l.as_str())
        || TEMP.contains(&l.as_str())
        || id_like(name)
}

/// `AinkradCore-wt` is the worktree folder of `AinkradCore`.
pub fn strip_wt(name: &str) -> &str {
    match name.strip_suffix("-wt") {
        Some(b) if !b.is_empty() => b,
        _ => name,
    }
}

/// Where a path points: the project, whether it came from a `Projects/<P>` folder and the repo
/// under `Projects/<P>/Repositories/<R>`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PathInfo {
    pub project: Option<String>,
    pub under_projects: bool,
    pub repo: Option<String>,
}

pub fn path_info(path: &str) -> PathInfo {
    let mut parts: Vec<&str> = path.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    let lower: Vec<String> = parts.iter().map(|p| p.to_lowercase()).collect();
    // Temp dirs: no project at all.
    let first = |i: usize| lower.get(i).map(String::as_str);
    if lower.iter().any(|p| TEMP.contains(&p.as_str()))
        || (first(0) == Some("var") && first(1) == Some("folders"))
        || (first(0) == Some("private") && matches!(first(1), Some("tmp" | "var")))
    {
        return PathInfo::default();
    }
    // `.claude/worktrees/<x>`: the repo is above.
    if let Some(i) =
        (1..parts.len()).find(|&i| parts[i - 1] == ".claude" && lower[i] == "worktrees")
    {
        parts.truncate(i - 1);
    }
    // `~/Home/Projects/<Project>/...` is the layout the rooms follow: the folder after `Projects`.
    if let Some(i) = parts
        .iter()
        .position(|p| p.eq_ignore_ascii_case("projects"))
        && let Some(p) = parts.get(i + 1)
        && !is_junk(p)
    {
        let repo = (parts
            .get(i + 2)
            .is_some_and(|r| r.eq_ignore_ascii_case("repositories")))
        .then(|| parts.get(i + 3))
        .flatten()
        .map(|r| strip_wt(r))
        .filter(|r| !is_junk(r))
        .map(str::to_owned);
        return PathInfo {
            project: Some(strip_wt(p).to_owned()),
            under_projects: true,
            repo,
        };
    }
    // The home folder and everything above it never name a project.
    let start = if parts.first() == Some(&"~") {
        1
    } else if matches!(first(0), Some("users" | "home")) {
        2
    } else {
        0
    };
    // A worktree folder (`X-wt/branch`) maps to `X`.
    if let Some(w) = parts
        .iter()
        .skip(start)
        .find(|p| p.len() > 3 && p.ends_with("-wt"))
    {
        let b = strip_wt(w);
        return PathInfo {
            project: (!is_junk(b)).then(|| b.to_owned()),
            ..PathInfo::default()
        };
    }
    PathInfo {
        project: parts
            .iter()
            .skip(start)
            .rev()
            .find(|p| !is_junk(p))
            .map(|p| (*p).to_owned()),
        ..PathInfo::default()
    }
}

/// Folders whose children are projects: `~/Home/Projects/<P>`, a vault's `WorkShop/<P>`.
const CONTAINERS: &[&str] = &["projects", "workshop"];

/// The project of a collected file, from its own path: the DEEPEST folder right under a container
/// folder (`~/Vault/WorkShop/Optimus/plan.md` is `Optimus`, never `Vault`), and the path from that
/// folder down (the only part a company may be read from). The file name itself is never one.
pub fn file_project(path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    let dirs = parts.len().saturating_sub(1);
    (1..dirs)
        .rev()
        .find(|&i| CONTAINERS.contains(&parts[i - 1].to_lowercase().as_str()) && !is_junk(parts[i]))
        .map(|i| (strip_wt(parts[i]).to_owned(), parts[i..].join("/")))
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
    } else if hint.contains(['/', '\\']) || hint.trim() == "~" {
        let p = path_info(hint);
        (s.project, s.under_projects, s.repo) = (p.project, p.under_projects, p.repo);
    } else if !hint.trim().is_empty() && !is_junk(hint.trim()) {
        s.project = Some(hint.trim().to_owned());
    }
    // A note in a big tree (a vault holding every project) belongs to its own project folder, and
    // the tree's top folder name says nothing about it.
    let mut path = item.origin.path.clone();
    if s.project.is_none()
        && matches!(
            item.source_kind,
            SourceKind::Doc | SourceKind::Vault | SourceKind::AgentsMd
        )
        && let Some((p, below)) = file_project(&item.origin.path)
    {
        (s.project, s.under_projects, path) = (Some(p), true, below);
    }
    let head: String = item.text.chars().take(2000).collect();
    for t in [hint, &item.title, &head] {
        tracker_prefixes(t, &mut s.trackers);
    }
    s.trackers.sort();
    s.trackers.dedup();
    let hay = format!(
        "{hint} {} {} {}",
        path,
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

    #[test]
    fn a_vault_note_belongs_to_its_deepest_project_folder() {
        let note = |path: &str| {
            let mut i = fixture("x");
            i.project_hint = None;
            i.source_kind = SourceKind::Vault;
            i.origin.path = path.to_owned();
            extract(&i)
        };
        let s = note("/Users/x/Ainkrad/WorkShop/Optimus/Plans/q3.md");
        assert_eq!(s.project.as_deref(), Some("Optimus"));
        assert_eq!(s.company, Some(("Optimus", RoomKind::Employer)));
        let s = note("/Users/x/Ainkrad/WorkShop/Workan.Space/notes.md");
        assert_eq!(s.project.as_deref(), Some("Workan.Space"));
        assert_eq!(
            s.company,
            Some(("Workan.Space", RoomKind::Product)),
            "not the vault's own name"
        );
        let s = note("/Users/x/Ainkrad/WorkShop/Bramble/notes.md");
        assert_eq!((s.project.as_deref(), s.company), (Some("Bramble"), None));
        assert_eq!(
            note("/Users/x/Home/Projects/Bramble/Docs/Projects/Kestrel/a.md")
                .project
                .as_deref(),
            Some("Kestrel"),
            "the deepest"
        );
        // Outside any project folder: as before (the tree's name may still be a company).
        let s = note("/Users/x/Ainkrad/Daily/2026-11-01.md");
        assert_eq!(s.project, None);
        assert_eq!(s.company, Some(("Ainkrad", RoomKind::Product)));
        assert_eq!(
            note("/Users/x/Ainkrad/WorkShop/readme.md").project,
            None,
            "a file is no folder"
        );
    }

    #[test]
    fn junk_and_worktree_paths() {
        let p = |h: &str| path_info(h).project;
        assert_eq!(p("/tmp/x/A0"), None);
        assert_eq!(p("/Users/someone"), None);
        assert_eq!(
            p("/Users/someone/5e26cc85-cb1d-4f00-9a00-000000000000"),
            None
        );
        assert_eq!(
            p("/Users/someone/Dev/Alpha-wt/foo").as_deref(),
            Some("Alpha")
        );
        assert_eq!(
            p("/Users/someone/Dev/Alpha/.claude/worktrees/x").as_deref(),
            Some("Alpha")
        );
        let i = path_info("/Users/someone/Home/Projects/Alpha/Repositories/Core-wt/x");
        assert_eq!(
            (i.project.as_deref(), i.repo.as_deref()),
            (Some("Alpha"), Some("Core"))
        );
    }
}
