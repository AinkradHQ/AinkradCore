//! Grouping items into proposed rooms (plan §2 B1, E2-2): by the strongest signal, then the
//! employer guard (two employers never share a proposal), then Unsorted for what no signal
//! places. ponytail: signals only, no similarity pass (plan B3, the safe fallback); a local
//! word-statistics pass is the upgrade if Unsorted turns out large.

use std::collections::BTreeMap;

use crate::item::{Item, SourceKind};
use crate::signals::{RoomKind, Signals, extract};

pub const UNSORTED: &str = "unsorted";

#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    /// Stable key inside one run: the lowercase group key.
    pub key: String,
    pub name: String,
    pub kind_guess: RoomKind,
    pub signals: Vec<String>,
    pub item_ids: Vec<String>,
    pub first: String,
    pub last: String,
    pub sample_titles: Vec<String>,
    pub warnings: Vec<String>,
}

struct Acc {
    /// Original spellings: (times seen, times under a `Projects/` path).
    names: BTreeMap<String, (usize, usize)>,
    items: Vec<usize>,
}

impl Acc {
    /// The most frequent spelling; a tie goes to the one under a `Projects/` path.
    fn name(&self) -> String {
        self.names
            .iter()
            .max_by_key(|(n, (c, u))| (*c, *u, std::cmp::Reverse((*n).clone())))
            .map(|(n, _)| n.clone())
            .unwrap_or_default()
    }
}

/// Lowercase with every non-alphanumeric removed: `Workan.Space` == `WorkanSpace`.
pub fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn group_key(item: &Item, s: &Signals) -> Option<(String, String)> {
    let by = |n: &str| Some((norm(n), n.to_owned())).filter(|(k, _)| !k.is_empty());
    if let Some(p) = &s.project
        && let Some(k) = by(p)
    {
        return Some(k);
    }
    if let Some((name, _)) = s.company {
        return by(name);
    }
    if let Some(o) = &s.org {
        return by(o);
    }
    // A key in the title or hint (`KAN-9 Fix login`) wins over one only mentioned in the text.
    let named = |t: &str| {
        let k = format!("{t}-");
        item.title.contains(&k) || item.project_hint.as_deref().is_some_and(|h| h.contains(&k))
    };
    s.trackers
        .iter()
        .max_by_key(|t| (named(t), std::cmp::Reverse(*t)))
        .map(|t| (format!("tracker-{}", t.to_lowercase()), t.clone()))
}

/// A signal stronger than a folder name: a company, an org, or the item's own tracker key (a Jira
/// issue). A key only mentioned in a text (`API-2`, `A0-1`, `AI-5`) may be a word, so it is as weak
/// as a folder name: its room needs three items like any other.
fn strong(item: &Item, s: &Signals) -> bool {
    s.company.is_some()
        || s.org.is_some()
        || (item.source_kind == SourceKind::Jira && !s.trackers.is_empty())
}

/// Repo folder -> project, from items under `Projects/<P>/Repositories/<R>`; a repo seen under
/// two projects is ambiguous and left out.
fn repo_index(sigs: &[Signals]) -> BTreeMap<String, Option<String>> {
    let mut idx: BTreeMap<String, Option<String>> = BTreeMap::new();
    for s in sigs {
        if let (Some(r), Some(p), true) = (&s.repo, &s.project, s.under_projects) {
            let e = idx.entry(norm(r)).or_insert_with(|| Some(p.clone()));
            if e.as_deref().is_some_and(|x| norm(x) != norm(p)) {
                *e = None;
            }
        }
    }
    idx
}

pub fn group(items: &[Item]) -> Vec<Proposal> {
    let sigs: Vec<Signals> = items.iter().map(extract).collect();
    let repos = repo_index(&sigs);
    let mut groups: BTreeMap<String, Acc> = BTreeMap::new();
    let mut unsorted: Vec<usize> = Vec::new();
    for (i, s) in sigs.iter().enumerate() {
        let Some((mut k, mut name)) = group_key(&items[i], s) else {
            unsorted.push(i);
            continue;
        };
        let mut under = usize::from(s.under_projects);
        // A repo folder run elsewhere joins its project (`OptimusBackend` -> `Optimus`).
        if s.project.is_some()
            && !s.under_projects
            && let Some(Some(p)) = repos.get(&k)
        {
            (k, name, under) = (norm(p), p.clone(), 1);
        }
        let acc = groups.entry(k).or_insert(Acc {
            names: BTreeMap::new(),
            items: vec![],
        });
        let n = acc.names.entry(name).or_default();
        n.0 += 1;
        n.1 += under;
        acc.items.push(i);
    }
    // Tiny rooms: under 3 items and nothing but a folder name or a mentioned key to go on. A folder
    // under `Projects/` is the user's own layout, so it stays a room even when small.
    groups.retain(|_, acc| {
        let keep = acc.items.len() >= 3
            || acc
                .items
                .iter()
                .any(|&i| strong(&items[i], &sigs[i]) || sigs[i].under_projects);
        if !keep {
            unsorted.extend(&acc.items);
        }
        keep
    });
    let mut out = Vec::new();
    let mut mixed_warning: Vec<String> = Vec::new();
    for (key, acc) in groups {
        let name = acc.name();
        let mut employers: Vec<&str> = acc
            .items
            .iter()
            .filter_map(|&i| {
                sigs[i]
                    .company
                    .filter(|(_, k)| *k == RoomKind::Employer)
                    .map(|(n, _)| n)
            })
            .collect();
        employers.sort();
        employers.dedup();
        if employers.len() <= 1 {
            out.push(build(&key, &name, &acc.items, items, &sigs, vec![]));
            continue;
        }
        // The employer guard: one proposal per employer, the rest to Unsorted.
        mixed_warning.push(format!(
            "'{}' mixed {} employers and was split",
            name,
            employers.len()
        ));
        for e in &employers {
            let part: Vec<usize> = acc
                .items
                .iter()
                .copied()
                .filter(|&i| sigs[i].company.is_some_and(|(n, _)| n == *e))
                .collect();
            let k = format!("{key}-{}", e.to_lowercase());
            out.push(build(
                &k,
                &format!("{name} ({e})"),
                &part,
                items,
                &sigs,
                vec![],
            ));
        }
        unsorted.extend(acc.items.iter().copied().filter(|&i| {
            !sigs[i]
                .company
                .is_some_and(|(_, k)| k == RoomKind::Employer)
        }));
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    if !unsorted.is_empty() {
        unsorted.sort_unstable();
        out.push(build(
            UNSORTED,
            "Unsorted",
            &unsorted,
            items,
            &sigs,
            mixed_warning,
        ));
    }
    out
}

fn build(
    key: &str,
    name: &str,
    idx: &[usize],
    items: &[Item],
    sigs: &[Signals],
    warnings: Vec<String>,
) -> Proposal {
    let kinds: Vec<RoomKind> = idx
        .iter()
        .filter_map(|&i| sigs[i].company.map(|(_, k)| k))
        .collect();
    let kind_guess = if kinds.contains(&RoomKind::Employer) {
        RoomKind::Employer
    } else if kinds.contains(&RoomKind::Product) {
        RoomKind::Product
    } else {
        RoomKind::General
    };
    let mut signals: Vec<String> = Vec::new();
    for &i in idx {
        let s = &sigs[i];
        let mut add = |v: String| {
            if !signals.contains(&v) {
                signals.push(v);
            }
        };
        if let Some(p) = &s.project {
            add(format!("folder:{p}"));
        }
        if let Some(o) = &s.org {
            add(format!("org:{o}"));
        }
        for t in &s.trackers {
            add(format!("tracker:{t}"));
        }
        if let Some((c, _)) = s.company {
            add(format!("company:{c}"));
        }
    }
    signals.truncate(12);
    let mut titles: Vec<String> = Vec::new();
    for &i in idx {
        if titles.len() < 3 && !titles.contains(&items[i].title) {
            titles.push(items[i].title.clone());
        }
    }
    Proposal {
        key: key.to_owned(),
        name: name.to_owned(),
        kind_guess: if key == UNSORTED {
            RoomKind::General
        } else {
            kind_guess
        },
        signals,
        item_ids: idx.iter().map(|&i| items[i].item_id.clone()).collect(),
        first: idx
            .iter()
            .map(|&i| items[i].started_at.as_str())
            .min()
            .unwrap_or("")
            .to_owned(),
        last: idx
            .iter()
            .map(|&i| items[i].started_at.as_str())
            .max()
            .unwrap_or("")
            .to_owned(),
        sample_titles: titles,
        warnings,
    }
}

/// One room that looks like another: `into` is the proposal to merge into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub into: String,
    pub reason: &'static str,
}

fn edit_distance(a: &[char], b: &[char]) -> usize {
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push(
                (prev[j] + usize::from(ca != cb))
                    .min(prev[j + 1] + 1)
                    .min(cur[j] + 1),
            );
        }
        prev = cur;
    }
    prev[b.len()]
}

fn similar(a: &str, b: &str) -> Option<&'static str> {
    let (s, l) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    if s.len() >= 4 && l.starts_with(s) {
        return Some("prefix");
    }
    let (ca, cb): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    (ca.len() >= 6 && cb.len() >= 6 && edit_distance(&ca, &cb) <= 2).then_some("close")
}

/// Merge hints for `(id, name, item count)` rooms: the smaller room points at the larger one it
/// looks like (a name that is a prefix of the other, or within two edits). Never applied here.
pub fn suggest_merges(rooms: &[(String, String, i64)]) -> BTreeMap<String, Suggestion> {
    let keys: Vec<String> = rooms.iter().map(|r| norm(&r.1)).collect();
    let mut out = BTreeMap::new();
    for (i, a) in rooms.iter().enumerate() {
        let best = rooms
            .iter()
            .enumerate()
            .filter(|(j, b)| *j != i && !keys[*j].is_empty() && (b.2, &b.0) > (a.2, &a.0))
            .filter_map(|(j, b)| similar(&keys[i], &keys[j]).map(|r| (b, r)))
            .max_by_key(|(b, _)| (b.2, std::cmp::Reverse(b.1.clone())));
        if let Some((b, reason)) = best {
            out.insert(
                a.0.clone(),
                Suggestion {
                    into: b.0.clone(),
                    reason,
                },
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Item, fixture};

    fn it(n: u32, hint: &str, title: &str) -> Item {
        let mut i = fixture(&format!("body {n}"));
        i.item_id = format!("01JD{n:022}");
        i.project_hint = Some(hint.to_owned());
        i.title = title.to_owned();
        i
    }

    #[test]
    fn three_projects_two_employers_unknown_to_unsorted() {
        let items = vec![
            it(1, "/h/Projects/Alpha/x", "a1"),
            it(2, "/h/Projects/Alpha/y", "a2"),
            it(3, "/h/Projects/Beta/x", "b1"),
            it(4, "/h/Projects/Optimus/api", "o1"),
            it(5, "/h/Projects/Gamma/x", "g1 for AutomotiveAi"),
            it(6, "", "nothing here"),
        ];
        let p = group(&items);
        let names: Vec<&str> = p.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["Alpha", "Beta", "Gamma", "Optimus", "Unsorted"]);
        let kind = |n: &str| p.iter().find(|p| p.name == n).unwrap().kind_guess;
        assert_eq!(kind("Optimus"), RoomKind::Employer);
        assert_eq!(kind("Gamma"), RoomKind::Employer);
        assert_eq!(kind("Alpha"), RoomKind::General);
        assert_eq!(p[0].item_ids.len(), 2);
        assert_eq!(p.last().unwrap().item_ids, vec![items[5].item_id.clone()]);
    }

    #[test]
    fn two_employers_in_one_folder_never_share_a_proposal() {
        let items = vec![
            it(1, "/h/Projects/Shared/a", "work for Optimus"),
            it(2, "/h/Projects/Shared/b", "work for AutomotiveAi"),
            it(3, "/h/Projects/Shared/c", "plain note"),
        ];
        let p = group(&items);
        for pr in &p {
            let employers: Vec<_> = pr
                .item_ids
                .iter()
                .filter_map(|id| items.iter().find(|i| &i.item_id == id))
                .filter_map(|i| extract(i).company)
                .filter(|(_, k)| *k == RoomKind::Employer)
                .map(|(n, _)| n)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            assert!(employers.len() <= 1, "{} mixes {employers:?}", pr.name);
        }
        let un = p.iter().find(|p| p.key == UNSORTED).unwrap();
        assert_eq!(un.item_ids, vec![items[2].item_id.clone()]);
        assert!(!un.warnings.is_empty());
    }

    fn many(hint: &str, from: u32) -> Vec<Item> {
        (from..from + 3)
            .map(|n| it(n, hint, &format!("t{n}")))
            .collect()
    }

    fn names(items: &[Item]) -> Vec<String> {
        group(items).into_iter().map(|p| p.name).collect()
    }

    #[test]
    fn junk_paths_go_to_unsorted() {
        let mut items = vec![];
        for (n, h) in [
            "/Users/someone/3f2b8c1a-9d4e-4b7a-8c11-0e5d6f7a8b9c",
            "/tmp/x/A0",
            "/private/var/folders/ab/T/zz",
            "/Users/someone",
            "/home/someone",
            "~",
            "/Users/someone/.hidden",
            "/Users/someone/Desktop",
        ]
        .iter()
        .enumerate()
        {
            items.extend(many(h, n as u32 * 10));
        }
        assert_eq!(names(&items), vec!["Unsorted"]);
    }

    #[test]
    fn walks_up_past_generic_folders() {
        let items = many("/Users/someone/Herd/Gizmo/src/lib", 0);
        assert_eq!(names(&items), vec!["Gizmo"]);
    }

    #[test]
    fn worktrees_map_to_the_base_repo() {
        let mut items = many("/Users/someone/Dev/Widget-wt/branch-a", 0);
        items.extend(many("/Users/someone/Dev/Widget/.claude/worktrees/x", 10));
        items.extend(many("/Users/someone/Dev/Widget", 20));
        assert_eq!(names(&items), vec!["Widget"]);
    }

    #[test]
    fn spellings_share_a_room_and_the_common_one_names_it() {
        let mut items = many("/u/Dev/Workan.Space", 0);
        items.extend(many("/u/Dev/WorkanSpace", 10));
        items.push(it(30, "/u/Dev/WorkanSpace", "x"));
        items.extend(many("/u/Dev/workan-space", 40));
        let p = group(&items);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "WorkanSpace");
        assert_eq!(p[0].item_ids.len(), 10);
    }

    #[test]
    fn repo_run_elsewhere_joins_its_project() {
        let mut items = many(
            "/Users/someone/Home/Projects/Acme/Repositories/AcmeBackend/src",
            0,
        );
        items.extend(many("/Users/someone/Herd/AcmeBackend", 10));
        let p = group(&items);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "Acme");
        assert_eq!(p[0].item_ids.len(), 6);
    }

    #[test]
    fn tiny_rooms_go_to_unsorted_unless_strong() {
        let mut issue = it(3, "", "KAN-5 thing");
        issue.source_kind = SourceKind::Jira;
        let items = vec![
            it(1, "/u/Dev/Lonely", "a"),
            it(2, "/u/Dev/Lonely", "b"),
            issue,
            it(4, "/u/Dev/Other", "KAN-6 mentioned"),
        ];
        let p = group(&items);
        let n: Vec<_> = p.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(n, vec!["KAN", "Unsorted"]);
        assert_eq!(p[1].item_ids.len(), 3);
    }

    /// The junk rooms of a real import: short uppercase words followed by a dash and a digit in one
    /// transcript each. They never name a room; a key several items mention still does.
    #[test]
    fn short_uppercase_words_never_make_a_room() {
        let junk = ["A0", "A690", "AD", "ADMIN", "AI", "AL", "API"];
        let mut items: Vec<Item> = junk
            .iter()
            .enumerate()
            .map(|(n, w)| {
                let mut i = it(n as u32, "~", "a session");
                i.text = format!("we talked about {w}-1 and more");
                i
            })
            .collect();
        items.extend(many("/u/Home/Projects/Alpha/x", 20));
        // A real short key in three items, one of them also naming a junk word: all three go to it.
        for n in 30..33 {
            let mut i = it(n, "~", &format!("KAN-{n} work"));
            i.text = "see AD-2 too".into();
            items.push(i);
        }
        let p = group(&items);
        let n: Vec<_> = p.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(n, vec!["Alpha", "KAN", "Unsorted"]);
        assert_eq!(p[1].item_ids.len(), 3);
        assert_eq!(p[2].item_ids.len(), junk.len());
    }

    #[test]
    fn suggestions_by_prefix_and_spelling() {
        let r = |id: &str, name: &str, n: i64| (id.to_owned(), name.to_owned(), n);
        let s = suggest_merges(&[
            r("a", "Optimus", 9),
            r("b", "OptimusApi", 2),
            r("c", "Gadgetry", 5),
            r("d", "Gadgetri", 3),
            r("e", "Zed", 4),
            r("f", "Zedd", 1),
        ]);
        assert_eq!(
            s["b"],
            Suggestion {
                into: "a".into(),
                reason: "prefix"
            }
        );
        assert_eq!(
            s["d"],
            Suggestion {
                into: "c".into(),
                reason: "close"
            }
        );
        assert!(!s.contains_key("a") && !s.contains_key("c"));
        assert!(!s.contains_key("f"), "prefix needs 4 characters");
    }
}
