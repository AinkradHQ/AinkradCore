//! One place per product, without the local model: rooms whose names share a product stem
//! (`Optimus` / `OptimusBackend`, `tree` / `tree-app` / `tree-cp` / `tree-mob`, `WorkanSpace` /
//! `FE-Workan.space`) are one product's repos. Pure: names in, merges out.

use super::plan::{REPO_PREFIXES, REPO_WORDS};

/// Words a product's domain adds to its name (`Workan.space`).
const DOMAIN_WORDS: &[&str] = &["space", "io", "com", "net", "org", "dev"];

/// The words of a name: split at separators and at case steps (`LeaderSMS-Hotspot` is
/// `leader sms hotspot`), lowercased.
fn words(name: &str) -> Vec<String> {
    let mut out = vec![];
    for part in name.split(|c: char| !c.is_alphanumeric()) {
        let cs: Vec<char> = part.chars().collect();
        let mut w = String::new();
        for (i, &c) in cs.iter().enumerate() {
            let step = i > 0
                && c.is_uppercase()
                && (cs[i - 1].is_lowercase()
                    || cs[i - 1].is_ascii_digit()
                    || (cs[i - 1].is_uppercase()
                        && cs.get(i + 1).is_some_and(|n| n.is_lowercase())));
            if step && !w.is_empty() {
                out.push(std::mem::take(&mut w));
            }
            w.extend(c.to_lowercase());
        }
        if !w.is_empty() {
            out.push(w);
        }
    }
    out
}

/// A name's product stem: its words with a leading repo prefix (`FE-`, `BE-`) and trailing repo or
/// domain words (`-app`, `Backend`, `-cp`, `.space`) dropped, at least one word kept, joined.
/// `None` for a stem under three letters: too short to name a product.
pub(crate) fn stem(name: &str) -> Option<String> {
    let mut w = words(name);
    while w.len() > 1 && REPO_PREFIXES.contains(&w[0].as_str()) {
        w.remove(0);
    }
    while w.len() > 1 {
        let last = w[w.len() - 1].as_str();
        if REPO_WORDS.contains(&last) || DOMAIN_WORDS.contains(&last) {
            w.pop();
        } else {
            break;
        }
    }
    let s = w.concat();
    (s.chars().count() >= 3).then_some(s)
}

/// For `(id, name, items)` rooms: every `(from, into)` merge that makes one room per stem. The room
/// kept is the one named just the stem (`Optimus`, `tree`), else the one with the most items (ties:
/// the lower id). Whether two employers forbid a merge is the caller's check.
pub(crate) fn stem_merges(rooms: &[(String, String, usize)]) -> Vec<(String, String)> {
    let mut by: std::collections::BTreeMap<String, Vec<&(String, String, usize)>> =
        Default::default();
    for r in rooms {
        if let Some(s) = stem(&r.1) {
            by.entry(s).or_default().push(r);
        }
    }
    let mut out = vec![];
    for (s, group) in by.into_iter().filter(|(_, g)| g.len() > 1) {
        let keep = group
            .iter()
            .max_by_key(|r| {
                (
                    brain_model::group::norm(&r.1) == s,
                    r.2,
                    std::cmp::Reverse(r.0.clone()),
                )
            })
            .expect("a group");
        out.extend(
            group
                .iter()
                .filter(|r| r.0 != keep.0)
                .map(|r| (r.0.clone(), keep.0.clone())),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stems_of_a_real_import() {
        let s = |n: &str| stem(n).unwrap();
        assert_eq!(s("Optimus"), "optimus");
        assert_eq!(s("OptimusBackend"), "optimus");
        assert_eq!(s("tree"), "tree");
        assert_eq!(s("tree-app"), "tree");
        assert_eq!(s("tree-cp"), "tree");
        assert_eq!(s("tree-mob"), "tree");
        assert_eq!(s("WorkanSpace"), "workan");
        assert_eq!(s("FE-Workan.space"), "workan");
        assert_eq!(s("Workan.space"), "workan");
        assert_eq!(s("LeaderSMS-Hotspot"), "leadersmshotspot");
        assert_eq!(s("openGym"), "opengym");
        assert_eq!(s("AutomotiveAi"), "automotiveai");
        assert_eq!(s("dvxmotive"), "dvxmotive");
        assert_eq!(s("NAS"), "nas");
        assert_eq!(
            s("treehouse"),
            "treehouse",
            "no word boundary: another name"
        );
        assert_eq!(stem("FE-ab"), None, "under three letters");
    }

    const REAL: [(&str, usize); 20] = [
        ("Ainkrad", 300),
        ("Althaqeel", 200),
        ("Argo", 150),
        ("AutomotiveAi", 1250),
        ("dvxmotive", 120),
        ("FE-Workan.space", 60),
        ("LeaderSMS-Hotspot", 1),
        ("MyCards", 8),
        ("NAS", 4),
        ("openGym", 13),
        ("Optimus", 735),
        ("OptimusBackend", 93),
        ("tree", 22),
        ("tree-app", 11),
        ("tree-cp", 26),
        ("tree-mob", 10),
        ("ULYNK", 400),
        ("Voutra", 90),
        ("WorkanSpace", 679),
        ("Workan.space", 5),
    ];

    #[test]
    fn one_room_per_product_of_a_real_import() {
        let rooms: Vec<(String, String, usize)> = REAL
            .iter()
            .map(|(n, c)| (format!("p-{n}"), (*n).to_owned(), *c))
            .collect();
        let mut got = stem_merges(&rooms);
        got.sort();
        let want: Vec<(String, String)> = [
            ("FE-Workan.space", "WorkanSpace"),
            ("OptimusBackend", "Optimus"),
            ("Workan.space", "WorkanSpace"),
            ("tree-app", "tree"),
            ("tree-cp", "tree"),
            ("tree-mob", "tree"),
        ]
        .iter()
        .map(|(a, b)| (format!("p-{a}"), format!("p-{b}")))
        .collect();
        assert_eq!(
            got, want,
            "the bare name is kept even when a repo is bigger (tree-cp)"
        );
    }

    /// The whole tidy without the local model: one place per product, the tiny ones in Unsorted.
    #[test]
    fn the_tidy_without_a_model_makes_one_place_per_product() {
        use super::super::plan::{Hints, RoomIn, plan};
        use std::collections::HashMap;
        let rooms: Vec<RoomIn> = REAL
            .iter()
            .map(|(n, c)| RoomIn {
                id: format!("p-{n}"),
                name: (*n).to_owned(),
                employer: None,
                items: (0..*c).map(|i| format!("{n}-{i}")).collect(),
            })
            .collect();
        let h = Hints {
            duplicates: &[],
            closest: &[],
        };
        let th = crate::semantic::Thresholds::for_strength(1);
        let ch = plan(rooms, &[], &HashMap::new(), &h, th);
        let gone: std::collections::HashSet<&str> =
            ch.iter().filter_map(|c| c.from.as_deref()).collect();
        let left: Vec<&str> = REAL
            .iter()
            .map(|(n, _)| *n)
            .filter(|n| !gone.contains(format!("p-{n}").as_str()))
            .collect();
        assert_eq!(
            left,
            [
                "Ainkrad",
                "Althaqeel",
                "Argo",
                "AutomotiveAi",
                "dvxmotive",
                "Optimus",
                "tree",
                "ULYNK",
                "Voutra",
                "WorkanSpace"
            ]
        );
        let to_unsorted: Vec<&str> = ch
            .iter()
            .filter(|c| c.to == brain_model::group::UNSORTED)
            .filter_map(|c| c.from_name.as_deref())
            .collect();
        assert_eq!(
            to_unsorted,
            ["LeaderSMS-Hotspot", "NAS", "MyCards", "openGym"]
        );
        assert!(super::super::plan::confident(&ch, 4_700, 20));
    }
}
