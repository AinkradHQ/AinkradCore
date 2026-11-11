//! Grouping items into proposed rooms (plan §2 B1, E2-2): by the strongest signal, then the
//! employer guard (two employers never share a proposal), then Unsorted for what no signal
//! places. ponytail: signals only, no similarity pass (plan B3, the safe fallback); a local
//! word-statistics pass is the upgrade if Unsorted turns out large.

use std::collections::BTreeMap;

use crate::item::Item;
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
    name: String,
    items: Vec<usize>,
}

fn group_key(s: &Signals) -> Option<(String, String)> {
    if let Some(p) = &s.project {
        return Some((p.to_lowercase(), p.clone()));
    }
    if let Some((name, _)) = s.company {
        return Some((name.to_lowercase(), name.to_owned()));
    }
    if let Some(o) = &s.org {
        return Some((o.to_lowercase(), o.clone()));
    }
    s.trackers
        .first()
        .map(|t| (format!("tracker-{}", t.to_lowercase()), t.clone()))
}

pub fn group(items: &[Item]) -> Vec<Proposal> {
    let sigs: Vec<Signals> = items.iter().map(extract).collect();
    let mut groups: BTreeMap<String, Acc> = BTreeMap::new();
    let mut unsorted: Vec<usize> = Vec::new();
    for (i, s) in sigs.iter().enumerate() {
        match group_key(s) {
            Some((k, name)) => groups
                .entry(k)
                .or_insert(Acc {
                    name,
                    items: vec![],
                })
                .items
                .push(i),
            None => unsorted.push(i),
        }
    }
    let mut out = Vec::new();
    let mut mixed_warning: Vec<String> = Vec::new();
    for (key, acc) in groups {
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
            out.push(build(&key, &acc.name, &acc.items, items, &sigs, vec![]));
            continue;
        }
        // The employer guard: one proposal per employer, the rest to Unsorted.
        mixed_warning.push(format!(
            "'{}' mixed {} employers and was split",
            acc.name,
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
                &format!("{} ({e})", acc.name),
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
}
