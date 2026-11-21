//! The AI tidy's planner: a pure function of the rooms, items, vectors and suggestions.

use std::collections::{BTreeMap, HashMap, HashSet};

use brain_model::group::UNSORTED;
use brain_model::semantic::{RoomVec, closest_room, normalized};

use super::TidyChange;
use crate::semantic::Thresholds;
use crate::suggest::{ClosestHint, DuplicateHint};

/// What the planner needs of one proposal: only `proposed` rooms with at most one employer take part.
pub(crate) struct RoomIn {
    pub id: String,
    pub name: String,
    pub employer: Option<String>,
    /// Item ids not marked refused.
    pub items: Vec<String>,
}

/// The strong suggestions of one semantic step. Merge hints (rooms whose items read alike) are not
/// among them: two named projects are never merged by likeness, only by name or by the person.
pub(crate) struct Hints<'a> {
    pub duplicates: &'a [DuplicateHint],
    pub closest: &'a [ClosestHint],
}

/// Merges the smaller of rooms `a` and `b` into the larger (ties: `a` into `b`; `directed`: always
/// `a` into `b`), unless they are one room already, either is gone or they belong to two employers.
fn merge_rooms(
    live: &mut BTreeMap<String, RoomIn>,
    alias: &mut HashMap<String, String>,
    out: &mut Vec<TidyChange>,
    a: String,
    b: String,
    score: f32,
    directed: bool,
) {
    let (Some(ra), Some(rb)) = (live.get(&a), live.get(&b)) else {
        return;
    };
    if a == b || matches!((&ra.employer, &rb.employer), (Some(x), Some(y)) if x != y) {
        return;
    }
    let (small, big) = if directed || ra.items.len() <= rb.items.len() {
        (a, b)
    } else {
        (b, a)
    };
    let s = live.remove(&small).expect("live");
    let big_r = live.get_mut(&big).expect("live");
    if big_r.employer.is_none() {
        big_r.employer = s.employer.clone();
    }
    big_r.items.extend(s.items.iter().cloned());
    alias.insert(small.clone(), big.clone());
    out.push(TidyChange {
        kind: "merge".into(),
        item_ids: s.items,
        from: Some(small),
        from_name: Some(s.name),
        to_name: Some(big_r.name.clone()),
        to: big,
        score,
        ..Default::default()
    });
}

/// Two spellings of one name: equal once case, spacing and punctuation go (`Workan.Space`,
/// `WorkanSpace`, `Workan Space`) and a plural `s` is dropped. Nothing looser: one name inside another
/// (`AcmeShopApi` / `Acme Shop`) is two projects as often as one, and that is the person's call.
pub(crate) fn same_name(a: &str, b: &str) -> bool {
    let k = |s: &str| {
        let n = brain_model::group::norm(s);
        n.strip_suffix('s').map(str::to_owned).unwrap_or(n)
    };
    let (x, y) = (k(a), k(b));
    !x.is_empty() && x == y
}

/// The first pair of live rooms of one name and no two employers, by id.
fn name_pair(live: &BTreeMap<String, RoomIn>) -> Option<(String, String)> {
    let rooms: Vec<&RoomIn> = live.values().collect();
    for (i, a) in rooms.iter().enumerate() {
        for b in &rooms[i + 1..] {
            let clash = matches!((&a.employer, &b.employer), (Some(x), Some(y)) if x != y);
            if !clash && same_name(&a.name, &b.name) {
                return Some((a.id.clone(), b.id.clone()));
            }
        }
    }
    None
}

/// A room with fewer items, once its product's repos are merged into it, is not a place of its own:
/// its items go to the closest room when that is clear, else to Unsorted.
pub(crate) const MIN_ROOM_ITEMS: usize = 15;
/// Below this many items in the run, small rooms are most of it and stay as they are.
pub(crate) const MIN_RUN_ITEMS: usize = 200;
/// A room this small may be one of a bigger room's repos.
const REPO_MAX: usize = 30;
/// Prefixes a repo name puts before its project's (`FE-Workan.space`).
pub(super) const REPO_PREFIXES: &[&str] = &["fe", "be", "api", "web", "app"];
/// Words a repo name puts after its project's (`OptimusBackend`, `tree-cp`).
pub(super) const REPO_WORDS: &[&str] = &[
    "backend",
    "frontend",
    "api",
    "web",
    "app",
    "mob",
    "mobile",
    "cp",
    "admin",
    "dashboard",
    "server",
    "client",
    "site",
    "fe",
    "be",
    "ios",
    "android",
];

/// The rest of `small` after `big`'s name, normalized, when `small` (a repo prefix like `FE-`
/// dropped) starts with `big`'s name followed by a word boundary (the end, a separator, a
/// lower-to-upper case step) or by a known repo word (`optimusbackend`). `big`'s name is 3+ letters.
fn after_project(small: &str, big: &str) -> Option<String> {
    let mut s = small;
    for p in REPO_PREFIXES {
        if let (Some(head), Some(sep)) = (s.get(..p.len()), s.as_bytes().get(p.len()))
            && head.eq_ignore_ascii_case(p)
            && matches!(sep, b'-' | b'_' | b'.' | b' ')
        {
            s = &s[p.len() + 1..];
            break;
        }
    }
    let want = brain_model::group::norm(big);
    if want.chars().count() < 3 {
        return None;
    }
    let chars: Vec<char> = s.chars().collect();
    let (mut got, mut i) = (String::new(), 0);
    while i < chars.len() && got.len() < want.len() {
        if chars[i].is_alphanumeric() {
            got.extend(chars[i].to_lowercase());
        }
        i += 1;
    }
    if got != want {
        return None;
    }
    let rest = brain_model::group::norm(&chars[i..].iter().collect::<String>());
    let boundary = i == chars.len()
        || !chars[i].is_alphanumeric()
        || (chars[i].is_uppercase() && chars[i - 1].is_lowercase());
    (boundary || REPO_WORDS.contains(&rest.as_str())).then_some(rest)
}

/// The next (repo room, project room) pair: a room of at most `REPO_MAX` items named after a room
/// with at least five times its items, or after any room when the rest is a known repo word
/// (`tree-app` next to `tree`). Never across two employers. Smallest repo first, then the longest
/// project name.
fn repo_pair(live: &BTreeMap<String, RoomIn>) -> Option<(String, String)> {
    let mut best: Option<(usize, String, usize, String)> = None;
    for s in live.values().filter(|r| r.items.len() <= REPO_MAX) {
        for b in live.values().filter(|b| b.id != s.id) {
            let Some(rest) = after_project(&s.name, &b.name) else {
                continue;
            };
            let clash = matches!((&s.employer, &b.employer), (Some(x), Some(y)) if x != y);
            let big = b.items.len() >= 5 * s.items.len().max(1);
            if clash || !(big || REPO_WORDS.contains(&rest.as_str())) {
                continue;
            }
            let key = (
                s.items.len(),
                s.id.clone(),
                usize::MAX - b.name.len(),
                b.id.clone(),
            );
            if best.as_ref().is_none_or(|x| key < *x) {
                best = Some(key);
            }
        }
    }
    best.map(|(_, s, _, b)| (s, b))
}

/// A name with no word of three letters or more (`AI-5`, `A0`, `x`): not a topic.
fn junk_name(name: &str) -> bool {
    brain_model::semantic::tokens(name).is_empty()
}

fn mean(ids: &[String], vecs: &HashMap<String, Vec<f32>>) -> Option<Vec<f32>> {
    let mut sum: Option<Vec<f32>> = None;
    for v in ids.iter().filter_map(|i| vecs.get(i)) {
        let s = sum.get_or_insert_with(|| vec![0.0; v.len()]);
        s.iter_mut().zip(v).for_each(|(a, b)| *a += b);
    }
    sum.map(normalized)
}

/// The tidy, as a pure function of the rooms, the Unsorted items, the vectors (unit, by item id)
/// and the suggestions: (a) near-copies merged into the newest, (b) rooms that are one name merged
/// smaller into larger, (c) junk-named rooms folded into the closest room or Unsorted, (d) Unsorted
/// items moved to the room they clearly belong in. Rooms merge by name only (one name, one product
/// stem, a repo of a project), never because their items read alike.
pub(crate) fn plan(
    rooms: Vec<RoomIn>,
    unsorted: &[String],
    vecs: &HashMap<String, Vec<f32>>,
    h: &Hints,
    th: Thresholds,
) -> Vec<TidyChange> {
    let mut out: Vec<TidyChange> = vec![];
    let mut live: BTreeMap<String, RoomIn> = rooms.into_iter().map(|r| (r.id.clone(), r)).collect();
    let mut loose: Vec<String> = unsorted.to_vec();
    // Where a merged or folded room went: a later hint naming it lands in its new room.
    let mut alias: HashMap<String, String> = HashMap::new();
    let resolve = |alias: &HashMap<String, String>, mut id: String| {
        while let Some(n) = alias.get(&id) {
            id = n.clone();
        }
        id
    };
    let name_of = |live: &BTreeMap<String, RoomIn>, id: &str| live.get(id).map(|r| r.name.clone());

    // (a) Near-copies: keep the newest, the others are merged into it.
    let known: HashSet<&String> = live.values().flat_map(|r| &r.items).chain(&loose).collect();
    let mut refused: HashSet<String> = HashSet::new();
    for d in h.duplicates.iter().filter(|d| d.score >= th.dup) {
        if !known.contains(&d.keep) || refused.contains(&d.keep) {
            continue;
        }
        let gone: Vec<String> = d
            .item_ids
            .iter()
            .filter(|i| **i != d.keep && known.contains(i) && !refused.contains(*i))
            .cloned()
            .collect();
        if gone.is_empty() {
            continue;
        }
        refused.extend(gone.iter().cloned());
        out.push(TidyChange {
            kind: "duplicate".into(),
            item_ids: gone,
            to: d.keep.clone(),
            score: d.score,
            ..Default::default()
        });
    }
    live.values_mut()
        .for_each(|r| r.items.retain(|i| !refused.contains(i)));
    loose.retain(|i| !refused.contains(i));

    // (b) Names that are one name: a plural, a case, spacing or punctuation variant ("Pricing
    // experiment" / "Pricing experiments"). Weaker name likenesses are left to the person.
    while let Some((a, b)) = name_pair(&live) {
        merge_rooms(&mut live, &mut alias, &mut out, a, b, 1.0, false);
    }
    // (b1) One product's rooms by name stem (`Optimus` / `OptimusBackend`, `tree` / `tree-cp`), whatever
    // their sizes: into the room named just the product, else the biggest.
    let named: Vec<(String, String, usize)> = live
        .values()
        .map(|r| (r.id.clone(), r.name.clone(), r.items.len()))
        .collect();
    for (from, into) in super::stem::stem_merges(&named) {
        let (from, into) = (resolve(&alias, from), resolve(&alias, into));
        merge_rooms(&mut live, &mut alias, &mut out, from, into, 1.0, true);
    }
    // (b2) A project's repo rooms ("OptimusBackend", "FE-Workan.space", "tree-app"): into the project.
    while let Some((a, b)) = repo_pair(&live) {
        merge_rooms(&mut live, &mut alias, &mut out, a, b, 1.0, true);
    }

    // (c) Junk-named rooms (`AI-5`) and, in a run of `MIN_RUN_ITEMS` or more, rooms under
    // `MIN_ROOM_ITEMS`: into the closest real room when it is clear, else Unsorted.
    let run_items: usize = live.values().map(|r| r.items.len()).sum::<usize>() + loose.len();
    let tiny = |r: &RoomIn| {
        junk_name(&r.name) || (run_items >= MIN_RUN_ITEMS && r.items.len() < MIN_ROOM_ITEMS)
    };
    let targets: Vec<RoomVec> = live
        .values()
        .filter(|r| !tiny(r))
        .filter_map(|r| {
            Some(RoomVec {
                id: r.id.clone(),
                name: r.name.clone(),
                centroid: mean(&r.items, vecs)?,
                employer: r.employer.clone(),
            })
        })
        .collect();
    let mut small: Vec<String> = live
        .values()
        .filter(|r| tiny(r))
        .map(|r| r.id.clone())
        .collect();
    small.sort_by_key(|id| (live[id].items.len(), id.clone()));
    for id in small {
        let r = live.remove(&id).expect("live");
        let close = mean(&r.items, vecs)
            .and_then(|c| closest_room(&c, r.employer.as_deref(), &targets, th.closest, th.margin));
        let (to, to_name, score) = match close {
            Some(c) => (c.room_id, Some(c.room_name), c.score),
            None => (UNSORTED.to_owned(), Some("Unsorted".to_owned()), 0.0),
        };
        if to == UNSORTED {
            loose.extend(r.items.iter().cloned());
        } else if let Some(t) = live.get_mut(&to) {
            t.items.extend(r.items.iter().cloned());
        }
        alias.insert(id.clone(), to.clone());
        out.push(TidyChange {
            kind: "fold".into(),
            item_ids: r.items,
            from: Some(id),
            from_name: Some(r.name),
            to,
            to_name,
            score,
            ..Default::default()
        });
    }

    // (d) Unsorted items that clearly belong in a room of this run.
    let loose_set: HashSet<String> = loose.into_iter().collect();
    for c in h
        .closest
        .iter()
        .filter(|c| c.in_review && c.score >= th.closest)
    {
        let to = resolve(&alias, c.room_id.clone());
        if !loose_set.contains(&c.item_id) || !live.contains_key(&to) {
            continue;
        }
        out.push(TidyChange {
            kind: "move".into(),
            item_ids: vec![c.item_id.clone()],
            from: Some(UNSORTED.to_owned()),
            from_name: Some("Unsorted".to_owned()),
            to_name: name_of(&live, &to),
            to,
            score: c.score,
            ..Default::default()
        });
    }
    out
}

/// Whether a planned tidy is believable: not when it would mark more than 30% of the `items` as
/// near-copies (at 20 items or more), or leave fewer than a third of `rooms` (at 6 rooms or more).
/// Such a plan says the vectors cannot tell items apart (a shared preamble), not that they are one.
pub(crate) fn confident(changes: &[TidyChange], items: usize, rooms: usize) -> bool {
    let dups: usize = changes
        .iter()
        .filter(|c| c.kind == "duplicate")
        .map(|c| c.item_ids.len())
        .sum();
    let gone = changes
        .iter()
        .filter(|c| c.kind == "merge" || c.kind == "fold")
        .count();
    let too_many_dups = items >= 20 && dups * 10 > items * 3;
    let too_few_rooms = rooms >= 6 && rooms.saturating_sub(gone) * 3 < rooms;
    !too_many_dups && !too_few_rooms
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room(id: &str, name: &str, items: &[&str]) -> RoomIn {
        RoomIn {
            id: id.into(),
            name: name.into(),
            employer: None,
            items: items.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn a_junk_name_folds_into_the_clear_room_and_a_tiny_named_room_of_a_small_run_stays() {
        let v = |x: f32, y: f32| normalized(vec![x, y, 0.0]);
        let garden: Vec<String> = (0..MIN_ROOM_ITEMS).map(|i| format!("a{i}")).collect();
        let mut vecs: HashMap<String, Vec<f32>> = garden
            .iter()
            .enumerate()
            .map(|(i, k)| (k.clone(), v(1.0, (i as f32 - 7.0) / 70.0)))
            .collect();
        vecs.extend(
            [
                ("j1", v(1.0, 0.05)),
                ("j2", v(1.0, 0.02)),
                ("j3", v(1.0, -0.05)),
                ("t1", v(0.0, 1.0)),
            ]
            .into_iter()
            .map(|(k, x)| (k.to_owned(), x)),
        );
        let g: Vec<&str> = garden.iter().map(String::as_str).collect();
        let rooms = vec![
            room("p-a", "Garden", &g),
            room("p-j", "AI-5", &["j1", "j2", "j3"]),
            room("p-t", "Kites", &["t1"]),
        ];
        let h = Hints {
            duplicates: &[],
            closest: &[],
        };
        let ch = plan(rooms, &[], &vecs, &h, Thresholds::for_strength(1));
        let got: Vec<(&str, Option<&str>, &str)> = ch
            .iter()
            .map(|c| (c.kind.as_str(), c.from.as_deref(), c.to.as_str()))
            .collect();
        assert_eq!(
            got,
            [("fold", Some("p-j"), "p-a")],
            "Kites is a project, and in a run this small its size says nothing"
        );
    }

    #[test]
    fn one_name_is_a_plural_a_case_spacing_or_punctuation_variant() {
        assert!(same_name("Pricing experiment", "Pricing experiments"));
        assert!(same_name("acme-shop", "Acme Shop"));
        assert!(same_name("Workan.Space", "WorkanSpace"));
        assert!(same_name("Workan Space", "workanspace"));
        assert!(
            !same_name("AcmeShopApi", "Acme Shop"),
            "inside is not one name"
        );
        assert!(!same_name("Kestrel", "Kestrel Portal"));
        assert!(
            !same_name("Chess", "Cheese"),
            "a near spelling is not one name"
        );
        assert!(!same_name("Ops", "Shops"));
    }

    #[test]
    fn a_projects_small_repo_rooms_merge_into_it() {
        let many = |n: usize| (0..n).map(|i| format!("i{i}")).collect::<Vec<_>>();
        let r = |id: &str, name: &str, n: usize, emp: Option<&str>| RoomIn {
            id: id.into(),
            name: name.into(),
            employer: emp.map(str::to_owned),
            items: many(n).into_iter().map(|i| format!("{id}-{i}")).collect(),
        };
        let rooms = vec![
            r("p-k", "Kestrel", 100, Some("acme")),
            r("p-kb", "kestrelbackend", 5, Some("acme")),
            r("p-kx", "KestrelPortal", 5, Some("other")),
            r("p-b", "BrambleSpace", 200, None),
            r("p-fb", "FE-Bramble.space", 1, None),
            r("p-l", "LARK", 300, None),
            r("p-lc", "lark-home-cloud", 5, None),
            r("p-t", "tree", 22, None),
            r("p-tc", "tree-cp", 26, None),
            r("p-ta", "tree-app", 11, None),
            r("p-tz", "treehouse", 4, None),
            r("p-big", "Larkspur", 40, None),
        ];
        let h = Hints {
            duplicates: &[],
            closest: &[],
        };
        let ch = plan(rooms, &[], &HashMap::new(), &h, Thresholds::for_strength(1));
        let got: Vec<(&str, &str)> = ch
            .iter()
            .map(|c| (c.from.as_deref().unwrap(), c.to.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("p-fb", "p-b"),
                ("p-ta", "p-t"),
                ("p-tc", "p-t"),
                ("p-kb", "p-k"),
                ("p-lc", "p-l"),
                ("p-tz", UNSORTED),
                ("p-kx", UNSORTED),
            ],
            "KestrelPortal is another employer's and treehouse has no boundary: both too small to \
             stay; Larkspur is too big to be a repo"
        );
        assert_eq!(ch.iter().filter(|c| c.kind == "merge").count(), 5);
        assert_eq!(
            after_project("OptimusPrime", "Optimus").as_deref(),
            Some("prime")
        );
        assert_eq!(after_project("optimusprime", "Optimus"), None);
        assert_eq!(
            after_project("Ops-x", "Op"),
            None,
            "a project name of 3+ letters"
        );
    }

    #[test]
    fn rooms_whose_items_read_alike_stay_apart_and_the_guard_trips_on_a_collapse() {
        // Three named projects whose items all read the same (one preamble): nothing merges.
        let v = normalized(vec![1.0, 0.0, 0.0]);
        let ids =
            |p: &str| -> Vec<String> { (0..MIN_ROOM_ITEMS).map(|i| format!("{p}{i}")).collect() };
        let (a, b, c) = (ids("a"), ids("b"), ids("c"));
        let vecs: HashMap<String, Vec<f32>> = a
            .iter()
            .chain(&b)
            .chain(&c)
            .map(|k| (k.clone(), v.clone()))
            .collect();
        fn refs(x: &[String]) -> Vec<&str> {
            x.iter().map(String::as_str).collect()
        }
        let rooms = vec![
            room("p-a", "Kestrel", &refs(&a)),
            room("p-b", "Bramble", &refs(&b)),
            room("p-c", "Larkspur", &refs(&c)),
        ];
        let h = Hints {
            duplicates: &[],
            closest: &[],
        };
        assert!(plan(rooms, &[], &vecs, &h, Thresholds::for_strength(2)).is_empty());
        let dup = |n: usize| TidyChange {
            kind: "duplicate".into(),
            item_ids: (0..n).map(|i| i.to_string()).collect(),
            ..Default::default()
        };
        let fold = || TidyChange {
            kind: "fold".into(),
            ..Default::default()
        };
        assert!(confident(&[dup(30)], 100, 10));
        assert!(!confident(&[dup(31)], 100, 10), "over 30% near-copies");
        assert!(confident(&[dup(5)], 10, 10), "too few items to judge");
        assert!(!confident(&vec![fold(); 15], 100, 20), "20 rooms to 5");
        assert!(
            confident(&vec![fold(); 2], 100, 3),
            "too few rooms to judge"
        );
    }
}
