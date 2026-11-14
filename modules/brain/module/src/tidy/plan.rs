//! The AI tidy's planner: a pure function of the rooms, items, vectors and suggestions.

use std::collections::{BTreeMap, HashMap, HashSet};

use brain_model::group::UNSORTED;
use brain_model::semantic::{RoomVec, closest_room, normalized};

use super::TidyChange;
use crate::semantic::Thresholds;
use crate::suggest::{ClosestHint, DuplicateHint, MergeHint};

/// What the planner needs of one proposal: only `proposed` rooms with at most one employer take part.
pub(crate) struct RoomIn {
    pub id: String,
    pub name: String,
    pub employer: Option<String>,
    /// Item ids not marked refused.
    pub items: Vec<String>,
}

/// The strong suggestions of one semantic step.
pub(crate) struct Hints<'a> {
    pub duplicates: &'a [DuplicateHint],
    pub merges: &'a [MergeHint],
    pub closest: &'a [ClosestHint],
}

/// Merges the smaller of rooms `a` and `b` into the larger (ties: `a` into `b`), unless they are one
/// room already, either is gone or they belong to two employers.
fn merge_rooms(
    live: &mut BTreeMap<String, RoomIn>,
    alias: &mut HashMap<String, String>,
    out: &mut Vec<TidyChange>,
    a: String,
    b: String,
    score: f32,
) {
    let (Some(ra), Some(rb)) = (live.get(&a), live.get(&b)) else {
        return;
    };
    if a == b || matches!((&ra.employer, &rb.employer), (Some(x), Some(y)) if x != y) {
        return;
    }
    let (small, big) = if ra.items.len() <= rb.items.len() {
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

/// Two names for one room: equal once case, spacing and punctuation go and a plural `s` is dropped,
/// or one (four letters or more) inside the other.
fn same_name(a: &str, b: &str) -> bool {
    let k = |s: &str| {
        let n = brain_model::group::norm(s);
        n.strip_suffix('s').map(str::to_owned).unwrap_or(n)
    };
    let (x, y) = (k(a), k(b));
    let (s, l) = if x.len() <= y.len() {
        (&x, &y)
    } else {
        (&y, &x)
    };
    !s.is_empty() && (s == l || (s.chars().count() >= 4 && l.contains(s.as_str())))
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
/// and the suggestions: (a) near-copies merged into the newest, (b) close rooms merged smaller into
/// larger, (c) tiny or junk rooms folded into the closest room or Unsorted, (d) Unsorted items moved
/// to the room they clearly belong in.
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

    // (b) Close rooms: the smaller into the larger, best score first.
    for m in h.merges.iter().filter(|m| m.score >= th.merge) {
        let (a, b) = (
            resolve(&alias, m.from.clone()),
            resolve(&alias, m.to.clone()),
        );
        merge_rooms(&mut live, &mut alias, &mut out, a, b, m.score);
    }
    // (b') Names that are one name: a plural, a case or spacing variant, or one inside the other
    // ("Pricing experiment" / "Pricing experiments", "AcmeShopApi" / "Acme Shop"). Weaker name
    // likenesses (a near spelling) are left alone and asked nowhere.
    while let Some((a, b)) = name_pair(&live) {
        merge_rooms(&mut live, &mut alias, &mut out, a, b, 1.0);
    }

    // (c) Tiny or junk rooms: into the closest real room when it is clear, else Unsorted.
    let tiny = |r: &RoomIn| r.items.len() <= 2 || junk_name(&r.name);
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
    fn a_junk_name_folds_into_the_clear_room_and_a_lonely_tiny_room_into_unsorted() {
        let v = |x: f32, y: f32| normalized(vec![x, y, 0.0]);
        let vecs: HashMap<String, Vec<f32>> = [
            ("a1", v(1.0, 0.0)),
            ("a2", v(1.0, 0.1)),
            ("a3", v(1.0, -0.1)),
            ("j1", v(1.0, 0.05)),
            ("j2", v(1.0, 0.02)),
            ("j3", v(1.0, -0.05)),
            ("t1", v(0.0, 1.0)),
        ]
        .into_iter()
        .map(|(k, x)| (k.to_owned(), x))
        .collect();
        let rooms = vec![
            room("p-a", "Garden", &["a1", "a2", "a3"]),
            room("p-j", "AI-5", &["j1", "j2", "j3"]),
            room("p-t", "Kites", &["t1"]),
        ];
        let h = Hints {
            duplicates: &[],
            merges: &[],
            closest: &[],
        };
        let ch = plan(rooms, &[], &vecs, &h, Thresholds::for_strength(1));
        let got: Vec<(&str, Option<&str>, &str)> = ch
            .iter()
            .map(|c| (c.kind.as_str(), c.from.as_deref(), c.to.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("fold", Some("p-t"), UNSORTED),
                ("fold", Some("p-j"), "p-a")
            ]
        );
        assert_eq!(ch.iter().filter(|c| c.kind == "fold").count(), 2);
    }

    #[test]
    fn one_name_is_a_plural_a_spacing_variant_or_inside_the_other() {
        assert!(same_name("Pricing experiment", "Pricing experiments"));
        assert!(same_name("AcmeShopApi", "Acme Shop"));
        assert!(same_name("acme-shop", "Acme Shop"));
        assert!(
            !same_name("Chess", "Cheese"),
            "a near spelling is not one name"
        );
        assert!(!same_name("Ops", "Shops"), "too short to be inside another");
    }
}
