//! Suggestions from sentence vectors (local semantic help). Pure functions over vectors: no model,
//! no I/O. Every output is a SUGGESTION with a score; nothing here moves an item.
//!
//! The vectors come from a local embedder (the module's `semantic` feature). They must be unit
//! length, so a dot product is the cosine.

use std::collections::{HashMap, HashSet};

use crate::item::Item;
use crate::rules::restricted_path;

/// How much of an item's text is embedded (bytes, cut on a char boundary).
pub const EMBED_CHARS: usize = 1000;
pub const DUP_THRESHOLD: f32 = 0.95;
// e5 vectors are bunched: unrelated texts already score about 0.82-0.85 (measured on the real model), so the
// cluster and merge cut-offs sit high. Tune on real Unsorted items before showing suggestions.
pub const CLUSTER_THRESHOLD: f32 = 0.88;
pub const MERGE_THRESHOLD: f32 = 0.93;
pub const MIN_CLUSTER: usize = 3;

/// Refused (restricted path) items are never embedded. The caller also drops private ones it knows of.
pub fn eligible(item: &Item) -> bool {
    !restricted_path(&item.origin.path)
}

/// The text one item is embedded as: title, then the start of the text.
pub fn embed_text(item: &Item) -> String {
    let mut end = item.text.len().min(EMBED_CHARS);
    while !item.text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n{}", item.title, &item.text[..end])
}

pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

pub fn normalized(mut v: Vec<f32>) -> Vec<f32> {
    let n = dot(&v, &v).sqrt();
    if n > 0.0 {
        v.iter_mut().for_each(|x| *x /= n);
    }
    v
}

/// What the engine needs of an item. `room` is `None` for Unsorted.
#[derive(Debug, Clone)]
pub struct Entry<'a> {
    pub item: &'a Item,
    pub room: Option<&'a str>,
    pub vector: &'a [f32],
}

#[derive(Debug, Clone, PartialEq)]
pub struct DuplicateGroup {
    /// The newest item, by `started_at`.
    pub keep: String,
    pub duplicates: Vec<String>,
    /// The lowest pair similarity inside the group.
    pub score: f32,
    pub reason: String,
}

/// Items whose vectors are at least `threshold` alike (union of pairs). Items with the same
/// `content_hash` are not listed: exact duplicates are the existing hash rule's.
pub fn duplicates(entries: &[Entry], threshold: f32) -> Vec<DuplicateGroup> {
    let n = entries.len();
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(p: &mut [usize], i: usize) -> usize {
        let mut r = i;
        while p[r] != r {
            r = p[r];
        }
        let mut c = i;
        while p[c] != r {
            (p[c], c) = (r, p[c]);
        }
        r
    }
    let mut low: HashMap<usize, f32> = HashMap::new();
    let mut pairs = vec![];
    for i in 0..n {
        for j in i + 1..n {
            if entries[i].item.content_hash == entries[j].item.content_hash {
                continue;
            }
            let s = dot(entries[i].vector, entries[j].vector);
            if s >= threshold {
                pairs.push((i, j, s));
                let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                parent[a] = b;
            }
        }
    }
    for (i, _, s) in &pairs {
        let r = find(&mut parent, *i);
        let e = low.entry(r).or_insert(1.0);
        *e = e.min(*s);
    }
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in pairs
        .iter()
        .flat_map(|(i, j, _)| [*i, *j])
        .collect::<HashSet<_>>()
    {
        groups.entry(find(&mut parent, i)).or_default().push(i);
    }
    let mut out: Vec<DuplicateGroup> = groups
        .into_iter()
        .map(|(root, mut m)| {
            // RFC 3339 UTC strings sort by time; ties break on id so the output is stable.
            m.sort_by(|&a, &b| {
                let (x, y) = (entries[a].item, entries[b].item);
                y.started_at.cmp(&x.started_at).then(x.item_id.cmp(&y.item_id))
            });
            let score = low[&root];
            DuplicateGroup {
                keep: entries[m[0]].item.item_id.clone(),
                duplicates: m[1..].iter().map(|&i| entries[i].item.item_id.clone()).collect(),
                score,
                reason: format!(
                    "these {} items look like duplicates (similarity at least {:.2}); keep the newest",
                    m.len(),
                    score
                ),
            }
        })
        .collect();
    out.sort_by(|a, b| a.keep.cmp(&b.keep));
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct SuggestedRoom {
    pub name: String,
    pub keywords: Vec<String>,
    pub item_ids: Vec<String>,
    /// Mean similarity of the members to the centroid.
    pub score: f32,
    pub centroid: Vec<f32>,
}

struct Cluster {
    members: Vec<usize>,
    sum: Vec<f32>,
}

impl Cluster {
    fn centroid(&self) -> Vec<f32> {
        normalized(self.sum.clone())
    }
}

/// Average-linkage-by-centroid agglomeration of the Unsorted entries (`room == None`), stopping
/// when the best pair of centroids is under `threshold`; clusters under `min_size` are dropped.
/// Each cluster keeps its unit centroid and its most similar neighbour, so a merge rescans only the
/// rows it touched: about O(n^2) dot products in all, where re-scoring every pair after every merge
/// was O(n^3) (an import with ~1,000 Unsorted transcripts ran for over ten minutes).
pub fn suggest_rooms(entries: &[Entry], threshold: f32, min_size: usize) -> Vec<SuggestedRoom> {
    let pool: Vec<usize> = (0..entries.len())
        .filter(|&i| entries[i].room.is_none())
        .collect();
    let mut cl: Vec<Option<Cluster>> = pool
        .iter()
        .map(|&i| {
            Some(Cluster {
                members: vec![i],
                sum: entries[i].vector.to_vec(),
            })
        })
        .collect();
    let mut cen: Vec<Vec<f32>> = cl.iter().flatten().map(Cluster::centroid).collect();
    // The live cluster most like `i` (ties to the lower index) and its score.
    let nearest = |i: usize, cl: &[Option<Cluster>], cen: &[Vec<f32>]| {
        let mut best: Option<(usize, f32)> = None;
        for j in (0..cl.len()).filter(|&j| j != i && cl[j].is_some()) {
            let s = dot(&cen[i], &cen[j]);
            if best.is_none_or(|(_, t)| s > t) {
                best = Some((j, s));
            }
        }
        best
    };
    let mut near: Vec<Option<(usize, f32)>> =
        (0..cl.len()).map(|i| nearest(i, &cl, &cen)).collect();
    loop {
        let mut best: Option<(usize, usize, f32)> = None;
        for (i, n) in near.iter().enumerate() {
            if let (true, Some((j, s))) = (cl[i].is_some(), *n) {
                let (a, b) = (i.min(j), i.max(j));
                if s >= threshold
                    && best.is_none_or(|(x, y, t)| s > t || (s == t && (a, b) < (x, y)))
                {
                    best = Some((a, b, s));
                }
            }
        }
        let Some((i, j, _)) = best else { break };
        let b = cl[j].take().expect("live");
        let a = cl[i].as_mut().expect("live");
        a.members.extend(b.members);
        a.sum.iter_mut().zip(&b.sum).for_each(|(x, y)| *x += y);
        cen[i] = a.centroid();
        near[j] = None;
        near[i] = nearest(i, &cl, &cen);
        for k in (0..cl.len()).filter(|&k| k != i && cl[k].is_some()) {
            let s = dot(&cen[k], &cen[i]);
            near[k] = match near[k] {
                // Its neighbour changed or is gone and the new cluster is no closer: look again.
                Some((m, t)) if (m == i || m == j) && s < t => nearest(k, &cl, &cen),
                Some((m, t)) if m != i && m != j && s <= t => Some((m, t)),
                _ => Some((i, s)),
            };
        }
    }
    let docs: Vec<Vec<String>> = entries
        .iter()
        .map(|e| tokens(&embed_text(e.item)))
        .collect();
    let mut df: HashMap<&str, usize> = HashMap::new();
    for d in &docs {
        for w in d.iter().collect::<HashSet<_>>() {
            *df.entry(w.as_str()).or_default() += 1;
        }
    }
    let mut out: Vec<SuggestedRoom> = cl
        .into_iter()
        .flatten()
        .filter(|c| c.members.len() >= min_size)
        .map(|c| {
            let centroid = c.centroid();
            let score = c
                .members
                .iter()
                .map(|&m| dot(entries[m].vector, &centroid))
                .sum::<f32>()
                / c.members.len() as f32;
            let keywords = keywords(&c.members, &docs, &df, entries.len());
            let mut item_ids: Vec<String> = c
                .members
                .iter()
                .map(|&m| entries[m].item.item_id.clone())
                .collect();
            item_ids.sort();
            SuggestedRoom {
                name: if keywords.is_empty() {
                    "Untitled topic".into()
                } else {
                    title_case(&keywords)
                },
                keywords,
                item_ids,
                score,
                centroid,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.item_ids
            .len()
            .cmp(&a.item_ids.len())
            .then(a.name.cmp(&b.name))
    });
    out
}

fn title_case(k: &[String]) -> String {
    k.iter()
        .take(3)
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map_or(String::new(), |f| f.to_uppercase().chain(c).collect())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

const STOP: &[&str] = &[
    "the", "and", "for", "with", "that", "this", "from", "are", "was", "not", "you", "have", "has",
    "but", "can", "will", "all", "its", "into", "use", "used", "using", "then", "when", "what",
    "there", "here", "also", "about", "should", "would", "could", "your", "our", "they", "them",
];

/// Lowercase alphanumeric words of 3+ chars (Arabic letters count), stop words dropped.
pub fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().count() >= 3 && !w.chars().all(|c| c.is_ascii_digit()))
        .map(str::to_lowercase)
        .filter(|w| !STOP.contains(&w.as_str()))
        .collect()
}

/// Top 3 words by tf-idf: frequency inside the cluster against how many corpus items hold the word.
fn keywords(
    members: &[usize],
    docs: &[Vec<String>],
    df: &HashMap<&str, usize>,
    n: usize,
) -> Vec<String> {
    let mut tf: HashMap<&str, f32> = HashMap::new();
    for &m in members {
        for w in docs[m].iter().collect::<HashSet<_>>() {
            *tf.entry(w.as_str()).or_default() += 1.0;
        }
    }
    let mut scored: Vec<(&str, f32)> = tf
        .into_iter()
        .map(|(w, f)| (w, f * ((1.0 + n as f32) / (1.0 + df[w] as f32)).ln()))
        .collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(b.0)));
    scored
        .into_iter()
        .take(3)
        .map(|(w, _)| w.to_owned())
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct MergeSuggestion {
    pub a: String,
    pub b: String,
    pub score: f32,
    pub reason: String,
}

/// Pairs of proposals (name, centroid) that are very close: "these two look like one topic".
pub fn merge_suggestions(proposals: &[(&str, &[f32])], threshold: f32) -> Vec<MergeSuggestion> {
    let mut out = vec![];
    for i in 0..proposals.len() {
        for j in i + 1..proposals.len() {
            let s = dot(proposals[i].1, proposals[j].1);
            if s >= threshold {
                out.push(MergeSuggestion {
                    a: proposals[i].0.to_owned(),
                    b: proposals[j].0.to_owned(),
                    score: s,
                    reason: format!(
                        "\"{}\" and \"{}\" cover very similar content (similarity {:.2}); consider one room",
                        proposals[i].0, proposals[j].0, s
                    ),
                });
            }
        }
    }
    out.sort_by(|x, y| y.score.total_cmp(&x.score));
    out
}

/// A room an Unsorted item could be filed in: the mean of its items' vectors (unit length).
#[derive(Debug, Clone)]
pub struct RoomVec {
    pub id: String,
    pub name: String,
    pub centroid: Vec<f32>,
    /// The employer this room belongs to, lowercase, when it is an employer's room.
    pub employer: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Close {
    pub room_id: String,
    pub room_name: String,
    pub score: f32,
    pub runner_up: Option<(String, String, f32)>,
}

/// The room closest to an item that no rule placed, or `None` when it is not clear: the best score must
/// reach `min_score` and lead the runner-up by `margin`. The employer guard: an item that names an
/// employer is never compared with another employer's room. Suggestion only; nothing moves.
pub fn closest_room(
    vector: &[f32],
    item_employer: Option<&str>,
    rooms: &[RoomVec],
    min_score: f32,
    margin: f32,
) -> Option<Close> {
    let mut scored: Vec<(&RoomVec, f32)> = rooms
        .iter()
        .filter(|r| match (&r.employer, item_employer) {
            (Some(re), Some(ie)) => re == ie,
            _ => true,
        })
        .map(|r| (r, dot(vector, &r.centroid)))
        .collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1));
    let (best, score) = *scored.first()?;
    let second = scored.get(1);
    if score < min_score || second.is_some_and(|s| score - s.1 < margin) {
        return None;
    }
    Some(Close {
        room_id: best.id.clone(),
        room_name: best.name.clone(),
        score,
        runner_up: second.map(|(r, s)| (r.id.clone(), r.name.clone(), *s)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Author, AuthorKind, Origin, SourceKind, hash_of};

    fn item(id: &str, title: &str, text: &str, at: &str, path: &str) -> Item {
        Item {
            item_id: id.into(),
            source_kind: SourceKind::Doc,
            content_hash: hash_of(text),
            origin: Origin {
                device: "d".into(),
                path: path.into(),
                range: None,
            },
            project_hint: None,
            author: Author {
                kind: AuthorKind::Person,
                name: "p".into(),
            },
            title: title.into(),
            text: text.into(),
            links: vec![],
            started_at: at.into(),
            ended_at: None,
        }
    }

    /// A unit vector along axis `k` with a little `wobble` toward axis `k + 1`.
    fn v(k: usize, wobble: f32) -> Vec<f32> {
        let mut x = vec![0.0; 6];
        x[k] = 1.0;
        x[k + 1] = wobble;
        normalized(x)
    }

    #[test]
    fn restricted_items_are_not_eligible() {
        assert!(!eligible(&item(
            "a",
            "t",
            "x",
            "2026-01-01T00:00:00Z",
            "/h/.env"
        )));
        assert!(eligible(&item(
            "a",
            "t",
            "x",
            "2026-01-01T00:00:00Z",
            "/h/notes.md"
        )));
    }

    #[test]
    fn embed_text_cuts_on_a_char_boundary() {
        let it = item("a", "T", &"ب".repeat(900), "2026-01-01T00:00:00Z", "/n.md");
        let t = embed_text(&it);
        assert!(t.len() <= 1002 && t.starts_with("T\n"));
    }

    #[test]
    fn duplicates_keep_the_newest_and_skip_exact_hashes() {
        let a = item("a", "t", "one", "2026-01-01T00:00:00Z", "/a");
        let b = item("b", "t", "two", "2026-03-01T00:00:00Z", "/b");
        let c = item("c", "t", "three", "2026-02-01T00:00:00Z", "/c");
        let d = item("d", "t", "four", "2026-02-01T00:00:00Z", "/d");
        let e = item("e", "t", "one", "2026-04-01T00:00:00Z", "/e"); // same hash as a: never paired with it
        let (v0, v1, v2, v4) = (v(0, 0.01), v(0, 0.02), v(2, 0.0), v(4, 0.0));
        let es = vec![
            Entry {
                item: &a,
                room: None,
                vector: &v0,
            },
            Entry {
                item: &b,
                room: None,
                vector: &v1,
            },
            Entry {
                item: &c,
                room: None,
                vector: &v0,
            },
            Entry {
                item: &d,
                room: None,
                vector: &v2,
            },
            Entry {
                item: &e,
                room: None,
                vector: &v4,
            },
        ];
        let g = duplicates(&es, DUP_THRESHOLD);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].keep, "b");
        assert_eq!(g[0].duplicates, vec!["c", "a"]);
        assert!(g[0].score >= DUP_THRESHOLD);
    }

    #[test]
    fn clusters_unsorted_items_and_names_them() {
        let docs = [
            ("invoice customer payment", 0),
            ("customer invoice reminder", 0),
            ("payment invoice overdue", 0),
            ("kubernetes deploy rollout", 2),
            ("deploy rollout kubernetes pods", 2),
            ("rollout deploy cluster", 2),
            ("lonely poem", 4),
        ];
        let items: Vec<Item> = docs
            .iter()
            .enumerate()
            .map(|(i, (t, _))| item(&format!("i{i}"), t, t, "2026-01-01T00:00:00Z", "/x"))
            .collect();
        let vecs: Vec<Vec<f32>> = docs
            .iter()
            .enumerate()
            .map(|(i, (_, k))| v(*k, 0.02 * i as f32))
            .collect();
        let mut es: Vec<Entry> = items
            .iter()
            .zip(&vecs)
            .map(|(item, vector)| Entry {
                item,
                room: None,
                vector,
            })
            .collect();
        es[6].room = Some("already"); // sorted items are never clustered
        let rooms = suggest_rooms(&es, CLUSTER_THRESHOLD, MIN_CLUSTER);
        assert_eq!(rooms.len(), 2);
        assert!(rooms.iter().all(|r| r.item_ids.len() == 3));
        let names: Vec<&str> = rooms.iter().map(|r| r.name.as_str()).collect();
        assert!(names.iter().any(|n| n.contains("Invoice")), "{names:?}");
        assert!(
            names
                .iter()
                .any(|n| n.contains("Deploy") || n.contains("Rollout")),
            "{names:?}"
        );
        // min size drops a pair
        assert!(suggest_rooms(&es, CLUSTER_THRESHOLD, 4).is_empty());
    }

    /// The old agglomeration, re-scoring every pair after every merge: the reference.
    fn naive_rooms(vs: &[Vec<f32>], threshold: f32) -> Vec<Vec<usize>> {
        let mut cl: Vec<Option<(Vec<usize>, Vec<f32>)>> = vs
            .iter()
            .enumerate()
            .map(|(i, v)| Some((vec![i], v.clone())))
            .collect();
        loop {
            let mut best: Option<(usize, usize, f32)> = None;
            for i in 0..cl.len() {
                for j in i + 1..cl.len() {
                    if let (Some(a), Some(b)) = (&cl[i], &cl[j]) {
                        let s = dot(&normalized(a.1.clone()), &normalized(b.1.clone()));
                        if s >= threshold && best.is_none_or(|(_, _, t)| s > t) {
                            best = Some((i, j, s));
                        }
                    }
                }
            }
            let Some((i, j, _)) = best else { break };
            let b = cl[j].take().unwrap();
            let a = cl[i].as_mut().unwrap();
            a.0.extend(b.0);
            a.1.iter_mut().zip(&b.1).for_each(|(x, y)| *x += y);
        }
        let mut out: Vec<Vec<usize>> = cl.into_iter().flatten().map(|c| c.0).collect();
        out.iter_mut().for_each(|m| m.sort_unstable());
        out.sort();
        out
    }

    #[test]
    fn agglomeration_matches_the_naive_one() {
        let mut seed = 7u64;
        let mut r = move || {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            ((seed >> 33) as f32 / (1u64 << 31) as f32) - 0.5
        };
        // Bunched like e5 vectors: a shared direction, a few topics and noise.
        let centers: Vec<Vec<f32>> = (0..5).map(|_| (0..12).map(|_| r()).collect()).collect();
        let vs: Vec<Vec<f32>> = (0..150)
            .map(|i| {
                normalized(
                    (0..12)
                        .map(|d| 2.0 + centers[i % 5][d] + 0.4 * r())
                        .collect(),
                )
            })
            .collect();
        let items: Vec<Item> = (0..vs.len())
            .map(|i| {
                item(
                    &format!("i{i:03}"),
                    "t",
                    &format!("x{i}"),
                    "2026-01-01T00:00:00Z",
                    "/x",
                )
            })
            .collect();
        let es: Vec<Entry> = items
            .iter()
            .zip(&vs)
            .map(|(item, vector)| Entry {
                item,
                room: None,
                vector,
            })
            .collect();
        // Cut-offs from the pair scores themselves: most pairs, some, few.
        let mut all: Vec<f32> = (0..vs.len())
            .flat_map(|i| (i + 1..vs.len()).map(move |j| (i, j)))
            .map(|(i, j)| dot(&vs[i], &vs[j]))
            .collect();
        all.sort_by(f32::total_cmp);
        for q in [0.5, 0.8, 0.95] {
            let th = all[(all.len() as f64 * q) as usize];
            let want: Vec<Vec<usize>> = naive_rooms(&vs, th)
                .into_iter()
                .filter(|m| m.len() >= 2)
                .collect();
            let mut got: Vec<Vec<usize>> = suggest_rooms(&es, th, 2)
                .into_iter()
                .map(|r| {
                    r.item_ids
                        .iter()
                        .map(|id| id[1..].parse().unwrap())
                        .collect()
                })
                .collect();
            got.iter_mut()
                .for_each(|m: &mut Vec<usize>| m.sort_unstable());
            got.sort();
            assert!(want.len() > 1, "threshold {th} merges something");
            assert_eq!(got, want, "threshold {th}");
        }
    }

    #[test]
    fn merge_suggestions_name_the_pair() {
        let (a, b, c) = (v(0, 0.0), v(0, 0.05), v(2, 0.0));
        let m = merge_suggestions(
            &[("Billing", &a), ("Invoices", &b), ("Ops", &c)],
            MERGE_THRESHOLD,
        );
        assert_eq!(m.len(), 1);
        assert!(m[0].reason.contains("Billing") && m[0].reason.contains("Invoices"));
    }

    #[test]
    fn arabic_words_are_tokens() {
        assert_eq!(tokens("الخادم الجديد 2026 the"), vec!["الخادم", "الجديد"]);
    }

    #[test]
    fn closest_room_needs_score_margin_and_the_employer_guard() {
        let room = |id: &str, c: [f32; 2], e: Option<&str>| RoomVec {
            id: id.into(),
            name: id.into(),
            centroid: normalized(c.to_vec()),
            employer: e.map(str::to_owned),
        };
        let rooms = [
            room("a", [1.0, 0.0], Some("acme")),
            room("b", [0.0, 1.0], None),
        ];
        let v = normalized(vec![1.0, 0.1]);
        let c = closest_room(&v, None, &rooms, 0.9, 0.1).unwrap();
        assert_eq!(c.room_id, "a");
        assert_eq!(c.runner_up.unwrap().0, "b");
        assert!(
            closest_room(&v, None, &rooms, 0.999, 0.1).is_none(),
            "low score"
        );
        assert!(
            closest_room(&normalized(vec![1.0, 1.0]), None, &rooms, 0.5, 0.1).is_none(),
            "tie"
        );
        assert!(
            closest_room(&v, Some("other"), &rooms, 0.9, 0.1).is_none(),
            "guard drops the acme room"
        );
    }
}
