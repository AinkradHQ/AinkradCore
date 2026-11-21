//! The Review proposal as one pure function: grouping, the semantic step and the AI tidy over a
//! list of collected items, with no database, no key and no store. The import runs the same steps
//! (`review::discover`, `suggest::work`, `tidy::apply`); a local evaluation harness calls this one
//! with real data and reads what the person would see.

use std::collections::{BTreeMap, HashMap, HashSet};

use brain_model::group::{Aliases, UNSORTED, canonical, group_with};
use brain_model::item::Item;
use brain_model::semantic::Boilerplate;
use brain_model::signals::{RoomKind, extract};

use crate::semantic::{self, Embedder, Input, ProposalRef, Thresholds, VectorCache};
use crate::suggest::{Cand, closest_hints, distinctive, dup_hints};
use crate::tidy::{Hints, RoomIn, TidyChange, TidySummary, confident, plan};

/// One room of the proposal after the tidy.
#[derive(Debug, Clone, PartialEq)]
pub struct ProposedRoom {
    /// The grouping key (stable for one input).
    pub id: String,
    pub name: String,
    /// The kind guess: `employer`, `product`, `general`, ...
    pub kind: String,
    pub item_ids: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Proposed {
    /// Rooms, Unsorted not among them, by name.
    pub rooms: Vec<ProposedRoom>,
    pub unsorted: Vec<String>,
    /// What the tidy changed (empty when it declined).
    pub changes: Vec<TidyChange>,
    /// Counts of the tidy (when declined: what it would have done).
    pub summary: TidySummary,
    /// False: the AI was not confident and the proposal is as the rules made it.
    pub confident: bool,
}

/// The proposal for `items` under the person's `aliases`, the local model `embedder` and
/// `semantic.strength` `strength` (0, 1 or 2). Items on a restricted path are never embedded.
pub fn propose(
    items: &[Item],
    aliases: &Aliases,
    embedder: &dyn Embedder,
    strength: i64,
) -> Result<Proposed, String> {
    let th = Thresholds::for_strength(strength);
    let groups = group_with(items, aliases);
    let mut room_of: HashMap<&str, &str> = HashMap::new();
    for g in &groups {
        for i in &g.item_ids {
            room_of.insert(i.as_str(), g.key.as_str());
        }
    }
    let docs: Vec<(&str, &str)> = items
        .iter()
        .map(|i| (i.title.as_str(), i.text.as_str()))
        .collect();
    let bp = Boilerplate::learn(&docs);
    let (mut owned, mut sketches) = (vec![], vec![]);
    for it in items {
        let room = room_of
            .get(it.item_id.as_str())
            .filter(|r| **r != UNSORTED)
            .map(|r| (*r).to_owned());
        let (item, sk) = distinctive(it.clone(), &bp);
        owned.push((item, room));
        sketches.push(sk);
    }
    let rooms: Vec<&brain_model::group::Proposal> =
        groups.iter().filter(|g| g.key != UNSORTED).collect();
    // One employer per room, as the person's aliases name it; a mixed room takes no part.
    let by_id: HashMap<&str, &Item> = items.iter().map(|i| (i.item_id.as_str(), i)).collect();
    let employer = |ids: &[String]| -> Option<Option<String>> {
        let set: HashSet<String> = ids
            .iter()
            .filter_map(|i| by_id.get(i.as_str()))
            .filter_map(|i| match extract(i).company {
                Some((n, RoomKind::Employer)) => Some(canonical(aliases, n).to_lowercase()),
                _ => None,
            })
            .collect();
        (set.len() <= 1).then(|| set.into_iter().next())
    };
    let employers: BTreeMap<String, Option<String>> = rooms
        .iter()
        .filter_map(|g| Some((g.key.clone(), employer(&g.item_ids)?)))
        .collect();
    let refs: Vec<ProposalRef> = rooms
        .iter()
        .map(|g| ProposalRef {
            name: &g.key,
            item_ids: &g.item_ids,
        })
        .collect();
    let inputs: Vec<Input> = owned
        .iter()
        .zip(&sketches)
        .map(|((item, room), sk)| Input {
            item,
            room: room.as_deref(),
            sketch: Some(sk),
        })
        .collect();
    let mut cache = VectorCache::default();
    let sug = semantic::run(embedder, &mut cache, &inputs, &refs, th)?;
    let cand: Vec<Cand> = rooms
        .iter()
        .filter_map(|g| {
            Some(Cand {
                id: g.key.clone(),
                name: g.name.clone(),
                employer: employers.get(&g.key)?.clone(),
                in_review: true,
                centroid: None,
            })
        })
        .collect();
    let model = embedder.model_id().to_owned();
    let closest = closest_hints(&cache, &model, &owned, cand, th, aliases);
    let vecs: HashMap<String, Vec<f32>> = owned
        .iter()
        .filter_map(|(i, _)| {
            Some((
                i.item_id.clone(),
                cache.get(&model, &i.content_hash)?.clone(),
            ))
        })
        .collect();
    let dups = dup_hints(&sug.duplicates);
    let room_in: Vec<RoomIn> = rooms
        .iter()
        .filter_map(|g| {
            Some(RoomIn {
                id: g.key.clone(),
                name: g.name.clone(),
                employer: employers.get(&g.key)?.clone(),
                items: g.item_ids.clone(),
            })
        })
        .collect();
    let unsorted: Vec<String> = groups
        .iter()
        .filter(|g| g.key == UNSORTED)
        .flat_map(|g| g.item_ids.clone())
        .collect();
    let before = rooms.len();
    let changes = plan(
        room_in,
        &unsorted,
        &vecs,
        &Hints {
            duplicates: &dups,
            closest: &closest,
        },
        th,
    );
    let ok = confident(&changes, items.len(), before);
    // The changes, in order, on a map of item -> room (`None`: merged away as a near-copy).
    let mut at: BTreeMap<String, Option<String>> = groups
        .iter()
        .flat_map(|g| g.item_ids.iter().map(|i| (i.clone(), Some(g.key.clone()))))
        .collect();
    let mut gone: HashSet<String> = HashSet::new();
    if ok {
        for c in &changes {
            match (c.kind.as_str(), &c.from) {
                ("duplicate", _) => c.item_ids.iter().for_each(|i| {
                    at.insert(i.clone(), None);
                }),
                ("move", _) => {
                    at.insert(c.item_ids[0].clone(), Some(c.to.clone()));
                }
                (_, Some(from)) => {
                    for r in at.values_mut() {
                        if r.as_deref() == Some(from.as_str()) {
                            *r = Some(c.to.clone());
                        }
                    }
                    gone.insert(from.clone());
                }
                _ => {}
            }
        }
    }
    let after = before - gone.len();
    let gone_n = changes
        .iter()
        .filter(|c| c.kind == "merge" || c.kind == "fold")
        .count();
    let summary = crate::tidy::summary(
        &changes,
        before as u64,
        (if ok {
            after
        } else {
            before.saturating_sub(gone_n)
        }) as u64,
    );
    let mut out = Proposed {
        changes: if ok { changes } else { vec![] },
        summary,
        confident: ok,
        ..Default::default()
    };
    for g in groups
        .iter()
        .filter(|g| g.key != UNSORTED && !gone.contains(&g.key))
    {
        out.rooms.push(ProposedRoom {
            id: g.key.clone(),
            name: g.name.clone(),
            kind: g.kind_guess.as_str().to_owned(),
            item_ids: at
                .iter()
                .filter(|(_, r)| r.as_deref() == Some(g.key.as_str()))
                .map(|(i, _)| i.clone())
                .collect(),
        });
    }
    out.unsorted = at
        .iter()
        .filter(|(_, r)| r.as_deref() == Some(UNSORTED))
        .map(|(i, _)| i.clone())
        .collect();
    Ok(out)
}

#[cfg(test)]
mod tests {
    //! Ahmed's import, made up: a vault named like one product holding every project's notes, 2,000
    //! AI-session transcripts that open with the same 3 KB of instructions, two employer rooms that
    //! are one project, and one real near-copy. No real text, path or note.
    use super::*;
    use brain_model::item::{Author, AuthorKind, Origin, SourceKind, hash_of};

    /// A bag of words hashed into 64 buckets: texts with the same words read alike, as in e5.
    struct Words;
    impl Embedder for Words {
        fn model_id(&self) -> &str {
            "fake-words"
        }
        fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
            Ok(texts
                .iter()
                .map(|t| {
                    let mut v = vec![0.0f32; 64];
                    v[0] = 0.01;
                    for w in brain_model::semantic::tokens(t) {
                        let h = w
                            .bytes()
                            .fold(7u64, |a, b| a.wrapping_mul(31).wrapping_add(b.into()));
                        v[(h % 63 + 1) as usize] += 1.0;
                    }
                    v
                })
                .collect())
        }
    }

    fn item(
        n: usize,
        kind: SourceKind,
        path: &str,
        hint: Option<&str>,
        title: &str,
        text: &str,
    ) -> Item {
        Item {
            item_id: format!("01JD{n:022}"),
            source_kind: kind,
            content_hash: hash_of(text),
            origin: Origin {
                device: "mac-1".into(),
                path: path.into(),
                range: None,
            },
            project_hint: hint.map(str::to_owned),
            author: Author {
                kind: AuthorKind::Person,
                name: "dev".into(),
            },
            title: title.into(),
            text: text.into(),
            links: vec![],
            started_at: format!("2026-10-{:02}T09:00:00Z", 1 + n % 28),
            ended_at: None,
        }
    }

    const WORDS: &[&str] = &[
        "lantern", "harbor", "copper", "meadow", "falcon", "quartz", "willow", "ember", "glacier",
        "orchid", "pebble", "thistle", "canyon", "saffron", "beacon", "juniper", "marble",
        "tundra", "velvet", "cobalt", "prairie", "sparrow", "granite", "nectar", "obsidian",
        "lagoon", "fennel", "ripple", "summit", "cinder", "hollow", "mosaic", "pylon", "quiver",
        "rustle", "sable",
    ];
    /// Project vocabulary: the room a note is about.
    const TOPIC: &[(&str, &str)] = &[
        ("ProjectA", "invoice ledger billing refund"),
        ("ProjectB", "garden seedling compost trellis"),
        ("ProjectC", "telescope orbit nebula lens"),
        ("HarborMotors", "dealer telephony callback voicemail"),
        ("harborauto", "dealer inventory listing showroom"),
    ];

    fn corpus() -> (Vec<Item>, String) {
        let pre: String = (0..45)
            .map(|i| {
                format!("Rule {i:02}: keep every change small, tested and reviewed by a person.\n")
            })
            .collect();
        assert!(pre.len() >= 3000);
        let first = pre.lines().next().unwrap().to_owned();
        let mut seed = 11u64;
        let mut word = move || {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1442695040888963407);
            WORDS[(seed >> 33) as usize % WORDS.len()]
        };
        let mut items = vec![];
        let mut n = 0;
        // 2,000 transcripts, one shared preamble, each its own work.
        for i in 0..2000 {
            let (p, topic) = TOPIC[i % TOPIC.len()];
            let work: Vec<String> = (0..14).map(|_| word().to_owned()).collect();
            let text = format!(
                "User: {pre}\nUser: {topic} session {i}: {} {}\n\nAssistant: Done.",
                work.join(" "),
                (0..6).map(|_| word()).collect::<Vec<_>>().join(" ")
            );
            n += 1;
            items.push(item(
                n,
                SourceKind::ClaudeCode,
                &format!("/u/.claude/projects/s{i}.jsonl"),
                Some(&format!("/u/Home/Projects/{p}/Repositories/app")),
                &first,
                &text,
            ));
        }
        // The vault, named like one product, holding notes of three projects and a few of its own.
        for (p, topic) in &TOPIC[..3] {
            for j in 0..20 {
                let text = format!(
                    "# {p} note {j}\n{topic} {}",
                    (0..30).map(|_| word()).collect::<Vec<_>>().join(" ")
                );
                n += 1;
                items.push(item(
                    n,
                    SourceKind::Vault,
                    &format!("/u/Ainkrad/WorkShop/{p}/Notes/n{j}.md"),
                    None,
                    &format!("{p} note {j}"),
                    &text,
                ));
            }
        }
        for j in 0..4 {
            n += 1;
            let text = format!(
                "# Daily {j}\nwalk {}",
                (0..20).map(|_| word()).collect::<Vec<_>>().join(" ")
            );
            items.push(item(
                n,
                SourceKind::Vault,
                &format!("/u/Ainkrad/Daily/d{j}.md"),
                None,
                &format!("Daily {j}"),
                &text,
            ));
        }
        // One real near-copy: the same long note saved twice, one word changed.
        let body: String = (0..60).map(|_| word()).collect::<Vec<_>>().join(" ");
        for (k, last) in ["draft", "final"].iter().enumerate() {
            n += 1;
            items.push(item(
                n,
                SourceKind::Vault,
                &format!("/u/Ainkrad/WorkShop/ProjectB/Plans/plan-{k}.md"),
                None,
                "ProjectB plan",
                &format!("# ProjectB plan\ngarden {body} {last}"),
            ));
        }
        (items, format!("01JD{n:022}"))
    }

    #[test]
    fn every_project_keeps_its_room_and_shared_preambles_are_no_duplicates() {
        let (items, newest) = corpus();
        let aliases: Aliases = [("harborauto".to_owned(), "HarborMotors".to_owned())].into();
        let p = propose(&items, &aliases, &Words, 2).unwrap();
        let room = |n: &str| {
            p.rooms.iter().find(|r| r.name == n).unwrap_or_else(|| {
                panic!(
                    "no room {n}: {:?}",
                    p.rooms.iter().map(|r| &r.name).collect::<Vec<_>>()
                )
            })
        };
        assert!(p.confident, "{:?}", p.summary);
        // Projects A, B, C: 400 transcripts each and their 20 vault notes (B: one near-copy merged).
        assert_eq!(room("ProjectA").item_ids.len(), 420);
        assert_eq!(room("ProjectC").item_ids.len(), 420);
        assert_eq!(
            room("ProjectB").item_ids.len(),
            421,
            "the kept copy of the plan"
        );
        // The alias: both employers' sessions in one room, never split by the employer guard.
        assert_eq!(room("HarborMotors").item_ids.len(), 800);
        assert!(p.rooms.iter().all(|r| r.name != "harborauto"));
        // Only the vault's own notes are filed under its name, and four are too few to be a place.
        assert!(
            p.rooms
                .iter()
                .all(|r| r.name != "Ainkrad" || r.item_ids.len() <= 4)
        );
        // Exactly one near-copy: the plan, never a transcript.
        let dups: Vec<&TidyChange> = p.changes.iter().filter(|c| c.kind == "duplicate").collect();
        assert_eq!(dups.len(), 1, "{dups:?}");
        assert_eq!(dups[0].to, newest);
        assert_eq!(dups[0].item_ids.len(), 1);
        assert!(
            p.changes
                .iter()
                .all(|c| c.kind != "merge" || c.from_name == c.to_name)
        );
    }

    #[test]
    fn the_guard_declines_a_tidy_that_would_collapse_the_proposal() {
        // 40 notes that are all one note with a word changed: 39 near-copies of 40 is not believable.
        let body: String = WORDS.iter().take(30).copied().collect::<Vec<_>>().join(" ");
        let items: Vec<Item> = (0..40)
            .map(|i| {
                item(
                    i,
                    SourceKind::Vault,
                    &format!("/u/Vault/WorkShop/Project{}/n{i}.md", i % 8),
                    None,
                    "note",
                    &format!("{body} {}", WORDS[i % WORDS.len()]),
                )
            })
            .collect();
        let p = propose(&items, &Aliases::new(), &Words, 1).unwrap();
        assert!(!p.confident);
        assert!(p.changes.is_empty());
        assert!(p.summary.duplicates_merged > 12, "{:?}", p.summary);
        assert_eq!(p.rooms.len(), 8, "as the rules made it");
        assert_eq!(p.rooms.iter().map(|r| r.item_ids.len()).sum::<usize>(), 40);
    }
}
