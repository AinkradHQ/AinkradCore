//! Local semantic help for sorting imported items: duplicates, topic rooms for Unsorted, merge hints.
//! Everything runs inside this process on this machine (the embedder is a local model file); no item
//! text leaves it, and every output is a suggestion the person approves. Wiring: see the PR.

use std::collections::HashMap;
use std::time::Instant;

use brain_model::item::Item;
pub use brain_model::semantic::MIN_CLUSTER;
use brain_model::semantic::{
    CLUSTER_THRESHOLD, DUP_THRESHOLD, DuplicateGroup, Entry, MERGE_THRESHOLD, MergeSuggestion,
    SuggestedRoom, duplicates, eligible, embed_text, merge_suggestions, normalized, suggest_rooms,
};
use serde_json::json;
use sqlx::SqliteConnection;

/// A local sentence embedder. Returns one unit vector per text, in order.
pub trait Embedder: Send + Sync {
    fn model_id(&self) -> &str;
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String>;
}

/// The cut-offs a run uses: duplicates, topic rooms, merge hints. Higher means fewer suggestions.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub dup: f32,
    pub cluster: f32,
    pub merge: f32,
}

impl Thresholds {
    /// `semantic.strength`: 0 low (few, sure suggestions), 1 normal (the engine's defaults), 2 high (more).
    pub fn for_strength(strength: i64) -> Self {
        match strength {
            0 => Self {
                dup: 0.97,
                cluster: 0.91,
                merge: 0.95,
            },
            2 => Self {
                dup: 0.93,
                cluster: 0.85,
                merge: 0.90,
            },
            _ => Self {
                dup: DUP_THRESHOLD,
                cluster: CLUSTER_THRESHOLD,
                merge: MERGE_THRESHOLD,
            },
        }
    }
}

/// Vectors by `content_hash`, so an unchanged item is embedded once.
/// ponytail: in memory; persist as a `brain_item_vectors(content_hash, model, vector)` table when
/// re-embedding the corpus per run becomes slow.
#[derive(Default)]
pub struct VectorCache(HashMap<(String, String), Vec<f32>>);

impl VectorCache {
    pub fn get(&self, model: &str, hash: &str) -> Option<&Vec<f32>> {
        self.0.get(&(model.to_owned(), hash.to_owned()))
    }
    pub fn put(&mut self, model: &str, hash: &str, v: Vec<f32>) {
        self.0.insert((model.to_owned(), hash.to_owned()), v);
    }
    /// Drops an item's vector under every model.
    pub fn forget(&mut self, hash: &str) {
        self.0.retain(|k, _| k.1 != hash);
    }
}

pub struct Input<'a> {
    pub item: &'a Item,
    /// The room the item is in, `None` for Unsorted.
    pub room: Option<&'a str>,
}

/// Deterministic proposals to compare for merging: name and member item ids.
pub struct ProposalRef<'a> {
    pub name: &'a str,
    pub item_ids: &'a [String],
}

#[derive(Debug, Default)]
pub struct Suggestions {
    pub duplicates: Vec<DuplicateGroup>,
    pub rooms: Vec<SuggestedRoom>,
    pub merges: Vec<MergeSuggestion>,
    pub stats: RunStats,
}

/// What the audit row holds: ids and counts, never text.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RunStats {
    pub model: String,
    pub items: usize,
    pub embedded: usize,
    pub duration_ms: u64,
}

/// One run. Refused items are dropped before anything is embedded. Cached vectors are reused.
pub fn run(
    embedder: &dyn Embedder,
    cache: &mut VectorCache,
    inputs: &[Input],
    proposals: &[ProposalRef],
    th: Thresholds,
) -> Result<Suggestions, String> {
    let t = Instant::now();
    let model = embedder.model_id().to_owned();
    let kept: Vec<&Input> = inputs.iter().filter(|i| eligible(i.item)).collect();
    let missing: Vec<&Input> = kept
        .iter()
        .filter(|i| {
            !cache
                .0
                .contains_key(&(model.clone(), i.item.content_hash.clone()))
        })
        .copied()
        .collect();
    let mut seen = std::collections::HashSet::new();
    let missing: Vec<&Input> = missing
        .into_iter()
        .filter(|i| seen.insert(i.item.content_hash.as_str()))
        .collect();
    if !missing.is_empty() {
        let texts: Vec<String> = missing.iter().map(|i| embed_text(i.item)).collect();
        let vecs = embedder.embed(&texts)?;
        if vecs.len() != texts.len() {
            return Err("embedder returned the wrong number of vectors".into());
        }
        for (i, v) in missing.iter().zip(vecs) {
            cache
                .0
                .insert((model.clone(), i.item.content_hash.clone()), normalized(v));
        }
    }
    let entries: Vec<Entry> = kept
        .iter()
        .map(|i| Entry {
            item: i.item,
            room: i.room,
            vector: &cache.0[&(model.clone(), i.item.content_hash.clone())],
        })
        .collect();
    let rooms = suggest_rooms(&entries, th.cluster, MIN_CLUSTER);
    let by_id: HashMap<&str, &[f32]> = entries
        .iter()
        .map(|e| (e.item.item_id.as_str(), e.vector))
        .collect();
    let mut cents: Vec<(String, Vec<f32>)> = proposals
        .iter()
        .filter_map(|p| centroid(p.item_ids, &by_id).map(|c| (p.name.to_owned(), c)))
        .collect();
    cents.extend(rooms.iter().map(|r| (r.name.clone(), r.centroid.clone())));
    let refs: Vec<(&str, &[f32])> = cents
        .iter()
        .map(|(n, c)| (n.as_str(), c.as_slice()))
        .collect();
    Ok(Suggestions {
        duplicates: duplicates(&entries, th.dup),
        merges: merge_suggestions(&refs, th.merge),
        rooms,
        stats: RunStats {
            model,
            items: kept.len(),
            embedded: missing.len(),
            duration_ms: t.elapsed().as_millis() as u64,
        },
    })
}

fn centroid(ids: &[String], by_id: &HashMap<&str, &[f32]>) -> Option<Vec<f32>> {
    let mut sum: Option<Vec<f32>> = None;
    for v in ids.iter().filter_map(|i| by_id.get(i.as_str())) {
        let s = sum.get_or_insert_with(|| vec![0.0; v.len()]);
        s.iter_mut().zip(*v).for_each(|(a, b)| *a += b);
    }
    sum.map(normalized)
}

/// One audit row per run: model id, item counts and duration. Never item text.
pub async fn audit(conn: &mut SqliteConnection, s: &RunStats) -> Result<(), sqlx::Error> {
    crate::record(
        conn,
        "brain.semantic.run",
        json!({"model": s.model, "items": s.items, "embedded": s.embedded, "duration_ms": s.duration_ms}),
        None,
    )
    .await
}

#[cfg(feature = "semantic")]
pub mod local;

#[cfg(test)]
mod tests {
    use super::*;
    use brain_model::item::{Author, AuthorKind, Origin, SourceKind, hash_of};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Fake embedder: a vector per topic word, so tests need no model.
    struct Fake(AtomicUsize);
    impl Embedder for Fake {
        fn model_id(&self) -> &str {
            "fake"
        }
        fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
            self.0.fetch_add(texts.len(), Ordering::SeqCst);
            Ok(texts
                .iter()
                .map(|t| {
                    let k = if t.contains("invoice") {
                        0
                    } else if t.contains("deploy") {
                        2
                    } else {
                        4
                    };
                    let mut v = vec![0.0; 6];
                    v[k] = 1.0;
                    v[k + 1] = 0.01 * (t.len() % 7) as f32;
                    v
                })
                .collect())
        }
    }

    fn item(id: &str, text: &str, path: &str) -> Item {
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
            title: text.into(),
            text: text.into(),
            links: vec![],
            started_at: "2026-01-01T00:00:00Z".into(),
            ended_at: None,
        }
    }

    #[test]
    fn run_skips_refused_items_caches_and_suggests() {
        let its: Vec<Item> = vec![
            item("a", "invoice one", "/a.md"),
            item("b", "invoice two!", "/b.md"),
            item("c", "invoice three!!", "/c.md"),
            item("secret", "invoice key", "/home/.env"),
            item("d", "deploy x", "/d.md"),
        ];
        let inputs: Vec<Input> = its.iter().map(|item| Input { item, room: None }).collect();
        let f = Fake(AtomicUsize::new(0));
        let mut cache = VectorCache::default();
        let s = run(&f, &mut cache, &inputs, &[], Thresholds::for_strength(1)).unwrap();
        assert_eq!(
            f.0.load(Ordering::SeqCst),
            4,
            "the refused item is never embedded"
        );
        assert_eq!(s.stats.items, 4);
        assert_eq!(s.rooms.len(), 1);
        assert!(!s.rooms[0].item_ids.contains(&"secret".to_owned()));
        run(&f, &mut cache, &inputs, &[], Thresholds::for_strength(1)).unwrap();
        assert_eq!(f.0.load(Ordering::SeqCst), 4, "the second run is all cache");
    }
}
