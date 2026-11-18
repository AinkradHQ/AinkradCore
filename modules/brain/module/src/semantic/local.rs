//! The local embedder now lives in `ainkrad-embed` (R2-01, one model per process). Brain keeps its
//! call sites through these re-exports; this file holds only the Brain-side loader and the benches.

pub use ainkrad_embed::local::{DEFAULT_DIR, FILES, Local, MODEL_ID, url};

/// Loads the shared model off the request path and hands it to the Brain when every file verifies.
/// A missing directory is normal (the installer's opt-in was not taken): the semantic step stays off.
pub fn load_in_background(b: &crate::Brain) {
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let dir = std::env::var_os("AINKRAD_BRAIN_MODEL_DIR")
        .map_or_else(|| std::path::PathBuf::from(DEFAULT_DIR), Into::into);
    if !dir.is_dir() {
        tracing::info!("semantic sorting is off: no model directory");
        return;
    }
    let b = b.clone();
    let rt2 = rt.clone();
    rt.spawn_blocking(move || match ainkrad_embed::shared(&dir) {
        Ok(m) => {
            if b.embedder().is_none() {
                b.set_embedder(m);
                tracing::info!("semantic sorting is on (local model loaded)");
                rt2.spawn(async move { b.resume_semantic().await });
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "semantic sorting is off: the model files did not verify")
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::Embedder;
    use std::path::Path;

    /// A made-up corpus shaped like a big AI-session import: `n` transcripts of 10 KB to 2 MB, one big
    /// room plus small ones, `unsorted` of them in Unsorted. Deterministic; no real data.
    pub(crate) fn corpus(
        n: usize,
        unsorted: usize,
    ) -> Vec<(brain_model::item::Item, Option<String>)> {
        use brain_model::item::{Author, AuthorKind, Item, Origin, SourceKind, hash_of};
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let syl = [
            "ka", "lo", "ver", "min", "tas", "ro", "qel", "dun", "ari", "sol", "pek", "zu",
        ];
        let words: Vec<String> = (0..2000)
            .map(|i| {
                (0..2 + i % 3)
                    .map(|k| syl[(i * 7 + k * 5 + i / 12) % syl.len()])
                    .collect()
            })
            .collect();
        (0..n)
            .map(|i| {
                let topic = (rnd() % 40) as usize;
                // log-uniform 10 KB .. 2 MB
                let len = (10_000.0 * 200f64.powf((rnd() % 1000) as f64 / 1000.0)) as usize;
                let mut text = String::with_capacity(len + 64);
                text.push_str("user: please continue the session on the task below.\n");
                while text.len() < len {
                    let w = if rnd() % 3 == 0 {
                        topic * 50 + (rnd() % 50) as usize
                    } else {
                        (rnd() % 2000) as usize
                    };
                    text.push_str(&words[w]);
                    text.push(if rnd() % 12 == 0 { '\n' } else { ' ' });
                }
                let item = Item {
                    item_id: format!("it{i:05}"),
                    source_kind: SourceKind::CoreTranscript,
                    content_hash: hash_of(&text),
                    origin: Origin {
                        device: "d".into(),
                        path: format!("/s/{i}.jsonl"),
                        range: None,
                    },
                    project_hint: None,
                    author: Author {
                        kind: AuthorKind::Agent,
                        name: "a".into(),
                    },
                    title: format!("Session {} {}", words[topic * 50], words[topic * 50 + 1]),
                    text,
                    links: vec![],
                    started_at: format!("2026-01-01T00:00:{:02}Z", i % 60),
                    ended_at: None,
                };
                let room = if i < unsorted {
                    None
                } else if i % 10 < 8 {
                    Some("big".to_owned())
                } else {
                    Some(format!("r{}", i % 34))
                };
                (item, room)
            })
            .collect()
    }

    /// The Review semantic step on a big made-up import, phase by phase:
    /// `AINKRAD_E5_DIR=<dir> BENCH_ITEMS=3000 BENCH_UNSORTED=500 cargo test --release -p brain-module
    /// --features semantic --lib bench_review_step -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn bench_review_step() {
        use crate::semantic::{Input, ProposalRef, Thresholds, VectorCache, run};
        let env = |k: &str, d: usize| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        let (n, u) = (env("BENCH_ITEMS", 3000), env("BENCH_UNSORTED", 500));
        let dir = std::env::var("AINKRAD_E5_DIR").expect("AINKRAD_E5_DIR");
        let t = std::time::Instant::now();
        let items = corpus(n, u);
        let mb = items.iter().map(|i| i.0.text.len()).sum::<usize>() >> 20;
        println!(
            "corpus: {n} items, {u} unsorted, {mb} MB, made in {:?}",
            t.elapsed()
        );
        let m = Local::load(Path::new(&dir)).unwrap();
        let texts: Vec<String> = items
            .iter()
            .map(|i| brain_model::semantic::embed_text(&i.0))
            .collect();
        let t = std::time::Instant::now();
        let enc = m.tok[0]
            .encode_batch(texts.iter().map(String::as_str).collect::<Vec<_>>(), true)
            .unwrap();
        println!(
            "tokenize (capped texts): {:?} ({} items)",
            t.elapsed(),
            enc.len()
        );
        let inputs: Vec<Input> = items
            .iter()
            .map(|(item, room)| Input {
                item,
                room: room.as_deref(),
                sketch: None,
            })
            .collect();
        let mut members: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
        for (i, r) in &items {
            if let Some(r) = r {
                members.entry(r).or_default().push(i.item_id.clone());
            }
        }
        let refs: Vec<ProposalRef> = members
            .iter()
            .map(|(name, ids)| ProposalRef {
                name,
                item_ids: ids,
            })
            .collect();
        let mut cache = VectorCache::default();
        // BENCH_VECS=<file>: reuse the vectors of an earlier bench (same corpus) to time the rest alone.
        let saved = std::env::var("BENCH_VECS").ok();
        if let Some(f) = saved.as_deref().filter(|f| Path::new(f).exists()) {
            let raw = std::fs::read(f).unwrap();
            for ((it, _), v) in items.iter().zip(raw.chunks(384 * 4)) {
                let v = v
                    .chunks(4)
                    .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
                    .collect();
                cache.put(m.model_id(), &it.content_hash, v);
            }
        }
        let t = std::time::Instant::now();
        let s = run(&m, &mut cache, &inputs, &refs, Thresholds::for_strength(1)).unwrap();
        let all = t.elapsed();
        if let Some(f) = saved.as_deref().filter(|f| !Path::new(f).exists()) {
            let raw: Vec<u8> = items
                .iter()
                .flat_map(|(it, _)| cache.get(m.model_id(), &it.content_hash).unwrap().clone())
                .flat_map(f32::to_le_bytes)
                .collect();
            std::fs::write(f, raw).unwrap();
        }
        let t = std::time::Instant::now();
        let s2 = run(&m, &mut cache, &inputs, &refs, Thresholds::for_strength(1)).unwrap();
        let math = t.elapsed();
        println!(
            "run: {all:?} total, {math:?} without embedding; {} duplicate groups, {} topic rooms, {} merges",
            s.duplicates.len(),
            s.rooms.len(),
            s.merges.len()
        );
        assert_eq!(s.rooms, s2.rooms);
    }
}
