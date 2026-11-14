//! The local embedder: `intfloat/multilingual-e5-small` (MIT, 384 dimensions, English + Arabic + 90
//! more languages) on `candle` (pure Rust, CPU). Feature `semantic`.
//!
//! The model files are NOT downloaded here. An installer fetches the three pinned files once; this
//! loader refuses any file whose SHA-256 differs from the pin, so a swapped or truncated file never runs.

use std::path::Path;

use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config};
use sha2::{Digest, Sha256};
use tokenizers::{PaddingParams, Tokenizer, TruncationParams};

use super::Embedder;

pub const MODEL_ID: &str = "intfloat/multilingual-e5-small@614241f";
const REV: &str = "614241f622f53c4eeff9890bdc4f31cfecc418b3";
/// (file, SHA-256, bytes). Fetch each from `https://huggingface.co/intfloat/multilingual-e5-small/resolve/<REV>/<file>`.
pub const FILES: [(&str, &str, u64); 3] = [
    (
        "config.json",
        "69137736cab8b8903a07fe8afaafdda25aac55415a12a55d1bffa9f581abf959",
        655,
    ),
    (
        "tokenizer.json",
        "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39",
        17_082_730,
    ),
    (
        "model.safetensors",
        "1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477",
        470_641_600,
    ),
];
/// Tokens kept per item: 128 is about twice as fast as 256 for a little less of each long item.
const DEFAULT_TOKENS: usize = 128;
const BATCH: usize = 16;

/// Where the installer puts the three files (root-owned, read-only to the Core).
pub const DEFAULT_DIR: &str = "/var/lib/ainkrad/core/models/e5-small";

/// Loads the model off the request path and hands it to the Brain when every file verifies.
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
    rt.spawn_blocking(move || match Local::load(&dir) {
        Ok(m) => {
            if b.embedder().is_none() {
                b.set_embedder(std::sync::Arc::new(m));
                tracing::info!("semantic sorting is on (local model loaded)");
                rt2.spawn(async move { b.resume_semantic().await });
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "semantic sorting is off: the model files did not verify")
        }
    });
}

pub fn url(file: &str) -> String {
    format!("https://huggingface.co/intfloat/multilingual-e5-small/resolve/{REV}/{file}")
}

pub struct Local {
    model: BertModel,
    /// The tokenizer cut at 128 and at 256 tokens; `tokens` picks one per call.
    tok: [Tokenizer; 2],
    tokens: std::sync::atomic::AtomicUsize,
    threads: std::sync::atomic::AtomicUsize,
    /// A rayon pool of `threads` threads for the matrix work, rebuilt when the setting changes.
    pool: std::sync::Mutex<Option<(usize, std::sync::Arc<rayon::ThreadPool>)>>,
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// A small file, read whole and checked against its pin.
fn verified(dir: &Path, i: usize) -> Result<Vec<u8>, String> {
    let (name, sha, _) = FILES[i];
    let bytes = std::fs::read(dir.join(name)).map_err(|e| format!("{name}: {e}"))?;
    if hex(&Sha256::digest(&bytes)) != sha {
        return Err(format!("{name}: SHA-256 does not match the pin"));
    }
    Ok(bytes)
}

/// The weights: hashed in chunks (never held whole), then read tensor by tensor from the file, so
/// the peak is the tensors plus one of them rather than the file plus the tensors.
fn weights(dir: &Path) -> Result<VarBuilder<'static>, String> {
    use std::io::{Read, Seek, SeekFrom};
    let (name, sha, _) = FILES[2];
    let path = dir.join(name);
    let err = |e: std::io::Error| format!("{name}: {e}");
    let mut f = std::fs::File::open(&path).map_err(err)?;
    let (mut h, mut buf) = (Sha256::new(), vec![0u8; 1 << 20]);
    loop {
        let n = f.read(&mut buf).map_err(err)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    drop(buf);
    if hex(&h.finalize()) != sha {
        return Err(format!("{name}: SHA-256 does not match the pin"));
    }
    f.seek(SeekFrom::Start(0)).map_err(err)?;
    let tensors = tensors(&mut f, name)?;
    Ok(VarBuilder::from_tensors(tensors, DType::F32, &Device::Cpu))
}

/// safetensors: u64 LE header length, a JSON header, then the raw tensors. Every tensor must be F32,
/// except `*position_ids`: an I64 buffer the checkpoint carries but `BertModel` never reads (it builds
/// the position ids itself), so it is skipped rather than refused.
fn tensors<R: std::io::Read + std::io::Seek>(
    f: &mut R,
    name: &str,
) -> Result<std::collections::HashMap<String, Tensor>, String> {
    use std::io::SeekFrom;
    let err = |e: std::io::Error| format!("{name}: {e}");
    let mut len = [0u8; 8];
    f.read_exact(&mut len).map_err(err)?;
    let len = usize::try_from(u64::from_le_bytes(len)).map_err(|e| e.to_string())?;
    if len > 16 << 20 {
        return Err(format!("{name}: the header is too large"));
    }
    let mut head = vec![0u8; len];
    f.read_exact(&mut head).map_err(err)?;
    let head: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&head).map_err(|e| e.to_string())?;
    let mut tensors = std::collections::HashMap::new();
    for (k, v) in head.iter().filter(|(k, _)| *k != "__metadata__") {
        let bad = || format!("{name}: tensor {k} is not in the expected form");
        if k.ends_with("position_ids") {
            continue;
        }
        if v["dtype"] != "F32" {
            return Err(bad());
        }
        let shape: Vec<usize> = v["shape"]
            .as_array()
            .ok_or_else(bad)?
            .iter()
            .map(|d| d.as_u64().map(|d| d as usize).ok_or_else(bad))
            .collect::<Result<_, _>>()?;
        let off = v["data_offsets"].as_array().ok_or_else(bad)?;
        let (a, b) = (
            off.first().and_then(|x| x.as_u64()).ok_or_else(bad)?,
            off.get(1).and_then(|x| x.as_u64()).ok_or_else(bad)?,
        );
        let mut raw = vec![0u8; usize::try_from(b.saturating_sub(a)).map_err(|e| e.to_string())?];
        f.seek(SeekFrom::Start(8 + len as u64 + a)).map_err(err)?;
        f.read_exact(&mut raw).map_err(err)?;
        let t = Tensor::from_raw_buffer(&raw, DType::F32, &shape, &Device::Cpu)
            .map_err(|e| e.to_string())?;
        tensors.insert(k.clone(), t);
    }
    Ok(tensors)
}

impl Local {
    pub fn load(dir: &Path) -> Result<Self, String> {
        let cfg: Config = serde_json::from_slice(&verified(dir, 0)?).map_err(|e| e.to_string())?;
        let bytes = verified(dir, 1)?;
        let cut = |max_length: usize| -> Result<Tokenizer, String> {
            let mut t = Tokenizer::from_bytes(&bytes).map_err(|e| e.to_string())?;
            t.with_padding(Some(PaddingParams::default()));
            t.with_truncation(Some(TruncationParams {
                max_length,
                ..Default::default()
            }))
            .map_err(|e| e.to_string())?;
            Ok(t)
        };
        let tok = [cut(128)?, cut(256)?];
        let model = BertModel::load(weights(dir)?, &cfg).map_err(|e| e.to_string())?;
        Ok(Self {
            model,
            tok,
            tokens: DEFAULT_TOKENS.into(),
            threads: 1.into(),
            pool: std::sync::Mutex::new(None),
        })
    }

    fn batch(&self, texts: &[&str]) -> candle_core::Result<Vec<Vec<f32>>> {
        let tok =
            &self.tok[usize::from(self.tokens.load(std::sync::atomic::Ordering::SeqCst) > 128)];
        let enc = tok
            .encode_batch(texts.to_vec(), true)
            .map_err(|e| candle_core::Error::Msg(e.to_string()))?;
        let d = &Device::Cpu;
        let ids = Tensor::new(
            enc.iter().map(|e| e.get_ids().to_vec()).collect::<Vec<_>>(),
            d,
        )?;
        let mask = Tensor::new(
            enc.iter()
                .map(|e| e.get_attention_mask().to_vec())
                .collect::<Vec<_>>(),
            d,
        )?;
        let h = self.model.forward(&ids, &ids.zeros_like()?, Some(&mask))?;
        let m = mask.to_dtype(DType::F32)?.unsqueeze(2)?;
        // mean over the real tokens only; `normalized` in the caller makes it unit length
        h.broadcast_mul(&m)?
            .sum(1)?
            .broadcast_div(&m.sum(1)?)?
            .to_vec2::<f32>()
    }
}

impl Embedder for Local {
    fn model_id(&self) -> &str {
        MODEL_ID
    }

    fn set_max_tokens(&self, n: usize) {
        self.tokens.store(n, std::sync::atomic::Ordering::SeqCst);
    }

    fn set_threads(&self, n: usize) {
        self.threads
            .store(n.max(1), std::sync::atomic::Ordering::SeqCst);
    }

    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        let n = self.threads.load(std::sync::atomic::Ordering::SeqCst);
        let pool = {
            let mut g = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            if g.as_ref().is_none_or(|(have, _)| *have != n) {
                let p = rayon::ThreadPoolBuilder::new()
                    .num_threads(n)
                    .build()
                    .map_err(|e| e.to_string())?;
                *g = Some((n, std::sync::Arc::new(p)));
            }
            g.as_ref().map(|(_, p)| p.clone()).expect("pool")
        };
        // Candle's matrix work uses the current rayon pool, so `install` bounds it to `n` threads.
        pool.install(|| self.embed_inner(texts))
    }
}

impl Local {
    fn embed_inner(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        // Sorted by length so a batch pads little; the order is restored at the end.
        let mut order: Vec<usize> = (0..texts.len()).collect();
        order.sort_by_key(|&i| texts[i].len());
        let mut out = vec![Vec::new(); texts.len()];
        for chunk in order.chunks(BATCH) {
            let prefixed: Vec<String> = chunk
                .iter()
                .map(|&i| format!("passage: {}", texts[i]))
                .collect();
            let refs: Vec<&str> = prefixed.iter().map(String::as_str).collect();
            for (&i, v) in chunk
                .iter()
                .zip(self.batch(&refs).map_err(|e| e.to_string())?)
            {
                out[i] = v;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny safetensors file shaped like the real checkpoint: an I64 `position_ids` plus F32 tensors.
    fn file(extra: &str) -> Vec<u8> {
        let head = format!(
            r#"{{"__metadata__":{{"format":"pt"}},"embeddings.position_ids":{{"dtype":"I64","shape":[1,2],"data_offsets":[0,16]}},"w":{{"dtype":"F32","shape":[2],"data_offsets":[16,24]}}{extra}}}"#
        );
        let mut b = (head.len() as u64).to_le_bytes().to_vec();
        b.extend(head.as_bytes());
        b.extend([0i64, 1].iter().flat_map(|x| x.to_le_bytes()));
        b.extend([1.5f32, -2.0].iter().flat_map(|x| x.to_le_bytes()));
        b.extend([0u8; 8]);
        b
    }

    /// The real e5-small file stores `embeddings.position_ids` as I64; it must load (skipped), not refuse.
    #[test]
    fn skips_the_i64_position_ids_and_keeps_the_rest_strict() {
        let t = tensors(&mut std::io::Cursor::new(file("")), "m").unwrap();
        assert_eq!(t.len(), 1);
        assert!(!t.contains_key("embeddings.position_ids"));
        assert_eq!(t["w"].to_vec1::<f32>().unwrap(), [1.5, -2.0]);
        // Any other non-F32 tensor is still refused.
        let e = tensors(
            &mut std::io::Cursor::new(file(
                r#","x":{"dtype":"I64","shape":[1],"data_offsets":[24,32]}"#,
            )),
            "m",
        )
        .unwrap_err();
        assert!(e.contains("tensor x is not in the expected form"), "{e}");
        // Offsets past the end are still caught.
        let e = tensors(
            &mut std::io::Cursor::new(file(
                r#","y":{"dtype":"F32","shape":[2],"data_offsets":[24,40]}"#,
            )),
            "m",
        );
        assert!(e.is_err());
    }

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

    /// Needs the three pinned files: `AINKRAD_E5_DIR=<dir> cargo test -p brain-module --features semantic -- --ignored`.
    #[test]
    #[ignore]
    fn real_model_ranks_by_meaning_across_languages() {
        let dir = std::env::var("AINKRAD_E5_DIR").expect("AINKRAD_E5_DIR");
        let t0 = std::time::Instant::now();
        let m = Local::load(Path::new(&dir)).unwrap();
        println!("loaded in {:?}", t0.elapsed());
        let t = |s: &str| s.to_owned();
        let v = m
            .embed(&[
                t("Invoice for the customer, payment overdue"),
                t("Customer billing: unpaid invoice reminder"),
                t("فاتورة العميل متأخرة السداد"),
                t("Kubernetes rollout of the new deployment failed"),
            ])
            .unwrap()
            .into_iter()
            .map(brain_model::semantic::normalized)
            .collect::<Vec<_>>();
        assert!(v.iter().all(|x| x.len() == 384));
        let s = |a: usize, b: usize| brain_model::semantic::dot(&v[a], &v[b]);
        println!(
            "en-en {:.3} en-ar {:.3} en-ops {:.3} ar-ops {:.3}",
            s(0, 1),
            s(0, 2),
            s(0, 3),
            s(2, 3)
        );
        assert!(s(0, 1) > s(0, 3) && s(0, 2) > s(0, 3) && s(0, 2) > s(2, 3));
    }
}
