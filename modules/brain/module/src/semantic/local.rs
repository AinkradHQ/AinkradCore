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
const MAX_TOKENS: usize = 256;
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
    rt.spawn_blocking(move || match Local::load(&dir) {
        Ok(m) => {
            if b.embedder().is_none() {
                b.set_embedder(std::sync::Arc::new(m));
                tracing::info!("semantic sorting is on (local model loaded)");
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
    tok: Tokenizer,
}

fn verified(dir: &Path, i: usize) -> Result<Vec<u8>, String> {
    let (name, sha, _) = FILES[i];
    let bytes = std::fs::read(dir.join(name)).map_err(|e| format!("{name}: {e}"))?;
    let got: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if got != sha {
        return Err(format!("{name}: SHA-256 does not match the pinned file"));
    }
    Ok(bytes)
}

impl Local {
    pub fn load(dir: &Path) -> Result<Self, String> {
        let cfg: Config = serde_json::from_slice(&verified(dir, 0)?).map_err(|e| e.to_string())?;
        let mut tok = Tokenizer::from_bytes(verified(dir, 1)?).map_err(|e| e.to_string())?;
        tok.with_padding(Some(PaddingParams::default()));
        tok.with_truncation(Some(TruncationParams {
            max_length: MAX_TOKENS,
            ..Default::default()
        }))
        .map_err(|e| e.to_string())?;
        // No mmap (the crate forbids unsafe): the bytes are read, checked and copied once.
        let vb = VarBuilder::from_buffered_safetensors(verified(dir, 2)?, DType::F32, &Device::Cpu)
            .map_err(|e| e.to_string())?;
        let model = BertModel::load(vb, &cfg).map_err(|e| e.to_string())?;
        Ok(Self { model, tok })
    }

    fn batch(&self, texts: &[&str]) -> candle_core::Result<Vec<Vec<f32>>> {
        let enc = self
            .tok
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

    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
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

    /// Needs the three pinned files: `AINKRAD_E5_DIR=<dir> cargo test -p brain-module --features semantic -- --ignored`.
    #[test]
    #[ignore]
    fn real_model_ranks_by_meaning_across_languages() {
        let dir = std::env::var("AINKRAD_E5_DIR").expect("AINKRAD_E5_DIR");
        let m = Local::load(Path::new(&dir)).unwrap();
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
