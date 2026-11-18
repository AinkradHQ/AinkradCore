//! The shared local embedder (R2-01): one pinned model per process, used by Brain and Lore.
//! The trait is always here; the model (`local`) is behind feature `semantic`.

/// A local sentence embedder. Returns one vector per text, in order.
pub trait Embedder: Send + Sync {
    fn model_id(&self) -> &str;
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String>;
    /// How many threads `embed` may use (default one). A model that cannot limit itself ignores it.
    fn set_threads(&self, _n: usize) {}
    /// How many tokens of each item `embed` reads: 128 (default) or 256. A fake may ignore it.
    fn set_max_tokens(&self, _n: usize) {}
}

#[cfg(feature = "semantic")]
pub mod local;
#[cfg(feature = "semantic")]
pub use local::{Local, MODEL_ID, shared};
