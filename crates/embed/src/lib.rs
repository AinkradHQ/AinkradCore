//! The shared local embedder (R2-01): one pinned model per process, used by Brain and Lore.
//! The trait is always here; the model (`local`) is behind feature `semantic`.

/// A local sentence embedder. Returns one vector per text, in order.
pub trait Embedder: Send + Sync {
    fn model_id(&self) -> &str;
    /// Vectors of stored text ("passage").
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String>;
    /// Vectors of a search question ("query"): e5 is trained with a different prefix for it. A model
    /// without that distinction (a fake) keeps this default.
    fn embed_query(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        self.embed(texts)
    }
    /// How many threads `embed` may use (default one). A model that cannot limit itself ignores it.
    fn set_threads(&self, _n: usize) {}
    /// How many tokens of each item `embed` reads: 128 (default) or 256. A fake may ignore it.
    fn set_max_tokens(&self, _n: usize) {}
}

/// What e5 wants in front of a text: `passage: ` for stored text, `query: ` for a search question.
/// The same text embeds differently under each, so a query must never use the passage prefix.
pub fn prefixed(query: bool, text: &str) -> String {
    format!("{}: {text}", if query { "query" } else { "passage" })
}

#[cfg(test)]
mod tests {
    use super::prefixed;

    #[test]
    fn a_query_and_a_passage_of_the_same_text_are_prefixed_differently() {
        assert_eq!(prefixed(true, "x"), "query: x");
        assert_eq!(prefixed(false, "x"), "passage: x");
        assert_ne!(prefixed(true, "x"), prefixed(false, "x"));
    }
}

#[cfg(feature = "semantic")]
pub mod local;
#[cfg(feature = "semantic")]
pub use local::{Local, MODEL_ID, shared};
