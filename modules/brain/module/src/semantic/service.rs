//! The Brain's shared semantic service: one embedder, one persistent vector store (by model id and
//! content hash) and one background worker with a queue. The import Review is its first caller;
//! later callers (matching a save to a room, duplicate check on save, recall, search) use the
//! methods on [`Brain`] below and never touch the model or the store directly.
//!
//! The worker runs one job at a time, so with the default of one embedding thread (the
//! `semantic.threads` setting) the Core stays responsive on a small host.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

use ainkrad_core_server::api::v1::ApiError;
use ainkrad_core_server::store::modsettings::ModuleSettings;
use tokio::sync::{mpsc, oneshot};

use super::{Embedder, VectorCache};
use crate::{Brain, code};

type Job = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Default)]
pub struct Service {
    embedder: Mutex<Option<Arc<dyn Embedder>>>,
    cache: Arc<Mutex<VectorCache>>,
    queue: OnceLock<mpsc::UnboundedSender<Job>>,
}

impl Service {
    pub fn embedder(&self) -> Option<Arc<dyn Embedder>> {
        self.embedder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_embedder(&self, e: Arc<dyn Embedder>) {
        *self.embedder.lock().unwrap_or_else(|x| x.into_inner()) = Some(e);
    }

    pub(crate) fn cache(&self) -> &Arc<Mutex<VectorCache>> {
        &self.cache
    }

    /// Runs `job` on the one background worker, after the jobs queued before it. Needs a runtime.
    pub(crate) fn enqueue(&self, job: impl Future<Output = ()> + Send + 'static) {
        let tx = self.queue.get_or_init(|| {
            let (tx, mut rx) = mpsc::unbounded_channel::<Job>();
            tokio::spawn(async move {
                while let Some(j) = rx.recv().await {
                    j.await;
                }
            });
            tx
        });
        let _ = tx.send(Box::pin(job));
    }
}

/// The `k` candidates most like `query` (unit vectors, so a dot product is the cosine), best first.
pub fn similar(query: &[f32], candidates: &[(String, Vec<f32>)], k: usize) -> Vec<(String, f32)> {
    let mut scored: Vec<(String, f32)> = candidates
        .iter()
        .map(|(id, v)| (id.clone(), brain_model::semantic::dot(query, v)))
        .collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1));
    scored.truncate(k);
    scored
}

impl Brain {
    /// Hands the model the limits the person chose: `semantic.threads` and `semantic.max_tokens`.
    pub(crate) async fn apply_threads(&self, app: &ainkrad_core_server::api::App) {
        let n = ModuleSettings::of(self)
            .get(&app.pool, "semantic.threads")
            .await
            .unwrap_or(1);
        let tokens = ModuleSettings::of(self)
            .get(&app.pool, "semantic.max_tokens")
            .await
            .unwrap_or(128);
        if let Some(e) = self.embedder() {
            e.set_threads(usize::try_from(n).unwrap_or(1).max(1));
            e.set_max_tokens(if tokens > 128 { 256 } else { 128 });
        }
    }

    /// Stored or cached vectors by content hash; nothing is embedded. Items not seen are absent.
    pub async fn vectors_for(
        &self,
        hashes: &[String],
    ) -> Result<HashMap<String, Vec<f32>>, ApiError> {
        let (Some(app), Some(e)) = (self.inner.app.get(), self.embedder()) else {
            return Err(code(503, "semantic_off", "no local model"));
        };
        let model = e.model_id().to_owned();
        self.fill_from_store(app, &model, hashes).await?;
        let c = self
            .inner
            .sem
            .cache()
            .lock()
            .unwrap_or_else(|x| x.into_inner());
        Ok(hashes
            .iter()
            .filter_map(|h| c.get(&model, h).map(|v| (h.clone(), v.clone())))
            .collect())
    }

    /// Vectors for `(content hash, text)` pairs, in order: from memory, then the encrypted store,
    /// then the model (on the background worker, and saved). Nothing leaves this machine.
    pub async fn embed_texts(&self, items: &[(String, String)]) -> Result<Vec<Vec<f32>>, ApiError> {
        let (Some(app), Some(e)) = (self.inner.app.get(), self.embedder()) else {
            return Err(code(503, "semantic_off", "no local model"));
        };
        let (b, app, items) = (self.clone(), app.clone(), items.to_vec());
        let (tx, rx) = oneshot::channel();
        self.inner.sem.enqueue(async move {
            let _ = tx.send(b.embed_now(&app, e, &items).await);
        });
        rx.await
            .map_err(|_| code(500, "semantic_failed", "the worker stopped"))?
    }

    async fn embed_now(
        &self,
        app: &ainkrad_core_server::api::App,
        e: Arc<dyn Embedder>,
        items: &[(String, String)],
    ) -> Result<Vec<Vec<f32>>, ApiError> {
        self.apply_threads(app).await;
        let model = e.model_id().to_owned();
        let hashes: Vec<String> = items.iter().map(|i| i.0.clone()).collect();
        self.fill_from_store(app, &model, &hashes).await?;
        let cache = self.inner.sem.cache().clone();
        let todo: Vec<(String, String)> = {
            let c = cache.lock().unwrap_or_else(|x| x.into_inner());
            let mut seen = std::collections::HashSet::new();
            items
                .iter()
                .filter(|i| c.get(&model, &i.0).is_none() && seen.insert(i.0.clone()))
                .cloned()
                .collect()
        };
        if !todo.is_empty() {
            let texts: Vec<String> = todo.iter().map(|i| i.1.clone()).collect();
            let vecs = tokio::task::spawn_blocking({
                let e = e.clone();
                move || e.embed(&texts)
            })
            .await
            .map_err(|x| code(500, "semantic_failed", x.to_string()))?
            .map_err(|x| code(500, "semantic_failed", x))?;
            if vecs.len() != todo.len() {
                return Err(code(500, "semantic_failed", "the wrong number of vectors"));
            }
            let rows: Vec<(String, Vec<f32>)> = todo
                .iter()
                .zip(vecs)
                .map(|(i, v)| (i.0.clone(), super::normalized(v)))
                .collect();
            {
                let mut c = cache.lock().unwrap_or_else(|x| x.into_inner());
                for (h, v) in &rows {
                    c.put(&model, h, v.clone());
                }
            }
            crate::vectors::save(app, self, &model, &rows).await?;
        }
        let c = cache.lock().unwrap_or_else(|x| x.into_inner());
        Ok(items
            .iter()
            .map(|i| c.get(&model, &i.0).cloned().unwrap_or_default())
            .collect())
    }

    /// Reads from the store the vectors of `hashes` that memory lacks.
    pub(crate) async fn fill_from_store(
        &self,
        app: &ainkrad_core_server::api::App,
        model: &str,
        hashes: &[String],
    ) -> Result<(), ApiError> {
        let missing: Vec<String> = {
            let c = self
                .inner
                .sem
                .cache()
                .lock()
                .unwrap_or_else(|x| x.into_inner());
            let mut seen = std::collections::HashSet::new();
            hashes
                .iter()
                .filter(|h| c.get(model, h).is_none() && seen.insert((*h).clone()))
                .cloned()
                .collect()
        };
        let stored = crate::vectors::load(app, self, model, &missing).await?;
        let mut c = self
            .inner
            .sem
            .cache()
            .lock()
            .unwrap_or_else(|x| x.into_inner());
        for (h, v) in stored {
            c.put(model, &h, v);
        }
        Ok(())
    }
}
