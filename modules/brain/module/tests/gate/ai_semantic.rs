//! `brainAiSearch` by meaning, with a fake embedder: a vector is an angle read from `ang=NN`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::modsettings::ModuleSettings;
use brain_module::Brain;
use brain_module::semantic::Embedder;
use serde_json::{Value, json};

use super::ai::{ALPHA, open_room, put_record, read, session};
use super::common::*;

#[derive(Default)]
pub struct Fake {
    pub seen: Mutex<Vec<String>>,
    /// What came in through `embed_query` (the search question), apart from stored text.
    pub queries: Mutex<Vec<String>>,
    pub hold: AtomicBool,
}

impl Embedder for Fake {
    fn model_id(&self) -> &str {
        "fake-angles"
    }
    fn embed_query(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        self.queries.lock().unwrap().extend(texts.iter().cloned());
        self.vectors(texts)
    }
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        self.seen.lock().unwrap().extend(texts.iter().cloned());
        self.vectors(texts)
    }
}

impl Fake {
    fn vectors(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        while self.hold.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(texts
            .iter()
            .map(|t| {
                let a: f32 = t
                    .split("ang=")
                    .nth(1)
                    .and_then(|r| r.split_whitespace().next())
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(180.0);
                let r = a.to_radians();
                vec![r.cos(), r.sin(), 0.0]
            })
            .collect())
    }
}

/// Alpha (visible to the session): a paraphrase of the query and an unrelated note.
async fn setup(brain: Brain) -> (Fx, String, String) {
    let fx = fx_with(brain, 1).await;
    let alpha = committed_room_named(&fx, "Alpha", &[("Keys", "unrelated source ang=170 ")]).await;
    put_record(&fx, &alpha, "r1", "fact", "accepted", "rotate the signing keys ang=10 ").await;
    put_record(&fx, &alpha, "r2", "fact", "accepted", "pasta menu ang=90 ").await;
    // Not memory: a candidate (and the source above is never searched by meaning).
    put_record(&fx, &alpha, "r3", "fact", "candidate", "ang=20 credentials draft ").await;
    let s = session(&fx, ALPHA, &["anthropic"]).await;
    open_room(&fx, &alpha).await;
    (fx, alpha, s)
}

async fn search(fx: &Fx, s: &str, mode: &str) -> Value {
    read(
        fx,
        s,
        "brainAiSearch",
        json!({"q": "credential renewal ang=20", "mode": mode}),
    )
    .await
}

/// Vectors are queued by the first search; poll until the paraphrase shows up.
async fn until_hit(fx: &Fx, s: &str, mode: &str) -> Value {
    for _ in 0..300 {
        let v = search(fx, s, mode).await;
        if !v["hits"].as_array().unwrap().is_empty() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no meaning hit");
}

#[tokio::test]
async fn meaning_ranks_a_paraphrase_that_keywords_miss_and_never_reads_hidden_rooms() {
    let fake = Arc::new(Fake::default());
    let (fx, _alpha, s) = setup(Brain::with_embedder(fake.clone())).await;
    // A room the session cannot see, with text that would match best.
    let beta = committed_room_named(&fx, "Beta", &[("Secret", "hidden ang=20 ")]).await;
    put_record(&fx, &beta, "b1", "fact", "accepted", "hidden ang=20 ").await;
    // Committing Beta embedded it (centroids); what matters is what searching reads from now on.
    fake.seen.lock().unwrap().clear();
    // Keywords alone miss the paraphrase; the first meaning search queues the vectors.
    assert!(
        search(&fx, &s, "keyword").await["hits"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let v = until_hit(&fx, &s, "auto").await;
    assert_eq!(v["ranked_by"], "both");
    let hits = v["hits"].as_array().unwrap();
    assert!(hits[0]["text"].as_str().unwrap().contains("signing keys"));
    assert!(hits.iter().all(|h| h["kind"] == "record"));
    assert!(!v.to_string().contains("unrelated source"));
    assert!(!v.to_string().contains("credentials draft"));
    assert!(!v.to_string().contains(&beta));
    let m = search(&fx, &s, "meaning").await;
    assert_eq!(m["ranked_by"], "meaning");
    assert!(
        m["hits"][0]["text"]
            .as_str()
            .unwrap()
            .contains("signing keys")
    );
    // The unrelated note is outside the margin of the best hit; the hidden room's text was never embedded.
    assert_eq!(m["hits"].as_array().unwrap().len(), 1);
    // The question was embedded as a query, never as a passage; stored text the other way round.
    assert!(
        fake.queries
            .lock()
            .unwrap()
            .iter()
            .all(|t| t.contains("credential renewal"))
    );
    assert!(
        !fake
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|t| t.contains("credential renewal"))
    );
    assert!(
        fake.seen
            .lock()
            .unwrap()
            .iter()
            .any(|t| t.contains("signing keys"))
    );
    assert!(
        !fake
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|t| t.contains("hidden"))
    );
}

#[tokio::test]
async fn model_off_or_setting_off_is_keyword_only() {
    let (fx, _a, s) = setup(Brain::default()).await;
    let v = search(&fx, &s, "meaning").await;
    assert_eq!(
        (v["ranked_by"].as_str(), v["hits"].as_array().unwrap().len()),
        (Some("keyword"), 0)
    );

    let fake = Arc::new(Fake::default());
    let (fx, _a, s) = setup(Brain::with_embedder(fake.clone())).await;
    until_hit(&fx, &s, "auto").await;
    ModuleSettings::of(&fx.brain)
        .set(
            &fx.app.pool,
            "semantic.enabled",
            "0",
            AuditActor::System,
            "2026-11-13T00:00:00Z",
        )
        .await
        .unwrap();
    let v = search(&fx, &s, "auto").await;
    assert_eq!(
        (v["ranked_by"].as_str(), v["hits"].as_array().unwrap().len()),
        (Some("keyword"), 0)
    );
}

#[tokio::test]
async fn a_slow_worker_falls_back_to_keywords() {
    let fake = Arc::new(Fake::default());
    let (fx, _a, s) = setup(Brain::with_embedder(fake.clone())).await;
    fake.hold.store(true, Ordering::SeqCst);
    let t = std::time::Instant::now();
    let v = read(
        &fx,
        &s,
        "brainAiSearch",
        json!({"q": "signing", "mode": "meaning"}),
    )
    .await;
    assert!(t.elapsed() < Duration::from_secs(5));
    assert_eq!(v["ranked_by"], "keyword");
    assert_eq!(v["hits"].as_array().unwrap().len(), 1);
    fake.hold.store(false, Ordering::SeqCst);
}
