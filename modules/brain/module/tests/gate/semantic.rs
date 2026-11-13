//! The semantic step of Review with a fake embedder (no model in CI): a vector is an angle read from
//! the text (`ang=NN`), so a cosine is `cos(difference)` and every outcome is known in advance.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::modsettings::ModuleSettings;
use axum::http::Method;
use brain_module::Brain;
use brain_module::semantic::Embedder;
use serde_json::{Value, json};

use super::common::*;

#[derive(Default)]
struct Fake {
    seen: Mutex<Vec<String>>,
    /// While true the embedder waits, so a test can look at `pending`.
    hold: AtomicBool,
    /// A different model id, as after a model upgrade.
    other: AtomicBool,
}

impl Embedder for Fake {
    fn model_id(&self) -> &str {
        if self.other.load(Ordering::SeqCst) {
            "fake-other"
        } else {
            "fake-angles"
        }
    }
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        while self.hold.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.seen.lock().unwrap().extend(texts.iter().cloned());
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

fn at(n: u32, hint: &str, angle: u32) -> Value {
    item(
        n,
        hint,
        &format!("note {n}"),
        &format!("text {n} ang={angle} "),
    )
}

async fn semantic(fx: &Fx, run: &str) -> Value {
    ok(fx, Method::GET, &format!("/imports/{run}/semantic"), None).await
}

async fn ready(fx: &Fx, run: &str) -> Value {
    for _ in 0..600 {
        let v = semantic(fx, run).await;
        if v["state"] != "pending" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the semantic step never finished");
}

async fn audits(fx: &Fx) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'brain.semantic.run'")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn regroup(fx: &Fx, run: &str) {
    ok(fx, Method::POST, &format!("/imports/{run}/regroup"), None).await;
}

/// Alpha and Beta (3 items each, close in meaning) and Unsorted: three near each other, one apart.
async fn sample_run(fx: &Fx) -> String {
    let run = start(fx).await;
    let mut items = vec![];
    items.extend((1..=3).map(|n| at(n, "/u/Dev/Alpha", 60 + n)));
    items.extend((10..=12).map(|n| at(n, "/u/Dev/Beta", 70 + n - 10)));
    items.extend([
        at(20, "", 0),
        at(21, "", 5),
        at(22, "", 10),
        at(23, "", 120),
    ]);
    send(fx, &run, items).await;
    run
}

fn ids(x: &Value) -> Vec<String> {
    x["item_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn pending_then_ready_with_suggestions_that_apply_through_the_existing_routes() {
    let fake = Arc::new(Fake::default());
    fake.hold.store(true, Ordering::SeqCst);
    let fx = fx_with(Brain::with_embedder(fake.clone()), 1).await;
    let run = sample_run(&fx).await;
    finish(&fx, &run).await;

    // Review is open at once with the rule-based rooms; the suggestions are not there yet.
    let p = proposals(&fx, &run).await;
    assert!(p.iter().all(|c| c["semantic"] == "pending"));
    assert_eq!(by_name(&p, "Alpha")["item_count"], 3);
    let v = semantic(&fx, &run).await;
    assert_eq!(v["state"], "pending");
    assert_eq!(v["rooms"], json!([]));

    fake.hold.store(false, Ordering::SeqCst);
    let v = ready(&fx, &run).await;
    assert_eq!(v["state"], "ready");
    let p = proposals(&fx, &run).await;
    assert!(p.iter().all(|c| c["semantic"] == "ready"));

    // Duplicates: the three Unsorted notes within 10 degrees (cos 0.985); the newest is kept.
    // (Alpha and Beta together are a group of six: near-identical notes are found across rooms.)
    assert_eq!(v["duplicates"].as_array().unwrap().len(), 2);
    let d = v["duplicates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| ids(d).len() == 3)
        .unwrap();
    assert_eq!(ids(d).len(), 3);
    assert!(ids(d).contains(&d["keep"].as_str().unwrap().to_owned()));
    assert!(d["score"].as_f64().unwrap() > 0.95);
    // A suggested room from the same three, named from keywords, with a score.
    let r = &v["rooms"][0];
    assert_eq!(ids(r).len(), 3);
    assert!(!r["name"].as_str().unwrap().is_empty());
    assert!(r["keywords"].is_array() && r["score"].as_f64().unwrap() > 0.88);
    // Alpha (61..63 degrees) and Beta (70..72) look like one topic; `from` is the smaller (a tie: either).
    let m = &v["merges"][0];
    let mut names = [
        m["from_name"].as_str().unwrap(),
        m["to_name"].as_str().unwrap(),
    ];
    names.sort();
    assert_eq!(names, ["Alpha", "Beta"]);
    assert!(m["score"].as_f64().unwrap() > 0.93 && !m["reason"].as_str().unwrap().is_empty());
    assert_eq!(audits(&fx).await, 1);

    // Accepting the room = split Unsorted; nothing applied by itself, and the hint is spent after.
    let new = ok(
        &fx,
        Method::POST,
        &format!("/imports/{run}/proposals/unsorted/split"),
        Some(json!({"item_ids": ids(r), "name": "Notes"})),
    )
    .await;
    assert_eq!(
        (new["name"].as_str(), new["item_count"].as_i64()),
        (Some("Notes"), Some(3))
    );
    assert_eq!(semantic(&fx, &run).await["rooms"], json!([]));
    // Accepting the duplicates = mark all but `keep` refused; the group is spent after.
    let extra: Vec<String> = ids(d)
        .into_iter()
        .filter(|i| i != d["keep"].as_str().unwrap())
        .collect();
    ok(
        &fx,
        Method::PATCH,
        &format!("/imports/{run}/items"),
        Some(json!({"ids": extra, "mark": "refused"})),
    )
    .await;
    let left = semantic(&fx, &run).await;
    assert_eq!(
        left["duplicates"].as_array().unwrap().len(),
        1,
        "only the Alpha/Beta group is left"
    );
}

#[tokio::test]
async fn without_a_model_the_step_is_off_and_review_is_unchanged() {
    let fx = fx().await;
    let run = sample_run(&fx).await;
    finish(&fx, &run).await;
    assert_eq!(semantic(&fx, &run).await["state"], "off");
    let p = proposals(&fx, &run).await;
    assert!(p.iter().all(|c| c["semantic"] == "off"));
    assert_eq!(by_name(&p, "Alpha")["item_count"], 3);
    assert_eq!(audits(&fx).await, 0);
}

#[tokio::test]
async fn refused_items_are_never_embedded_and_a_regroup_recomputes() {
    let fake = Arc::new(Fake::default());
    let brain = Brain::default();
    let fx = fx_with(brain.clone(), 1).await;
    let run = sample_run(&fx).await;
    finish(&fx, &run).await; // no model yet: off
    assert_eq!(semantic(&fx, &run).await["state"], "off");
    // The person refuses one Unsorted note; only then does the model arrive and the run re-sort.
    ok(
        &fx,
        Method::PATCH,
        &format!("/imports/{run}/items"),
        Some(json!({"ids": [format!("01JD{:022}", 23)], "mark": "refused"})),
    )
    .await;
    brain.set_embedder(fake.clone());
    regroup(&fx, &run).await;
    assert_eq!(ready(&fx, &run).await["state"], "ready");
    let seen = fake.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 9, "ten items, one refused");
    assert!(!seen.iter().any(|t| t.contains("text 23 ")));
    assert_eq!(audits(&fx).await, 1);
}

#[tokio::test]
async fn the_strength_setting_moves_the_cut_offs() {
    let fake = Arc::new(Fake::default());
    let fx = fx_with(Brain::with_embedder(fake.clone()), 1).await;
    let run = start(&fx).await;
    // 16 degrees apart: cos 0.961, a duplicate pair at normal and high but not at low (0.97).
    send(&fx, &run, vec![at(1, "", 0), at(2, "", 16), at(3, "", 120)]).await;
    finish(&fx, &run).await;
    let dups = |v: &Value| v["duplicates"].as_array().unwrap().len();
    assert_eq!(dups(&ready(&fx, &run).await), 1, "normal is the default");

    let set = |v: &'static str| {
        let (pool, brain) = (fx.app.pool.clone(), fx.brain.clone());
        async move {
            ModuleSettings::of(&brain)
                .set(
                    &pool,
                    "semantic.strength",
                    v,
                    AuditActor::System,
                    "2026-11-13T00:00:00Z",
                )
                .await
                .unwrap();
        }
    };
    set("0").await;
    regroup(&fx, &run).await;
    assert_eq!(dups(&ready(&fx, &run).await), 0, "low");
    set("2").await;
    regroup(&fx, &run).await;
    assert_eq!(dups(&ready(&fx, &run).await), 1, "high");
    assert_eq!(
        fake.seen.lock().unwrap().len(),
        3,
        "vectors are cached across runs"
    );
    assert_eq!(audits(&fx).await, 3);
}

async fn set_setting(fx: &Fx, name: &str, v: &str) {
    ModuleSettings::of(&fx.brain)
        .set(
            &fx.app.pool,
            name,
            v,
            AuditActor::System,
            "2026-11-13T00:00:00Z",
        )
        .await
        .unwrap();
}

/// (model, rows) in the encrypted vectors file.
async fn stored(fx: &Fx) -> Vec<(String, i64)> {
    let key = key_of(fx).await;
    let path = brain_module::files::vectors_path(&brain_module::files::root(&fx.app));
    let p = brain_module::files::open_migrated(&path, &key, false, brain_module::files::VECTORS)
        .await
        .unwrap();
    let rows = sqlx::query_as("SELECT model, count(*) FROM vectors GROUP BY model ORDER BY model")
        .fetch_all(&p)
        .await
        .unwrap();
    p.close().await;
    rows
}

#[tokio::test]
async fn vectors_survive_a_restart_a_new_model_drops_them_and_a_refusal_deletes() {
    let fake = Arc::new(Fake::default());
    let fx = fx_with(Brain::with_embedder(fake.clone()), 1).await;
    let run = start(&fx).await;
    send(&fx, &run, vec![at(1, "", 0), at(2, "", 40), at(3, "", 80)]).await;
    finish(&fx, &run).await;
    ready(&fx, &run).await;
    let n = || fake.seen.lock().unwrap().len();
    assert_eq!(
        (n(), stored(&fx).await),
        (3, vec![("fake-angles".into(), 3)])
    );

    // A restart forgets memory; the re-sort reads the stored vectors and embeds nothing.
    fx.brain.drop_memory_vectors();
    regroup(&fx, &run).await;
    ready(&fx, &run).await;
    assert_eq!(n(), 3);

    // The vectors are not in the clear: the file does not open without the brain key.
    let path = brain_module::files::vectors_path(&brain_module::files::root(&fx.app));
    assert!(
        !std::fs::read(&path)
            .unwrap()
            .starts_with(b"SQLite format 3\0")
    );

    // A refused item's vector is deleted, from disk and memory.
    ok(
        &fx,
        Method::PATCH,
        &format!("/imports/{run}/items"),
        Some(json!({"ids": [format!("01JD{:022}", 1)], "mark": "refused"})),
    )
    .await;
    assert_eq!(stored(&fx).await, vec![("fake-angles".to_owned(), 2)]);

    // A new model id: the old vectors are not used and are dropped; the two live items are embedded again.
    fake.other.store(true, Ordering::SeqCst);
    fx.brain.drop_memory_vectors();
    regroup(&fx, &run).await;
    ready(&fx, &run).await;
    assert_eq!(
        (n(), stored(&fx).await),
        (5, vec![("fake-other".into(), 2)])
    );
}

#[tokio::test]
async fn the_enabled_setting_turns_the_step_off_without_a_rebuild() {
    let fake = Arc::new(Fake::default());
    let fx = fx_with(Brain::with_embedder(fake.clone()), 1).await;
    // Through the API the App uses: both settings listed, a write changes the value, bounds refused.
    let list = ok(&fx, Method::GET, "/settings", None).await;
    let names: Vec<_> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["semantic.enabled", "semantic.strength"]);
    assert_eq!(list[0]["value"], 1);
    let v = ok(
        &fx,
        Method::PUT,
        "/settings/semantic.enabled",
        Some(json!({"value": 0})),
    )
    .await;
    assert_eq!(v["value"], 0);
    let (st, _) = call(
        &fx,
        &fx.admin,
        Method::PUT,
        "/settings/semantic.strength",
        Some(json!({"value": 3})),
    )
    .await;
    assert_eq!(st, axum::http::StatusCode::BAD_REQUEST);
    let (st, _) = call(
        &fx,
        &fx.admin,
        Method::PUT,
        "/settings/nope",
        Some(json!({"value": 1})),
    )
    .await;
    assert_eq!(st, axum::http::StatusCode::NOT_FOUND);
    let run = sample_run(&fx).await;
    finish(&fx, &run).await;
    assert_eq!(semantic(&fx, &run).await["state"], "off");
    assert!(
        proposals(&fx, &run)
            .await
            .iter()
            .all(|c| c["semantic"] == "off")
    );
    assert_eq!(fake.seen.lock().unwrap().len(), 0, "nothing is embedded");
    assert_eq!(audits(&fx).await, 0);

    set_setting(&fx, "semantic.enabled", "1").await;
    regroup(&fx, &run).await;
    assert_eq!(ready(&fx, &run).await["state"], "ready");

    // Off again: the step reports off at once and the next re-sort drops the old suggestions.
    set_setting(&fx, "semantic.enabled", "0").await;
    assert_eq!(semantic(&fx, &run).await["state"], "off");
}
