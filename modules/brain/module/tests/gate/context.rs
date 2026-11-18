//! `brainAiContext` (B7-03): memory only, no contested record, a budget, no repeats in prompt mode,
//! every loaded id recorded, and no other room. Every item here is synthetic.

use std::sync::Arc;
use std::time::Duration;

use ainkrad_core::untrusted::OPEN;
use brain_module::Brain;
use serde_json::{Value, json};

use super::ai::{ALPHA, open_room, put_record, read, session};
use super::ai_semantic::Fake;
use super::common::*;

const MARK: &str = "SRCMARKERc4";

async fn setup() -> (Fx, String, String) {
    let fx = fx_with(Brain::with_embedder(Arc::new(Fake::default())), 1).await;
    let alpha = committed_room_named(&fx, "Alpha", &[("Notes", &format!("{MARK} ang=20 "))]).await;
    let s = session(&fx, ALPHA, &["anthropic"]).await;
    (fx, alpha, s)
}

async fn ctx(fx: &Fx, s: &str, args: Value) -> Value {
    read(fx, s, "brainAiContext", args).await
}

fn ids(v: &Value) -> Vec<String> {
    v["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.as_str().unwrap().to_owned())
        .collect()
}

async fn loaded(fx: &Fx, s: &str) -> Vec<(String, String)> {
    sqlx::query_as("SELECT room, record FROM brain_session_loaded WHERE session = ? ORDER BY record")
        .bind(s)
        .fetch_all(&fx.app.pool)
        .await
        .unwrap()
}

/// A prompt gets nothing until the vectors exist (the first call queues them); poll for the hit.
async fn until_ids(fx: &Fx, s: &str, args: Value) -> Value {
    for _ in 0..300 {
        let v = ctx(fx, s, args.clone()).await;
        if !ids(&v).is_empty() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no context");
}

#[tokio::test]
async fn context_is_memory_only_and_never_carries_a_contested_record() {
    let (fx, alpha, s) = setup().await;
    put_record(&fx, &alpha, "live", "fact", "accepted", "rotate the signing keys ang=10 ").await;
    put_record(&fx, &alpha, "arch", "fact", "accepted", "archived fact ang=10 ").await;
    put_record(&fx, &alpha, "cand", "fact", "candidate", "candidate fact ang=10 ").await;
    put_record(&fx, &alpha, "fight", "fact", "accepted", "contesting fact ang=10 ").await;
    put_record(&fx, &alpha, "tagged", "fact", "accepted", "tagged fact ang=10 ").await;
    let p = canon_pool(&fx, &alpha).await;
    sqlx::query("UPDATE records SET contests = 'live' WHERE id = 'fight'")
        .execute(&p)
        .await
        .unwrap();
    sqlx::query("UPDATE records SET tags = '[\"conflict\"]' WHERE id = 'tagged'")
        .execute(&p)
        .await
        .unwrap();
    sqlx::query("UPDATE records SET archived_at = '2026-11-12T00:00:00Z' WHERE id = 'arch'")
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
    open_room(&fx, &alpha).await;

    let start = ctx(&fx, &s, json!({"mode": "start", "prompt": "signing keys ang=10"})).await;
    assert_eq!(ids(&start), ["live"], "{start}");
    let text = start["text"].as_str().unwrap();
    // Wrapped once, the id on the line, no source text.
    assert!(text.starts_with(OPEN) && text.matches(OPEN).count() == 1, "{text}");
    assert!(text.contains("[live]") && !text.contains(MARK), "{text}");
    // The meaning pass runs after the first call queued the vectors: still never a contested one.
    let prompt = until_ids(&fx, &s_fresh(&fx).await, json!({"mode": "prompt", "prompt": "signing keys ang=10"})).await;
    for v in [&start, &prompt] {
        let t = v.to_string();
        for bad in ["fight", "tagged", "arch", "cand", MARK] {
            assert!(!t.contains(bad), "{bad} leaked: {t}");
        }
    }
}

/// B3-04: a record an AI session saved says `origin=ai` on its line of the bundle; others do not.
#[tokio::test]
async fn an_ai_record_says_origin_ai_in_the_bundle() {
    let (fx, alpha, s) = setup().await;
    put_record(&fx, &alpha, "mine", "fact", "accepted", "rotate the signing keys ang=10 ").await;
    put_record(&fx, &alpha, "bot", "fact", "accepted", "rotate the backup keys ang=10 ").await;
    let p = canon_pool(&fx, &alpha).await;
    sqlx::query("UPDATE records SET origin = 'ai' WHERE id = 'bot'")
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
    open_room(&fx, &alpha).await;
    let v = ctx(&fx, &s, json!({"mode": "start"})).await;
    let text = v["text"].as_str().unwrap();
    assert!(text.contains("[bot, origin=ai]"), "{text}");
    assert!(text.contains("[mine]") && !text.contains("[mine, origin=ai]"), "{text}");
}

/// A second session in the same room (a prompt never repeats within one session, not across).
async fn s_fresh(fx: &Fx) -> String {
    session(fx, ALPHA, &["anthropic"]).await
}

#[tokio::test]
async fn the_start_bundle_stays_inside_its_budget_and_says_when_it_cut() {
    let (fx, alpha, s) = setup().await;
    for n in 0..40 {
        put_record(&fx, &alpha, &format!("r{n:02}"), "fact", "accepted", &format!("{n} {}", "word ".repeat(80))).await;
    }
    open_room(&fx, &alpha).await;
    let v = ctx(&fx, &s, json!({"mode": "start"})).await;
    assert!(v["tokens"].as_u64().unwrap() <= 1500 && !ids(&v).is_empty(), "{v}");
    assert!(ids(&v).len() <= 10, "{v}");
    let small = ctx(&fx, &s, json!({"mode": "start", "budget": 100})).await;
    assert!(small["tokens"].as_u64().unwrap() <= 100, "{small}");
    assert_eq!(small["complete"], false, "{small}");
    // A caller cannot raise the cap.
    let big = ctx(&fx, &s, json!({"mode": "start", "budget": 100000})).await;
    assert!(big["tokens"].as_u64().unwrap() <= 1500);
}

#[tokio::test]
async fn prompt_mode_never_repeats_a_record_to_the_same_session_and_empty_is_normal() {
    let (fx, alpha, s) = setup().await;
    put_record(&fx, &alpha, "r1", "fact", "accepted", "rotate the signing keys ang=10 ").await;
    put_record(&fx, &alpha, "r2", "fact", "accepted", "pasta menu ang=90 ").await;
    open_room(&fx, &alpha).await;
    let args = json!({"mode": "prompt", "prompt": "credential renewal ang=20"});
    let first = until_ids(&fx, &s, args.clone()).await;
    assert_eq!(ids(&first), ["r1"], "{first}");
    // The same prompt again: r1 was loaded, r2 is below the floor, so nothing.
    let again = ctx(&fx, &s, args.clone()).await;
    assert!(ids(&again).is_empty() && again["text"] == "", "{again}");
    // Another session still gets it.
    let other = until_ids(&fx, &s_fresh(&fx).await, args).await;
    assert_eq!(ids(&other), ["r1"]);
    // A prompt below the floor: empty, nothing recorded for it.
    let none = ctx(&fx, &s, json!({"mode": "prompt", "prompt": "unrelated ang=170"})).await;
    assert!(ids(&none).is_empty() && none["text"] == "");
}

#[tokio::test]
async fn every_loaded_record_is_recorded_for_the_session_and_audited_by_ids_only() {
    let (fx, alpha, s) = setup().await;
    put_record(&fx, &alpha, "r1", "fact", "accepted", "rotate the signing keys ang=10 ").await;
    put_record(&fx, &alpha, "r2", "rule", "accepted", "never push to main ang=50 ").await;
    open_room(&fx, &alpha).await;
    let v = ctx(&fx, &s, json!({"mode": "start"})).await;
    let mut want: Vec<(String, String)> = ids(&v).into_iter().map(|i| (alpha.clone(), i)).collect();
    want.sort_by(|a, b| a.1.cmp(&b.1));
    assert!(!want.is_empty());
    assert_eq!(loaded(&fx, &s).await, want);
    let rows: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'brain.ai.context'")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].contains("signing keys") && !rows[0].contains(MARK), "{}", rows[0]);
}

#[tokio::test]
async fn a_room_the_session_cannot_see_never_reaches_the_bundle_or_the_ledger() {
    let (fx, alpha, s) = setup().await;
    put_record(&fx, &alpha, "a1", "fact", "accepted", "alpha fact ang=10 ").await;
    let beta = committed_room_named(&fx, "Beta", &[("B", "beta text")]).await;
    put_record(&fx, &beta, "b1", "fact", "accepted", "hidden beta fact ang=10 ").await;
    open_room(&fx, &alpha).await;
    open_room(&fx, &beta).await;
    for args in [
        json!({"mode": "start", "prompt": "fact ang=10"}),
        json!({"mode": "prompt", "prompt": "fact ang=10"}),
    ] {
        let v = ctx(&fx, &s, args).await;
        assert!(!v.to_string().contains("beta") && !ids(&v).contains(&"b1".to_owned()), "{v}");
    }
    // Naming the hidden room is the 404 of an unknown one.
    let (ok_, _, code) = super::ai::op(&fx, &s, "brainAiContext", json!({"mode": "start", "room": beta})).await;
    assert!(!ok_ && code == "not_found", "{code}");
    assert!(loaded(&fx, &s).await.iter().all(|(r, _)| *r == alpha));
}
