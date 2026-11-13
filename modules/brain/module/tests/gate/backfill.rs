//! Closest-room backfill: a room committed before centroids existed gets one when its owner opens it.

use std::sync::Arc;
use std::time::Duration;

use axum::http::Method;
use brain_module::Brain;
use serde_json::Value;

use super::ai::open_room;
use super::ai_semantic::Fake;
use super::common::*;

async fn backfills(fx: &Fx) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'brain.room.centroid_backfilled'",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap()
}

/// The closest-room hint for one unsorted item (angle `ang`), from a fresh review run.
async fn hint(fx: &Fx, n: u32, ang: u32) -> Option<Value> {
    let run = start(fx).await;
    send(
        fx,
        &run,
        vec![item(n, "", "note", &format!("text {n} ang={ang} "))],
    )
    .await;
    finish(fx, &run).await;
    for _ in 0..600 {
        let v = ok(fx, Method::GET, &format!("/imports/{run}/semantic"), None).await;
        if v["state"] != "pending" {
            return v["closest"].as_array().unwrap().first().cloned();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("semantic never finished");
}

#[tokio::test]
async fn an_old_room_gets_its_centroid_when_opened_and_then_closest_room_offers_it() {
    // Committed with no model: no centroid, as before closest-room existed.
    let fx = fx_with(Brain::default(), 1).await;
    let alpha = committed_room_named(
        &fx,
        "Alpha",
        &[
            ("a1", "keys ang=61 "),
            ("a2", "tokens ang=62 "),
            ("a3", "certs ang=63 "),
        ],
    )
    .await;
    let beta = committed_room_named(
        &fx,
        "Beta",
        &[("b1", "menu ang=100 "), ("b2", "pasta ang=101 ")],
    )
    .await;
    let fake = Arc::new(Fake::default());
    fx.brain.set_embedder(fake.clone());

    assert!(hint(&fx, 30, 62).await.is_none(), "no centroid yet");
    assert!(
        backfills(&fx).await.is_empty(),
        "nothing before a room is opened"
    );
    assert!(
        !fake
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|t| t.contains("ang=61")),
        "a closed room is never read"
    );

    open_room(&fx, &alpha).await;
    for _ in 0..600 {
        if !backfills(&fx).await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let rows = backfills(&fx).await;
    assert_eq!(rows.len(), 1, "one audit row per backfill");
    let d: Value = serde_json::from_str(&rows[0]).unwrap();
    assert_eq!(
        (d["room"].as_str(), d["count"].as_u64()),
        (Some(alpha.as_str()), Some(3))
    );
    assert!(!rows[0].contains("keys"), "no text in the audit row");
    // Beta was never opened: no centroid, never read.
    assert!(
        !fake
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|t| t.contains("pasta"))
    );
    let h = hint(&fx, 31, 62).await.expect("the old room is offered");
    assert_eq!(
        (h["room_id"].as_str(), h["in_review"].as_bool()),
        (Some(alpha.as_str()), Some(false))
    );
    // Opening again does not redo it.
    open_room(&fx, &alpha).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(backfills(&fx).await.len(), 1);
    let _ = beta;
}
