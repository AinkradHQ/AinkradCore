//! An agent's runs, a run, its transcript in pages.

use ainkrad_core::work::ProjectMode;
use serde_json::json;

use super::*;
use crate::store::exec::append_run_event;

#[tokio::test]
async fn lists_runs_and_pages_the_transcript() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    for seq in 1..=5u64 {
        let chunk = json!({"kind": "text", "text": format!("line {seq}")});
        append_run_event(&fx.app.pool, a.run.id, a.runner, seq, &chunk, NOW)
            .await
            .unwrap();
    }

    let runs = fx.ok(&format!("/api/v1/agents/{}/runs", a.agent.0)).await;
    assert_eq!(runs["items"][0]["id"], a.run.id.0);
    assert_eq!(runs["items"][0]["state"], "running");
    let queued = runs["items"][0]["queued_at"].as_str().unwrap();
    assert!(
        queued.len() == 24 && queued.ends_with('Z'),
        "{queued}: milliseconds, UTC"
    );
    assert!(runs["next_after"].is_null());
    let run = fx.ok(&format!("/api/v1/runs/{}", a.run.id.0)).await;
    assert_eq!(run["issue_id"], a.issue.0);
    // Stage timings (E15.6): the first chunk is the harness up; none of them is an answer.
    assert!(run["woken_at"].is_string() && run["harness_started_at"].is_string());
    assert!(run["first_token_at"].is_null());
    let timing = fx
        .ok(&format!("/api/v1/projects/{}/timing", a.project.0))
        .await;
    assert_eq!(timing[0]["stage"], "wake_to_claim");
    assert_eq!(timing[0]["runs"], 1);
    assert_eq!(timing[3]["stage"], "harness_to_first_token");
    assert_eq!(timing[3]["runs"], 0);
    assert!(timing[3]["p50_secs"].is_null());
    let bad = format!("/api/v1/projects/{}/timing?since=soon", a.project.0);
    assert_eq!(fx.get(&bad).await.0, StatusCode::BAD_REQUEST);

    let uri = |q: &str| format!("/api/v1/runs/{}/transcript{q}", a.run.id.0);
    let first = fx.ok(&uri("?limit=2")).await;
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    assert_eq!(first["next_after"], 2);
    let rest = fx.ok(&uri("?after=2&limit=10")).await;
    let seqs: Vec<i64> = rest["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["seq"].as_i64().unwrap())
        .collect();
    assert_eq!(seqs, [3, 4, 5]);
    assert!(rest["next_after"].is_null());
    assert_eq!(rest["items"][0]["at"], NOW);

    for missing in [
        "/api/v1/runs/99",
        "/api/v1/runs/99/transcript",
        "/api/v1/agents/99/runs",
        "/api/v1/projects/99/timing",
    ] {
        assert_eq!(fx.get(missing).await.0, StatusCode::NOT_FOUND, "{missing}");
    }
}
