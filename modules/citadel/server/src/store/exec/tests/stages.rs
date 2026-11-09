//! Stage timings (E15.6): a run's stages are stamped once, in order; a first token past its
//! budget is warned once; a project's stages are summarised as p50 / p95.

use citadel_core::audit::AuditActor;
use citadel_core::exec::RunEvent;
use citadel_core::settings::{Key, Scope};
use serde_json::json;

use super::wake::{dispatch, runner, wake};
use super::*;
use crate::store::work::get_issue;

const NOW: &str = "2026-10-22T10:00:00.000Z";

/// A dispatched run of the fixture's agent, started on its runner, and its project.
async fn started(pool: &SqlitePool) -> (Run, RunnerId, citadel_core::work::ProjectId) {
    let (dev, i) = fixture(pool, "A").await;
    let project = get_issue(pool, i).await.unwrap().unwrap().project_id;
    let r = runner(pool, "box").await;
    enqueue_wake(pool, &wake(dev, Some(i), "w")).await.unwrap();
    let run = dispatch(pool, r, NOW).await.unwrap();
    assert!(run.woken_at.is_some(), "stamped at dispatch");
    start_run(pool, run.id, AuditActor::Runner(r), None, NOW)
        .await
        .unwrap();
    (run, r, project)
}

async fn chunk(pool: &SqlitePool, run: RunId, r: RunnerId, seq: u64, kind: &str) {
    let payload = json!({"type": kind, "input": 10});
    append_run_event(pool, run, r, seq, &payload, NOW)
        .await
        .unwrap();
}

async fn slow_warnings(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'run.first_token_slow'")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn stages_are_stamped_once_in_order_and_summarised() {
    let db = db().await;
    let pool = &db.pool;
    let (run, r, project) = started(pool).await;
    chunk(pool, run.id, r, 1, "session_started").await;
    let up = get_run(pool, run.id).await.unwrap().unwrap();
    assert!(up.harness_started_at.is_some());
    assert_eq!(up.first_token_at, None, "a session start is no answer");
    chunk(pool, run.id, r, 2, "assistant_text").await;
    chunk(pool, run.id, r, 3, "tool_use").await;
    let answered = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!(
        answered.harness_started_at, up.harness_started_at,
        "stamped once"
    );
    let first = answered.first_token_at.clone().unwrap();
    let by = AuditActor::Runner(r);
    transition_run(pool, run.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap();
    let ordered: bool = sqlx::query_scalar(
        "SELECT julianday(woken_at) <= julianday(claimed_at) \
         AND julianday(claimed_at) <= julianday(started_at) \
         AND julianday(started_at) <= julianday(harness_started_at) \
         AND julianday(harness_started_at) <= julianday(first_token_at) \
         AND julianday(first_token_at) <= julianday(ended_at) FROM runs WHERE id = ?",
    )
    .bind(run.id.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(ordered, "{:?}", get_run(pool, run.id).await.unwrap());
    let ended = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!(ended.first_token_at.as_deref(), Some(first.as_str()));

    let stats = stage_timing(pool, project, None).await.unwrap();
    let names: Vec<&str> = stats.iter().map(|s| s.stage).collect();
    assert_eq!(names, STAGES);
    for s in &stats {
        assert_eq!(s.runs, 1, "{}", s.stage);
        assert!(
            s.p50_secs.unwrap() >= 0.0 && s.p50_secs == s.p95_secs,
            "{s:?}"
        );
    }
    let later = stage_timing(pool, project, Some("2099-01-01T00:00:00Z")).await;
    assert!(
        later
            .unwrap()
            .iter()
            .all(|s| s.runs == 0 && s.p50_secs.is_none())
    );
    let bad = stage_timing(pool, project, Some("soon")).await;
    assert!(matches!(bad, Err(Error::InvalidArgument(_))));
    assert_eq!(slow_warnings(pool).await, 0, "well inside the 10 s default");
}

#[tokio::test]
async fn a_first_token_past_its_budget_is_warned_once() {
    let db = db().await;
    let pool = &db.pool;
    let (run, r, project) = started(pool).await;
    let by = AuditActor::System;
    let at = Scope::Project(project);
    crate::store::settings::set(pool, Key::FirstTokenBudgetSecs, at, "5", by, NOW)
        .await
        .unwrap();
    // The wake came due a minute ago.
    sqlx::query("UPDATE runs SET woken_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-60 seconds') WHERE id = ?")
        .bind(run.id.0)
        .execute(pool)
        .await
        .unwrap();
    chunk(pool, run.id, r, 1, "usage_so_far").await;
    chunk(pool, run.id, r, 2, "assistant_text").await;
    assert_eq!(slow_warnings(pool).await, 1);
    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'run.first_token_slow' AND run_id = ?",
    )
    .bind(run.id.0)
    .fetch_one(pool)
    .await
    .unwrap();
    let details: serde_json::Value = serde_json::from_str(&details).unwrap();
    assert_eq!(details["budget_secs"], 5);
    assert!(details["secs"].as_f64().unwrap() >= 60.0, "{details}");
}

#[test]
fn percentiles_are_nearest_rank() {
    let v: Vec<f64> = (1..=20).map(f64::from).collect();
    assert_eq!(percentile(&v, 50.0), Some(10.0));
    assert_eq!(percentile(&v, 95.0), Some(19.0));
    assert_eq!(percentile(&[3.0], 95.0), Some(3.0));
    assert_eq!(percentile(&[], 50.0), None);
}
