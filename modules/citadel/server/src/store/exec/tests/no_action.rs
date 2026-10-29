//! A run that ends `succeeded` without acting on the issue still waiting on it: one nudge
//! re-wake, then an escalation up the chain; reset when the issue changes; a run that acted
//! is a plain success.

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::exec::RunEvent;
use citadel_core::work::IssueTransition;
use serde_json::json;

use super::breaker::led;
use super::wake::{dispatch, runner, wake};
use super::*;
use crate::store::audit;
use crate::store::work::{get_issue, transition_issue};

const NOW: &str = "2026-10-21T10:00:00.000Z";

/// Hands `i` to `to`, as a person would.
async fn hand(pool: &SqlitePool, i: IssueId, to: AgentId) {
    let next = NextActor::Agent(to);
    transition_issue(
        pool,
        i,
        &IssueTransition::Reassign { next },
        AuditActor::System,
    )
    .await
    .unwrap();
    // `issues.updated_at` is SQLite's clock, to the millisecond: the runs after end later.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
}

/// Dispatches the next due run, which says `said`, calls each of `tools` (all succeeding) and
/// ends `succeeded`.
async fn work(pool: &SqlitePool, mac: RunnerId, said: &str, tools: &[&str]) -> Run {
    let run = dispatch(pool, mac, NOW).await.expect("a run is due");
    let by = AuditActor::Runner(mac);
    start_run(pool, run.id, by, None, NOW).await.unwrap();
    sqlx::query("INSERT INTO run_events (run_id, seq, at, kind, payload) VALUES (?, 1, ?, ?, ?)")
        .bind(run.id.0)
        .bind(NOW)
        .bind("assistant_text")
        .bind(json!({"type": "assistant_text", "text": said}).to_string())
        .execute(pool)
        .await
        .unwrap();
    for tool in tools {
        let event = NewAuditEvent {
            actor: AuditActor::Agent(run.agent_id),
            action: format!("mcp.{tool}"),
            entity: run.issue_id.map(|i| AuditEntity {
                kind: "issue".to_owned(),
                id: i.0,
            }),
            company_id: None,
            run_id: Some(run.id),
            details: json!({"ok": true, "error": null}).to_string(),
        };
        audit::append(pool, &event).await.unwrap();
    }
    transition_run(pool, run.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap()
}

/// The reasons of the pending wakes of `agent` on `i`.
async fn pending(pool: &SqlitePool, agent: AgentId, i: IssueId) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT reason FROM wake_requests WHERE agent_id = ? AND issue_id = ? \
         AND status = 'pending' ORDER BY id",
    )
    .bind(agent.0)
    .bind(i.0)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// `(in_a_row, action)` of each `run.ended_without_action`, in order.
async fn audited(pool: &SqlitePool) -> Vec<(i64, String)> {
    sqlx::query_as(
        "SELECT json_extract(details, '$.in_a_row'), json_extract(details, '$.action') \
         FROM audit_events WHERE action = 'run.ended_without_action' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_run_that_ends_without_acting_is_nudged_once_then_escalated() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    let mac = runner(pool, "mac").await;
    hand(pool, i, dev).await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();

    let first = work(
        pool,
        mac,
        "I read it and changed nothing yet.",
        &["get_issue"],
    )
    .await;
    assert_eq!(first.state, RunState::Succeeded);
    assert_eq!(first.terminal_reason.as_deref(), Some(ENDED_WITHOUT_ACTION));
    let nudge = pending(pool, dev, i).await;
    assert_eq!(nudge.len(), 1, "one nudge: {nudge:?}");
    assert!(
        nudge[0].starts_with("your last run ended without acting: \"I read it and changed"),
        "{}",
        nudge[0]
    );
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(issue.next_actor, Some(NextActor::Agent(dev)));

    // The nudged run only comments: still no action, so the issue goes up the chain.
    let second = work(pool, mac, "Summary again.", &["comment"]).await;
    assert_eq!(
        second.terminal_reason.as_deref(),
        Some(ENDED_WITHOUT_ACTION)
    );
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(issue.next_actor, Some(NextActor::Agent(lead)), "escalated");
    assert!(pending(pool, dev, i).await.is_empty(), "no third wake");
    let to_lead = pending(pool, lead, i).await;
    assert_eq!(to_lead.len(), 1, "{to_lead:?}");
    assert!(
        to_lead[0].contains("2 runs in a row without acting") && to_lead[0].contains("Summary"),
        "{}",
        to_lead[0]
    );
    assert_eq!(
        audited(pool).await,
        vec![(1, "rewake".to_owned()), (2, "escalate".to_owned())]
    );
}

#[tokio::test]
async fn a_run_that_acted_is_a_plain_success() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    led(pool, dev).await;
    let mac = runner(pool, "mac").await;
    hand(pool, i, dev).await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    // It estimated the issue: the issue still waits on it, but it acted.
    let run = work(pool, mac, "Estimated.", &["get_issue", "estimate_issue"]).await;
    assert_eq!(run.terminal_reason.as_deref(), Some("succeeded"));
    assert!(pending(pool, dev, i).await.is_empty());
    assert!(audited(pool).await.is_empty());
}

#[tokio::test]
async fn a_change_to_the_issue_resets_the_count() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    let mac = runner(pool, "mac").await;
    hand(pool, i, dev).await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    work(pool, mac, "Nothing.", &[]).await;
    assert_eq!(pending(pool, dev, i).await.len(), 1);
    // The lead takes it and hands it back before the nudge runs: a fresh start.
    hand(pool, i, lead).await;
    hand(pool, i, dev).await;
    work(pool, mac, "Nothing again.", &[]).await;
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(
        issue.next_actor,
        Some(NextActor::Agent(dev)),
        "not escalated"
    );
    assert_eq!(
        audited(pool).await,
        vec![(1, "rewake".to_owned()), (1, "rewake".to_owned())]
    );
}

#[tokio::test]
async fn a_run_whose_issue_no_longer_waits_on_it_is_a_plain_success() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    // The fixture's issue waits on the admin.
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    let run = work(pool, mac, "Looked.", &[]).await;
    assert_eq!(run.terminal_reason.as_deref(), Some("succeeded"));
    assert!(audited(pool).await.is_empty());
}
