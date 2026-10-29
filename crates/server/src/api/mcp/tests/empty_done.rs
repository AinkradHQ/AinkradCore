//! Agents pretending to work (E15.7, pain #3): a `done` with nothing to show for it (no diff
//! from the issue's runs, no PR, no comment from this run) is refused with the reason, and the
//! agent's second one escalates the issue; a diff or a comment lets it through.

use ainkrad_core::work::{IssueState, NextActor, UserId};
use serde_json::json;

use super::plan::{ok, refused};
use super::*;
use crate::store::exec::record_progress;
use crate::store::work::get_issue;

async fn refusals(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'issue.done_refused'")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn an_empty_done_is_refused_and_a_second_escalates() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    ok(&fx, &a, "transition", json!({"transition": "start"})).await;
    let done = json!({"transition": "done"});
    let why = refused(&fx, &a, "transition", done.clone()).await;
    assert!(why.contains("nothing shows this work was done"), "{why}");
    assert!(why.contains("second empty done escalates"), "{why}");
    let issue = get_issue(pool, a.issue).await.unwrap().unwrap();
    assert_eq!(issue.state, IssueState::InProgress, "not done");
    assert_eq!(issue.next_actor, Some(NextActor::Agent(a.agent)));
    assert_eq!(refusals(pool).await, 1);

    // A diff of nothing (the runner measured 0 files) is still nothing.
    let runner = a.run.runner_id.unwrap();
    record_progress(pool, a.run.id, runner, Some(0), &[], NOW)
        .await
        .unwrap();
    let why = refused(&fx, &a, "transition", done).await;
    assert!(why.contains("escalated to"), "{why}");
    let issue = get_issue(pool, a.issue).await.unwrap().unwrap();
    assert_eq!(issue.state, IssueState::InProgress);
    assert_eq!(
        issue.next_actor,
        Some(NextActor::Human(UserId(1))),
        "no team: straight to the admin"
    );
    assert_eq!(refusals(pool).await, 2);
}

#[tokio::test]
async fn a_done_with_a_diff_or_a_comment_goes_through() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    ok(&fx, &a, "transition", json!({"transition": "start"})).await;
    let runner = a.run.runner_id.unwrap();
    assert!(
        record_progress(pool, a.run.id, runner, Some(3), &[], NOW)
            .await
            .unwrap()
    );
    let done = ok(&fx, &a, "transition", json!({"transition": "done"})).await;
    assert_eq!(done["state"], "done");

    let b = company(pool, "B", "BBB").await;
    ok(&fx, &b, "transition", json!({"transition": "start"})).await;
    let body = json!({"body": "Reviewed: the bound was already right; nothing to change."});
    ok(&fx, &b, "comment", body).await;
    let done = ok(&fx, &b, "transition", json!({"transition": "done"})).await;
    assert_eq!(done["state"], "done");
    assert_eq!(refusals(pool).await, 0);
}

#[tokio::test]
async fn progress_is_recorded_only_for_the_runners_live_run() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let runner = a.run.runner_id.unwrap();
    let other = ainkrad_core::exec::RunnerId(runner.0 + 100);
    assert!(
        !record_progress(pool, a.run.id, other, Some(1), &[], NOW)
            .await
            .unwrap()
    );
    assert!(
        record_progress(pool, a.run.id, runner, None, &[], NOW)
            .await
            .unwrap()
    );
    let run = crate::store::exec::get_run(pool, a.run.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.last_progress_at.as_deref(), Some(NOW));
    assert_eq!(run.diff_files, None, "no measure, no diff");
}
