//! Stale wakes: a wake whose issue has moved on to another actor is dropped at dispatch, never
//! run, and the issue keeps its owner and next actor.

use super::wake::{finish, runner, wake};
use super::*;
use crate::store::org::get_agent;
use crate::store::work::get_issue;
use citadel_core::exec::RunEvent;

const NOW: &str = "2026-10-21T10:00:00.000Z";

/// `issue` in `state`, owned by and waiting on `dev`.
async fn hand_to(pool: &SqlitePool, issue: IssueId, dev: AgentId, state: &str) {
    sqlx::query(
        "UPDATE issues SET state = ?1, owner_agent_id = ?2, next_agent_id = ?2, \
         next_user_id = NULL, owner_user_id = NULL WHERE id = ?3",
    )
    .bind(state)
    .bind(dev.0)
    .bind(issue.0)
    .execute(pool)
    .await
    .unwrap();
}

fn source(w: NewWakeRequest, source: WakeSource) -> NewWakeRequest {
    NewWakeRequest { source, ..w }
}

#[tokio::test]
async fn a_stale_wake_is_dropped_and_audited_and_a_valid_one_still_runs() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    let qa = agent(pool, company).await;
    hand_to(pool, i, dev, "in_progress").await;
    let r = runner(pool, "box").await;

    // QA's follow-up after it sent the issue back to the developer: dropped, never run.
    let stale = enqueue_wake(
        pool,
        &source(wake(qa, Some(i), "qa"), WakeSource::Assignment),
    )
    .await
    .unwrap();
    assert!(super::wake::dispatch(pool, r, NOW).await.is_none());
    let (status, why): (String, Option<String>) =
        sqlx::query_as("SELECT status, dropped_reason FROM wake_requests WHERE id = ?")
            .bind(stale.id.0)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(status, "dropped");
    assert!(why.unwrap().starts_with("superseded"));
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'wake.dropped' AND entity_id = ?",
    )
    .bind(stale.id.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);
    let runs: i64 = sqlx::query_scalar("SELECT count(*) FROM runs")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(runs, 0);
    let after = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(after.next_actor, Some(NextActor::Agent(dev)));
    assert_eq!(after.state, IssueState::InProgress);

    // A person's comment for QA is theirs to answer: kept and run.
    enqueue_wake(pool, &wake(qa, Some(i), "comment:1"))
        .await
        .unwrap();
    let run = super::wake::dispatch(pool, r, NOW).await.unwrap();
    assert_eq!(run.agent_id, qa);
    // One run per issue: the developer's wake waits for QA's run to end.
    finish(pool, &run, RunEvent::Succeed).await;

    // The developer's own wake runs.
    enqueue_wake(pool, &source(wake(dev, Some(i), "dev"), WakeSource::Retry))
        .await
        .unwrap();
    let run = super::wake::dispatch(pool, r, NOW).await.unwrap();
    assert_eq!(run.agent_id, dev);
}

#[tokio::test]
async fn a_wake_on_an_issue_in_review_by_another_agent_is_dropped() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    let qa = agent(pool, company).await;
    hand_to(pool, i, qa, "in_review").await;
    let r = runner(pool, "box").await;
    enqueue_wake(pool, &source(wake(dev, Some(i), "d"), WakeSource::Retry))
        .await
        .unwrap();
    assert!(super::wake::dispatch(pool, r, NOW).await.is_none());
    enqueue_wake(
        pool,
        &source(wake(qa, Some(i), "q"), WakeSource::Assignment),
    )
    .await
    .unwrap();
    assert_eq!(
        super::wake::dispatch(pool, r, NOW).await.unwrap().agent_id,
        qa
    );
}

async fn status_of(pool: &SqlitePool, id: WakeRequestId) -> String {
    sqlx::query_scalar("SELECT status FROM wake_requests WHERE id = ?")
        .bind(id.0)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn count(pool: &SqlitePool, sql: &'static str, id: Option<i64>) -> i64 {
    let q = sqlx::query_scalar(sql);
    match id {
        Some(id) => q.bind(id),
        None => q,
    }
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn one_run_per_issue_across_agents() {
    let db = db().await;
    let pool = &db.pool;
    let (a, i) = fixture(pool, "A").await;
    let company = get_agent(pool, a).await.unwrap().unwrap().company_id;
    let b = agent(pool, company).await;
    hand_to(pool, i, a, "in_progress").await;
    let (ra, rb) = (runner(pool, "a").await, runner(pool, "b").await);
    // B's wake is a person's (`manual`), so it is pending and valid, not stale.
    enqueue_wake(pool, &source(wake(a, Some(i), "a"), WakeSource::Retry))
        .await
        .unwrap();
    enqueue_wake(pool, &source(wake(b, Some(i), "b"), WakeSource::Manual))
        .await
        .unwrap();
    assert_eq!(
        super::wake::dispatch(pool, ra, NOW).await.unwrap().agent_id,
        a
    );
    assert!(super::wake::dispatch(pool, rb, NOW).await.is_none());
    assert_eq!(count(pool, "SELECT count(*) FROM runs", None).await, 1);
}

#[tokio::test]
async fn reassigning_mid_queue_drops_the_old_actors_wake() {
    let db = db().await;
    let pool = &db.pool;
    let (a, i) = fixture(pool, "A").await;
    let company = get_agent(pool, a).await.unwrap().unwrap().company_id;
    let b = agent(pool, company).await;
    hand_to(pool, i, a, "todo").await;
    let r = runner(pool, "box").await;
    let wa = enqueue_wake(pool, &source(wake(a, Some(i), "a"), WakeSource::Assignment))
        .await
        .unwrap();
    let wb = enqueue_wake(pool, &source(wake(b, Some(i), "b"), WakeSource::Assignment))
        .await
        .unwrap();
    hand_to(pool, i, b, "todo").await;
    assert_eq!(
        super::wake::dispatch(pool, r, NOW).await.unwrap().agent_id,
        b
    );
    assert_eq!(status_of(pool, wa.id).await, "dropped");
    assert_eq!(status_of(pool, wb.id).await, "dispatched");
    let audited =
        "SELECT count(*) FROM audit_events WHERE action = 'wake.dropped' AND entity_id = ?";
    assert_eq!(count(pool, audited, Some(wa.id.0)).await, 1);
    assert_eq!(count(pool, "SELECT count(*) FROM runs", None).await, 1);
}

#[tokio::test]
async fn a_stale_wake_on_a_todo_issue_is_dropped() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    let qa = agent(pool, company).await;
    hand_to(pool, i, dev, "todo").await;
    let r = runner(pool, "box").await;
    let w = enqueue_wake(
        pool,
        &source(wake(qa, Some(i), "q"), WakeSource::Assignment),
    )
    .await
    .unwrap();
    assert!(super::wake::dispatch(pool, r, NOW).await.is_none());
    assert_eq!(status_of(pool, w.id).await, "dropped");
}

#[tokio::test]
async fn issue_less_wakes_stay_per_agent() {
    let db = db().await;
    let pool = &db.pool;
    let (a, _) = fixture(pool, "A").await;
    let company = get_agent(pool, a).await.unwrap().unwrap().company_id;
    let b = agent(pool, company).await;
    let r = runner(pool, "box").await;
    enqueue_wake(pool, &wake(a, None, "a")).await.unwrap();
    enqueue_wake(pool, &wake(b, None, "b")).await.unwrap();
    assert_eq!(
        super::wake::dispatch(pool, r, NOW).await.unwrap().agent_id,
        a
    );
    // B is not held by A's live run.
    assert_eq!(
        super::wake::dispatch(pool, r, NOW).await.unwrap().agent_id,
        b
    );
}
