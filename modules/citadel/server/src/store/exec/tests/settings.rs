//! The engine's thresholds are read from settings (E15.17): each test changes one and shows
//! the behaviour change, at the scope the engine reads it for (the run's project, the agent's
//! company, the runner).

use citadel_core::audit::AuditActor;
use citadel_core::exec::RunEvent;
use citadel_core::settings::{Key, Scope};

use super::breaker::fresh_fail_at;
use super::flow::{set as set_issue, sibling};
use super::wake::{dispatch, runner, wake};
use super::*;
use crate::store::org::get_agent;
use crate::store::settings;
use crate::store::work::get_issue;

const NOW: &str = "2026-10-21T10:00:00.000Z";
const BY: AuditActor = AuditActor::User(UserId(1));

pub(super) async fn set(pool: &SqlitePool, key: Key, at: Scope, value: i64) {
    settings::set(pool, key, at, &value.to_string(), BY, NOW)
        .await
        .unwrap();
}

async fn project_of(pool: &SqlitePool, i: IssueId) -> Scope {
    Scope::Project(get_issue(pool, i).await.unwrap().unwrap().project_id)
}

async fn company_of(pool: &SqlitePool, a: AgentId) -> Scope {
    Scope::Company(get_agent(pool, a).await.unwrap().unwrap().company_id)
}

fn fail() -> RunEvent {
    RunEvent::Fail {
        reason: "tests red".to_owned(),
        fingerprint: None,
    }
}

/// Dispatches `dev`'s next wake at `at` and fails it.
async fn failed(pool: &SqlitePool, mac: RunnerId, at: &str) -> Run {
    let run = dispatch(pool, mac, at).await.unwrap();
    let by = AuditActor::Runner(mac);
    start_run(pool, run.id, by, None, at).await.unwrap();
    transition_run(pool, run.id, by, &fail(), at).await.unwrap()
}

#[tokio::test]
async fn wake_attempts_and_the_backoff_cap_are_settings() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    // The company caps the backoff at 45 s: attempt 2 waits 45 s, not 60.
    set(
        pool,
        Key::RetryBackoffMaxSecs,
        company_of(pool, dev).await,
        45,
    )
    .await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    let run1 = failed(pool, mac, NOW).await;
    let Retry::Scheduled(w2) = schedule_retry(pool, run1.id, NOW).await.unwrap() else {
        panic!("not scheduled");
    };
    assert_eq!(w2.not_before.as_deref(), Some("2026-10-21T10:00:30.000Z"));
    let at = "2026-10-21T10:00:30.000Z";
    let run2 = failed(pool, mac, at).await;
    let Retry::Scheduled(w3) = schedule_retry(pool, run2.id, at).await.unwrap() else {
        panic!("not scheduled");
    };
    assert_eq!(w3.not_before.as_deref(), Some("2026-10-21T10:01:15.000Z"));
}

#[tokio::test]
async fn wake_attempts_are_the_projects_setting() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    set(pool, Key::WakeMaxAttempts, project_of(pool, i).await, 2).await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    let run1 = failed(pool, mac, NOW).await;
    let retry = schedule_retry(pool, run1.id, NOW).await.unwrap();
    assert!(matches!(retry, Retry::Scheduled(_)), "{retry:?}");
    let run2 = failed(pool, mac, "2026-10-21T10:00:30.000Z").await;
    assert_eq!(
        schedule_retry(pool, run2.id, NOW).await.unwrap(),
        Retry::Exhausted { attempt: 2 },
        "two attempts, not the default three"
    );
}

const TRIPS: &str = "SELECT count(*) FROM audit_events WHERE action = 'loop_breaker.tripped'";

async fn count(pool: &SqlitePool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn the_loop_breaker_threshold_is_the_projects_setting() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    set(
        pool,
        Key::LoopBreakerThreshold,
        project_of(pool, i).await,
        2,
    )
    .await;
    fresh_fail_at(pool, mac, (dev, i), "k1", "tests red", NOW).await;
    assert_eq!(count(pool, TRIPS).await, 0);
    fresh_fail_at(pool, mac, (dev, i), "k2", "tests red", NOW).await;
    assert_eq!(
        count(pool, TRIPS).await,
        1,
        "tripped at 2, not the default 3"
    );
}

/// Trips `dev`'s breaker (threshold 2) on a new issue next to `i` at `at`; whether `dev` is
/// paused after it.
async fn trip(pool: &SqlitePool, mac: RunnerId, dev: AgentId, i: IssueId, at: &str) -> bool {
    let issue = sibling(pool, i).await;
    for n in 0..2 {
        let key = format!("{}:{n}", issue.0);
        fresh_fail_at(pool, mac, (dev, issue), &key, "tests red", at).await;
    }
    let a = get_agent(pool, dev).await.unwrap().unwrap();
    a.status == AgentStatus::Paused
}

#[tokio::test]
async fn agent_trips_and_their_window_are_the_companys_settings() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    let company = company_of(pool, dev).await;
    set(pool, Key::LoopBreakerThreshold, company, 2).await;
    set(pool, Key::AgentBreakerTrips, company, 2).await;
    // Two trips 2 min apart: inside the default hour, outside a 60 s window.
    set(pool, Key::AgentBreakerWindowSecs, company, 60).await;
    assert!(!trip(pool, mac, dev, i, "2026-10-21T10:00:00.000Z").await);
    assert!(!trip(pool, mac, dev, i, "2026-10-21T10:02:00.000Z").await);
    // Back to the hour: the next trip is the second within it.
    settings::reset(pool, Key::AgentBreakerWindowSecs, company, BY, NOW)
        .await
        .unwrap();
    assert!(trip(pool, mac, dev, i, "2026-10-21T10:03:00.000Z").await);
}

#[tokio::test]
async fn one_trip_pauses_when_the_company_says_so() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    let company = company_of(pool, dev).await;
    set(pool, Key::LoopBreakerThreshold, company, 2).await;
    set(pool, Key::AgentBreakerTrips, company, 1).await;
    assert!(trip(pool, mac, dev, i, NOW).await);
}

#[tokio::test]
async fn the_lease_ttl_is_the_runners_setting() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let (mac, pc) = (runner(pool, "mac").await, runner(pool, "pc").await);
    set(pool, Key::LeaseTtlSecs, Scope::Runner(mac), 30).await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    let run = dispatch(pool, mac, NOW).await.unwrap();
    let lease = get_lease(pool, run.id).await.unwrap().unwrap();
    assert_eq!(lease.expires_at, "2026-10-21T10:00:30.000Z");
    let renewed = renew_lease(pool, run.id, mac, "2026-10-21T10:00:10.000Z").await;
    assert_eq!(renewed.unwrap().expires_at, "2026-10-21T10:00:40.000Z");
    // Another runner keeps the server's 90 s.
    let other = sibling(pool, i).await;
    enqueue_wake(pool, &wake(dev, Some(other), "o"))
        .await
        .unwrap();
    let run = dispatch(pool, pc, NOW).await.unwrap();
    let lease = get_lease(pool, run.id).await.unwrap().unwrap();
    assert_eq!(lease.expires_at, "2026-10-21T10:01:30.000Z");
}

/// The database clock plus `secs`: issues are stamped by it (the stuck detector measures from it).
async fn after(pool: &SqlitePool, secs: i64) -> String {
    sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)")
        .bind(format!("+{secs} seconds"))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn stuck_after_is_the_projects_setting_over_the_companys() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    set_issue(pool, i, IssueState::Todo, Some(NextActor::Agent(dev))).await;
    let stuck = |secs| async move { stuck_report(pool, &after(pool, secs).await).await.unwrap() };
    assert!(stuck(300).await.is_empty(), "the default is 10 min");
    set(pool, Key::StuckAfterSecs, company_of(pool, dev).await, 240).await;
    assert_eq!(stuck(300).await.len(), 1, "the company's 4 min");
    set(pool, Key::StuckAfterSecs, project_of(pool, i).await, 3600).await;
    assert!(
        stuck(1800).await.is_empty(),
        "the project's hour beats the company"
    );
    assert_eq!(stuck(3700).await.len(), 1);
}
