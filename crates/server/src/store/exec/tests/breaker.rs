//! The loop breaker: the same failure three times in a row on one agent and issue stops
//! retrying and escalates once; three trips within the hour pause the agent.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::exec::{LOOP_BREAKER_THRESHOLD, MAX_WAKE_ATTEMPTS, RunEvent};

use super::flow::{sibling, wakes_for};
use super::wake::{dispatch, runner, wake};
use super::*;
use crate::store::org::get_agent;
use crate::store::work::get_issue;

const NOW: &str = "2026-10-21T10:00:00.000Z";

/// `dev` with a lead (its team's) in its company; the lead needs a tag the test runner lacks, so its
/// wakes wait and every dispatch here serves `dev`.
pub(super) async fn led(pool: &SqlitePool, dev: AgentId) -> AgentId {
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(dev.0)
        .fetch_one(pool)
        .await
        .unwrap();
    let lead = agent(pool, CompanyId(company)).await;
    lead_team(pool, dev, lead).await;
    sqlx::query("UPDATE agents SET runner_tags = '[\"lead\"]' WHERE id = ?")
        .bind(lead.0)
        .execute(pool)
        .await
        .unwrap();
    lead
}

/// Dispatches the next due wake at `at`, starts it and ends it with `end`.
async fn run_once(pool: &SqlitePool, mac: RunnerId, at: &str, end: RunEvent) -> Run {
    let run = dispatch(pool, mac, at).await.unwrap();
    let by = AuditActor::Runner(mac);
    start_run(pool, run.id, by, None, at).await.unwrap();
    transition_run(pool, run.id, by, &end, at).await.unwrap()
}

/// A fresh wake (attempt 1) for `dev` on `i`, then a run that fails with `reason` at `at`.
pub(super) async fn fresh_fail_at(
    pool: &SqlitePool,
    mac: RunnerId,
    (dev, i): (AgentId, IssueId),
    key: &str,
    reason: &str,
    at: &str,
) -> Run {
    enqueue_wake(pool, &wake(dev, Some(i), key)).await.unwrap();
    run_once(pool, mac, at, fail(reason)).await
}

/// `fresh_fail_at` at `NOW`.
async fn fresh_fail(
    pool: &SqlitePool,
    mac: RunnerId,
    dev: AgentId,
    i: IssueId,
    key: &str,
    reason: &str,
) -> Run {
    fresh_fail_at(pool, mac, (dev, i), key, reason, NOW).await
}

fn fail(reason: &str) -> RunEvent {
    RunEvent::Fail {
        reason: reason.to_owned(),
        fingerprint: None,
    }
}

async fn count(pool: &SqlitePool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

const TRIPS: &str = "SELECT count(*) FROM audit_events WHERE action = 'loop_breaker.tripped'";
const ESCALATIONS: &str = "SELECT count(*) FROM wake_requests WHERE source = 'escalation'";
/// Escalations hand the issue over with a `reassign`; one to the same lead adds no wake.
const REASSIGNS: &str =
    "SELECT count(*) FROM audit_events WHERE json_extract(details, '$.transition') = 'reassign'";

#[tokio::test]
async fn a_failed_run_trips_at_three_with_no_retry_asked_for() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    let mac = runner(pool, "mac").await;
    for n in 0..LOOP_BREAKER_THRESHOLD {
        fresh_fail(pool, mac, dev, i, &format!("k{n}"), "tests red").await;
        let tripped = n + 1 == LOOP_BREAKER_THRESHOLD;
        assert_eq!(count(pool, TRIPS).await, tripped as i64, "{n}");
        assert_eq!(count(pool, REASSIGNS).await, tripped as i64, "{n}");
    }
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(issue.next_actor, Some(NextActor::Agent(lead)));
    assert_eq!(count(pool, ESCALATIONS).await, 1);
}

#[tokio::test]
async fn a_token_capped_run_escalates_when_it_ends_and_only_then() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    let mac = runner(pool, "mac").await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    let run = run_once(pool, mac, NOW, RunEvent::TokenCap).await;
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(issue.next_actor, Some(NextActor::Agent(lead)));

    // Neither the retry call nor the reaper escalates it again.
    let retry = schedule_retry(pool, run.id, NOW).await.unwrap();
    assert_eq!(retry, Retry::TokenCap);
    let reaped = reap_expired_leases(pool, "2026-10-22T10:00:00.000Z").await;
    assert!(reaped.unwrap().is_empty());
    assert_eq!(
        (count(pool, REASSIGNS).await, count(pool, ESCALATIONS).await),
        (1, 1)
    );
}

#[tokio::test]
async fn a_last_attempt_escalates_when_it_ends() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    let mac = runner(pool, "mac").await;
    let mut last = enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    last.attempt = MAX_WAKE_ATTEMPTS;
    assert!(update_wake_request(pool, &last).await.unwrap());
    let run = run_once(pool, mac, NOW, fail("tests red")).await;
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(issue.next_actor, Some(NextActor::Agent(lead)));
    assert_eq!(count(pool, TRIPS).await, 0);

    let retry = schedule_retry(pool, run.id, NOW).await.unwrap();
    assert_eq!(
        retry,
        Retry::Exhausted {
            attempt: MAX_WAKE_ATTEMPTS
        }
    );
    assert_eq!(count(pool, REASSIGNS).await, 1);
}

#[tokio::test]
async fn a_repeating_failure_trips_at_exactly_three_with_one_escalation() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    let mac = runner(pool, "mac").await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();

    // Same error, differing only in path, line and worktree id: one fingerprint.
    let reasons = [
        "error[E0308] at src/lib.rs:41:5 in wt 550e8400-e29b-41d4-a716-446655440000",
        "error[E0308] at /tmp/wt/src/lib.rs:44:9 in wt 123e4567-e89b-12d3-a456-426614174000",
        "error[E0308] at crates/x/src/lib.rs:7:1 in wt 9b2c1d00-0000-4000-8000-00000000abcd",
    ];
    let times = [NOW, "2026-10-21T10:00:30.000Z", "2026-10-21T10:01:30.000Z"];
    let mut runs = vec![];
    let mut last = None;
    for (reason, at) in reasons.iter().zip(times) {
        let run = dispatch(pool, mac, at).await.unwrap();
        let by = AuditActor::Runner(mac);
        start_run(pool, run.id, by, None, at).await.unwrap();
        runs.push(run.id);
        if runs.len() == LOOP_BREAKER_THRESHOLD {
            // A wake that arrives meanwhile is dropped by the trip, not served.
            enqueue_wake(pool, &wake(dev, Some(i), "late"))
                .await
                .unwrap();
        }
        // The run's own end trips the breaker; the retry call only reports it.
        transition_run(pool, run.id, by, &fail(reason), at)
            .await
            .unwrap();
        last = Some(schedule_retry(pool, run.id, at).await.unwrap());
        if runs.len() < LOOP_BREAKER_THRESHOLD {
            assert!(matches!(last, Some(Retry::Scheduled(_))), "{last:?}");
        }
    }
    let Some(Retry::Tripped(trip)) = last else {
        panic!("{last:?}");
    };
    runs.reverse();
    assert_eq!(trip.runs, runs);
    assert_eq!(
        trip.fingerprint,
        "failed:error[E0308] at <path> in wt #-#-#-#-#"
    );
    // Already escalated by the run's end: the retry call does not escalate again.
    assert_eq!(trip.escalated_to, None);

    // Stopped: no retry for the last run, nothing pending for dev, the issue is the lead's.
    let retry = "SELECT count(*) FROM wake_requests WHERE idempotency_key = 'retry:run:3'";
    assert_eq!(count(pool, retry).await, 0);
    let pending = wakes_for(pool, i).await;
    assert!(
        pending
            .iter()
            .all(|w| w.agent_id != dev || w.status != WakeStatus::Pending)
    );
    let late = pending
        .iter()
        .find(|w| w.idempotency_key == "late")
        .unwrap();
    assert_eq!(late.status, WakeStatus::Dropped);
    assert!(
        late.dropped_reason
            .as_deref()
            .unwrap()
            .starts_with("loop breaker: failed:")
    );
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(issue.next_actor, Some(NextActor::Agent(lead)));
    let escalation = pending
        .iter()
        .find(|w| w.source == WakeSource::Escalation)
        .unwrap();
    assert_eq!(
        (escalation.agent_id, escalation.status),
        (lead, WakeStatus::Pending)
    );

    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'loop_breaker.tripped'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(
        details.contains(r#""count":3"#) && details.contains(r#""runs":[3,2,1]"#),
        "{details}"
    );
    assert!(details.contains(&trip.fingerprint), "{details}");
    let to = format!(r#""escalated_to":"agent:{}""#, lead.0);
    assert!(details.contains(&to), "{details}");

    // Asking again is idempotent: one trip, one escalation.
    let again = schedule_retry(pool, runs[0], NOW).await.unwrap();
    assert!(
        matches!(&again, Retry::Tripped(t) if t.escalated_to.is_none()),
        "{again:?}"
    );
    assert_eq!(
        (count(pool, TRIPS).await, count(pool, ESCALATIONS).await),
        (1, 1)
    );
}

#[tokio::test]
async fn a_success_in_between_resets_the_count_and_fresh_wakes_still_trip() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    fresh_fail(pool, mac, dev, i, "k1", "tests red").await;
    fresh_fail(pool, mac, dev, i, "k2", "tests red").await;
    enqueue_wake(pool, &wake(dev, Some(i), "k3")).await.unwrap();
    run_once(pool, mac, NOW, RunEvent::Succeed).await;
    fresh_fail(pool, mac, dev, i, "k4", "tests red").await;
    let fifth = fresh_fail(pool, mac, dev, i, "k5", "tests red").await;
    // Two since the success: retried.
    let Retry::Scheduled(w) = schedule_retry(pool, fifth.id, NOW).await.unwrap() else {
        panic!("not scheduled");
    };
    let sixth = run_once(
        pool,
        mac,
        w.not_before.as_deref().unwrap(),
        fail("tests red"),
    )
    .await;
    let tripped = schedule_retry(pool, sixth.id, NOW).await.unwrap();
    assert!(
        matches!(&tripped, Retry::Tripped(t) if t.runs.len() == 3),
        "{tripped:?}"
    );
    // No lead: the admin gets the issue.
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(issue.next_actor, Some(NextActor::Human(UserId(1))));
}

#[tokio::test]
async fn different_fingerprints_do_not_trip() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    fresh_fail(pool, mac, dev, i, "k1", "error[E0308] mismatched").await;
    fresh_fail(pool, mac, dev, i, "k2", "error[E0599] no method").await;
    let third = fresh_fail(pool, mac, dev, i, "k3", "error[E0308] mismatched").await;
    let retry = schedule_retry(pool, third.id, NOW).await.unwrap();
    assert!(matches!(retry, Retry::Scheduled(_)), "{retry:?}");
    // Another agent's or issue's failures do not count either.
    let other = sibling(pool, i).await;
    fresh_fail(pool, mac, dev, other, "o1", "error[E0308] mismatched").await;
    assert_eq!(count(pool, TRIPS).await, 0);
}

/// Trips `dev`'s breaker on a new issue next to `i` with runs ending at `at`, with no retry
/// asked for; whether `dev` is paused after it.
async fn trip(pool: &SqlitePool, mac: RunnerId, dev: AgentId, i: IssueId, at: &str) -> bool {
    let issue = sibling(pool, i).await;
    let trips = count(pool, TRIPS).await;
    for n in 0..LOOP_BREAKER_THRESHOLD {
        let key = format!("{}:{n}", issue.0);
        fresh_fail_at(pool, mac, (dev, issue), &key, "tests red", at).await;
    }
    assert_eq!(count(pool, TRIPS).await, trips + 1);
    let a = get_agent(pool, dev).await.unwrap().unwrap();
    a.status == AgentStatus::Paused
}

#[tokio::test]
async fn three_trips_within_the_hour_pause_the_agent() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    let mac = runner(pool, "mac").await;
    assert!(!trip(pool, mac, dev, i, "2026-10-21T10:00:00.000Z").await);
    assert!(!trip(pool, mac, dev, i, "2026-10-21T10:30:00.000Z").await);
    assert!(trip(pool, mac, dev, i, "2026-10-21T10:59:59.000Z").await);

    let a = get_agent(pool, dev).await.unwrap().unwrap();
    assert_eq!(a.status, AgentStatus::Paused);
    let paused = "SELECT count(*) FROM audit_events WHERE action = 'agent.paused_by_breaker'";
    assert_eq!(count(pool, paused).await, 1);
    let woken = list_wake_requests(pool, lead).await.unwrap();
    assert!(
        woken
            .iter()
            .any(|w| w.source == WakeSource::Escalation && w.issue_id.is_none()),
        "{woken:?}"
    );
}

#[tokio::test]
async fn three_trips_spread_beyond_the_hour_do_not_pause() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = runner(pool, "mac").await;
    for at in [
        "2026-10-21T10:00:00.000Z",
        "2026-10-21T10:40:00.000Z",
        "2026-10-21T11:20:00.000Z",
    ] {
        assert!(!trip(pool, mac, dev, i, at).await, "{at}");
    }
    let a = get_agent(pool, dev).await.unwrap().unwrap();
    assert_eq!(a.status, AgentStatus::Active);
}
