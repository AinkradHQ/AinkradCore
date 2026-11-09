//! Stuck auto-repair (E15.8): one test per rule (build the stuck state, tick, see it repaired
//! without a human), the repair budget handing an issue to the admin once, idle escalation, and
//! the stuck report's last repair. States the engine forbids are built with raw SQL.

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::exec::RepairAction;
use citadel_core::settings::{Key, Scope};
use citadel_core::work::BlockerLink;

use super::breaker::led;
use super::flow::{set, sibling};
use super::stuck::{HOUR, after, agent_status, online};
use super::wake::wake;
use super::*;
use crate::store::audit;
use crate::store::work::{add_blocker, get_issue};

/// One tick `secs` after the database clock: what it repaired, as (rule, action, changed).
async fn tick_at(pool: &SqlitePool, secs: i64) -> Vec<(String, String, bool)> {
    let report = tick(pool, &after(pool, secs).await).await.unwrap();
    let all = report.repaired.into_iter();
    all.map(|r| (r.rule, r.action, r.changed)).collect()
}

fn one(rule: &str, action: &str) -> Vec<(String, String, bool)> {
    vec![(rule.to_owned(), action.to_owned(), true)]
}

async fn next_of(pool: &SqlitePool, i: IssueId) -> (IssueState, Option<NextActor>) {
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    (issue.state, issue.next_actor)
}

async fn pending_wakes(pool: &SqlitePool, a: AgentId, i: IssueId) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM wake_requests WHERE agent_id = ? AND issue_id = ? \
         AND status = 'pending'",
    )
    .bind(a.0)
    .bind(i.0)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn audits(pool: &SqlitePool, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn no_next_actor_goes_to_the_lead() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    let mut c = pool.acquire().await.unwrap();
    for sql in [
        "PRAGMA ignore_check_constraints = ON",
        "UPDATE issues SET next_user_id = NULL",
        "PRAGMA ignore_check_constraints = OFF",
    ] {
        sqlx::query(sql).execute(&mut *c).await.unwrap();
    }
    drop(c);
    assert_eq!(
        tick_at(pool, 0).await,
        one("no_next_actor", "reassign_to_lead")
    );
    assert_eq!(next_of(pool, i).await.1, Some(NextActor::Agent(lead)));
    assert_eq!(audits(pool, "repair.no_next_actor").await, 1);
}

#[tokio::test]
async fn a_blocked_issue_with_no_open_blocker_is_unblocked() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    online(pool, "mac", &[]).await;
    // No blocker at all.
    set(pool, i, IssueState::Blocked, Some(NextActor::Agent(dev))).await;
    assert_eq!(tick_at(pool, 0).await, one("blocked_no_blocker", "unblock"));
    assert_eq!(next_of(pool, i).await.0, IssueState::Todo);

    // Every blocker closed: unblocked, and its agent woken.
    let b = sibling(pool, i).await;
    let link = BlockerLink {
        blocker: b,
        blocked: i,
    };
    add_blocker(pool, link).await.unwrap();
    set(pool, i, IssueState::Blocked, Some(NextActor::Agent(dev))).await;
    set(pool, b, IssueState::Done, None).await;
    assert_eq!(
        tick_at(pool, 0).await,
        one("blocked_blockers_closed", "unblock")
    );
    assert_eq!(next_of(pool, i).await.0, IssueState::Todo);
    assert_eq!(pending_wakes(pool, dev, i).await, 1);
}

#[tokio::test]
async fn an_inactive_or_breaker_paused_agents_issue_goes_up_the_chain() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    let cases = [
        (IssueState::Todo, "next_actor_inactive"),
        (IssueState::InReview, "reviewer_inactive"),
        (IssueState::InProgress, "agent_paused_by_breaker"),
    ];
    for (state, rule) in cases {
        set(pool, i, state, Some(NextActor::Agent(dev))).await;
        agent_status(pool, dev, "paused").await;
        if rule == "agent_paused_by_breaker" {
            let company: i64 = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
                .bind(dev.0)
                .fetch_one(pool)
                .await
                .unwrap();
            let paused = NewAuditEvent {
                actor: AuditActor::System,
                action: "agent.paused_by_breaker".to_owned(),
                entity: Some(AuditEntity {
                    kind: "agent".to_owned(),
                    id: dev.0,
                }),
                company_id: Some(CompanyId(company)),
                run_id: None,
                details: "{}".to_owned(),
            };
            audit::append(pool, &paused).await.unwrap();
        }
        assert_eq!(tick_at(pool, 0).await, one(rule, "escalate"), "{rule}");
        assert_eq!(
            next_of(pool, i).await,
            (state, Some(NextActor::Agent(lead)))
        );
    }
}

#[tokio::test]
async fn an_idle_issue_wakes_its_agent_again() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    led(pool, dev).await;
    online(pool, "mac", &[]).await;
    let cases = [
        (IssueState::Todo, "todo_idle"),
        (IssueState::InProgress, "in_progress_idle"),
        (IssueState::InReview, "review_no_reviewer"),
    ];
    for (n, (state, rule)) in cases.into_iter().enumerate() {
        set(pool, i, state, Some(NextActor::Agent(dev))).await;
        // Each repair touches the issue: the next is stuck only an hour later.
        let at = (2 * n as i64 + 1) * HOUR;
        assert_eq!(tick_at(pool, at).await, one(rule, "rewake"), "{rule}");
        assert_eq!(tick_at(pool, at).await, vec![], "idempotent: {rule}");
        assert_eq!(pending_wakes(pool, dev, i).await, 1, "{rule}");
        sqlx::query("UPDATE wake_requests SET status = 'dropped', dropped_reason = 'test'")
            .execute(pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn a_review_waiting_on_a_timer_goes_to_the_lead() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    let timer = NextActor::Timer("2026-10-22T09:00:00.000Z".to_owned());
    set(pool, i, IssueState::InReview, Some(timer)).await;
    assert_eq!(
        tick_at(pool, 0).await,
        one("review_no_reviewer", "reassign_to_lead")
    );
    assert_eq!(next_of(pool, i).await.1, Some(NextActor::Agent(lead)));
}

#[tokio::test]
async fn a_wake_no_runner_can_serve_is_dropped_and_its_issue_escalated() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    sqlx::query("UPDATE agents SET runner_tags = '[\"xcode\"]' WHERE id = ?")
        .bind(dev.0)
        .execute(pool)
        .await
        .unwrap();
    online(pool, "linux", &["linux"]).await;
    set(pool, i, IssueState::Todo, Some(NextActor::Agent(dev))).await;
    enqueue_wake(pool, &wake(dev, Some(i), "on-issue"))
        .await
        .unwrap();
    enqueue_wake(pool, &wake(dev, None, "no-issue"))
        .await
        .unwrap();
    let mut repaired = tick_at(pool, HOUR).await;
    repaired.sort();
    assert_eq!(
        repaired,
        vec![
            ("wake_no_runner".to_owned(), "drop_wake".to_owned(), true),
            ("wake_no_runner".to_owned(), "escalate".to_owned(), true),
        ]
    );
    assert_eq!(next_of(pool, i).await.1, Some(NextActor::Agent(lead)));
    let reasons: Vec<String> = sqlx::query_scalar(
        "SELECT dropped_reason FROM wake_requests WHERE agent_id = ? ORDER BY id",
    )
    .bind(dev.0)
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(reasons.len(), 2);
    assert!(
        reasons.iter().all(|r| r.starts_with("repair: ")),
        "{reasons:?}"
    );
}

#[tokio::test]
async fn a_lost_queued_run_is_requeued_and_a_dead_checkout_released() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    online(pool, "mac", &[]).await;
    set(pool, i, IssueState::InProgress, Some(NextActor::Agent(dev))).await;
    let run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    assert_eq!(
        tick_at(pool, HOUR).await,
        one("run_queued_no_lease", "requeue")
    );
    let run = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!(run.state, RunState::Cancelled);
    assert_eq!(pending_wakes(pool, dev, i).await, 1, "woken again");

    // A checkout held by that ended run.
    sqlx::query(
        "UPDATE issues SET checkout_run_id = ?, checked_out_at = '2026-10-21T10:00:00.000Z' \
         WHERE id = ?",
    )
    .bind(run.id.0)
    .bind(i.0)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        tick_at(pool, 2 * HOUR).await,
        one("checkout_dead", "release_checkout")
    );
    let held: Option<i64> = sqlx::query_scalar("SELECT checkout_run_id FROM issues WHERE id = ?")
        .bind(i.0)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(held, None);
}

/// The budget (3 a day by default): the fourth time the issue is stuck it goes to the admin,
/// once, with its repair history; then nothing repairs it again.
#[tokio::test]
async fn past_its_budget_an_issue_goes_to_the_admin_once() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    online(pool, "mac", &[]).await;
    set(pool, i, IssueState::InProgress, Some(NextActor::Agent(dev))).await;
    for n in 1..=3 {
        assert_eq!(
            tick_at(pool, n * HOUR).await,
            one("in_progress_idle", "rewake"),
            "{n}"
        );
        // The woken agent does nothing: the wake is dropped and the issue idles again.
        sqlx::query("UPDATE wake_requests SET status = 'dropped', dropped_reason = 'test'")
            .execute(pool)
            .await
            .unwrap();
    }
    assert_eq!(
        tick_at(pool, 4 * HOUR).await,
        one("exhausted", "escalate_to_admin")
    );
    assert_eq!(next_of(pool, i).await.1, Some(NextActor::Human(UserId(1))));
    let history: String = sqlx::query_scalar(
        "SELECT json_extract(details, '$.history') FROM audit_events \
         WHERE action = 'repair.exhausted'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let history: serde_json::Value = serde_json::from_str(&history).unwrap();
    assert_eq!(history.as_array().unwrap().len(), 3, "{history}");
    assert_eq!(history[0]["rule"], "in_progress_idle");
    for n in 5..8 {
        assert_eq!(tick_at(pool, n * HOUR).await, vec![], "never again: {n}");
    }
    assert_eq!(audits(pool, "repair.exhausted").await, 1);

    // The report shows the last repair.
    set(pool, i, IssueState::Todo, Some(NextActor::Agent(dev))).await;
    let stuck = stuck_report(pool, &after(pool, 9 * HOUR).await)
        .await
        .unwrap();
    assert_eq!(stuck[0].repair, RepairAction::Rewake);
    let last = stuck[0].last_repair.as_ref().unwrap();
    assert_eq!(last.action, "escalate_to_admin");
}

#[tokio::test]
async fn a_zero_budget_hands_over_at_once_and_the_budget_is_per_project() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    online(pool, "mac", &[]).await;
    let p = get_issue(pool, i).await.unwrap().unwrap().project_id;
    let now = after(pool, 0).await;
    crate::store::settings::set(
        pool,
        Key::RepairBudget,
        Scope::Project(p),
        "0",
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    set(pool, i, IssueState::Todo, Some(NextActor::Agent(dev))).await;
    assert_eq!(
        tick_at(pool, HOUR).await,
        one("exhausted", "escalate_to_admin")
    );
}

#[tokio::test]
async fn an_issue_untouched_past_the_idle_limit_escalates() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let lead = led(pool, dev).await;
    online(pool, "mac", &[]).await;
    // A pending wake is a wake path, so nothing is stuck; it just never moves.
    set(pool, i, IssueState::Todo, Some(NextActor::Agent(dev))).await;
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    assert_eq!(tick_at(pool, 23 * HOUR).await, vec![]);
    assert_eq!(
        tick_at(pool, 25 * HOUR).await,
        one("issue_idle", "escalate")
    );
    assert_eq!(next_of(pool, i).await.1, Some(NextActor::Agent(lead)));

    // 0 turns it off.
    let now = after(pool, 0).await;
    crate::store::settings::set(
        pool,
        Key::IdleEscalateSecs,
        Scope::Server,
        "0",
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    let j = sibling(pool, i).await;
    set(pool, j, IssueState::Todo, Some(NextActor::Agent(dev))).await;
    enqueue_wake(pool, &wake(dev, Some(j), "k2")).await.unwrap();
    let later = tick_at(pool, 30 * 24 * HOUR).await;
    assert!(
        !later.iter().any(|(rule, ..)| rule == "issue_idle"),
        "{later:?}"
    );
}
