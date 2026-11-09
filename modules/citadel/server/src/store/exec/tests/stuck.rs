//! The stuck detector: one test per rule. States the engine forbids are built with raw SQL.

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::exec::{RunEvent, StuckIssue, StuckKind};
use citadel_core::work::BlockerLink;

use super::flow::{set, sibling};
use super::wake::wake;
use super::*;
use crate::store::audit;
use crate::store::work::add_blocker;

/// The database clock plus `secs`: rows were stamped by it, so ages are measured from it.
pub(super) async fn after(pool: &SqlitePool, secs: i64) -> String {
    sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)")
        .bind(format!("+{secs} seconds"))
        .fetch_one(pool)
        .await
        .unwrap()
}

pub(super) const HOUR: i64 = 3600;

async fn report(pool: &SqlitePool, secs: i64) -> Vec<StuckIssue> {
    stuck_report(pool, &after(pool, secs).await).await.unwrap()
}

async fn kinds(pool: &SqlitePool, secs: i64) -> Vec<(StuckKind, Option<IssueId>)> {
    let all = report(pool, secs).await;
    all.into_iter().map(|s| (s.kind, s.issue_id)).collect()
}

pub(super) async fn agent_status(pool: &SqlitePool, a: AgentId, status: &str) {
    sqlx::query("UPDATE agents SET status = ? WHERE id = ?")
        .bind(status)
        .bind(a.0)
        .execute(pool)
        .await
        .unwrap();
}

/// An online runner with `tags`, so wakes needing no more than those are servable.
pub(super) async fn online(pool: &SqlitePool, name: &str, tags: &[&str]) -> RunnerId {
    let r = NewRunner {
        name: name.to_owned(),
        tags: tags.iter().map(|t| t.to_string()).collect(),
    };
    let id = create_runner(pool, &r, name).await.unwrap().id;
    sqlx::query("UPDATE runners SET status = 'online' WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn blocked_with_no_blocker_is_stuck_and_a_healthy_issue_is_not() {
    let db = db().await;
    let pool = &db.pool;
    let (_, i) = fixture(pool, "A").await;
    // Waiting on a human: fine, however long.
    assert_eq!(kinds(pool, 24 * HOUR).await, vec![]);
    set(
        pool,
        i,
        IssueState::Blocked,
        Some(NextActor::Human(UserId(1))),
    )
    .await;
    let stuck = report(pool, 0).await;
    assert_eq!(stuck.len(), 1);
    assert_eq!(
        (stuck[0].kind, stuck[0].issue_id),
        (StuckKind::BlockedNoBlocker, Some(i))
    );
    assert!(stuck[0].reason.contains("no linked blocker"));
    assert!(!stuck[0].action.is_empty());
}

#[tokio::test]
async fn blocked_with_every_blocker_closed_is_stuck() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let b = sibling(pool, i).await;
    let link = BlockerLink {
        blocker: b,
        blocked: i,
    };
    add_blocker(pool, link).await.unwrap();
    set(pool, i, IssueState::Blocked, Some(NextActor::Agent(dev))).await;
    // An open blocker holds it: not stuck.
    assert_eq!(kinds(pool, HOUR).await, vec![]);
    set(pool, b, IssueState::Done, None).await;
    assert_eq!(
        kinds(pool, 0).await,
        vec![(StuckKind::BlockedBlockersClosed, Some(i))]
    );
}

#[tokio::test]
async fn in_review_with_no_pending_reviewer_is_stuck() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    online(pool, "mac", &[]).await;
    let timer = NextActor::Timer("2026-10-22T09:00:00.000Z".to_owned());
    set(pool, i, IssueState::InReview, Some(timer)).await;
    assert_eq!(
        kinds(pool, 0).await,
        vec![(StuckKind::ReviewNoReviewer, Some(i))]
    );
    // An agent reviewer with no wake and no run: nobody will review it.
    set(pool, i, IssueState::InReview, Some(NextActor::Agent(dev))).await;
    assert_eq!(kinds(pool, 60).await, vec![]);
    let stuck = report(pool, HOUR).await;
    assert_eq!(
        (stuck[0].kind, stuck[0].agent_id),
        (StuckKind::ReviewNoReviewer, Some(dev))
    );
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    assert_eq!(kinds(pool, HOUR).await, vec![]);
}

#[tokio::test]
async fn in_review_by_a_paused_or_terminated_agent_is_stuck() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    set(pool, i, IssueState::InReview, Some(NextActor::Agent(dev))).await;
    for status in ["paused", "terminated"] {
        agent_status(pool, dev, status).await;
        let stuck = report(pool, 0).await;
        assert_eq!(stuck.len(), 1, "{status}");
        assert_eq!(stuck[0].kind, StuckKind::ReviewerInactive);
        assert!(stuck[0].reason.contains(status), "{}", stuck[0].reason);
    }
}

#[tokio::test]
async fn in_progress_with_no_live_run_and_no_wake_is_stuck() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mac = online(pool, "mac", &[]).await;
    set(pool, i, IssueState::InProgress, Some(NextActor::Agent(dev))).await;
    assert_eq!(
        kinds(pool, HOUR).await,
        vec![(StuckKind::InProgressIdle, Some(i))]
    );
    // A live run on it, or a pending wake for its agent, is a wake path.
    enqueue_wake(pool, &wake(dev, Some(i), "run"))
        .await
        .unwrap();
    let run = dispatch_next(pool, mac, &[], &Harness::ALL, &after(pool, 0).await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kinds(pool, HOUR).await, vec![]);
    let cancel = RunEvent::Cancel {
        reason: "stop".to_owned(),
    };
    let now = after(pool, 0).await;
    transition_run(pool, run.id, AuditActor::System, &cancel, &now)
        .await
        .unwrap();
    enqueue_wake(pool, &wake(dev, Some(i), "k")).await.unwrap();
    assert_eq!(kinds(pool, HOUR).await, vec![]);
}

#[tokio::test]
async fn a_queued_run_with_no_lease_is_stuck_after_the_threshold() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    set(pool, i, IssueState::InProgress, Some(NextActor::Agent(dev))).await;
    // Only a raw insert leaves a run queued: dispatch claims what it queues.
    let run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    assert_eq!(kinds(pool, 60).await, vec![]);
    let stuck = report(pool, HOUR).await;
    assert_eq!(stuck.len(), 1, "{stuck:?}");
    assert_eq!(
        (stuck[0].kind, stuck[0].issue_id, stuck[0].agent_id),
        (StuckKind::RunQueuedNoLease, Some(i), Some(dev))
    );
    assert!(stuck[0].reason.contains(&format!("run {}", run.id.0)));
    // Once it ends, the issue's own idleness is what is reported.
    let cancel = RunEvent::Cancel {
        reason: "stop".to_owned(),
    };
    let now = after(pool, 0).await;
    transition_run(pool, run.id, AuditActor::System, &cancel, &now)
        .await
        .unwrap();
    assert_eq!(
        kinds(pool, HOUR).await,
        vec![(StuckKind::InProgressIdle, Some(i))]
    );
}

#[tokio::test]
async fn todo_for_an_idle_agent_is_stuck_only_after_the_threshold() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    set(pool, i, IssueState::Todo, Some(NextActor::Agent(dev))).await;
    let threshold = citadel_core::exec::STUCK_AFTER_SECS;
    assert_eq!(kinds(pool, threshold - 60).await, vec![]);
    let stuck = report(pool, threshold + 60).await;
    assert_eq!(
        (stuck[0].kind, stuck[0].issue_id, stuck[0].agent_id),
        (StuckKind::TodoIdle, Some(i), Some(dev))
    );
    assert!(stuck[0].reason.contains("11 min"), "{}", stuck[0].reason);
}

#[tokio::test]
async fn an_issue_waiting_on_an_inactive_agent_is_stuck() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    set(pool, i, IssueState::Todo, Some(NextActor::Agent(dev))).await;
    for status in ["paused", "terminated"] {
        agent_status(pool, dev, status).await;
        assert_eq!(
            kinds(pool, 0).await,
            vec![(StuckKind::NextActorInactive, Some(i))],
            "{status}"
        );
    }
}

#[tokio::test]
async fn an_open_issue_with_no_next_actor_is_stuck() {
    let db = db().await;
    let pool = &db.pool;
    let (_, i) = fixture(pool, "A").await;
    // The schema forbids it; switch its checks off on one connection to build the case.
    let mut c = pool.acquire().await.unwrap();
    for sql in [
        "PRAGMA ignore_check_constraints = ON",
        "UPDATE issues SET next_user_id = NULL",
        "PRAGMA ignore_check_constraints = OFF",
    ] {
        sqlx::query(sql).execute(&mut *c).await.unwrap();
    }
    drop(c);
    let stuck = report(pool, 0).await;
    assert_eq!(
        (stuck[0].kind, stuck[0].issue_id),
        (StuckKind::NoNextActor, Some(i))
    );
    assert!(stuck[0].reason.contains("engine error"));
}

#[tokio::test]
async fn a_wake_no_online_runner_can_serve_is_stuck() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, _) = fixture(pool, "A").await;
    sqlx::query("UPDATE agents SET runner_tags = '[\"macos\", \"xcode\"]' WHERE id = ?")
        .bind(dev.0)
        .execute(pool)
        .await
        .unwrap();
    online(pool, "linux", &["linux", "macos"]).await;
    enqueue_wake(pool, &wake(dev, None, "k")).await.unwrap();
    assert_eq!(kinds(pool, 60).await, vec![]);
    let stuck = report(pool, HOUR).await;
    assert_eq!(
        (stuck[0].kind, stuck[0].issue_id, stuck[0].agent_id),
        (StuckKind::WakeNoRunner, None, Some(dev))
    );
    assert!(stuck[0].reason.contains("xcode"), "{}", stuck[0].reason);

    let mac = online(pool, "mac", &["macos", "xcode"]).await;
    assert_eq!(kinds(pool, HOUR).await, vec![]);
    // Offline runners do not count.
    sqlx::query("UPDATE runners SET status = 'offline' WHERE id = ?")
        .bind(mac.0)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(
        kinds(pool, HOUR).await,
        vec![(StuckKind::WakeNoRunner, None)]
    );
}

#[tokio::test]
async fn open_issues_of_an_agent_the_breaker_paused_are_stuck() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    set(pool, i, IssueState::InProgress, Some(NextActor::Agent(dev))).await;
    agent_status(pool, dev, "paused").await;
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
    let stuck = report(pool, 0).await;
    assert_eq!(
        (stuck[0].kind, stuck[0].issue_id, stuck[0].agent_id),
        (StuckKind::AgentPausedByBreaker, Some(i), Some(dev))
    );
    assert!(stuck[0].reason.contains("loop breaker"));
}

/// A `todo` issue a full kanban `in_progress` column holds back waits on the flow, not on its
/// agent: not stuck (E5.3). Once the column has room, its idleness counts again.
#[tokio::test]
async fn todo_held_by_a_full_wip_column_is_not_stuck() {
    use crate::store::work::set_wip_limit;

    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let p = crate::store::work::get_issue(pool, i)
        .await
        .unwrap()
        .unwrap()
        .project_id;
    sqlx::query("UPDATE projects SET mode = 'kanban' WHERE id = ?")
        .bind(p.0)
        .execute(pool)
        .await
        .unwrap();
    let limit = |n| set_wip_limit(pool, p, IssueState::InProgress, Some(n), AuditActor::System);
    limit(1).await.unwrap();
    set(pool, i, IssueState::Todo, Some(NextActor::Agent(dev))).await;
    let busy = sibling(pool, i).await;
    set(
        pool,
        busy,
        IssueState::InProgress,
        Some(NextActor::Human(UserId(1))),
    )
    .await;
    assert_eq!(kinds(pool, HOUR).await, vec![]);
    limit(2).await.unwrap();
    assert_eq!(
        kinds(pool, HOUR).await,
        vec![(StuckKind::TodoIdle, Some(i))]
    );
}
