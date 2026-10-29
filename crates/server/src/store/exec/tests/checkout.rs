//! Issue checkout: one live run holds an issue; racers lose with `Conflict`.

use ainkrad_core::audit::{AuditActor, AuditEntity, AuditFilter};
use ainkrad_core::exec::RunEvent;

use super::flow::set;
use super::*;
use crate::store::audit;
use crate::store::work::{CheckoutError, checkout_issue, get_issue, release_issue, update_issue};

const NOW: &str = "2026-10-21T10:00:00.000Z";

async fn issue_audit(pool: &SqlitePool, id: IssueId) -> Vec<String> {
    let filter = AuditFilter {
        entity: Some(AuditEntity {
            kind: "issue".to_owned(),
            id: id.0,
        }),
        ..AuditFilter::default()
    };
    audit::list(pool, &filter, None, 100)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect()
}

async fn run_for(pool: &SqlitePool, dev: AgentId, i: IssueId) -> RunId {
    create_run(pool, &new_run(dev, Some(i))).await.unwrap().id
}

#[tokio::test]
async fn concurrent_checkouts_have_exactly_one_winner() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let mut runs = vec![];
    for _ in 0..8 {
        runs.push(run_for(pool, dev, i).await);
    }
    let tasks: Vec<_> = runs
        .iter()
        .map(|&r| {
            let pool = pool.clone();
            tokio::spawn(async move { (r, checkout_issue(&pool, i, r, NOW).await) })
        })
        .collect();
    let (mut winners, mut losers) = (vec![], vec![]);
    for t in tasks {
        match t.await.unwrap() {
            (r, Ok(_)) => winners.push(r),
            (_, Err(CheckoutError::Conflict { held_by })) => losers.push(held_by),
            (_, Err(e)) => panic!("unexpected {e}"),
        }
    }
    assert_eq!(winners.len(), 1, "{winners:?}");
    // Every loser is told who holds it.
    assert_eq!(losers, vec![winners[0]; 7]);
    let held = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(held.checkout_run_id, Some(winners[0]));
    assert_eq!(issue_audit(pool, i).await, ["issue.checked_out"]);
}

#[tokio::test]
async fn checkout_starts_the_issue_and_is_idempotent_for_the_holder() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let r = run_for(pool, dev, i).await;
    let first = checkout_issue(pool, i, r, NOW).await.unwrap();
    assert_eq!(first.state, IssueState::InProgress);
    assert_eq!(first.owner, Some(Actor::Agent(dev)));
    assert_eq!(first.next_actor, Some(NextActor::Agent(dev)));
    assert_eq!(first.checkout_run_id, Some(r));
    let again = checkout_issue(pool, i, r, "2026-10-21T11:00:00Z")
        .await
        .unwrap();
    assert_eq!(again, first);
    let at: String = sqlx::query_scalar("SELECT checked_out_at FROM issues WHERE id = ?")
        .bind(i.0)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(at, NOW);
    assert_eq!(issue_audit(pool, i).await, ["issue.checked_out"]);
    // An ordinary update leaves the checkout alone.
    assert!(update_issue(pool, &first).await.unwrap());
    let kept = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(kept.checkout_run_id, Some(r));
}

#[tokio::test]
async fn a_terminal_run_cannot_check_out() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let r = run_for(pool, dev, i).await;
    let cancel = RunEvent::Cancel {
        reason: "stop".to_owned(),
    };
    transition_run(pool, r, AuditActor::System, &cancel, NOW)
        .await
        .unwrap();
    assert!(matches!(
        checkout_issue(pool, i, r, NOW).await,
        Err(CheckoutError::RunNotLive(RunState::Cancelled))
    ));
    assert!(matches!(
        checkout_issue(pool, i, RunId(999), NOW).await,
        Err(CheckoutError::RunNotFound)
    ));
    assert!(matches!(
        checkout_issue(pool, IssueId(999), run_for(pool, dev, i).await, NOW).await,
        Err(CheckoutError::IssueNotFound)
    ));
    assert!(matches!(
        checkout_issue(pool, i, run_for(pool, dev, i).await, "yesterday").await,
        Err(CheckoutError::Db(Error::InvalidArgument(_)))
    ));
    let untouched = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(
        (untouched.state, untouched.checkout_run_id),
        (IssueState::Todo, None)
    );
    assert!(issue_audit(pool, i).await.is_empty());
}

#[tokio::test]
async fn release_lets_another_run_claim() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let (a, b) = (run_for(pool, dev, i).await, run_for(pool, dev, i).await);
    checkout_issue(pool, i, a, NOW).await.unwrap();
    assert!(matches!(
        checkout_issue(pool, i, b, NOW).await,
        Err(CheckoutError::Conflict { held_by }) if held_by == a
    ));
    // Only the holder releases.
    assert!(!release_issue(pool, i, b, AuditActor::System).await.unwrap());
    assert!(release_issue(pool, i, a, AuditActor::System).await.unwrap());
    assert!(!release_issue(pool, i, a, AuditActor::System).await.unwrap());
    let released = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(released.checkout_run_id, None);
    assert_eq!(released.state, IssueState::InProgress);
    assert_eq!(
        checkout_issue(pool, i, b, NOW)
            .await
            .unwrap()
            .checkout_run_id,
        Some(b)
    );
    assert_eq!(
        issue_audit(pool, i).await,
        ["issue.checked_out", "issue.released", "issue.checked_out"]
    );
}

#[tokio::test]
async fn a_holder_that_ended_without_releasing_is_replaced() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let (a, b) = (run_for(pool, dev, i).await, run_for(pool, dev, i).await);
    checkout_issue(pool, i, a, NOW).await.unwrap();
    // Ended outside the engine (a run transition would have released it, E2.6).
    sqlx::query("UPDATE runs SET state = 'cancelled', terminal_reason = 'crashed' WHERE id = ?")
        .bind(a.0)
        .execute(pool)
        .await
        .unwrap();
    let taken = checkout_issue(pool, i, b, NOW).await.unwrap();
    assert_eq!(taken.checkout_run_id, Some(b));
    let replaced: Option<i64> = sqlx::query_scalar(
        "SELECT details ->> 'replaced' FROM audit_events \
         WHERE entity_id = ? AND action = 'issue.checked_out' ORDER BY seq DESC LIMIT 1",
    )
    .bind(i.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(replaced, Some(a.0));
}

#[tokio::test]
async fn blocked_and_closed_issues_cannot_be_checked_out_and_review_keeps_its_reviewer() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    for state in [IssueState::Blocked, IssueState::Done, IssueState::Cancelled] {
        let next = (!state.is_terminal()).then_some(NextActor::Human(UserId(1)));
        set(pool, i, state, next).await;
        assert!(matches!(
            checkout_issue(pool, i, run_for(pool, dev, i).await, NOW).await,
            Err(CheckoutError::NotCheckable(s)) if s == state
        ));
    }
    set(
        pool,
        i,
        IssueState::InReview,
        Some(NextActor::Human(UserId(1))),
    )
    .await;
    let mut issue = get_issue(pool, i).await.unwrap().unwrap();
    issue.owner = Some(Actor::Human(UserId(1)));
    assert!(update_issue(pool, &issue).await.unwrap());
    let reviewing = checkout_issue(pool, i, run_for(pool, dev, i).await, NOW)
        .await
        .unwrap();
    assert_eq!(reviewing.state, IssueState::InReview);
    assert_eq!(reviewing.owner, Some(Actor::Human(UserId(1))));
    assert_eq!(reviewing.next_actor, Some(NextActor::Human(UserId(1))));
}

/// Checking out a `todo` issue starts it, so a full kanban `in_progress` column refuses it
/// (E5.3), changing nothing.
#[tokio::test]
async fn checkout_respects_the_wip_limit() {
    use crate::store::work::set_wip_limit;

    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let p = get_issue(pool, i).await.unwrap().unwrap().project_id;
    sqlx::query("UPDATE projects SET mode = 'kanban' WHERE id = ?")
        .bind(p.0)
        .execute(pool)
        .await
        .unwrap();
    let limit = |n| set_wip_limit(pool, p, IssueState::InProgress, Some(n), AuditActor::System);
    limit(1).await.unwrap();
    let busy = super::flow::sibling(pool, i).await;
    set(
        pool,
        busy,
        IssueState::InProgress,
        Some(NextActor::Agent(dev)),
    )
    .await;
    let run = run_for(pool, dev, i).await;
    let refused = checkout_issue(pool, i, run, NOW).await;
    assert!(
        matches!(refused, Err(CheckoutError::WipLimit { limit: 1 })),
        "{refused:?}"
    );
    let still = get_issue(pool, i).await.unwrap().unwrap();
    assert_eq!(
        (still.state, still.checkout_run_id),
        (IssueState::Todo, None)
    );
    limit(2).await.unwrap();
    let held = checkout_issue(pool, i, run, NOW).await.unwrap();
    assert_eq!(held.state, IssueState::InProgress);
}
