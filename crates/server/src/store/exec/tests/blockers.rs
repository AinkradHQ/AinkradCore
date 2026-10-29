//! Blockers: closing the last open blocker unblocks and wakes the parked dependant.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::work::{BlockerLink, IssueTransition};

use super::flow::{sibling, wakes_for};
use super::*;
use crate::store::work::{
    BlockerError, add_blocker, delete_issue, get_issue, remove_blocker, transition_issue,
};

const BY: AuditActor = AuditActor::System;

/// `dev`'s issue, parked behind `n` fresh blockers (each `todo`, waiting on a human).
async fn parked(pool: &SqlitePool, n: usize) -> (AgentId, IssueId, Vec<IssueId>) {
    let (dev, d) = fixture(pool, "A").await;
    let mut blockers = vec![];
    for _ in 0..n {
        let b = sibling(pool, d).await;
        add_blocker(
            pool,
            BlockerLink {
                blocker: b,
                blocked: d,
            },
        )
        .await
        .unwrap();
        blockers.push(b);
    }
    let to_dev = IssueTransition::Reassign {
        next: NextActor::Agent(dev),
    };
    transition_issue(pool, d, &to_dev, BY).await.unwrap();
    transition_issue(pool, d, &IssueTransition::Start, BY)
        .await
        .unwrap();
    let blocked = transition_issue(pool, d, &IssueTransition::Block, BY)
        .await
        .unwrap();
    assert_eq!(blocked.state, IssueState::Blocked);
    // Only the assignment woke it so far.
    assert_eq!(wakes_for(pool, d).await.len(), 1);
    (dev, d, blockers)
}

async fn finish(pool: &SqlitePool, b: IssueId) {
    transition_issue(pool, b, &IssueTransition::Start, BY)
        .await
        .unwrap();
    transition_issue(pool, b, &IssueTransition::Done, BY)
        .await
        .unwrap();
}

/// The dependant is back in `todo` with its agent, woken once by `blocker_closed`.
async fn assert_resumed(pool: &SqlitePool, dev: AgentId, d: IssueId) {
    let resumed = get_issue(pool, d).await.unwrap().unwrap();
    assert_eq!(
        (resumed.state, resumed.next_actor),
        (IssueState::Todo, Some(NextActor::Agent(dev)))
    );
    let wakes = wakes_for(pool, d).await;
    assert_eq!(wakes.len(), 2, "{wakes:?}");
    assert_eq!(
        (wakes[1].agent_id, wakes[1].source),
        (dev, WakeSource::BlockerClosed)
    );
    let unblocks: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE entity_kind = 'issue' AND entity_id = ? \
         AND details ->> 'transition' = 'unblock'",
    )
    .bind(d.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(unblocks, 1);
}

#[tokio::test]
async fn closing_the_blocker_unblocks_and_wakes_the_parked_dependant() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, d, blockers) = parked(pool, 1).await;
    finish(pool, blockers[0]).await;
    assert_resumed(pool, dev, d).await;
}

#[tokio::test]
async fn a_diamond_unblocks_only_after_both_blockers_close() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, d, blockers) = parked(pool, 2).await;
    finish(pool, blockers[0]).await;
    let still = get_issue(pool, d).await.unwrap().unwrap();
    assert_eq!(still.state, IssueState::Blocked);
    assert_eq!(wakes_for(pool, d).await.len(), 1);
    finish(pool, blockers[1]).await;
    assert_resumed(pool, dev, d).await;
}

#[tokio::test]
async fn a_cancelled_blocker_counts_as_closed() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, d, blockers) = parked(pool, 1).await;
    transition_issue(pool, blockers[0], &IssueTransition::Cancel, BY)
        .await
        .unwrap();
    assert_resumed(pool, dev, d).await;
}

#[tokio::test]
async fn concurrent_closes_of_both_blockers_unblock_once() {
    for _ in 0..5 {
        let db = db().await;
        let pool = &db.pool;
        let (dev, d, blockers) = parked(pool, 2).await;
        let tasks: Vec<_> = blockers
            .iter()
            .map(|&b| {
                let pool = pool.clone();
                tokio::spawn(async move {
                    transition_issue(&pool, b, &IssueTransition::Cancel, BY).await
                })
            })
            .collect();
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        assert_resumed(pool, dev, d).await;
    }
}

#[tokio::test]
async fn removing_the_last_blocker_link_unblocks_and_wakes_once() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, d, blockers) = parked(pool, 2).await;
    let link = |blocker| BlockerLink {
        blocker,
        blocked: d,
    };
    assert!(remove_blocker(pool, link(blockers[0]), BY).await.unwrap());
    // One blocker still open: stays parked, nobody woken.
    let still = get_issue(pool, d).await.unwrap().unwrap();
    assert_eq!(still.state, IssueState::Blocked);
    assert_eq!(wakes_for(pool, d).await.len(), 1);
    assert!(remove_blocker(pool, link(blockers[1]), BY).await.unwrap());
    assert_resumed(pool, dev, d).await;
    // Removing a link that is gone changes nothing.
    assert!(!remove_blocker(pool, link(blockers[1]), BY).await.unwrap());
    assert_resumed(pool, dev, d).await;
}

#[tokio::test]
async fn deleting_the_blocker_issue_unblocks_and_wakes_once() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, d, blockers) = parked(pool, 1).await;
    assert!(delete_issue(pool, blockers[0], BY).await.unwrap());
    assert_resumed(pool, dev, d).await;
}

#[tokio::test]
async fn deleting_a_story_whose_subtask_blocks_unblocks_the_dependant() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, d, blockers) = parked(pool, 1).await;
    // The blocker becomes a subtask of a new story; deleting the story cascades to it.
    let story = sibling(pool, d).await;
    sqlx::query("UPDATE issues SET kind = 'subtask', parent_id = ? WHERE id = ?")
        .bind(story.0)
        .bind(blockers[0].0)
        .execute(pool)
        .await
        .unwrap();
    assert!(delete_issue(pool, story, BY).await.unwrap());
    assert_eq!(get_issue(pool, blockers[0]).await.unwrap(), None);
    assert_resumed(pool, dev, d).await;
}

#[tokio::test]
async fn linking_a_blocker_does_not_block_and_blocking_needs_one() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, d) = fixture(pool, "A").await;
    let to_dev = IssueTransition::Reassign {
        next: NextActor::Agent(dev),
    };
    transition_issue(pool, d, &to_dev, BY).await.unwrap();
    transition_issue(pool, d, &IssueTransition::Start, BY)
        .await
        .unwrap();
    // No open blocker: blocking is refused.
    assert!(
        transition_issue(pool, d, &IssueTransition::Block, BY)
            .await
            .is_err()
    );
    let b = sibling(pool, d).await;
    let link = BlockerLink {
        blocker: b,
        blocked: d,
    };
    add_blocker(pool, link).await.unwrap();
    let working = get_issue(pool, d).await.unwrap().unwrap();
    assert_eq!(working.state, IssueState::InProgress);
}

/// A link racing an uncommitted link the other way waits for it and is then refused as a
/// `Cycle`; a deferred transaction would check a stale snapshot and fail busy, or close the
/// cycle.
#[tokio::test]
async fn a_racing_link_cannot_pass_the_cycle_check_on_a_stale_read() {
    let db = db().await;
    let pool = &db.pool;
    let (_, a) = fixture(pool, "A").await;
    let b = sibling(pool, a).await;
    let mut other = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    sqlx::query("INSERT INTO blocker_links (blocker_id, blocked_id) VALUES (?, ?)")
        .bind(a.0)
        .bind(b.0)
        .execute(&mut *other)
        .await
        .unwrap();
    let racer = {
        let pool = pool.clone();
        let link = BlockerLink {
            blocker: b,
            blocked: a,
        };
        tokio::spawn(async move { add_blocker(&pool, link).await })
    };
    tokio::task::spawn_blocking(|| std::thread::sleep(std::time::Duration::from_millis(300)))
        .await
        .unwrap();
    other.commit().await.unwrap();
    let result = racer.await.unwrap();
    assert!(matches!(result, Err(BlockerError::Cycle)), "{result:?}");
}
