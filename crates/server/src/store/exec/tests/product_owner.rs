//! The product owner's wakes (R7a): an issue parked on a person for over 15 minutes, a merged PR,
//! and a sprint's start for each committed owner. Each one is queued once and dispatched, and the
//! product owner's merge wake survives the stale-wake rule that drops the rest (R4).

use ainkrad_core::audit::AuditActor;
use ainkrad_core::exec::{NewWakeRequest, WakeSource};
use ainkrad_core::work::{
    IssueKind, IssueState, NewIssue, NewSprint, NextActor, ProjectId, SprintState, UserId,
};

use super::stuck::{after, online};
use super::wake::{dispatch, runner, wake};
use super::*;
use crate::store::exec::PARKED_WAKE_SECS;
use crate::store::org::get_agent;
use crate::store::work::{add_to_sprint, commit_sprint, create_issue, get_issue, plan_sprint};

/// `dev`'s team's product owner: a new agent seated as the team lead, then promoted (E5.4).
async fn product_owner(pool: &SqlitePool, dev: AgentId) -> AgentId {
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    let po = agent(pool, company).await;
    lead_team(pool, dev, po).await;
    sqlx::query("UPDATE team_memberships SET team_role = 'product_owner' WHERE agent_id = ?")
        .bind(po.0)
        .execute(pool)
        .await
        .unwrap();
    po
}

/// Pending or dispatched wakes of `source` for `agent` on `issue`.
async fn wakes(pool: &SqlitePool, agent: AgentId, issue: IssueId, source: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM wake_requests WHERE agent_id = ? AND issue_id = ? \
         AND source = ? AND status IN ('pending', 'dispatched')",
    )
    .bind(agent.0)
    .bind(issue.0)
    .bind(source)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn status_of(pool: &SqlitePool, key: &str) -> String {
    sqlx::query_scalar("SELECT status FROM wake_requests WHERE idempotency_key = ?")
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn an_issue_parked_on_a_person_wakes_its_product_owner_once() {
    let db = db().await;
    let pool = &db.pool;
    // The fixture issue is `todo` and waits on a person.
    let (dev, i) = fixture(pool, "A").await;
    let po = product_owner(pool, dev).await;
    // A runner that serves the wake: with none online, repair drops it as stuck.
    let r = online(pool, "box", &[]).await;

    // At the threshold, not over it: no wake.
    tick(pool, &after(pool, PARKED_WAKE_SECS).await)
        .await
        .unwrap();
    assert_eq!(wakes(pool, po, i, "escalation").await, 0);

    // Over it: one wake, and a later pass does not add a second.
    tick(pool, &after(pool, PARKED_WAKE_SECS + 60).await)
        .await
        .unwrap();
    tick(pool, &after(pool, PARKED_WAKE_SECS + 120).await)
        .await
        .unwrap();
    assert_eq!(wakes(pool, po, i, "escalation").await, 1);

    let now = after(pool, PARKED_WAKE_SECS + 120).await;
    let run = dispatch(pool, r, &now)
        .await
        .expect("the product owner runs");
    assert_eq!((run.agent_id, run.issue_id), (po, Some(i)));
    let state: IssueState = get_issue(pool, i).await.unwrap().unwrap().state;
    assert_eq!(
        state,
        IssueState::Todo,
        "the wake changes nothing on the issue"
    );
}

#[tokio::test]
async fn a_merged_pr_wakes_the_product_owner_while_the_issue_waits_on_qa() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    let po = product_owner(pool, dev).await;
    let qa = agent(pool, company).await;
    // Two repos: one PR merged, the issue still in review with QA next.
    sqlx::query(
        "UPDATE issues SET state = 'in_review', owner_agent_id = ?1, next_agent_id = ?2, \
         next_user_id = NULL, owner_user_id = NULL WHERE id = ?3",
    )
    .bind(dev.0)
    .bind(qa.0)
    .bind(i.0)
    .execute(pool)
    .await
    .unwrap();
    let merged = NewWakeRequest {
        source: WakeSource::Comment,
        reason: "PR #7 merged.".to_owned(),
        ..wake(po, Some(i), "pr:1:1:merged:7")
    };
    enqueue_wake(pool, &merged).await.unwrap();

    let r = runner(pool, "box").await;
    let run = dispatch(pool, r, &after(pool, 0).await)
        .await
        .expect("the merge wake runs");
    assert_eq!((run.agent_id, run.issue_id), (po, Some(i)));
    assert_eq!(status_of(pool, "pr:1:1:merged:7").await, "dispatched");
}

#[tokio::test]
async fn a_sprint_start_wakes_each_committed_owner_once_per_issue() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let po = product_owner(pool, dev).await;
    let project: i64 = sqlx::query_scalar("SELECT project_id FROM issues WHERE id = ?")
        .bind(i.0)
        .fetch_one(pool)
        .await
        .unwrap();
    let project = ProjectId(project);
    // The product owner commits alone; the sprint starts at the commit.
    sqlx::query("UPDATE projects SET sprint_approval = 'product_owner' WHERE id = ?")
        .bind(project.0)
        .execute(pool)
        .await
        .unwrap();
    let other = create_issue(
        pool,
        &NewIssue {
            project_id: project,
            epic_id: None,
            parent_id: None,
            kind: IssueKind::Task,
            title: "Second".to_owned(),
            body: String::new(),
            state: IssueState::Todo,
            owner: None,
            next_actor: Some(NextActor::Human(UserId(1))),
            points: None,
            sprint_id: None,
        },
    )
    .await
    .unwrap()
    .id;
    for issue in [i, other] {
        sqlx::query(
            "UPDATE issues SET owner_agent_id = ?1, next_agent_id = ?1, \
             next_user_id = NULL WHERE id = ?2",
        )
        .bind(dev.0)
        .bind(issue.0)
        .execute(pool)
        .await
        .unwrap();
    }
    // The commit gate refuses unpointed work.
    sqlx::query("UPDATE issues SET points = 1 WHERE id IN (?, ?)")
        .bind(i.0)
        .bind(other.0)
        .execute(pool)
        .await
        .unwrap();
    let sprint = plan_sprint(
        pool,
        &NewSprint {
            project_id: project,
            name: "S1".to_owned(),
            goal: "ship".to_owned(),
            state: SprintState::Planned,
            starts_on: Some("2026-10-21".to_owned()),
            ends_on: Some("2026-11-03".to_owned()),
        },
        AuditActor::System,
    )
    .await
    .unwrap();
    for issue in [i, other] {
        add_to_sprint(pool, sprint.id, issue, AuditActor::System)
            .await
            .unwrap();
    }
    assert_eq!(
        wakes(pool, dev, i, "assignment").await,
        0,
        "not started yet"
    );

    commit_sprint(pool, sprint.id, po, None, None, &after(pool, 0).await)
        .await
        .unwrap();
    for issue in [i, other] {
        assert_eq!(wakes(pool, dev, issue, "assignment").await, 1);
    }

    let r = runner(pool, "box").await;
    let run = dispatch(pool, r, &after(pool, 0).await)
        .await
        .expect("the owner starts its work");
    assert_eq!(run.agent_id, dev);
}

#[tokio::test]
async fn a_burst_of_wakes_for_one_agent_on_one_issue_coalesces() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let po = product_owner(pool, dev).await;
    for n in 1..=3 {
        enqueue_wake(pool, &wake(po, Some(i), &format!("comment:{n}")))
            .await
            .unwrap();
    }
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM wake_requests WHERE agent_id = ? AND status = 'pending'",
    )
    .bind(po.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(pending, 1);
    let folded: i64 = sqlx::query_scalar(
        "SELECT coalesced_count FROM wake_requests WHERE agent_id = ? AND status = 'pending'",
    )
    .bind(po.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(folded, 2);
}
