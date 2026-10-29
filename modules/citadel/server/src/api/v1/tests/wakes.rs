//! Who a wake reaches: a person's comment (a mention, `wake_agent_id`, else the issue's working
//! agent), resume (no stale wakes replayed), and the admin's blocker link.

use citadel_core::work::ProjectMode;
use serde_json::json;

use super::*;
use crate::store::exec::{list_wake_requests, run_prompt};

async fn agent(pool: &SqlitePool, company: CompanyId, name: &str) -> AgentId {
    let a = NewAgent {
        company_id: company,
        name: name.to_owned(),
        role: name.to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Opencode,
        model: String::new(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    create_agent(pool, &a).await.unwrap().id
}

async fn issue(
    pool: &SqlitePool,
    project: ProjectId,
    state: IssueState,
    owner: Option<AgentId>,
    next: NextActor,
) -> IssueId {
    let i = NewIssue {
        project_id: project,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Work".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: owner.map(citadel_core::work::Actor::Agent),
        next_actor: Some(next),
        points: None,
        sprint_id: None,
    };
    let id = create_issue(pool, &i).await.unwrap().id;
    // Where the trial left it, past the steps that led there.
    sqlx::query("UPDATE issues SET state = ? WHERE id = ?")
        .bind(state.as_str())
        .bind(id.0)
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn comment(fx: &Fx, issue: IssueId, body: Value) -> Value {
    fx.ok_post(&format!("/api/v1/issues/{}/comments", issue.0), body)
        .await
}

#[tokio::test]
async fn a_mention_wakes_that_agent_and_wake_agent_id_overrides() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let qa = agent(pool, a.company, "QA").await;
    let posted = comment(&fx, a.issue, json!({"body": "@qa please look again."})).await;
    assert_eq!(posted["woke_agent_id"], qa.0, "by name, any case");
    let by_id = format!("ping @agent:{}", a.agent.0);
    let posted = comment(&fx, a.issue, json!({"body": by_id})).await;
    assert_eq!(posted["woke_agent_id"], a.agent.0, "by id");
    let posted = comment(&fx, a.issue, json!({"body": "mail @qafoo"})).await;
    assert_eq!(
        posted["woke_agent_id"], a.agent.0,
        "a longer word is no mention"
    );
    let explicit = json!({"body": "@qa?", "wake_agent_id": a.agent.0});
    assert_eq!(
        comment(&fx, a.issue, explicit).await["woke_agent_id"],
        a.agent.0
    );

    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/issues/{}/comments", a.issue.0);
    let other = json!({"body": "hi", "wake_agent_id": b.agent.0});
    assert_eq!(fx.post(&uri, other).await.0, StatusCode::BAD_REQUEST);
    // Another company's agent's name is no mention.
    let posted = comment(&fx, a.issue, json!({"body": "@b dev hi"})).await;
    assert_eq!(posted["woke_agent_id"], a.agent.0);
}

/// The trial's bug: QA failed the issue back to the developer, a comment woke QA again.
#[tokio::test]
async fn a_comment_on_a_developer_owned_issue_in_progress_wakes_the_developer_not_qa() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let qa = agent(pool, a.company, "QA").await;
    let next = NextActor::Agent(qa);
    let worked = issue(pool, a.project, IssueState::InProgress, Some(a.agent), next).await;
    // A wake already waiting folds the comment in; the run is still told the comment.
    let assigned = NewWakeRequest {
        agent_id: a.agent,
        issue_id: Some(worked),
        source: WakeSource::Assignment,
        reason: "handed back".to_owned(),
        idempotency_key: "handed-back".to_owned(),
        not_before: None,
    };
    enqueue_wake(pool, &assigned).await.unwrap();
    let posted = comment(&fx, worked, json!({"body": "Fix   the\nlint first."})).await;
    assert_eq!(posted["woke_agent_id"], a.agent.0);
    assert!(list_wake_requests(pool, qa).await.unwrap().is_empty());

    let run = dispatch_next(pool, a.runner, &[], &Harness::ALL, NOW)
        .await
        .unwrap()
        .expect("the developer's wake is due");
    assert_eq!((run.agent_id, run.issue_id), (a.agent, Some(worked)));
    let prompt = run_prompt(pool, run.id).await.unwrap().unwrap();
    assert!(
        prompt.contains(
            "Why you were woken: it was handed to you (comment: \"Fix the lint first.\"; \
             handed back)."
        ),
        "{prompt}"
    );
}

#[tokio::test]
async fn a_comment_wake_quotes_the_comment_cut_to_300_chars() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let long = "y".repeat(400);
    comment(&fx, a.issue, json!({"body": long})).await;
    let wakes = list_wake_requests(pool, a.agent).await.unwrap();
    let w = wakes
        .iter()
        .find(|w| w.source == WakeSource::Comment)
        .unwrap();
    assert_eq!(w.reason, format!("comment: \"{}…\"", "y".repeat(300)));
}

#[tokio::test]
async fn resume_drops_stale_wakes_and_keeps_valid_ones() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let qa = agent(pool, a.company, "QA").await;
    let mine = issue(
        pool,
        a.project,
        IssueState::InReview,
        Some(a.agent),
        NextActor::Agent(qa),
    )
    .await;
    let gone = issue(
        pool,
        a.project,
        IssueState::InProgress,
        Some(a.agent),
        NextActor::Agent(a.agent),
    )
    .await;
    fx.ok_post(&format!("/api/v1/agents/{}/pause", qa.0), json!({}))
        .await;
    for (i, key) in [(mine, "w-mine"), (gone, "w-gone")] {
        let w = NewWakeRequest {
            agent_id: qa,
            issue_id: Some(i),
            source: WakeSource::Comment,
            reason: "a comment".to_owned(),
            idempotency_key: key.to_owned(),
            not_before: None,
        };
        enqueue_wake(pool, &w).await.unwrap();
    }
    fx.ok_post(&format!("/api/v1/agents/{}/resume", qa.0), json!({}))
        .await;
    let wakes = list_wake_requests(pool, qa).await.unwrap();
    let status = |i: IssueId| -> Vec<(String, WakeSource)> {
        wakes
            .iter()
            .filter(|w| w.issue_id == Some(i))
            .map(|w| (w.status.as_str().to_owned(), w.source))
            .collect()
    };
    assert_eq!(
        status(mine),
        [
            ("pending".to_owned(), WakeSource::Comment),
            ("coalesced".to_owned(), WakeSource::Manual)
        ]
    );
    assert_eq!(status(gone), [("dropped".to_owned(), WakeSource::Comment)]);
    let dropped = wakes.iter().find(|w| w.issue_id == Some(gone)).unwrap().id;
    let listed: String = sqlx::query_scalar(
        "SELECT details ->> 'dropped_wakes' FROM audit_events WHERE action = 'agent.resumed'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(listed, format!("[{}]", dropped.0));
}

#[tokio::test]
async fn the_admin_links_a_blocker_and_its_close_unblocks_and_wakes() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let blocker = issue(
        pool,
        a.project,
        IssueState::Todo,
        None,
        NextActor::Human(citadel_core::work::UserId(1)),
    )
    .await;
    let step = format!("/api/v1/issues/{}/transition", a.issue.0);
    let (status, _) = fx.post(&step, json!({"kind": "block"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "no open blocker yet");

    let link = format!("/api/v1/issues/{}/blockers/{}", a.issue.0, blocker.0);
    let put = |uri: &str| send(&fx.app, req(Method::PUT, uri, Some(&fx.key), None));
    let (status, linked) = put(&link).await;
    assert_eq!((status, &linked["state"]), (StatusCode::OK, &json!("todo")));
    assert_eq!(
        put(&link).await.0,
        StatusCode::OK,
        "linking again keeps the link"
    );
    let listed = fx
        .ok(&format!("/api/v1/issues/{}/blockers", a.issue.0))
        .await;
    assert_eq!(listed[0]["id"], blocker.0);
    let blocked = fx.ok_post(&step, json!({"kind": "block"})).await;
    assert_eq!(blocked["state"], "blocked");
    let delete = send(&fx.app, req(Method::DELETE, &link, Some(&fx.key), None)).await;
    assert_eq!(
        (delete.0, &delete.1["state"]),
        (StatusCode::OK, &json!("todo"))
    );
    let again = send(&fx.app, req(Method::DELETE, &link, Some(&fx.key), None)).await;
    assert_eq!(again.0, StatusCode::NOT_FOUND);

    // Link and block in one step; closing the blocker unblocks and wakes the next actor.
    let one = json!({"kind": "block", "blocker_issue_id": blocker.0});
    assert_eq!(fx.ok_post(&step, one).await["state"], "blocked");
    let close = format!("/api/v1/issues/{}/transition", blocker.0);
    fx.ok_post(&close, json!({"kind": "start"})).await;
    fx.ok_post(&close, json!({"kind": "done"})).await;
    let back = fx.ok(&format!("/api/v1/issues/{}", a.issue.0)).await;
    assert_eq!(back["state"], "todo");
    let wakes = list_wake_requests(pool, a.agent).await.unwrap();
    assert!(
        wakes
            .iter()
            .any(|w| w.issue_id == Some(a.issue) && w.source == WakeSource::BlockerClosed),
        "{wakes:?}"
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action IN \
         ('issue.blocker_linked', 'issue.blocker_unlinked') AND actor_kind = 'user'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(audited, 3, "linked, unlinked, linked again");

    // Refused: itself, another company's issue, a cycle.
    let me = format!("/api/v1/issues/{}/blockers/{}", a.issue.0, a.issue.0);
    assert_eq!(put(&me).await.0, StatusCode::BAD_REQUEST);
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let theirs = format!("/api/v1/issues/{}/blockers/{}", a.issue.0, b.issue.0);
    assert_eq!(put(&theirs).await.0, StatusCode::BAD_REQUEST);
    let cycle = format!("/api/v1/issues/{}/blockers/{}", blocker.0, a.issue.0);
    assert_eq!(put(&cycle).await.0, StatusCode::BAD_REQUEST);
}
