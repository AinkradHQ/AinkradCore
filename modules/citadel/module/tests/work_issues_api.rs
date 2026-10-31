//! Issues through the Core's gate: create, the state machine, rank, estimate, epic, and chat by
//! comment. Ported from the monolith's `api/v1/tests/issues.rs`.

mod common;
mod work_seed;

use axum::http::StatusCode;
use citadel_module::domain::org::AgentId;
use citadel_module::domain::work::{IssueId, ProjectMode, WakeSource};
use citadel_module::store::exec::list_wake_requests;
use common::*;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use work_seed::*;

async fn actions(pool: &SqlitePool) -> Vec<(String, String, Option<i64>)> {
    sqlx::query_as("SELECT action, actor_kind, actor_id FROM audit_events ORDER BY seq")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn creates_assigns_and_steps_an_issue_as_the_admin() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/projects/{}/issues", a.project);

    let backlog = ok_post(&fx, &uri, json!({"title": "Later", "kind": "story"})).await;
    assert_eq!(
        (backlog["state"].clone(), backlog["kind"].clone()),
        (json!("backlog"), json!("story"))
    );
    assert_eq!(backlog["key"], "AAA-2");
    let assigned = ok_post(
        &fx,
        &uri,
        json!({"title": "Now", "assignee_agent_id": a.agent}),
    )
    .await;
    assert_eq!(assigned["state"], "todo");
    assert_eq!(
        assigned["next_actor"],
        json!({"kind": "agent", "agent_id": a.agent})
    );
    let id = assigned["id"].as_i64().unwrap();
    // The agent assigned at creation is woken on the new issue.
    let wakes = list_wake_requests(&fx.app.pool, AgentId(a.agent))
        .await
        .unwrap();
    assert!(
        wakes.iter().any(|w| w.issue_id == Some(IssueId(id))),
        "the agent is woken"
    );

    let (status, _) = post(&fx, &uri, json!({"title": "x", "state": "done"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(&fx, "/projects/99/issues", json!({"title": "x"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let step_uri = format!("/issues/{id}/transition");
    let step = |t: Value| post(&fx, &step_uri, t);
    let (status, body) = step(json!({"kind": "done"})).await;
    assert_eq!(status, StatusCode::CONFLICT, "todo cannot be done: {body}");
    assert_eq!(body["code"], "conflict");
    let (status, body) = step(json!({"kind": "cancel"})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "cancelled");
    let (status, _) = step(json!({"kind": "teleport"})).await;
    assert!(
        status.is_client_error(),
        "an unknown step is refused: {status}"
    );

    let by_admin: Vec<_> = actions(&fx.app.pool)
        .await
        .into_iter()
        .filter(|(_, kind, id)| kind == "user" && *id == Some(1))
        .map(|(action, ..)| action)
        .collect();
    for want in ["citadel.issue.created", "citadel.issue.cancelled"] {
        assert!(by_admin.iter().any(|a| a == want), "{want} in {by_admin:?}");
    }
    let got = ok(&fx, &format!("/issues/{id}")).await;
    assert_eq!(got["state"], "cancelled");
    assert_eq!(get(&fx, "/issues/999").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ranks_estimates_and_files_under_an_epic() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/projects/{}/issues", a.project);
    let second = ok_post(&fx, &uri, json!({"title": "Second"})).await["id"].clone();
    let first = a.issue;

    let moved = ok_post(
        &fx,
        &format!("/issues/{second}/move"),
        json!({"to": "before", "anchor_issue_id": first}),
    )
    .await;
    let first_rank = ok(&fx, &format!("/issues/{first}")).await["rank"]
        .as_f64()
        .unwrap();
    assert!(moved["rank"].as_f64().unwrap() < first_rank);
    let (status, _) = post(
        &fx,
        &format!("/issues/{second}/move"),
        json!({"to": "after"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "after what?");

    let est = ok_post(
        &fx,
        &format!("/issues/{second}/estimate"),
        json!({"points": 3}),
    )
    .await;
    assert_eq!(est["points"], 3);
    let cleared = ok_post(&fx, &format!("/issues/{second}/estimate"), json!({})).await;
    assert!(cleared["points"].is_null());

    let epic = ok_post(
        &fx,
        &format!("/projects/{}/epics", a.project),
        json!({"title": "Billing"}),
    )
    .await;
    let filed = ok_post(
        &fx,
        &format!("/issues/{second}/epic"),
        json!({"epic_id": epic["id"]}),
    )
    .await;
    assert_eq!(filed["epic_id"], epic["id"]);
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let other = ok_post(
        &fx,
        &format!("/projects/{}/epics", b.project),
        json!({"title": "Theirs"}),
    )
    .await;
    let (status, _) = post(
        &fx,
        &format!("/issues/{second}/epic"),
        json!({"epic_id": other["id"]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "another project's epic");
}

#[tokio::test]
async fn a_comment_is_a_chat_message_that_wakes_the_issues_agent_once() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/issues/{}/comments", a.issue);
    let body = json!({"body": "Use the staging key.", "idempotency_key": "m1"});
    let posted = ok_post(&fx, &uri, body.clone()).await;
    assert_eq!(posted["woke_agent_id"], a.agent);
    assert_eq!(
        posted["comment"]["author"],
        json!({"kind": "human", "user_id": 1})
    );
    let again = ok_post(&fx, &uri, body).await;
    assert_eq!(again["comment"]["id"], posted["comment"]["id"]);
    assert!(
        again["woke_agent_id"].is_null(),
        "a retry wakes no one again"
    );
    let comment_wakes = list_wake_requests(&fx.app.pool, AgentId(a.agent))
        .await
        .unwrap()
        .into_iter()
        .filter(|w| w.source == WakeSource::Comment)
        .count();
    assert_eq!(comment_wakes, 1);

    let thread = ok(&fx, &uri).await;
    assert_eq!(thread.as_array().unwrap().len(), 1);
    assert_eq!(thread[0]["body"], "Use the staging key.");
    let (status, _) = post(&fx, &uri, json!({"body": "  "})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(&fx, "/issues/999/comments", json!({"body": "hi"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let commented = actions(&fx.app.pool)
        .await
        .into_iter()
        .filter(|(action, ..)| action == "citadel.issue.commented")
        .count();
    assert_eq!(commented, 1);
}

#[tokio::test]
async fn the_activity_lists_the_audit_rows_about_an_issue_newest_first() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/issues/{}", a.issue);
    ok_post(&fx, &format!("{uri}/estimate"), json!({"points": 2})).await;
    ok_post(&fx, &format!("{uri}/comments"), json!({"body": "hi"})).await;
    let page = ok(&fx, &format!("{uri}/activity")).await;
    let actions: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, ["issue.commented", "issue.estimated"], "{page}");
    assert_eq!(
        page["items"][0]["actor"],
        json!({"kind": "user", "user_id": 1})
    );
    let one = ok(&fx, &format!("{uri}/activity?limit=1")).await;
    assert_eq!(one["items"].as_array().unwrap().len(), 1);
    assert!(one["next_before"].is_i64(), "{one}");
}
