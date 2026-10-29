//! Issues: create, the state machine, rank, estimate, epic, and chat by comment.

use ainkrad_core::exec::WakeSource;
use ainkrad_core::work::ProjectMode;
use serde_json::json;

use super::*;
use crate::store::exec::list_wake_requests;

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
    let uri = format!("/api/v1/projects/{}/issues", a.project.0);

    let backlog = fx
        .ok_post(&uri, json!({"title": "Later", "kind": "story"}))
        .await;
    assert_eq!(
        (backlog["state"].clone(), backlog["kind"].clone()),
        (json!("backlog"), json!("story"))
    );
    assert_eq!(backlog["key"], "AAA-2");
    let assigned = fx
        .ok_post(
            &uri,
            json!({"title": "Now", "assignee_agent_id": a.agent.0}),
        )
        .await;
    assert_eq!(assigned["state"], "todo");
    assert_eq!(
        assigned["next_actor"],
        json!({"kind": "agent", "agent_id": a.agent.0})
    );
    let wakes = list_wake_requests(&fx.app.pool, a.agent).await.unwrap();
    let id = assigned["id"].as_i64().unwrap();
    assert!(
        wakes.iter().any(|w| w.issue_id.map(|i| i.0) == Some(id)),
        "the agent is woken"
    );

    let (status, _) = fx.post(&uri, json!({"title": "x", "state": "done"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = fx
        .post("/api/v1/projects/99/issues", json!({"title": "x"}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let step_uri = format!("/api/v1/issues/{id}/transition");
    let step = |t: Value| fx.post(&step_uri, t);
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
    for want in ["issue.created", "issue.cancelled"] {
        assert!(by_admin.iter().any(|a| a == want), "{want} in {by_admin:?}");
    }
    let got = fx.ok(&format!("/api/v1/issues/{id}")).await;
    assert_eq!(got["state"], "cancelled");
    assert_eq!(fx.get("/api/v1/issues/999").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ranks_estimates_and_files_under_an_epic() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/projects/{}/issues", a.project.0);
    let second = fx.ok_post(&uri, json!({"title": "Second"})).await["id"].clone();
    let first = a.issue.0;

    let moved = fx
        .ok_post(
            &format!("/api/v1/issues/{second}/move"),
            json!({"to": "before", "anchor_issue_id": first}),
        )
        .await;
    let first_rank = fx.ok(&format!("/api/v1/issues/{first}")).await["rank"]
        .as_f64()
        .unwrap();
    assert!(moved["rank"].as_f64().unwrap() < first_rank);
    let (status, _) = fx
        .post(
            &format!("/api/v1/issues/{second}/move"),
            json!({"to": "after"}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "after what?");

    let est = fx
        .ok_post(
            &format!("/api/v1/issues/{second}/estimate"),
            json!({"points": 3}),
        )
        .await;
    assert_eq!(est["points"], 3);
    let cleared = fx
        .ok_post(&format!("/api/v1/issues/{second}/estimate"), json!({}))
        .await;
    assert!(cleared["points"].is_null());

    let epic = fx
        .ok_post(
            &format!("/api/v1/projects/{}/epics", a.project.0),
            json!({"title": "Billing"}),
        )
        .await;
    let filed = fx
        .ok_post(
            &format!("/api/v1/issues/{second}/epic"),
            json!({"epic_id": epic["id"]}),
        )
        .await;
    assert_eq!(filed["epic_id"], epic["id"]);
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let other = fx
        .ok_post(
            &format!("/api/v1/projects/{}/epics", b.project.0),
            json!({"title": "Theirs"}),
        )
        .await;
    let (status, _) = fx
        .post(
            &format!("/api/v1/issues/{second}/epic"),
            json!({"epic_id": other["id"]}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "another project's epic");
}

#[tokio::test]
async fn a_comment_is_a_chat_message_that_wakes_the_issues_agent_once() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/issues/{}/comments", a.issue.0);
    let body = json!({"body": "Use the staging key.", "idempotency_key": "m1"});
    let posted = fx.ok_post(&uri, body.clone()).await;
    assert_eq!(posted["woke_agent_id"], a.agent.0);
    assert_eq!(
        posted["comment"]["author"],
        json!({"kind": "human", "user_id": 1})
    );
    let again = fx.ok_post(&uri, body).await;
    assert_eq!(again["comment"]["id"], posted["comment"]["id"]);
    assert!(
        again["woke_agent_id"].is_null(),
        "a retry wakes no one again"
    );
    let comment_wakes = list_wake_requests(&fx.app.pool, a.agent)
        .await
        .unwrap()
        .into_iter()
        .filter(|w| w.source == WakeSource::Comment)
        .count();
    assert_eq!(comment_wakes, 1);

    let thread = fx.ok(&uri).await;
    assert_eq!(thread.as_array().unwrap().len(), 1);
    assert_eq!(thread[0]["body"], "Use the staging key.");
    let (status, _) = fx.post(&uri, json!({"body": "  "})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = fx
        .post("/api/v1/issues/999/comments", json!({"body": "hi"}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let commented = actions(&fx.app.pool)
        .await
        .into_iter()
        .filter(|(action, ..)| action == "issue.commented")
        .count();
    assert_eq!(commented, 1);
}
