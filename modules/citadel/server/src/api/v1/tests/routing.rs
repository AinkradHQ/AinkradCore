//! Per-task routing (E15.5): an agent's tiers and a project's rules are read and replaced; the
//! run shows its tier; the per-task report lists the issue's runs.

use serde_json::json;

use super::*;

#[tokio::test]
async fn tiers_and_rules_are_read_and_replaced_and_tasks_are_reported() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/agents/{}/tiers", a.agent.0);
    assert_eq!(fx.ok(&uri).await, json!([]));
    let tiers = json!([{"tier": "small", "harness": "opencode", "model": "opencode/mini"}]);
    let put = |uri: &str, body: Value| req(Method::PUT, uri, Some(&fx.key), Some(body));
    let (status, set) = send(&fx.app, put(&uri, tiers.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(set, tiers);
    let standard = json!([{"tier": "standard", "harness": "opencode", "model": "x"}]);
    assert_eq!(
        send(&fx.app, put(&uri, standard)).await.0,
        StatusCode::BAD_REQUEST
    );
    let missing = put("/api/v1/agents/999/tiers", json!([]));
    assert_eq!(send(&fx.app, missing).await.0, StatusCode::NOT_FOUND);

    let rules_uri = format!("/api/v1/projects/{}/tier-rules", a.project.0);
    let defaults = fx.ok(&rules_uri).await;
    assert_eq!(defaults["defaults"], true);
    assert_eq!(
        defaults["rules"][0],
        json!({"rule": "label:chore", "tier": "small"})
    );
    let rules = json!([{"rule": "kind:bug", "tier": "large"}]);
    let (status, set) = send(&fx.app, put(&rules_uri, rules.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(set, json!({"rules": rules, "defaults": false}));
    let bad = json!([{"rule": "chore", "tier": "small"}]);
    assert_eq!(
        send(&fx.app, put(&rules_uri, bad)).await.0,
        StatusCode::BAD_REQUEST
    );

    let run = fx.ok(&format!("/api/v1/runs/{}", a.run.id.0)).await;
    assert_eq!(run["tier"], "standard", "an unestimated task");
    let tasks = fx
        .ok(&format!("/api/v1/companies/{}/costs/tasks", a.company.0))
        .await;
    assert_eq!(tasks[0]["key"], "AAA-1");
    assert_eq!(tasks[0]["runs"], 1);
    assert_eq!(tasks[0]["tier"], "standard");
    let later = format!(
        "/api/v1/companies/{}/costs/tasks?since=2099-01-01T00:00:00.000Z",
        a.company.0
    );
    assert_eq!(fx.ok(&later).await, json!([]));
    let bad = format!("/api/v1/companies/{}/costs/tasks?since=soon", a.company.0);
    assert_eq!(fx.get(&bad).await.0, StatusCode::BAD_REQUEST);
}
