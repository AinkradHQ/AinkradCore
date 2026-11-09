//! The project profile (E15.13): read, changed a field at a time, refused when bad, audited;
//! agents' pending proposals listed with it.

use citadel_core::gov::KnowledgeKind;
use citadel_core::work::ProjectMode;
use serde_json::json;

use super::*;
use crate::store::gov::{Proposal, propose};

#[tokio::test]
async fn the_profile_round_trips_and_changes_only_what_is_given() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "PRO", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/projects/{}/profile", a.project.0);
    let put = |body: Value| send(&fx.app, req(Method::PUT, &uri, Some(&fx.key), Some(body)));

    let empty = fx.ok(&uri).await;
    assert_eq!(empty["profile"]["definition_of_done"], json!([]));
    assert_eq!(
        (
            empty["injected_bytes"].as_u64(),
            empty["budget_bytes"].as_u64()
        ),
        (Some(0), Some(4096))
    );
    assert_eq!(empty["permission_mode"], "ask");
    assert!(
        empty.get("updated_at").is_none_or(Value::is_null),
        "{empty}"
    );

    let (status, set) = put(json!({"definition_of_done": ["tests pass"],
        "environments": [{"name": "Prod", "url": "https://prod.example", "deploy": "owner"}],
        "models": [{"role": "QA", "model": "sonnet"}], "sprint_approval": "product_owner"}))
    .await;
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(set["profile"]["environments"][0]["deploy"], "owner");
    assert_eq!(set["sprint_approval"], "product_owner");
    assert!(set["injected_bytes"].as_u64().unwrap() > 0);
    assert!(
        set["updated_at"].as_str().is_some_and(|t| t.ends_with('Z')),
        "{set}"
    );

    // A partial update leaves the rest.
    let (_, set) = put(json!({"stack": "Rust"})).await;
    assert_eq!(set["profile"]["stack"], "Rust");
    assert_eq!(set["profile"]["definition_of_done"], json!(["tests pass"]));
    assert_eq!(fx.ok(&uri).await["profile"], set["profile"]);

    for bad in [
        json!({"environments": [{"name": "Prod", "url": "https://u:p@prod.example"}]}),
        json!({"colour": "red"}),
        json!({"merge_method": "octopus"}),
        json!({"permission_mode": "sandboxed"}),
    ] {
        let (status, body) = put(bad.clone()).await;
        assert!(status.is_client_error(), "{bad}: {status} {body}");
    }
    assert_eq!(
        fx.ok(&uri).await["profile"],
        set["profile"],
        "nothing changed"
    );
    let (status, _) = send(
        &fx.app,
        req(
            Method::PUT,
            "/api/v1/projects/999/profile",
            Some(&fx.key),
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'project.profile_set'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 2);

    // An agent's proposal is listed, not applied.
    let p = Proposal {
        project: a.project,
        kind: KnowledgeKind::Decision,
        title: "Format first".to_owned(),
        body: "Run cargo fmt before committing.".to_owned(),
        spec: false,
        profile_field: Some("conventions".to_owned()),
        rationale: Some("we lint on CI".to_owned()),
    };
    propose(&fx.app.pool, &p, a.agent).await.unwrap();
    let got = fx.ok(&uri).await;
    assert_eq!(got["proposals"][0]["field"], "conventions", "{got}");
    assert_eq!(got["profile"]["conventions"], "");
}
