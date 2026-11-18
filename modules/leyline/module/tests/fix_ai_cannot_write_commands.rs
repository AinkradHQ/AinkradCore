//! Y4-02 review, HIGH: an AI session never creates, changes or deletes a pre-set command, whatever
//! it changes (steps, flag, scope). A person's scope change on a read-only command needs a step-up.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;

#[tokio::test]
async fn a_session_cannot_create_patch_or_delete_a_command() {
    let fx = fx().await;
    let c = mk(
        &fx,
        json!({"name": "ro", "steps": ["true"], "read_only": true}),
    )
    .await;
    let id = c["id"].as_str().unwrap();
    let (_, creator) = session(&fx, "as_w").await;
    let ai = caller(&fx, &creator, "code_mode:as_w").await;
    for (m, path, body) in [
        (
            Method::POST,
            "/commands".to_owned(),
            Some(json!({"name": "x", "steps": ["id"]})),
        ),
        (
            Method::PATCH,
            format!("/commands/{id}"),
            Some(json!({"steps": ["rm -rf /"]})),
        ),
        (
            Method::PATCH,
            format!("/commands/{id}"),
            Some(json!({"scope": {"kind": "tag", "value": "web"}})),
        ),
        (
            Method::PATCH,
            format!("/commands/{id}"),
            Some(json!({"read_only": false})),
        ),
        (Method::DELETE, format!("/commands/{id}"), None),
    ] {
        let (s, v) = as_caller(&fx, ai.clone(), m.clone(), &path, body).await;
        assert_eq!(
            (s, &v["code"]),
            (StatusCode::FORBIDDEN, &json!("gate_refused")),
            "{m} {path}"
        );
    }
    // nothing changed
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/commands/{id}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        (v["steps"].clone(), v["scope"].clone()),
        (json!(["true"]), json!(null))
    );
}

#[tokio::test]
async fn changing_the_scope_of_a_read_only_command_needs_a_step_up() {
    let fx = fx().await;
    let c = mk(
        &fx,
        json!({"name": "ro", "steps": ["true"], "read_only": true}),
    )
    .await;
    let id = c["id"].as_str().unwrap();
    let (s, _) = call(
        &fx,
        &fx.weak,
        Method::PATCH,
        &format!("/commands/{id}"),
        Some(json!({"scope": {"kind": "tag", "value": "web"}})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/commands/{id}"),
        Some(json!({"scope": {"kind": "tag", "value": "web"}})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}
