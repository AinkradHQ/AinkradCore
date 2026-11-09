//! The org routes end to end through the Core's client gate: signed, scoped, step-up on the
//! destructive ones, audited, and the module's migrations applied on top of the platform's.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;

async fn actions(fx: &Fx) -> Vec<String> {
    sqlx::query_scalar("SELECT action FROM audit_events WHERE action LIKE 'citadel.%' ORDER BY seq")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_company_is_created_listed_changed_and_audited() {
    let fx = fx().await;
    let d = Some(&fx.dev);
    let (status, c) = call(
        &fx,
        d,
        Method::POST,
        "/companies",
        Some(json!({"name": " Ainkrad ", "kind": "client"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{c}");
    assert_eq!(
        (&c["name"], &c["kind"]),
        (&json!("Ainkrad"), &json!("client"))
    );
    let id = c["id"].as_i64().unwrap();

    let (_, list) = call(&fx, d, Method::GET, "/companies", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (status, c) = call(
        &fx,
        d,
        Method::PUT,
        &format!("/companies/{id}"),
        Some(json!({"name": "Ainkrad HQ"})),
    )
    .await;
    assert_eq!(
        (status, &c["name"], &c["kind"]),
        (StatusCode::OK, &json!("Ainkrad HQ"), &json!("client"))
    );
    assert_eq!(
        call(&fx, d, Method::GET, "/companies/99", None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        actions(&fx).await,
        ["citadel.company.created", "citadel.company.updated"]
    );
}

#[tokio::test]
async fn bad_input_is_refused_before_anything_is_written() {
    let fx = fx().await;
    let d = Some(&fx.dev);
    let blank = call(
        &fx,
        d,
        Method::POST,
        "/companies",
        Some(json!({"name": "  "})),
    )
    .await;
    assert_eq!(blank.0, StatusCode::BAD_REQUEST);
    let kind = call(
        &fx,
        d,
        Method::POST,
        "/companies",
        Some(json!({"name": "A", "kind": "x"})),
    )
    .await;
    assert_eq!(kind.0, StatusCode::BAD_REQUEST);
    assert!(actions(&fx).await.is_empty());
    // A duplicate department name is a conflict, and writes no audit row.
    let (_, c) = call(
        &fx,
        d,
        Method::POST,
        "/companies",
        Some(json!({"name": "A"})),
    )
    .await;
    let path = format!("/companies/{}/departments", c["id"]);
    assert_eq!(
        call(&fx, d, Method::POST, &path, Some(json!({"name": "Eng"})))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&fx, d, Method::POST, &path, Some(json!({"name": "Eng"})))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        actions(&fx).await,
        ["citadel.company.created", "citadel.department.added"]
    );
}

#[tokio::test]
async fn departments_and_teams_nest_and_deleting_one_takes_its_teams() {
    let fx = fx().await;
    let d = Some(&fx.dev);
    let (_, c) = call(
        &fx,
        d,
        Method::POST,
        "/companies",
        Some(json!({"name": "A"})),
    )
    .await;
    let (_, dep) = call(
        &fx,
        d,
        Method::POST,
        &format!("/companies/{}/departments", c["id"]),
        Some(json!({"name": "Eng"})),
    )
    .await;
    let teams = format!("/departments/{}/teams", dep["id"]);
    let (_, team) = call(&fx, d, Method::POST, &teams, Some(json!({"name": "Core"}))).await;
    let (status, team) = call(
        &fx,
        d,
        Method::PUT,
        &format!("/teams/{}", team["id"]),
        Some(json!({"name": "Platform"})),
    )
    .await;
    assert_eq!(
        (status, &team["name"]),
        (StatusCode::OK, &json!("Platform"))
    );
    assert_eq!(
        call(&fx, d, Method::GET, &teams, None)
            .await
            .1
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let gone = format!("/departments/{}", dep["id"]);
    assert_eq!(
        call(&fx, d, Method::DELETE, &gone, None).await.0,
        StatusCode::OK
    );
    assert!(
        call(&fx, d, Method::GET, &teams, None)
            .await
            .1
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        call(&fx, d, Method::DELETE, &gone, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&fx, d, Method::GET, "/agents/1", None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_core_gate_covers_the_module_scope_and_step_up() {
    let fx = fx().await;
    let (_, c) = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        "/companies",
        Some(json!({"name": "A"})),
    )
    .await;
    assert_eq!(
        call(&fx, None, Method::GET, "/companies", None).await.0,
        StatusCode::UNAUTHORIZED
    );

    let phone = enroll(&fx.app, "phone", &["read"], true).await;
    // A read-only device reads (the route declares `read`), but cannot write.
    assert_eq!(
        call(&fx, Some(&phone), Method::GET, "/companies", None)
            .await
            .0,
        StatusCode::OK
    );
    let (status, body) = call(
        &fx,
        Some(&phone),
        Method::POST,
        "/companies",
        Some(json!({"name": "B"})),
    )
    .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
    );

    // Deleting a department is destructive: admin scope is not enough without a step-up.
    let (_, dep) = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        &format!("/companies/{}/departments", c["id"]),
        Some(json!({"name": "Eng"})),
    )
    .await;
    let plain = enroll(&fx.app, "laptop", &["admin"], true).await;
    let gone = format!("/departments/{}", dep["id"]);
    let (status, body) = call(&fx, Some(&plain), Method::DELETE, &gone, None).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    assert_eq!(
        call(&fx, Some(&fx.dev), Method::DELETE, &gone, None)
            .await
            .0,
        StatusCode::OK
    );
}
