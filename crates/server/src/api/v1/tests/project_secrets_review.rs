//! Review fixes of P4-04: `project-*` secret groups are off limits to the generic group routes,
//! and the generic `POST /secrets` keeps off a project's `<slug>.*` namespace.

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::ops::secretbox::SecretBox;
use crate::store::project_secrets::fixtures::{VALUE, broker};

async fn call(fx: &Fx, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(&fx.dev), body)).await
}

fn status(r: &(StatusCode, Value)) -> StatusCode {
    r.0
}

#[tokio::test]
async fn generic_group_routes_refuse_project_groups() {
    let mut fx = fx().await;
    fx.app.secrets = Some(Arc::new(SecretBox::new(&[7; 32])));
    broker(&fx.app.pool).await;
    let made = call(
        &fx,
        Method::POST,
        "/api/v1/projects",
        json!({"slug": "shop", "name": "Shop"}),
    )
    .await;
    let id = made.1["id"].as_i64().unwrap();
    let put = call(
        &fx,
        Method::PUT,
        &format!("/api/v1/projects/{id}/secrets/db_password"),
        json!({"value": VALUE}),
    )
    .await;
    assert_eq!(put.0, StatusCode::OK, "{}", put.1);

    let g = "/api/v1/secret-groups";
    let r = call(&fx, Method::POST, g, json!({"name": "project-evil"})).await;
    assert_eq!(status(&r), StatusCode::BAD_REQUEST);
    let r = call(
        &fx,
        Method::PUT,
        &format!("{g}/project-shop"),
        json!({"description": "x"}),
    )
    .await;
    assert_eq!(status(&r), StatusCode::BAD_REQUEST);
    let r = call(
        &fx,
        Method::DELETE,
        &format!("{g}/project-shop"),
        Value::Null,
    )
    .await;
    assert_eq!(status(&r), StatusCode::BAD_REQUEST);
    let r = call(
        &fx,
        Method::POST,
        &format!("{g}/project-shop/leases"),
        json!({"runner": "d_aaaaaaaaaaaaaaaaaaaaaaaaaa"}),
    )
    .await;
    assert_eq!(status(&r), StatusCode::BAD_REQUEST);

    // Nor can a single project secret be leased through the generic route.
    let r = call(
        &fx,
        Method::POST,
        "/api/v1/secrets/shop.db_password/leases",
        json!({"runner": "d_aaaaaaaaaaaaaaaaaaaaaaaaaa"}),
    )
    .await;
    assert_eq!(status(&r), StatusCode::BAD_REQUEST, "{}", r.1);

    // An ordinary group still works.
    let r = call(&fx, Method::POST, g, json!({"name": "aws"})).await;
    assert_eq!(status(&r), StatusCode::OK, "{}", r.1);
}

#[tokio::test]
async fn generic_create_refuses_an_existing_project_slug_namespace() {
    let mut fx = fx().await;
    fx.app.secrets = Some(Arc::new(SecretBox::new(&[7; 32])));
    broker(&fx.app.pool).await;
    call(
        &fx,
        Method::POST,
        "/api/v1/projects",
        json!({"slug": "shop", "name": "Shop"}),
    )
    .await;
    let r = call(
        &fx,
        Method::POST,
        "/api/v1/secrets",
        json!({"name": "shop.planted", "value": VALUE}),
    )
    .await;
    assert_eq!(status(&r), StatusCode::BAD_REQUEST, "{}", r.1);
    // Other dotted names are untouched.
    let r = call(
        &fx,
        Method::POST,
        "/api/v1/secrets",
        json!({"name": "other.key", "value": VALUE}),
    )
    .await;
    assert_eq!(status(&r), StatusCode::OK, "{}", r.1);
}
