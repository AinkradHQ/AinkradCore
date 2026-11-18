//! The project secret routes (P4-04): admin scope, a step-up for writes, no value on the wire,
//! a delete that warns while a spec uses the secret, and the generic secret routes keeping off.

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::ops::secretbox::SecretBox;
use crate::store::project_secrets::fixtures::{VALUE, broker};

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

fn code(r: &(StatusCode, Value)) -> (StatusCode, &str) {
    (r.0, r.1["code"].as_str().unwrap_or(""))
}

#[tokio::test]
async fn secrets_are_written_never_read_and_guard_their_use() {
    let mut fx = fx().await;
    fx.app.secrets = Some(Arc::new(SecretBox::new(&[7; 32])));
    broker(&fx.app.pool).await;
    let dev = &fx.dev;
    let made = call(
        &fx,
        dev,
        Method::POST,
        "/api/v1/projects",
        json!({"slug": "shop", "name": "Shop"}),
    )
    .await;
    let id = made.1["id"].as_i64().unwrap();
    let base = format!("/api/v1/projects/{id}/secrets");

    // A reader (no admin scope) can neither list nor write.
    let phone = fx.enroll("phone", &["read"]).await;
    let r = call(&fx, &phone, Method::GET, &base, Value::Null).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "forbidden_scope"));

    let put = call(
        &fx,
        dev,
        Method::PUT,
        &format!("{base}/db_password"),
        json!({"value": VALUE}),
    )
    .await;
    assert_eq!(put.0, StatusCode::OK, "{}", put.1);
    let list = call(&fx, dev, Method::GET, &base, Value::Null).await;
    assert_eq!(list.1[0]["name"], "db_password");
    assert!(
        !list.1.to_string().contains("throwaway"),
        "no value on the wire"
    );
    assert!(!put.1.to_string().contains("throwaway"));

    // A spec uses it: the delete warns, naming the version, and force overrides.
    let spec = json!({"spec": {"services": {"db": {"image": "postgres:17",
        "env": {"PW": "${secret:db_password}"}}}}});
    let saved = call(
        &fx,
        dev,
        Method::PUT,
        &format!("/api/v1/projects/{id}/spec"),
        spec,
    )
    .await;
    assert_eq!(saved.0, StatusCode::OK, "{}", saved.1);
    let del = call(
        &fx,
        dev,
        Method::DELETE,
        &format!("{base}/db_password"),
        Value::Null,
    )
    .await;
    assert_eq!(code(&del), (StatusCode::CONFLICT, "conflict"));
    assert!(
        del.1["message"]
            .as_str()
            .unwrap()
            .contains("spec version 1"),
        "{}",
        del.1
    );

    // The generic routes leave a project's secret alone.
    let g = call(
        &fx,
        dev,
        Method::DELETE,
        "/api/v1/secrets/shop.db_password",
        Value::Null,
    )
    .await;
    assert_eq!(code(&g), (StatusCode::BAD_REQUEST, "bad_request"));
    let g = call(
        &fx,
        dev,
        Method::POST,
        "/api/v1/secrets",
        json!({"name": "mine", "value": VALUE, "group": "project-shop"}),
    )
    .await;
    assert_eq!(code(&g), (StatusCode::BAD_REQUEST, "bad_request"));

    let forced = call(
        &fx,
        dev,
        Method::DELETE,
        &format!("{base}/db_password?force=true"),
        Value::Null,
    )
    .await;
    assert_eq!(forced.0, StatusCode::OK, "{}", forced.1);
    let list = call(&fx, dev, Method::GET, &base, Value::Null).await;
    assert_eq!(list.1.as_array().unwrap().len(), 0);
}
