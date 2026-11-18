//! Y4-02 review, MEDIUM + LOW: an exact id wins over a name that looks like one, such names are
//! refused, and steps that cannot be read are an error, never an empty command.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;

#[tokio::test]
async fn an_id_like_name_is_refused_and_an_exact_id_wins() {
    let fx = fx().await;
    let real = mk(&fx, json!({"name": "real", "steps": ["true"]})).await;
    let id = real["id"].as_str().unwrap().to_owned();
    for name in ["lc_anything", "LC_Anything", &id] {
        let (s, _) = call(
            &fx,
            &fx.admin,
            Method::POST,
            "/commands",
            Some(json!({"name": name, "steps": ["id"]})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{name}");
    }
    // even if such a name got into the store some other way, the exact id is found first
    sqlx::query("INSERT INTO leyline_commands (id, name, steps) VALUES ('lc_0000000000000001', ?, '[\"evil\"]')")
        .bind(&id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/commands/{id}"),
        None,
    )
    .await;
    assert_eq!((s, v["steps"].clone()), (StatusCode::OK, json!(["true"])));
}

#[tokio::test]
async fn unreadable_steps_are_an_error_not_an_empty_list() {
    let fx = fx().await;
    let c = mk(&fx, json!({"name": "c", "steps": ["true"]})).await;
    let id = c["id"].as_str().unwrap();
    sqlx::query("UPDATE leyline_commands SET steps = '[1]' WHERE id = ?")
        .bind(id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/commands/{id}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    let h = add(&fx, "web", "allowed").await;
    let (s, _) = run_of(&fx, id, &h).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
}
