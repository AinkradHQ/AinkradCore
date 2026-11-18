//! The Core routes the app's host page assumes (#157): health read, and a person's files. (Session
//! history, recordings and the Mac-direct lease have their own tests in history.rs and direct.rs.)

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;

async fn term(fx: &Fx) -> ainkrad_core_server::auth::testing::TestDevice {
    let d = enroll(&fx.app, "term", &["admin", "read", "terminal"]).await;
    let s = d.session.lock().unwrap().clone().unwrap();
    fx.app.auth.elevate(&s, &d.id, fx.app.clock.unix() + 3600);
    d
}

#[tokio::test]
async fn health_reads_the_stored_samples_and_goes_unknown_when_stale() {
    let fx = fx().await;
    let id = add(&fx, "alpha", "ask").await;
    let (s, v) = call(&fx, &fx.admin, Method::GET, "/hosts/alpha/health", None).await;
    assert_eq!(
        (s, v["state"].as_str()),
        (StatusCode::OK, Some("unknown")),
        "{v}"
    );
    let now = fx.app.clock.unix();
    for (at, up, load) in [
        (now - 120, 1, 0.5),
        (now - 60, 1, 1.5),
        (now - 3600, 1, 9.0),
    ] {
        sqlx::query(
            "INSERT INTO leyline_health_samples (host_id, at, up, load1, cpus, mem_pct) VALUES (?, ?, ?, ?, 2, 40.0)",
        )
        .bind(&id)
        .bind(at)
        .bind(up)
        .bind(load)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    }
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/hosts/{id}/health"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["state"], "up");
    assert_eq!(v["load1"], 1.5);
    assert_eq!(v["history"].as_array().unwrap().len(), 3);
    assert_eq!(v["history"][0]["load1"], 9.0, "oldest first");
    sqlx::query("UPDATE leyline_health_samples SET at = at - 7200")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let (_, v) = call(&fx, &fx.admin, Method::GET, "/hosts/alpha/health", None).await;
    assert_eq!(v["state"], "unknown", "an old sample is not now");
}

#[tokio::test]
async fn file_routes_refuse_without_a_runner_and_echo_nothing() {
    let fx = fx().await;
    add(&fx, "alpha", "ask").await;
    let t = term(&fx).await;
    for (m, p, b) in [
        (Method::GET, "/hosts/alpha/files?path=/PATH-SENTINEL", None),
        (
            Method::GET,
            "/hosts/alpha/files/content?path=/PATH-SENTINEL",
            None,
        ),
        (
            Method::PUT,
            "/hosts/alpha/files/content?path=/PATH-SENTINEL",
            Some(json!({"offset": 0, "data": "aGk=", "done": true})),
        ),
    ] {
        let (s, v) = call(&fx, &t, m, p, b).await;
        assert!(!s.is_success(), "{p}: {s} {v}");
        assert!(!v.to_string().contains("PATH-SENTINEL"), "{v}");
    }
    // a device without the terminal scope never reaches them
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::GET,
        "/hosts/alpha/files?path=/",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_upload_chunk_out_of_order_or_without_the_step_up_is_refused() {
    let fx = fx().await;
    add(&fx, "alpha", "ask").await;
    let t = term(&fx).await;
    let path = "/hosts/alpha/files/content?path=/x";
    let (s, v) = call(
        &fx,
        &t,
        Method::PUT,
        path,
        Some(json!({"offset": 4, "data": "aGk=", "done": false})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, v) = call(
        &fx,
        &t,
        Method::PUT,
        path,
        Some(json!({"offset": 0, "data": "!!", "done": false})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let cold = enroll(&fx.app, "cold", &["admin", "read", "terminal"]).await;
    let (s, v) = call(
        &fx,
        &cold,
        Method::PUT,
        path,
        Some(json!({"offset": 0, "data": "aGk=", "done": false})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
}
