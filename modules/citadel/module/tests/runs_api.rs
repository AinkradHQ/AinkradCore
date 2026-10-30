//! The run engine's routes through the Core's gate (S7): who may stop an agent or make one act,
//! what a phone may read, and the company scope.

mod common;
mod work_seed;

use axum::http::{Method, StatusCode};
use citadel_module::domain::work::ProjectMode;
use common::*;
use serde_json::{Value, json};
use work_seed::{post, seed};

/// The routes that make an agent act or stop one: each needs `admin` and a live step-up.
fn mutating(agent: i64) -> Vec<(Method, String, Option<Value>)> {
    vec![
        (Method::POST, "/runs/1/cancel".into(), None),
        (Method::POST, "/runs/1/kill".into(), None),
        (
            Method::POST,
            "/runs/1/message".into(),
            Some(json!({"text": "go"})),
        ),
        (
            Method::POST,
            format!("/agents/{agent}/wake"),
            Some(json!({"reason": "now"})),
        ),
        (
            Method::POST,
            "/engine".into(),
            Some(json!({"enabled": true})),
        ),
    ]
}

async fn code(
    fx: &Fx,
    dev: &citadel_module_testdev::Dev,
    m: &Method,
    path: &str,
    body: &Option<Value>,
) -> (StatusCode, String) {
    let (status, v) = call(fx, Some(dev), m.clone(), path, body.clone()).await;
    (status, v["code"].as_str().unwrap_or_default().to_owned())
}

mod citadel_module_testdev {
    pub use ainkrad_core_server::auth::testing::TestDevice as Dev;
}

#[tokio::test]
async fn every_mutating_run_route_needs_admin_and_a_step_up() {
    let fx = fx().await;
    let s = seed(&fx.app.pool, "A", "ENG", ProjectMode::Scrum).await;
    let read = enroll(&fx.app, "phone", &["read"], true).await;
    let approve = enroll(&fx.app, "approver", &["read", "approve"], true).await;
    let agent = enroll(&fx.app, "agent", &["agent", "read"], true).await;
    let unelevated = enroll(&fx.app, "admin2", &["admin", "read", "approve"], true).await;
    for (m, path, body) in mutating(s.agent) {
        for dev in [&read, &approve, &agent] {
            let (status, c) = code(&fx, dev, &m, &path, &body).await;
            assert_eq!(
                (status, c.as_str()),
                (StatusCode::FORBIDDEN, "forbidden_scope"),
                "{m} {path}"
            );
        }
        let (status, c) = code(&fx, &unelevated, &m, &path, &body).await;
        assert_eq!(
            (status, c.as_str()),
            (StatusCode::FORBIDDEN, "step_up_required"),
            "{m} {path} without a step-up"
        );
    }
    // Nothing happened: no engine switch, no wake, nothing audited as run control.
    let wakes: i64 = sqlx::query_scalar("SELECT count(*) FROM citadel_wake_requests")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    let engine: i64 = sqlx::query_scalar("SELECT count(*) FROM citadel_engine")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!((wakes, engine), (0, 0));
}

#[tokio::test]
async fn a_phone_reads_runs_but_not_their_transcripts_or_the_engine() {
    let fx = fx().await;
    let s = seed(&fx.app.pool, "A", "ENG", ProjectMode::Scrum).await;
    sqlx::query("INSERT INTO citadel_runs (agent_id, issue_id, harness) VALUES (?, ?, 'claude')")
        .bind(s.agent)
        .bind(s.issue)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let phone = enroll(&fx.app, "phone", &["read"], false).await;
    for path in ["/runs", "/runs/1"] {
        let (status, _) = call(&fx, Some(&phone), Method::GET, path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}");
    }
    for path in ["/runs/1/transcript", "/engine"] {
        let (status, v) = call(&fx, Some(&phone), Method::GET, path, None).await;
        assert_eq!(
            (status, v["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("forbidden_scope")),
            "{path}"
        );
    }
    let (status, _) = call(&fx, None, Method::GET, "/runs", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_admin_switches_the_engine_wakes_an_agent_and_stops_a_run_that_has_no_session() {
    let fx = fx().await;
    let s = seed(&fx.app.pool, "A", "ENG", ProjectMode::Scrum).await;
    assert_eq!(fx.ok("/engine").await["enabled"], false);
    let on = fx.ok_post("/engine", json!({"enabled": true})).await;
    assert_eq!(on["enabled"], true);
    assert_eq!(fx.ok("/engine").await["enabled"], true);
    let by: String = sqlx::query_scalar("SELECT by_device FROM citadel_engine")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(
        by, fx.dev.id,
        "the device that stepped up is the accountable one"
    );

    let w = fx
        .ok_post(
            &format!("/agents/{}/wake", s.agent),
            json!({"reason": "look at it", "issue_id": s.issue}),
        )
        .await;
    assert_eq!(w["status"], "pending");
    for bad in [json!({"reason": ""}), json!({"reason": "x".repeat(501)})] {
        let (status, _) = post(&fx, &format!("/agents/{}/wake", s.agent), bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, _) = post(&fx, "/agents/9999/wake", json!({"reason": "x"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A claimed run that never got a session: cancel ends it; a second cancel and a kill are 409.
    sqlx::query("INSERT INTO citadel_runs (agent_id, issue_id, harness, state, runner, claimed_at) VALUES (?, ?, 'claude', 'claimed', 'd_x', ?)")
        .bind(s.agent)
        .bind(s.issue)
        .bind("2026-11-01T00:00:00.000Z")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let (status, msg) = post(&fx, "/runs/1/message", json!({"text": "hi"})).await;
    assert_eq!(
        (status, msg["code"].as_str()),
        (StatusCode::CONFLICT, Some("run_not_live"))
    );
    let cancelled = fx.ok_post("/runs/1/cancel", json!({})).await;
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(cancelled["terminal_reason"], "cancelled by the admin");
    for path in ["/runs/1/cancel", "/runs/1/kill"] {
        let (status, v) = post(&fx, path, json!({})).await;
        assert_eq!(
            (status, v["code"].as_str()),
            (StatusCode::CONFLICT, Some("run_not_live")),
            "{path}"
        );
    }
    let (status, _) = post(&fx, "/runs/99/kill", json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = post(&fx, "/runs/1/message", json!({"text": ""})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action IN ('citadel.run.cancelled', 'citadel.engine.enabled')")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert!(audited >= 2, "both the switch and the cancel are audited");
}

#[tokio::test]
async fn a_client_working_in_one_company_never_reaches_another_companys_runs() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Scrum).await;
    for s in [&a, &b] {
        sqlx::query("INSERT INTO citadel_runs (agent_id, issue_id, harness, state, runner, claimed_at) VALUES (?, ?, 'claude', 'claimed', 'd_x', ?)")
            .bind(s.agent)
            .bind(s.issue)
            .bind("2026-11-01T00:00:00.000Z")
            .execute(&fx.app.pool)
            .await
            .unwrap();
    }
    let company = a.company.to_string();
    let mine = call_in(
        &fx,
        Some(&fx.dev),
        Some(&company),
        Method::GET,
        "/runs",
        None,
    )
    .await
    .1;
    assert_eq!(mine.as_array().unwrap().len(), 1);
    assert_eq!(mine[0]["agent_id"], a.agent);
    for (m, path, body) in [
        (Method::GET, "/runs/2", None),
        (Method::GET, "/runs/2/transcript", None),
        (Method::POST, "/runs/2/cancel", Some(json!({}))),
        (Method::POST, "/runs/2/kill", Some(json!({}))),
        (Method::POST, "/runs/2/message", Some(json!({"text": "x"}))),
        (
            Method::POST,
            &format!("/agents/{}/wake", b.agent),
            Some(json!({"reason": "x"})),
        ),
    ] {
        let (status, _) = call_in(&fx, Some(&fx.dev), Some(&company), m.clone(), path, body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{m} {path} across companies");
    }
    let state: String = sqlx::query_scalar("SELECT state FROM citadel_runs WHERE id = 2")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(state, "claimed", "the other company's run was not touched");
}

#[tokio::test]
async fn a_manual_wake_cannot_name_another_companys_issue() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "ENG", ProjectMode::Scrum).await;
    let b = seed(&fx.app.pool, "B", "BEE", ProjectMode::Scrum).await;
    let path = format!("/agents/{}/wake", a.agent);
    let (status, _) = post(&fx, &path, json!({"reason": "x", "issue_id": b.issue})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(&fx, &path, json!({"reason": "x", "issue_id": 99999})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let wakes: i64 = sqlx::query_scalar("SELECT count(*) FROM citadel_wake_requests")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(wakes, 0);
    let (status, _) = post(&fx, &path, json!({"reason": "x", "issue_id": a.issue})).await;
    assert_eq!(status, StatusCode::OK);
}
