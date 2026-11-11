//! The data the App's runner, Home and Add device screens read: a runner invite, the Core's health,
//! the runner facts and the accounts' month spend.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::store::gov;

async fn invite(fx: &Fx, body: Value) -> (StatusCode, Value) {
    let r = req(
        Method::POST,
        "/api/v1/pairings/invites",
        Some(&fx.dev),
        Some(body),
    );
    send(&fx.app, r).await
}

async fn claim(fx: &Fx, secret: &str) -> (StatusCode, Value) {
    let dev = TestDevice::new(&fx.app.auth.identity.fp, fx.clock.clone());
    let body = dev.claim_body(None, Some(secret));
    send(
        &fx.app,
        from(
            "203.0.113.7",
            req(Method::POST, "/pair/claim", None, Some(body)),
        ),
    )
    .await
}

/// A runner invite: the `runner` scope alone (scopes may be left out), a token that names the
/// Core, 15 minutes, single use; the claimant is an active runner with no check code.
#[tokio::test]
async fn a_runner_invite_lasts_fifteen_minutes_and_enrols_an_active_runner() {
    let fx = fx().await;
    let (s, made) = invite(&fx, json!({"name": "Build box", "kind": "runner"})).await;
    assert_eq!(s, StatusCode::OK, "{made}");
    let secret = made["secret"].as_str().unwrap();
    assert_eq!(made["kind"], "runner");
    assert_eq!(
        made["token"],
        format!("{HOST}/{}.{secret}", fx.app.auth.identity.fp)
    );
    let ends = made["expires_at"].as_str().unwrap().to_owned();
    assert_eq!(
        ends,
        crate::scheduler::iso_of_unix(fx.clock.unix() + gov::RUNNER_INVITE_SECS)
    );
    let (s, got) = claim(&fx, secret).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{got}");
    let d = gov::get_device(&fx.app.pool, got["device_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (d.kind.as_str(), d.status.as_str(), d.scopes),
        ("runner", "active", vec!["runner".to_owned()])
    );
    // Single use.
    let (s, _) = claim(&fx, secret).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_unclaimed_runner_invite_ends_after_fifteen_minutes() {
    let fx = fx().await;
    let (_, made) = invite(&fx, json!({"name": "Late", "kind": "runner"})).await;
    fx.clock.advance(gov::RUNNER_INVITE_SECS + 1);
    let (s, _) = claim(&fx, made["secret"].as_str().unwrap()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_runner_invite_takes_no_other_scope_and_a_device_invite_is_unchanged() {
    let fx = fx().await;
    let (s, _) = invite(
        &fx,
        json!({"name": "x", "kind": "runner", "scopes": ["runner", "read"]}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = invite(&fx, json!({"name": "x", "kind": "robot"})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, made) = invite(&fx, json!({"name": "Phone", "scopes": ["read"]})).await;
    assert_eq!(s, StatusCode::OK, "{made}");
    assert_eq!(
        (
            made["kind"].as_str(),
            made["expires_at"].is_null(),
            made["token"].is_null()
        ),
        (Some("device"), true, true),
        "a device invite never expires"
    );
}

#[tokio::test]
async fn the_core_health_route_answers_a_read_device() {
    let fx = fx().await;
    let phone = fx.enroll("phone", &["read"]).await;
    let (s, h) = send(
        &fx.app,
        req(Method::GET, "/api/v1/core/health", Some(&phone), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{h}");
    assert_eq!(h["version"], env!("CARGO_PKG_VERSION"));
    assert!(h["uptime_secs"].is_u64(), "{h}");
}

/// An offline runner still has its slots (nothing used) and no live facts; the built-in mark
/// follows the installer's local enrolment, not the name.
#[tokio::test]
async fn a_runner_lists_its_slots_and_the_built_in_mark() {
    let fx = fx().await;
    let r = TestDevice::enroll(
        &fx.app.pool,
        "vm",
        "runner",
        &["runner"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    sqlx::query(
        "INSERT INTO core_pairings (id, code_hash, secret_hash, kind, name, scopes, bootstrap, \
         invite, created_at, expires_at, status, device_id, sas) \
         VALUES ('p_aaaaaaaaaaaaaaaaaaaaaaaaaa', randomblob(32), randomblob(32), 'runner', 'This Core (built-in)', '[\"runner\"]', 0, 0, \
         '2026-01-01T00:00:00Z', '2026-01-01T00:05:00Z', 'approved', ?, ?)",
    )
    .bind(&r.id)
    .bind(gov::LOCAL_ENROL_SAS)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let (s, list) = send(
        &fx.app,
        req(Method::GET, "/api/v1/runners", Some(&fx.dev), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(list[0]["built_in"], true);
    assert_eq!(list[0]["slots"]["agents_used"], 0);
    assert_eq!(list[0]["slots"]["terminals_used"], 0);
    assert!(list[0]["accounts"].is_null(), "offline: nothing reported");
}
