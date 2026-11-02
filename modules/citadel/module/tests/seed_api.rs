//! Seeding a live server (KAN-275): `POST /admin/seed` is admin scope and a step-up route, applies
//! in one transaction, is idempotent, refuses any field but names and kinds, and leaves one audit
//! row holding counts and a hash, never a name.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{Value, json};
use sha2::Digest;

const PATH: &str = "/admin/seed";
const NAME: &str = "Distinctive Seed Name Ltd";

async fn count(fx: &Fx, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn companies(fx: &Fx) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM citadel_companies")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn seeding_needs_admin_and_a_step_up() {
    let fx = fx().await;
    let laptop = enroll(&fx.app, "laptop", &["admin"], true).await;
    let reader = enroll(&fx.app, "reader", &["read"], true).await;
    let body = || Some(json!({"companies": [{"name": NAME}]}));
    let before = companies(&fx).await;
    let r = call(&fx, Some(&laptop), Method::POST, PATH, body()).await;
    assert_eq!(r.0, StatusCode::FORBIDDEN, "{r:?}");
    assert_eq!(r.1["code"], "step_up_required");
    assert_eq!(
        count(&fx, "citadel.seed.applied").await,
        0,
        "no row for a refused step-up"
    );
    assert_eq!(count(&fx, "citadel.company.created").await, 0);
    let r = call(&fx, Some(&reader), Method::POST, PATH, body()).await;
    assert_eq!(r.0, StatusCode::FORBIDDEN, "{r:?}");
    assert_ne!(r.1["code"], "step_up_required", "scope is checked first");
    let r = call(&fx, None, Method::POST, PATH, body()).await;
    assert!(r.0.is_client_error(), "unsigned: {r:?}");
    assert_eq!(companies(&fx).await, before, "nothing applied");
    assert_eq!(count(&fx, "citadel.seed.applied").await, 0);
}

#[tokio::test]
async fn a_request_pinned_to_a_company_is_refused_even_elevated() {
    let fx = fx().await;
    let laptop = enroll(&fx.app, "laptop", &["admin"], true).await;
    sqlx::query("INSERT INTO citadel_companies (name, kind) VALUES ('Pinned', 'own')")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let id: i64 = sqlx::query_scalar("SELECT id FROM citadel_companies WHERE name = 'Pinned'")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    let before = companies(&fx).await;
    let body = Some(json!({"companies": [{"name": NAME}]}));
    // Elevated admin (fx.dev): the header alone makes it a 400.
    let pinned = id.to_string();
    let (s, b) = call_in(
        &fx,
        Some(&fx.dev),
        Some(&pinned),
        Method::POST,
        PATH,
        body.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    // Not elevated: the step-up still comes first.
    let (s, b) = call_in(&fx, Some(&laptop), Some(&pinned), Method::POST, PATH, body).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    assert_eq!(b["code"], "step_up_required");
    assert_eq!(companies(&fx).await, before, "nothing applied");
    assert_eq!(count(&fx, "citadel.seed.applied").await, 0);
    assert_eq!(count(&fx, "citadel.company.created").await, 0);
}

#[tokio::test]
async fn a_seed_applies_once_audits_counts_and_refuses_credentials() {
    let fx = fx().await;
    let before = companies(&fx).await;
    let seed =
        json!({"companies": [{"name": NAME, "kind": "own"}, {"name": "Second", "kind": "client"}]});
    let (s, a) = call(&fx, Some(&fx.dev), Method::POST, PATH, Some(seed.clone())).await;
    assert_eq!(s, StatusCode::OK, "{a}");
    assert_eq!(a["added"], 2);
    assert_eq!(companies(&fx).await, before + 2);
    let (s, a) = call(&fx, Some(&fx.dev), Method::POST, PATH, Some(seed.clone())).await;
    assert_eq!(s, StatusCode::OK, "{a}");
    assert_eq!(a["added"], 0, "a second apply changes nothing");
    let other = json!({"companies": [{"name": NAME, "kind": "client"}]});
    let (_, a) = call(&fx, Some(&fx.dev), Method::POST, PATH, Some(other)).await;
    assert_eq!(a["kind_mismatch"], 1);

    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'citadel.seed.applied' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 3);
    let first: Value = serde_json::from_str(&rows[0]).unwrap();
    assert_eq!(first["added"], 2);
    assert_eq!(first["via"], "api");
    assert_eq!(first["by_device"], fx.dev.id);
    // The hash and size are of the raw request body, as the CLI hashes the raw file.
    let raw = seed.to_string();
    assert_eq!(first["bytes"], raw.len());
    assert_eq!(first["sha256"], hex(&sha2::Sha256::digest(raw.as_bytes())));
    // A `company.created` event per created company, none for an existing one.
    assert_eq!(count(&fx, "citadel.company.created").await, 2);
    for row in &rows {
        assert!(!row.contains("Distinctive"), "no content in the row: {row}");
    }

    // Nothing but names and kinds is accepted; a refused seed applies none of it and says nothing
    // of what it was sent.
    let count = companies(&fx).await;
    let audits = rows.len();
    for bad in [
        json!({"companies": [{"name": "X", "password": "hunter2-marker"}]}),
        json!({"token": "hunter2-marker", "companies": []}),
        json!({"companies": [{"name": "Good"}, {"name": "Bad", "kind": "evil"}]}),
        json!({"companies": [{"name": "  "}]}),
        json!({"companies": [{"name": "x".repeat(201)}]}),
        json!({"companies": (0..501).map(|i| json!({"name": format!("c{i}")})).collect::<Vec<_>>()}),
    ] {
        let (s, b) = call(&fx, Some(&fx.dev), Method::POST, PATH, Some(bad)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        assert!(!b.to_string().contains("hunter2-marker"), "{b}");
    }
    assert_eq!(companies(&fx).await, count, "a refused seed adds nothing");
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'citadel.seed.applied'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(
        n as usize, audits,
        "a refused seed is not audited as applied"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
