//! The Core page's preferences, storage and update check (Core 0.10, E2-3).

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;

async fn put(fx: &Fx, body: Value) -> (StatusCode, Value) {
    send(
        &fx.app,
        req(Method::PUT, "/api/v1/core/prefs", Some(&fx.dev), Some(body)),
    )
    .await
}

#[tokio::test]
async fn prefs_start_at_their_defaults_and_keep_what_is_set() {
    let fx = fx().await;
    let first = fx.ok("/api/v1/core/prefs").await;
    assert_eq!(first["crash_reports"], false);
    assert_eq!(first["auto_update"], true);
    assert_eq!(first["update_hour"], 3);
    assert!(first["name"].is_null());

    let (s, got) = put(
        &fx,
        json!({"name": "  Studio server ", "crash_reports": true}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{got}");
    assert_eq!(got["name"], "Studio server");
    assert_eq!(got["crash_reports"], true);
    // A field left out stays as it was.
    let (_, got) = put(&fx, json!({"update_hour": 5})).await;
    assert_eq!(
        (got["name"].as_str(), got["update_hour"].as_i64()),
        (Some("Studio server"), Some(5))
    );
    assert_eq!(fx.ok("/api/v1/core/prefs").await["crash_reports"], true);
}

#[tokio::test]
async fn a_bad_name_or_hour_is_refused_and_changes_nothing() {
    let fx = fx().await;
    for body in [
        json!({"name": "   "}),
        json!({"name": "x".repeat(65)}),
        json!({"update_hour": 24}),
        json!({"nope": 1}),
    ] {
        let (s, got) = put(&fx, body).await;
        // An unknown field is refused by the JSON extractor (422); the others by the handler (400).
        assert!(
            s == StatusCode::BAD_REQUEST || s == StatusCode::UNPROCESSABLE_ENTITY,
            "{s} {got}"
        );
    }
    assert!(fx.ok("/api/v1/core/prefs").await["name"].is_null());
}

#[tokio::test]
async fn only_an_admin_changes_prefs_and_a_change_is_audited() {
    let fx = fx().await;
    let phone = fx.enroll("phone", &["read"]).await;
    let (s, _) = send(
        &fx.app,
        req(
            Method::PUT,
            "/api/v1/core/prefs",
            Some(&phone),
            Some(json!({"name": "x"})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = send(
        &fx.app,
        req(Method::GET, "/api/v1/core/prefs", Some(&phone), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    put(&fx, json!({"name": "Studio"})).await;
    let audit = fx.ok("/api/v1/audit").await.to_string();
    assert!(audit.contains("core.prefs_changed"), "{audit}");
}

#[tokio::test]
async fn an_update_check_records_that_it_ran_and_says_there_is_no_feed() {
    let fx = fx().await;
    let (s, got) = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/core/update/check",
            Some(&fx.dev),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{got}");
    assert_eq!(got["status"], "feed_unavailable");
    assert_eq!(got["current_version"], env!("CARGO_PKG_VERSION"));
    let prefs = fx.ok("/api/v1/core/prefs").await;
    assert_eq!(prefs["update_checked_at"], got["checked_at"]);
}

#[tokio::test]
async fn storage_answers_for_an_admin() {
    let fx = fx().await;
    let got = fx.ok("/api/v1/core/storage").await;
    assert!(
        got["backups_count"].is_u64() || got["backups_count"].is_null(),
        "{got}"
    );
}
