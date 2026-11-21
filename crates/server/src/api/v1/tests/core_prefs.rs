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

async fn check(fx: &Fx) -> Value {
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
    got
}

/// A local feed (update.sh takes an absolute path as `BASE` too) holding `core`/`runner`, signed by a test key.
fn feed(fx: &mut Fx, core: &str, signed_by_other: bool) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "core-feed-route-{}-{core}-{signed_by_other}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (public, sign) = crate::update_feed::test_signer();
    let m = format!(
        r#"{{"expires":9999999999,"channels":{{"stable":{{"core":{{"version":"{core}"}},"runner":{{"version":"{core}"}}}}}}}}"#
    );
    std::fs::write(dir.join("manifest.json"), &m).unwrap();
    let sig = if signed_by_other {
        crate::update_feed::test_signer().1(m.as_bytes())
    } else {
        sign(m.as_bytes())
    };
    std::fs::write(dir.join("manifest.json.minisig"), sig).unwrap();
    fx.app.update_feed = std::sync::Arc::new(crate::update_feed::Feed {
        fixed: Some((dir.to_str().unwrap().to_owned(), "stable".into(), public)),
    });
    dir
}

#[tokio::test]
async fn an_update_check_reads_the_signed_feed() {
    let mut fx = fx().await;
    let d = feed(&mut fx, "99.0.0", false);
    let got = check(&fx).await;
    assert_eq!(got["status"], "available", "{got}");
    assert_eq!(got["latest_version"], "99.0.0");
    assert_eq!(got["runner_latest_version"], "99.0.0");
    assert_eq!(got["current_version"], env!("CARGO_PKG_VERSION"));
    let prefs = fx.ok("/api/v1/core/prefs").await;
    assert_eq!(prefs["update_checked_at"], got["checked_at"]);
    let _ = std::fs::remove_dir_all(d);

    let d = feed(&mut fx, env!("CARGO_PKG_VERSION"), false);
    let got = check(&fx).await;
    assert_eq!(got["status"], "up_to_date", "{got}");
    assert!(got["latest_version"].is_null());
    let _ = std::fs::remove_dir_all(d);
}

#[tokio::test]
async fn a_feed_that_does_not_verify_is_unavailable_and_never_read() {
    let mut fx = fx().await;
    let d = feed(&mut fx, "99.0.0", true);
    let got = check(&fx).await;
    assert_eq!(got["status"], "feed_unavailable", "{got}");
    assert_eq!(got["reason"], "bad_signature");
    assert!(got["latest_version"].is_null() && got["runner_latest_version"].is_null());
    std::fs::remove_file(d.join("manifest.json.minisig")).unwrap();
    assert_eq!(check(&fx).await["reason"], "no_manifest");
    let _ = std::fs::remove_dir_all(d);
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
