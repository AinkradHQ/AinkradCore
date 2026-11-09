//! `GET /api/v1/me` and `GET /api/v1/events/latest`: the signature check, the versions and the
//! newest event seq.

use serde_json::json;

use super::*;
use crate::api::v1::types::API_MINOR;
use crate::store::events::last_event_seq;

#[tokio::test]
async fn me_names_the_device_and_the_versions() {
    let fx = fx().await;
    let me = fx.ok("/api/v1/me").await;
    assert_eq!(me["device"]["name"], "test");
    assert_eq!(me["device"]["id"], fx.dev.id.as_str());
    let v = &me["versions"];
    assert_eq!(v["server"], env!("CARGO_PKG_VERSION"));
    assert!(!v["server"].as_str().unwrap().is_empty());
    assert_eq!(v["api"], json!({"major": "v1", "minor": API_MINOR}));
    // Built from a git checkout here; absent only when the build had no git.
    if let Some(sha) = option_env!("CITADEL_GIT_SHA") {
        assert_eq!(v["git_sha"], sha);
        assert!(!sha.is_empty());
    }

    let latest = fx.ok("/api/v1/events/latest").await;
    let head = last_event_seq(&fx.app.pool).await.unwrap();
    assert!(head > 0, "enrolling the device was audited");
    assert_eq!(latest, json!({"seq": head, "floor": 0}));

    let spec: Value = serde_json::from_str(&super::super::spec::json()).unwrap();
    assert_eq!(spec["info"]["version"], format!("1.{API_MINOR}.0"));
}

#[tokio::test]
async fn me_and_latest_need_a_signature() {
    let fx = fx().await;
    let stranger = fx.stranger();
    for uri in ["/api/v1/me", "/api/v1/events/latest"] {
        let (status, body) = send(&fx.app, req(Method::GET, uri, None, None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}: {body}");
        let (status, _) = send(&fx.app, req(Method::GET, uri, Some(&stranger), None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
    }
}
