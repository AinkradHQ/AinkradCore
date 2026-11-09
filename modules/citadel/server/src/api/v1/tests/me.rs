//! `GET /api/v1/me` and `GET /api/v1/events/latest`: the key check, the versions, the
//! companies a key sees and the newest event seq, all kept to the acting company.

use citadel_core::work::ProjectMode;
use serde_json::json;

use super::*;
use crate::api::v1::scope::COMPANY_HEADER;
use crate::api::v1::types::API_MINOR;
use crate::store::events::last_event_seq;

fn as_company(c: CompanyId, uri: &str, key: &str) -> Request<Body> {
    let mut r = req(Method::GET, uri, Some(key), None);
    let v = c.0.to_string().parse().unwrap();
    r.headers_mut().insert(COMPANY_HEADER, v);
    r
}

#[tokio::test]
async fn me_names_the_device_the_admin_and_the_versions() {
    let fx = fx().await;
    let me = fx.ok("/api/v1/me").await;
    assert_eq!(me["device"]["name"], "test");
    assert!(me["device"]["id"].as_i64().unwrap() > 0);
    assert_eq!(me["user"], json!({"id": 1, "name": "admin"}));
    let v = &me["versions"];
    assert_eq!(v["server"], env!("CARGO_PKG_VERSION"));
    assert!(!v["server"].as_str().unwrap().is_empty());
    assert_eq!(v["api"], json!({"major": "v1", "minor": API_MINOR}));
    assert_eq!(
        v["runner_protocol"],
        ainkrad_proto::runner::PROTOCOL_VERSION
    );
    // Built from a git checkout here; absent only when the build had no git.
    if let Some(sha) = option_env!("CITADEL_GIT_SHA") {
        assert_eq!(v["git_sha"], sha);
        assert!(!sha.is_empty());
    }
    assert_eq!(me["companies"], json!([]));
    let head = last_event_seq(&fx.app.pool).await.unwrap();
    assert_eq!(me["latest_seq"], head);

    let spec: Value = serde_json::from_str(&super::super::spec::json()).unwrap();
    assert_eq!(spec["info"]["version"], format!("1.{API_MINOR}.0"));
}

#[tokio::test]
async fn me_and_latest_need_a_key() {
    let fx = fx().await;
    for uri in ["/api/v1/me", "/api/v1/events/latest"] {
        let (status, body) = send(&fx.app, req(Method::GET, uri, None, None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}: {body}");
        let (status, _) = send(&fx.app, req(Method::GET, uri, Some("wrong"), None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn companies_and_the_latest_seq_keep_to_the_acting_company() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let head = last_event_seq(&fx.app.pool).await.unwrap();

    // Without a company: every company, the newest event of all.
    let me = fx.ok("/api/v1/me").await;
    let ids: Vec<_> = me["companies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].clone())
        .collect();
    assert_eq!(ids, vec![json!(a.company.0), json!(b.company.0)]);
    assert_eq!(me["latest_seq"], head);
    assert_eq!(fx.ok("/api/v1/events/latest").await, json!({"seq": head}));

    // As A: only A, and the newest event A's stream shows, which B's later events are not.
    let (_, page) = send(
        &fx.app,
        as_company(a.company, "/api/v1/events?limit=999", &fx.key),
    )
    .await;
    assert!(page["next_after"].is_null());
    let a_head = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_i64().unwrap())
        .max()
        .unwrap();
    assert!(a_head < head, "B's events are newer than A's");
    let (status, me) = send(&fx.app, as_company(a.company, "/api/v1/me", &fx.key)).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["companies"].as_array().unwrap().len(), 1);
    assert_eq!(me["companies"][0]["id"], a.company.0);
    assert_eq!(me["latest_seq"], a_head);
    let (_, latest) = send(
        &fx.app,
        as_company(a.company, "/api/v1/events/latest", &fx.key),
    )
    .await;
    assert_eq!(latest, json!({"seq": a_head}));

    // As B: its own newest, the head.
    let (_, latest) = send(
        &fx.app,
        as_company(b.company, "/api/v1/events/latest", &fx.key),
    )
    .await;
    assert_eq!(latest, json!({"seq": head}));
}
