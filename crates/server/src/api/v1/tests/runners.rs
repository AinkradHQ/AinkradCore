//! Runner admin over the API (protocol 1.20): register (key once), drain, remove, Power Nap,
//! log tails, and what a runner reports of itself; account plan tiers; error ids.

use std::collections::BTreeMap;

use ainkrad_core::work::ProjectMode;
use ainkrad_proto::runner::{Login, RunnerInfo};

use super::*;
use crate::store::exec::{get_runner, record_info};

async fn audited(pool: &SqlitePool, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_runner_is_registered_drained_and_removed_from_the_app() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let new = json!({"name": "mac-mini", "tags": ["macos"]});
    let added = fx.ok_post("/api/v1/runners", new.clone()).await;
    let key = added["key"].as_str().unwrap();
    assert!(key.starts_with("cit_runner_"), "{added}");
    let id = added["runner"]["id"].as_i64().unwrap();
    assert_eq!(added["runner"]["status"], "offline");
    assert_eq!(added["runner"]["asleep"], true, "an offline Mac");
    assert_eq!(audited(pool, "runner.registered").await, 1);
    let (status, body) = fx.post("/api/v1/runners", new).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body["error_id"].as_str().unwrap().starts_with("err_"));
    let listed = fx.ok("/api/v1/runners").await;
    assert!(
        listed.to_string().find(key).is_none(),
        "the key is never listed"
    );

    let drain = format!("/api/v1/runners/{id}/drain");
    let drained = fx.ok_post(&drain, json!({})).await;
    assert!(drained["drained_at"].is_string());
    fx.ok_post(&drain, json!({})).await;
    assert_eq!(audited(pool, "runner.drained").await, 1, "once");
    let (status, back) = send(&fx.app, req(Method::DELETE, &drain, Some(&fx.key), None)).await;
    assert_eq!(
        (status, back["drained_at"].clone()),
        (StatusCode::OK, Value::Null)
    );
    assert_eq!(audited(pool, "runner.undrained").await, 1);

    let nap = format!("/api/v1/runners/{id}/power-nap");
    let body = Some(json!({"enabled": false}));
    let (status, r) = send(&fx.app, req(Method::PUT, &nap, Some(&fx.key), body)).await;
    assert_eq!(
        (status, r["power_nap"].clone()),
        (StatusCode::OK, json!(false))
    );
    assert_eq!(audited(pool, "runner.power_nap").await, 1);

    let logs = format!("/api/v1/runners/{id}/logs");
    let (status, body) = fx.get(&logs).await;
    assert_eq!(status, StatusCode::CONFLICT, "offline: {body}");
    let probe = format!("/api/v1/runners/{id}/probe");
    let (status, body) = fx.post(&probe, json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT, "offline: {body}");
    assert_eq!(
        fx.post("/api/v1/runners/999/probe", json!({})).await.0,
        StatusCode::NOT_FOUND
    );

    let gone = format!("/api/v1/runners/{id}");
    let (status, _) = send(&fx.app, req(Method::DELETE, &gone, Some(&fx.key), None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(get_runner(pool, RunnerId(id)).await.unwrap().is_none());
    assert_eq!(audited(pool, "runner.removed").await, 1);
}

#[tokio::test]
async fn a_runner_holding_live_runs_is_not_removed() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/runners/{}", a.runner.0);
    let (status, body) = send(&fx.app, req(Method::DELETE, &uri, Some(&fx.key), None)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body["message"].as_str().unwrap().contains("live runs"));
    let refused: Value =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'api.refused'")
            .fetch_one(&fx.app.pool)
            .await
            .map(|d: String| serde_json::from_str(&d).unwrap())
            .unwrap();
    assert_eq!(
        refused["error_id"], body["error_id"],
        "the id finds its audit row"
    );
    assert_eq!(
        (refused["method"].clone(), refused["code"].clone()),
        (json!("DELETE"), json!("conflict"))
    );
}

#[tokio::test]
async fn a_runner_shows_what_it_reported_with_its_accounts_logins() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let account = json!({"harness": "claude", "label": "claude-a"});
    let account = fx.ok_post("/api/v1/accounts", account).await["id"]
        .as_i64()
        .unwrap();
    let info = RunnerInfo {
        slots: 1,
        uptime_secs: 3600,
        logins: vec![
            Login {
                dir: "claude".to_owned(),
                harness: Some("claude".to_owned()),
                state: "unknown".to_owned(),
            },
            Login {
                dir: "accounts/claude-a".to_owned(),
                harness: None,
                state: "logged_in".to_owned(),
            },
        ],
        slept_secs: Some(7200),
        power_nap: Some(true),
    };
    let harnesses = BTreeMap::from([
        ("claude".to_owned(), "2.1.306".to_owned()),
        ("codex".to_owned(), "9.0.0".to_owned()),
        ("opencode".to_owned(), "0.1.0".to_owned()),
    ]);
    record_info(pool, a.runner, &info, Some(&harnesses), NOW)
        .await
        .unwrap();
    let all = fx.ok("/api/v1/runners").await;
    let r = &all[0];
    assert_eq!(r["harnesses"]["claude"], "2.1.306");
    assert_eq!(
        (r["slots"].clone(), r["last_slept_secs"].clone()),
        (json!(1), json!(7200))
    );
    assert_eq!(r["uptime_secs"], Value::Null, "offline: no uptime");
    assert_eq!(r["power_nap_applied"], true);
    assert_eq!(r["logins"][1]["account_ids"], json!([account]));
    assert_eq!(r["logins"][0]["account_ids"], json!([]));
    // Every harness against the tested versions (E3.6).
    let status = |name: &str| {
        let h = r["harness_status"].as_array().unwrap().iter();
        let h = h.clone().find(|h| h["name"] == name).unwrap().clone();
        (
            h["status"].clone(),
            h["offered"].clone(),
            h["reason"].clone(),
        )
    };
    assert_eq!(
        status("claude"),
        (json!("supported"), json!(true), Value::Null)
    );
    let note = "codex: untested version 9.0.0 (tested up to 0.154.0)";
    assert_eq!(
        status("codex"),
        (json!("untested_newer"), json!(true), json!(note))
    );
    assert_eq!(status("opencode").0, "too_old");
    assert_eq!(status("opencode").1, false);
    assert_eq!(status("agy"), (json!("missing"), json!(false), Value::Null));
    assert_eq!(r["harness_status"][0]["tested_up_to"], "2.1.306");
}

#[tokio::test]
async fn an_accounts_plan_tier_is_set_and_cleared() {
    let fx = fx().await;
    let new = json!({"harness": "claude", "label": "claude-a"});
    let id = fx.ok_post("/api/v1/accounts", new).await["id"]
        .as_i64()
        .unwrap();
    let uri = format!("/api/v1/accounts/{id}/plan");
    let put = |b: Value| send(&fx.app, req(Method::PUT, &uri, Some(&fx.key), Some(b)));
    let (status, a) = put(json!({"plan_tier": " Max 20x "})).await;
    assert_eq!(
        (status, a["plan_tier"].clone()),
        (StatusCode::OK, json!("Max 20x"))
    );
    let (status, _) = put(json!({"plan_tier": "x".repeat(65)})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, a) = put(json!({"plan_tier": null})).await;
    assert_eq!(a["plan_tier"], Value::Null);
    assert_eq!(audited(&fx.app.pool, "account.plan_set").await, 2);
    let usage = fx.ok("/api/v1/accounts/usage").await;
    assert_eq!(
        (
            usage[0]["drops_window_secs"].clone(),
            usage[0]["recent_drops_window_secs"].clone()
        ),
        (json!(600), json!(86_400)),
        "the unhealthy window and the display window are separate settings"
    );
}

#[tokio::test]
async fn every_error_carries_an_id_and_reads_are_not_audited() {
    let fx = fx().await;
    let (status, body) = fx.get("/api/v1/runs/99").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error_id"].as_str().unwrap().starts_with("err_"));
    let (_, again) = fx.get("/api/v1/runs/99").await;
    assert_ne!(body["error_id"], again["error_id"]);
    assert_eq!(
        audited(&fx.app.pool, "api.refused").await,
        0,
        "a read is no refused write"
    );
}
