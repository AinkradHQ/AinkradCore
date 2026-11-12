//! E6-1 and E6-3: a session claims a room only when its whole fallback chain is inside the room's
//! model policy; a local-only room never claims a cloud account.

use axum::http::{Method, StatusCode};
use serde_json::json;

use super::common::*;

async fn claim(fx: &Fx, room: &str, session: &str) -> (StatusCode, serde_json::Value) {
    call(
        fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{room}/claims"),
        Some(json!({"session": session})),
    )
    .await
}

#[tokio::test]
async fn a_cloud_room_claims_a_chain_of_approved_providers() {
    let fx = fx().await;
    let room = committed_room(&fx, &[("A", "alpha text")]).await;
    let s = chain_session(&fx, &["anthropic", "claude-sub"]).await;
    let (st, v) = claim(&fx, &room, &s).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["entries"], 2);
    // One claim per session.
    let (st, v) = claim(&fx, &room, &s).await;
    assert_eq!(
        (st, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("already_claimed"))
    );
}

#[tokio::test]
async fn one_entry_outside_the_policy_refuses_the_whole_claim_and_names_it() {
    let fx = fx().await;
    let room = committed_room(&fx, &[("A", "alpha text")]).await;
    // The first entry is fine; the fallback behind it is not.
    let s = chain_session(&fx, &["anthropic", "openai"]).await;
    let (st, v) = claim(&fx, &room, &s).await;
    assert_eq!(
        (st, v["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("claim_refused"))
    );
    let why = v["message"].as_str().unwrap();
    assert!(why.contains("entry 2") && why.contains("openai"), "{why}");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_session_rooms")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn a_session_without_a_chain_never_falls_back_to_the_runner_login() {
    let fx = fx().await;
    let room = committed_room(&fx, &[("A", "alpha text")]).await;
    let now = fx.app.clock.now();
    let policy = json!({"mode": "ask"});
    let new = ainkrad_core_server::store::agents::NewSession {
        runner: &fx.admin.id,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.admin.id,
    };
    let plain = ainkrad_core_server::store::agents::create_owned_ref(
        &fx.app.pool,
        &new,
        None,
        None,
        ainkrad_core_server::api::v1::BY,
        &now,
    )
    .await
    .unwrap();
    let (st, v) = claim(&fx, &room, &plain.id).await;
    assert_eq!(
        (st, v["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("claim_refused"))
    );
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("runner's own login")
    );
}

#[tokio::test]
async fn a_local_only_room_never_claims_a_cloud_account() {
    let fx = fx().await;
    let room = committed_room(&fx, &[("A", "alpha text")]).await;
    let v = ok(
        &fx,
        Method::PATCH,
        &format!("/rooms/{room}/policy"),
        Some(json!({"model": "local_only"})),
    )
    .await;
    assert_eq!(v["model"], "local_only");
    for chain in [&["anthropic"][..], &["claude-sub", "google"][..]] {
        let s = chain_session(&fx, chain).await;
        let (st, v) = claim(&fx, &room, &s).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(v["code"], "claim_refused");
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_session_rooms")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    // Back to cloud: the same chain is now fine.
    ok(
        &fx,
        Method::PATCH,
        &format!("/rooms/{room}/policy"),
        Some(json!({"model": "cloud"})),
    )
    .await;
    let s = chain_session(&fx, &["anthropic"]).await;
    assert_eq!(claim(&fx, &room, &s).await.0, StatusCode::OK);
}

#[tokio::test]
async fn a_started_session_cannot_claim_and_policy_defaults_are_off() {
    let fx = fx().await;
    let room = committed_room(&fx, &[("A", "alpha text")]).await;
    let p = ok(&fx, Method::GET, &format!("/rooms/{room}/policy"), None).await;
    assert_eq!(p["model"], "cloud");
    assert_eq!(p["auto_accept"], json!([]));
    let s = chain_session(&fx, &["anthropic"]).await;
    sqlx::query("UPDATE core_agent_sessions SET state = 'running' WHERE id = ?")
        .bind(&s)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let (st, v) = claim(&fx, &room, &s).await;
    assert_eq!(
        (st, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("session_started"))
    );
    // Policy widening and unknown kinds are refused.
    let (st, _) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/rooms/{room}/policy"),
        Some(json!({"auto_accept": ["decision"]})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}
