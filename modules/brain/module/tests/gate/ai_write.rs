//! E6: `brain.propose` through the Code Mode dispatcher. It is a `write` (nothing it does is
//! accepted without a person), so it needs no approval; it lands in the Inbox as a candidate, a
//! retry returns the first result, and a room the session cannot see is an unknown one.

use ainkrad_core_server::ops_catalog::pending;
use axum::http::Method;
use serde_json::json;

use super::ai::{ALPHA, op, open_room, session};
use super::common::*;

#[tokio::test]
async fn an_ai_proposal_through_the_dispatcher_waits_in_the_inbox_and_a_retry_adds_nothing() {
    let fx = fx().await;
    let room = committed_room_named(&fx, "Alpha", &[("A", "alpha text")]).await;
    open_room(&fx, &room).await;
    // Even a room that auto-accepts decisions does not accept an AI session's.
    ok(
        &fx,
        Method::PATCH,
        &format!("/rooms/{room}/policy"),
        Some(json!({"auto_accept": ["decision"]})),
    )
    .await;
    let s = session(&fx, ALPHA, &["anthropic"]).await;
    // A proposal is an `agent` route: the creator device needs that scope, a session never gets more.
    sqlx::query("UPDATE core_devices SET scopes = '[\"admin\",\"read\",\"agent\"]' WHERE id = ?")
        .bind(&fx.admin.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let args = json!({"room": room, "body": {"type": "decision", "body": "Use SQLite for the cache.", "tags": ["db"]}});
    let (ok_, first, code) = op(&fx, &s, "brainAiPropose", args.clone()).await;
    assert!(ok_, "{code}");
    assert_eq!(
        (first["status"].as_str(), first["duplicate"].as_bool()),
        (Some("candidate"), Some(false))
    );
    // No approval was needed or asked for: it is a write, not a risky one.
    assert!(pending(&fx.app, &s).await.unwrap().is_empty());

    // The script sent it again: the first result, the Inbox unchanged.
    let (ok_, again, _) = op(&fx, &s, "brainAiPropose", args).await;
    assert!(ok_);
    assert_eq!(again, json!({"replayed": true, "result": first}));
    let inbox = ok(&fx, Method::GET, &format!("/rooms/{room}/inbox"), None).await;
    let items = inbox["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{inbox}");
    assert_eq!(
        (items[0]["status"].as_str(), items[0]["proposed_by"].as_str()),
        (Some("candidate"), Some(s.as_str()))
    );
    // Never in the Brain: no accepted record exists for a read to find.
    let d = op(&fx, &s, "brainAiDecisions", json!({})).await.1;
    assert!(d["records"].as_array().unwrap().is_empty());

    // A room this session cannot see is an unknown one, and nothing lands anywhere.
    let other = committed_room_named(&fx, "Beta", &[("B", "beta text")]).await;
    open_room(&fx, &other).await;
    let args = json!({"room": other, "body": {"type": "fact", "body": "Sneaked in."}});
    let (ok_, _, code) = op(&fx, &s, "brainAiPropose", args).await;
    assert!(!ok_ && code == "not_found", "{code}");
    let inbox = ok(&fx, Method::GET, &format!("/rooms/{other}/inbox"), None).await;
    assert!(inbox["items"].as_array().unwrap().is_empty());

    // The dispatcher's own row: a write, ok, rooted in the session, no text in it.
    let rows: Vec<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT origin, origin_ref, details FROM audit_events WHERE action = 'code_mode.call' \
         AND details LIKE '%brainAiPropose%' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 3, "{rows:?}");
    for (origin, oref, details) in &rows {
        assert_eq!((origin.as_str(), oref.as_deref()), ("ai_session", Some(s.as_str())));
        assert!(details.contains("\"project\":\"Alpha\"") && details.contains("\"risk\":\"write\"") && !details.contains("SQLite"), "{details}");
    }
}
