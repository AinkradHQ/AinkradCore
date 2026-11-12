//! E6-2, E6-3, E6-4 (Core half): distillation, the per-room model policy and the Inbox.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::common::*;

const DOCS: &[(&str, &str)] = &[
    ("Billing", "we decided to export invoices as CSV"),
    ("Deploy", "the deploy runs on Fridays only"),
];

async fn distil(fx: &Fx, room: &str) -> (StatusCode, Value) {
    call(
        fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{room}/distil"),
        None,
    )
    .await
}

async fn count(fx: &Fx, table: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn item_ids(fx: &Fx, room: &str) -> Vec<String> {
    let p = canon_pool(fx, room).await;
    let v = sqlx::query_scalar("SELECT item_id FROM sources ORDER BY item_id")
        .fetch_all(&p)
        .await
        .unwrap();
    p.close().await;
    v
}

/// A distillation whose session already ended with `answer`, as the job would find it.
async fn ended_distil(fx: &Fx, room: &str, answer: &str) -> (String, String) {
    ended_distil_for(fx, room, answer, "dst-test").await
}

async fn ended_distil_for(fx: &Fx, room: &str, answer: &str, id: &str) -> (String, String) {
    let session = chain_session(fx, &["anthropic"]).await;
    let (st, v) = call(
        fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{room}/claims"),
        Some(json!({"session": session})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    for (seq, body) in [
        (
            1,
            json!({"type": "user", "message": {"role": "user", "content": "SECRET SOURCE TEXT"}}),
        ),
        (
            2,
            json!({"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": answer}]}}),
        ),
    ] {
        sqlx::query("INSERT INTO core_agent_transcript (session, user_id, seq, at, body) VALUES (?, 1, ?, 0, ?)")
            .bind(&session)
            .bind(seq)
            .bind(body.to_string())
            .execute(&fx.app.pool)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE core_agent_sessions SET state = 'ended' WHERE id = ?")
        .bind(&session)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let id = id.to_owned();
    sqlx::query("INSERT INTO brain_distils (id, room, state, session, requested_by, sources) VALUES (?, ?, 'running', ?, ?, 2)")
        .bind(&id)
        .bind(room)
        .bind(&session)
        .bind(&fx.admin.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let p = canon_pool(fx, room).await;
    sqlx::query("UPDATE sources SET distilled = ?")
        .bind(&id)
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
    (id, session)
}

fn answer(ids: &[String]) -> String {
    json!({"candidates": [
        {"type": "decision", "body": "Invoices are exported as CSV.", "tags": ["billing"], "sources": [ids[0]]},
        {"type": "preference", "body": "Deploy only on Fridays.", "sources": [ids[1]]},
    ]})
    .to_string()
}

#[tokio::test]
async fn a_local_only_room_waits_for_a_local_model_and_never_claims_a_cloud_account() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    ok(
        &fx,
        Method::PATCH,
        &format!("/rooms/{room}/policy"),
        Some(json!({"model": "local_only"})),
    )
    .await;
    // Even with an approved cloud chain bound, the room does not take it.
    bind_distil_chain(&fx, make_chain(&fx, &["anthropic"]).await).await;
    let (st, v) = distil(&fx, &room).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["state"], "needs_local_model");
    assert!(v["detail"].as_str().unwrap().contains("anthropic"), "{v}");
    assert_eq!(count(&fx, "brain_session_rooms").await, 0);
    assert_eq!(count(&fx, "core_agent_sessions").await, 0);
    // A second request while it waits is refused, not queued twice.
    assert_eq!(distil(&fx, &room).await.1["code"], "distil_open");
}

#[tokio::test]
async fn a_cloud_room_waits_with_the_reason_when_it_cannot_start() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    // No chain bound or default: no runner-login fallback.
    let v = distil(&fx, &room).await.1;
    assert_eq!(v["state"], "waiting");
    assert!(
        v["detail"].as_str().unwrap().contains("no fallback chain"),
        "{v}"
    );
    // A chain with an entry outside the policy names it.
    bind_distil_chain(&fx, make_chain(&fx, &["anthropic", "openai"]).await).await;
    fx.brain.distil_step().await.unwrap();
    let l = ok(&fx, Method::GET, &format!("/rooms/{room}/distils"), None).await;
    assert_eq!(l[0]["state"], "waiting");
    assert!(l[0]["detail"].as_str().unwrap().contains("entry 2"), "{l}");
    // An approved chain passes the check and then waits for a runner.
    bind_distil_chain(&fx, make_chain(&fx, &["anthropic"]).await).await;
    fx.brain.distil_step().await.unwrap();
    let l = ok(&fx, Method::GET, &format!("/rooms/{room}/distils"), None).await;
    assert_eq!(l[0]["detail"], "no runner is online");
    assert_eq!(count(&fx, "core_agent_sessions").await, 0);
}

#[tokio::test]
async fn a_valid_answer_becomes_candidates_linked_to_sources_and_the_core_keeps_a_placeholder() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    let ids = item_ids(&fx, &room).await;
    let (_, session) = ended_distil(&fx, &room, &answer(&ids)).await;
    fx.brain.distil_step().await.unwrap();
    let l = ok(&fx, Method::GET, &format!("/rooms/{room}/distils"), None).await;
    assert_eq!(
        (l[0]["state"].as_str(), l[0]["candidates"].as_i64()),
        (Some("done"), Some(2)),
        "{l}"
    );
    ok(&fx, Method::POST, &format!("/rooms/{room}/open"), None).await;
    let inbox = ok(&fx, Method::GET, &format!("/rooms/{room}/inbox"), None).await;
    let items = inbox["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(
        items
            .iter()
            .all(|c| c["status"] == "candidate" && !c["sources"].as_array().unwrap().is_empty())
    );
    // The answer is in the room; the Core's transcript and first message are placeholders.
    let p = canon_pool(&fx, &room).await;
    let kept: String =
        sqlx::query_scalar("SELECT detail FROM room_audit WHERE action = 'distil.answer'")
            .fetch_one(&p)
            .await
            .unwrap();
    assert!(kept.contains("Invoices are exported as CSV."));
    p.close().await;
    let bodies: Vec<String> =
        sqlx::query_scalar("SELECT body FROM core_agent_transcript WHERE session = ?")
            .bind(&session)
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    assert!(
        bodies.iter().all(|b| b == r#"{"sealed":true}"#),
        "{bodies:?}"
    );
    let prompt: Option<String> =
        sqlx::query_scalar("SELECT prompt FROM core_agent_sessions WHERE id = ?")
            .bind(&session)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(prompt, None);
    // The sources were read: a second request has nothing new.
    assert_eq!(distil(&fx, &room).await.1["code"], "nothing_new");
}

#[tokio::test]
async fn an_invalid_answer_is_rejected_and_stores_nothing() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    let ids = item_ids(&fx, &room).await;
    // The second candidate cites a source that was never read.
    let bad = json!({"candidates": [
        {"type": "fact", "body": "ok", "sources": [ids[0]]},
        {"type": "fact", "body": "made up", "sources": ["01JDNOTASOURCE"]},
    ]})
    .to_string();
    ended_distil(&fx, &room, &bad).await;
    fx.brain.distil_step().await.unwrap();
    let l = ok(&fx, Method::GET, &format!("/rooms/{room}/distils"), None).await;
    assert_eq!(l[0]["state"], "failed");
    assert!(
        l[0]["detail"]
            .as_str()
            .unwrap()
            .starts_with("answer rejected"),
        "{l}"
    );
    let p = canon_pool(&fx, &room).await;
    let records: i64 = sqlx::query_scalar("SELECT count(*) FROM records")
        .fetch_one(&p)
        .await
        .unwrap();
    let audit: i64 =
        sqlx::query_scalar("SELECT count(*) FROM room_audit WHERE action = 'distil.answer'")
            .fetch_one(&p)
            .await
            .unwrap();
    let still_marked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sources WHERE distilled IS NOT NULL")
            .fetch_one(&p)
            .await
            .unwrap();
    p.close().await;
    // Nothing of the answer is kept, and the sources are free to be read again.
    assert_eq!((records, audit, still_marked), (0, 0, 0));
}

#[tokio::test]
async fn the_inbox_accepts_edits_and_rejects_and_auto_accept_is_off_until_set() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    let ids = item_ids(&fx, &room).await;
    ended_distil(&fx, &room, &answer(&ids)).await;
    fx.brain.distil_step().await.unwrap();
    // Closed room: the Inbox is as private as the room.
    let (st, v) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/rooms/{room}/inbox"),
        None,
    )
    .await;
    assert_eq!(
        (st, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("room_closed"))
    );
    ok(&fx, Method::POST, &format!("/rooms/{room}/open"), None).await;
    let inbox = ok(&fx, Method::GET, &format!("/rooms/{room}/inbox"), None).await;
    assert_eq!(inbox["waiting"], 2);
    let (a, b) = (
        inbox["items"][0]["id"].as_str().unwrap(),
        inbox["items"][1]["id"].as_str().unwrap(),
    );
    let v = ok(
        &fx,
        Method::POST,
        &format!("/rooms/{room}/inbox/{a}"),
        Some(json!({"action": "accept"})),
    )
    .await;
    assert_eq!(v["status"], "accepted");
    let v = ok(
        &fx,
        Method::POST,
        &format!("/rooms/{room}/inbox/{b}"),
        Some(json!({"action": "edit", "body": "Deploy on Fridays, never Mondays."})),
    )
    .await;
    assert_eq!(
        (v["status"].as_str(), v["body"].as_str()),
        (Some("accepted"), Some("Deploy on Fridays, never Mondays."))
    );
    // Decided already: a second decision is a conflict.
    let (st, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{room}/inbox/{a}"),
        Some(json!({"action": "reject"})),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(
        ok(&fx, Method::GET, &format!("/rooms/{room}/inbox"), None).await["waiting"],
        0
    );
    // Nothing is ever deleted: a reject keeps the record as rejected.
    let p = canon_pool(&fx, &room).await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM records")
        .fetch_one(&p)
        .await
        .unwrap();
    let ops: i64 = sqlx::query_scalar("SELECT count(*) FROM op_log WHERE op LIKE 'record.%'")
        .fetch_one(&p)
        .await
        .unwrap();
    p.close().await;
    assert_eq!(n, 2);
    assert!(ops >= 4, "{ops}");

    // Auto-accept: off by default; once `preference` is on, a preference lands accepted, a decision waits.
    let room2 = committed_room_named(
        &fx,
        "Beta",
        &[
            ("Notes", "we prefer small pull requests"),
            ("Chat", "the retro is on Thursdays"),
        ],
    )
    .await;
    assert_eq!(
        ok(&fx, Method::GET, &format!("/rooms/{room2}/policy"), None).await["auto_accept"],
        json!([])
    );
    ok(
        &fx,
        Method::PATCH,
        &format!("/rooms/{room2}/policy"),
        Some(json!({"auto_accept": ["preference"]})),
    )
    .await;
    let ids2 = item_ids(&fx, &room2).await;
    ended_distil_for(&fx, &room2, &answer(&ids2), "dst-two").await;
    fx.brain.distil_step().await.unwrap();
    ok(&fx, Method::POST, &format!("/rooms/{room2}/open"), None).await;
    let inbox = ok(&fx, Method::GET, &format!("/rooms/{room2}/inbox"), None).await;
    assert_eq!(inbox["waiting"], 1);
    assert_eq!(inbox["items"][0]["type"], "decision");
    let p = canon_pool(&fx, &room2).await;
    let auto: String =
        sqlx::query_scalar("SELECT decided_by FROM records WHERE type = 'preference'")
            .fetch_one(&p)
            .await
            .unwrap();
    p.close().await;
    assert_eq!(auto, "auto");
}
