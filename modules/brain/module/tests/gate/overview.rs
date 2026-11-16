//! The room Overview through the Core's gate: a fake provider is an AI session that already ended
//! with a canned answer, as in the distillation tests. Every item is made up.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::common::*;

const DOCS: &[(&str, &str)] = &[
    (
        "Billing",
        "we export invoices as CSV\nAlways run the linter before you push.",
    ),
    (
        "Deploy",
        "the deploy runs on Fridays\nNever deploy without a tagged release.",
    ),
];

async fn write(fx: &Fx, room: &str) -> (StatusCode, Value) {
    call(
        fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{room}/overview/write"),
        None,
    )
    .await
}

async fn get(fx: &Fx, room: &str) -> Value {
    ok(fx, Method::GET, &format!("/rooms/{room}/overview"), None).await
}

async fn sessions(fx: &Fx) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM core_agent_sessions")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn ids(fx: &Fx, room: &str) -> Vec<String> {
    let p = canon_pool(fx, room).await;
    let v = sqlx::query_scalar("SELECT item_id FROM sources ORDER BY item_id")
        .fetch_all(&p)
        .await
        .unwrap();
    p.close().await;
    v
}

/// The room's overview write as the job would find it: running, its session ended with `answer`.
async fn ended(fx: &Fx, room: &str, answer: &str, attempt: i64) {
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
            json!({"type": "user", "message": {"role": "user", "content": "x"}}),
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
    sqlx::query("INSERT OR REPLACE INTO brain_overview_queue (room, batch, state, attempt, session, requested_by, created_at, updated_at) VALUES (?, 'b', 'running', ?, ?, ?, 'x', 'x')")
        .bind(room)
        .bind(attempt)
        .bind(&session)
        .bind(&fx.admin.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let p = canon_pool(fx, room).await;
    sqlx::query("INSERT OR IGNORE INTO room_overview (id, updated_at) VALUES (1, 'x')")
        .execute(&p)
        .await
        .unwrap();
    sqlx::query("UPDATE room_overview SET selection = ?, state = 'writing' WHERE id = 1")
        .bind(json!(ids(fx, room).await).to_string())
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
}

fn good(ids: &[String]) -> String {
    json!({
        "summary": "A billing and deploy project.",
        "facts": {"stack": "Rust", "state": "active", "last_activity": "today"},
        "rules": {
            "workflow": [{"text": "Tag a release before deploying.", "sources": [ids[1], "not-an-item"]}],
            "code": [{"text": "Run the linter before you push.", "sources": [ids[0]]}],
            "design": [],
            "never": [{"text": "Never invent sources.", "sources": ["not-an-item"]}]
        },
        "instructions": "Run the linter. Tag releases."
    })
    .to_string()
}

#[tokio::test]
async fn cloud_off_and_no_account_call_nothing() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    assert_eq!(get(&fx, &room).await["state"], "not_written");
    // No chain bound: needs an account, and no session was made.
    let (st, v) = write(&fx, &room).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["state"], "needs_account");
    assert_eq!(sessions(&fx).await, 0);
    // Cloud off wins even with an approved chain bound.
    bind_distil_chain(&fx, make_chain(&fx, &["anthropic"]).await).await;
    ok(
        &fx,
        Method::PATCH,
        &format!("/rooms/{room}/policy"),
        Some(json!({"model": "local_only"})),
    )
    .await;
    let (st, v) = write(&fx, &room).await;
    assert_eq!(
        (st, v["state"].as_str()),
        (StatusCode::OK, Some("cloud_off"))
    );
    assert_eq!(sessions(&fx).await, 0);
    assert_eq!(
        ok(&fx, Method::GET, "/overview/progress", None).await["total"],
        0
    );
}

#[tokio::test]
async fn an_account_queues_it_and_one_open_write_blocks_another() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    bind_distil_chain(&fx, make_chain(&fx, &["anthropic"]).await).await;
    let (st, v) = write(&fx, &room).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["state"], "writing");
    assert_eq!(v["progress"]["total"], 1);
    assert_eq!(write(&fx, &room).await.1["code"], "overview_open");
}

#[tokio::test]
async fn a_good_answer_is_stored_with_unseen_sources_dropped_and_instructions_round_trip() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    let ids = ids(&fx, &room).await;
    ended(&fx, &room, &good(&ids), 1).await;
    fx.brain.overview_step().await.unwrap();
    let v = get(&fx, &room).await;
    assert_eq!(v["state"], "written", "{v}");
    assert_eq!(
        v["overview"]["rules"]["workflow"][0]["sources"],
        json!([ids[1]])
    );
    assert_eq!(
        v["overview"]["rules"]["never"],
        json!([]),
        "a rule with no shown source is dropped"
    );
    assert_eq!(v["overview"]["rules"]["code"].as_array().unwrap().len(), 1);
    assert_eq!(v["instructions"], "Run the linter. Tag releases.");
    assert!(v["instructions_approved_at"].is_null());
    assert!(v["written_at"].is_string());
    // Edit and approve; a plain edit later withdraws the approval.
    let url = format!("/rooms/{room}/overview/instructions");
    let p = |b: Value| ok(&fx, Method::PATCH, &url, Some(b));
    let v = p(json!({"text": "Lint first.", "approved": true})).await;
    assert_eq!(v["instructions"], "Lint first.");
    assert!(v["instructions_approved_at"].is_string());
    let v = get(&fx, &room).await;
    assert_eq!(v["instructions"], "Lint first.");
    let v = p(json!({"text": "Lint, then test.", "approved": false})).await;
    assert!(v["instructions_approved_at"].is_null());
    // A new write keeps an approved text of the person's.
    p(json!({"approved": true})).await;
    ended(&fx, &room, &good(&ids), 1).await;
    fx.brain.overview_step().await.unwrap();
    assert_eq!(get(&fx, &room).await["instructions"], "Lint, then test.");
}

#[tokio::test]
async fn invalid_json_is_retried_once_then_fails() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    ended(&fx, &room, "I think the project is nice.", 1).await;
    fx.brain.overview_step().await.unwrap();
    let a: (String, i64) =
        sqlx::query_as("SELECT state, attempt FROM brain_overview_queue WHERE room = ?")
            .bind(&room)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(a, ("queued".to_owned(), 2), "one retry is queued");
    assert_eq!(get(&fx, &room).await["state"], "writing");
    ended(&fx, &room, "{\"summary\":", 2).await;
    fx.brain.overview_step().await.unwrap();
    let v = get(&fx, &room).await;
    assert_eq!(v["state"], "failed", "{v}");
    assert!(v["detail"].as_str().unwrap().contains("rejected"));
    assert!(v["overview"].is_null());
    assert_eq!(v["progress"]["failed"], 1);
}

#[tokio::test]
async fn instructions_need_an_overview_first() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    let (st, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/rooms/{room}/overview/instructions"),
        Some(json!({"approved": true})),
    )
    .await;
    assert_eq!(
        (st, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("not_written"))
    );
}
