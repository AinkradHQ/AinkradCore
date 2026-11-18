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

/// What the gate offers by default: one candidate per item, `c1` for the first.
async fn offered(fx: &Fx, room: &str) -> Value {
    let rules: Vec<Value> = ids(fx, room)
        .await
        .iter()
        .enumerate()
        .map(|(n, id)| json!({"id": format!("c{}", n + 1), "text": "t", "items": [id], "doc": false}))
        .collect();
    json!({"rules": rules, "min_sources": 1})
}

/// The room's overview write as the job would find it: running, its session ended with `answer`.
async fn ended(fx: &Fx, room: &str, answer: &str, attempt: i64) {
    let o = offered(fx, room).await;
    ended_with(fx, room, answer, attempt, &o).await;
}

/// As `ended`, with the candidates `offered` stored as the selection.
async fn ended_with(fx: &Fx, room: &str, answer: &str, attempt: i64, offered: &Value) {
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
        (1, json!({"type": "message", "text": "x"})),
        // The Core's stored shape: the model's words come as text blocks, often a line first.
        (
            2,
            json!({"type": "assistant_text", "text": "Here is the answer."}),
        ),
        (3, json!({"type": "assistant_text", "text": answer})),
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
        .bind(offered.to_string())
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
}

fn good() -> String {
    json!({
        "summary": "A billing and deploy project.",
        "facts": {"stack": "Rust", "state": "active", "last_activity": "today"},
        "rules": {
            "workflow": [{"text": "Tag a release before deploying.", "candidates": ["c2", "not-offered"]}],
            "code": [{"text": "Run the linter before you push.", "candidates": ["c1"]}],
            "design": [],
            "never": [{"text": "Never invent sources.", "candidates": ["not-offered"]}]
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
async fn a_good_answer_is_stored_with_counted_sources_and_instructions_round_trip() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    let ids = ids(&fx, &room).await;
    ended(&fx, &room, &good(), 1).await;
    fx.brain.overview_step().await.unwrap();
    let v = get(&fx, &room).await;
    assert_eq!(v["state"], "written", "{v}");
    assert_eq!(
        v["overview"]["rules"]["workflow"][0]["sources"],
        json!([ids[1]])
    );
    assert!(
        v["source_titles"][ids[1].as_str()].is_string(),
        "a cited item has its title: {v}"
    );
    assert_eq!(
        v["overview"]["rules"]["never"],
        json!([]),
        "a rule with no offered candidate is dropped"
    );
    assert_eq!(v["overview"]["rules"]["code"].as_array().unwrap().len(), 1);
    // Built from the rules that passed, not the model's own text.
    assert_eq!(
        v["instructions"],
        "- Tag a release before deploying.\n- Run the linter before you push."
    );
    assert!(v["instructions_approved_at"].is_null());
    assert!(v["written_at"].is_string());
    // `State` and `Last activity` come from the items' dates (the newest made-up one is 2026-11-07),
    // never from the model's "active" / "today".
    let f = &v["overview"]["facts"];
    assert!(
        f["last_activity"]
            .as_str()
            .unwrap()
            .starts_with("2026-11-07 ("),
        "{f}"
    );
    assert_ne!(f["last_activity"], "today");
    assert!(
        matches!(f["state"].as_str(), Some("active" | "quiet" | "dormant")),
        "{f}"
    );
    assert_eq!(f["stack"], "Rust", "the stack is still the model's");
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
    ended(&fx, &room, &good(), 1).await;
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

async fn session_of(fx: &Fx, room: &str) -> String {
    sqlx::query_scalar("SELECT session FROM brain_overview_queue WHERE room = ?")
        .bind(room)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_write_starts_at_once_and_shows_its_stage() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    assert!(get(&fx, &room).await["stage"].is_null());
    bind_distil_chain(&fx, make_chain(&fx, &["anthropic"]).await).await;
    // The POST answers with the first stage and queues the start itself: no wait for the job.
    let (st, v) = write(&fx, &room).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["state"], "writing");
    assert!(v["stage_since"].is_string(), "{v}");
    assert!(
        ["queued", "waiting_runner"].contains(&v["stage"].as_str().unwrap()),
        "{v}"
    );
    // No runner is online in the gate: the started write says so.
    let mut v = get(&fx, &room).await;
    for _ in 0..100 {
        if v["stage"] == "waiting_runner" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        v = get(&fx, &room).await;
    }
    assert_eq!(v["stage"], "waiting_runner", "{v}");
    assert!(v["picked"].is_null());
    let since = v["stage_since"].clone();
    fx.brain.overview_step().await.unwrap();
    assert_eq!(
        get(&fx, &room).await["stage_since"],
        since,
        "the same stage keeps its start time"
    );
}

#[tokio::test]
async fn the_stage_follows_the_session_to_reading_and_clears_when_written() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    ended(&fx, &room, &good(), 1).await;
    let s = session_of(&fx, &room).await;
    let set = |state: &'static str| {
        let s = s.clone();
        let pool = fx.app.pool.clone();
        async move {
            sqlx::query("UPDATE core_agent_sessions SET state = ? WHERE id = ?")
                .bind(state)
                .bind(s)
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    set("starting").await;
    fx.brain.overview_step().await.unwrap();
    let v = get(&fx, &room).await;
    assert_eq!(v["stage"], "starting", "{v}");
    let since = v["stage_since"].clone();
    assert!(since.is_string());
    set("running").await;
    fx.brain.overview_step().await.unwrap();
    let v = get(&fx, &room).await;
    assert_eq!(v["stage"], "writing", "{v}");
    assert_ne!(v["stage_since"], Value::Null);
    set("ended").await;
    fx.brain.overview_step().await.unwrap();
    let v = get(&fx, &room).await;
    assert_eq!(v["state"], "written", "{v}");
    for k in ["stage", "stage_since", "picked"] {
        assert!(v[k].is_null(), "{k} clears once written: {v}");
    }
}

#[tokio::test]
async fn a_rejected_answer_shows_retrying_and_a_failure_clears_the_stage() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    ended(&fx, &room, "not json", 1).await;
    fx.brain.overview_step().await.unwrap();
    let v = get(&fx, &room).await;
    assert_eq!(
        (v["state"].as_str(), v["stage"].as_str()),
        (Some("writing"), Some("retrying")),
        "{v}"
    );
    ended(&fx, &room, "{\"summary\":", 2).await;
    fx.brain.overview_step().await.unwrap();
    let v = get(&fx, &room).await;
    assert_eq!(v["state"], "failed", "{v}");
    assert!(v["stage"].is_null() && v["stage_since"].is_null());
}

/// The owner's case, through the room's own selection (made-up text): an AGENTS.md states three
/// conventions, session prompts repeat one of them twice among one-off orders. The overview keeps
/// the three and the repeated one; its sources are the two items counted, not what the model cited.
#[tokio::test]
async fn documentation_leads_and_support_is_counted_not_cited() {
    let fx = fx().await;
    let mut texts: Vec<(String, String)> = vec![
        ("AGENTS.md".into(), "# Conventions\n- Open every PR against the development branch.\n- Keep controllers thin; business logic lives in app/Actions.\n- Never commit secrets or .env files.".into()),
        ("fix login".into(), "User: always run the test suite before you push.\nMerge #312 now, it is billing-blocked until then.".into()),
        ("tidy".into(), "User: Always run the test suite before you push!\nDon't touch the billing code until 2026-12-01.".into()),
        ("plan".into(), "User: you must read docs/plan.md first and do step 3".into()),
    ];
    texts.extend((0..20).map(|i| {
        (
            format!("chat {i}"),
            format!("we talked about widget {i} today"),
        )
    }));
    let refs: Vec<(&str, &str)> = texts
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let room = committed_room(&fx, &refs).await;
    let p = canon_pool(&fx, &room).await;
    let sel = brain_module::overview_select::select(&fx.brain, &p, vec![])
        .await
        .unwrap();
    p.close().await;
    let offered = &sel.offered.rules;
    let texts: Vec<&str> = offered.iter().map(|r| r.text.as_str()).collect();
    assert_eq!(texts.len(), 4, "{texts:?}");
    assert!(
        texts
            .iter()
            .all(|t| !t.contains("#312") && !t.contains("2026") && !t.contains("plan.md"))
    );
    let repeated = offered
        .iter()
        .find(|r| r.text.contains("test suite"))
        .unwrap();
    assert_eq!(repeated.items.len(), 2);
    let doc_id = &offered[0].items[0];
    assert!(
        sel.items.first().is_some_and(|i| &i.0 == doc_id),
        "the doc is the first excerpt"
    );
    // The model picks every candidate and adds a one-off; it cites one id per rule.
    let pick =
        |r: &brain_module::overview_write::Shown| json!({"text": r.text, "candidates": [r.id]});
    let answer = json!({
        "summary": "A made-up web shop.",
        "rules": {
            "workflow": offered.iter().map(pick).chain([json!({"text": "Merge #312 now.", "candidates": [repeated.id]})]).collect::<Vec<_>>(),
        }
    })
    .to_string();
    ended_with(&fx, &room, &answer, 1, &json!(sel.offered)).await;
    fx.brain.overview_step().await.unwrap();
    let v = get(&fx, &room).await;
    assert_eq!(v["state"], "written", "{v}");
    let kept = v["overview"]["rules"]["workflow"].as_array().unwrap();
    assert_eq!(kept.len(), 4, "{v}");
    let r = kept
        .iter()
        .find(|r| r["text"].as_str().unwrap().contains("test suite"))
        .unwrap();
    assert_eq!(r["sources"], json!(repeated.items));
    assert_eq!(v["instructions"].as_str().unwrap().lines().count(), 4);
}
