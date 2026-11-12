//! Live AI sessions (N41) at the Core's routes and store, without a runner: the state a client
//! sees (`waiting`) follows what the runner says and never goes back on a late answer, a message
//! to a session whose harness is gone is kept for the supervisor and titles the session, a title
//! can be set, a create may carry no first message, and a session nobody comes back to ends.
//! The runner end to end is `tests/hub/live.rs`.

use ainkrad_proto::v2::{AgentEvents, AgentState, TranscriptEntry};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::store::agents::{self as store, NewSession};

async fn call(fx: &Fx, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(&fx.dev), body)).await
}

/// A live session of the admin device, running on its runner.
async fn live(fx: &Fx, vm: &str, state: &str) -> store::Session {
    let policy = json!({});
    let new = NewSession {
        runner: vm,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let sys = ainkrad_core::audit::AuditActor::System;
    let s = store::create(&fx.app.pool, &new, sys, NOW).await.unwrap();
    store::configure(&fx.app.pool, &s.id, true, None)
        .await
        .unwrap();
    if state != "starting" {
        store::set_state(&fx.app.pool, &s.id, state, "test", false, NOW)
            .await
            .unwrap();
    }
    store::get(&fx.app.pool, &s.id).await.unwrap().unwrap()
}

fn answer(s: &store::Session, state: AgentState, seq: u64, body: Value) -> AgentEvents {
    AgentEvents {
        session: s.id.clone(),
        state,
        last_seq: seq,
        entries: vec![TranscriptEntry { seq, at: 1, body }],
        harness_session: None,
        usage: None,
        outcome: None,
        gateway: vec![],
        plan_limit: None,
    }
}

fn uri(s: &store::Session, tail: &str) -> String {
    format!("/api/v1/agent-sessions/{}{tail}", s.id)
}

#[tokio::test]
async fn a_live_session_is_waiting_between_answers_and_a_late_answer_does_not_undo_it() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = live(&fx, &vm.id, "running").await;
    let shown = fx.ok(&uri(&s, "")).await;
    assert_eq!(
        (shown["state"].as_str(), shown["live"].as_bool()),
        (Some("running"), Some(true))
    );
    assert!(shown["idle_since"].is_null());

    let now = fx.clock.now();
    let idle = answer(&s, AgentState::Waiting, 1, json!({"type": "waiting"}));
    store::apply(&fx.app.pool, &s.id, &idle, &now)
        .await
        .unwrap();
    let shown = fx.ok(&uri(&s, "")).await;
    assert_eq!(shown["state"], "waiting");
    assert_eq!(shown["idle_since"], "2026-10-22T10:00:00.000Z");
    let t = fx.ok(&uri(&s, "/transcript")).await;
    assert_eq!(t["state"], "waiting");

    // An answer to an older read (it saw nothing past seq 0) cannot turn it back.
    let stale = AgentEvents {
        entries: vec![],
        last_seq: 0,
        ..answer(&s, AgentState::Running, 0, json!({}))
    };
    store::apply(&fx.app.pool, &s.id, &stale, &now)
        .await
        .unwrap();
    assert_eq!(fx.ok(&uri(&s, "")).await["state"], "waiting");

    // The next message starts an answer: running again.
    let busy = answer(
        &s,
        AgentState::Running,
        2,
        json!({"type": "message", "text": "x"}),
    );
    store::apply(&fx.app.pool, &s.id, &busy, &now)
        .await
        .unwrap();
    let shown = fx.ok(&uri(&s, "")).await;
    assert_eq!(shown["state"], "running");
    assert!(shown["idle_since"].is_null());

    // The events a client follows: waiting (turn_ended), then running (message).
    let states: Vec<String> = sqlx::query_scalar(
        "SELECT json_extract(payload, '$.state') || ':' || json_extract(payload, '$.reason') \
         FROM events WHERE kind = 'agent.state' AND payload LIKE '%turn_ended%' \
         OR kind = 'agent.state' AND payload LIKE '%\"message\"%' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(states, ["waiting:turn_ended", "running:message"]);
}

#[tokio::test]
async fn a_message_to_a_session_with_no_harness_is_kept_titles_it_and_wakes_its_supervisor() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let msg = |text: &str| json!({"text": text});
    // Not on its runner yet: refused, nothing kept.
    let starting = live(&fx, &vm.id, "starting").await;
    let r = call(&fx, Method::POST, &uri(&starting, "/messages"), msg("hi")).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("session_starting"))
    );

    // Its runner restarted: the message is kept for the supervisor, and is the session's title.
    let s = live(&fx, &vm.id, "interrupted").await;
    let text =
        "fix the flaky test in the billing module, then run the whole suite again and tell me";
    let r = call(&fx, Method::POST, &uri(&s, "/messages"), msg(text)).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    let row = store::get(&fx.app.pool, &s.id).await.unwrap().unwrap();
    assert_eq!(row.pending.as_deref(), Some(text));
    assert_eq!(row.state, "interrupted");
    assert_eq!(row.title.as_deref(), Some(&text[..60]));
    assert_eq!(r.1["title"], text[..60]);
    // A later message does not retitle it.
    call(&fx, Method::POST, &uri(&s, "/messages"), msg("and another")).await;
    let row = store::get(&fx.app.pool, &s.id).await.unwrap().unwrap();
    assert_eq!(row.title.as_deref(), Some(&text[..60]));

    // One the idle end (or a lost runner) ended is started again by a message.
    let ended = live(&fx, &vm.id, "running").await;
    sqlx::query("UPDATE core_agent_sessions SET harness_session = 'h-1' WHERE id = ?")
        .bind(&ended.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let outcome = json!({"kind": "succeeded", "reason": "idle_timeout"});
    store::end(&fx.app.pool, &ended.id, "ended", &outcome, NOW)
        .await
        .unwrap();
    // Its supervisor (none here) must not be mid-way through ending it.
    let r = call(
        &fx,
        Method::POST,
        &uri(&ended, "/messages"),
        msg("back again"),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    let row = store::get(&fx.app.pool, &ended.id).await.unwrap().unwrap();
    assert_eq!(
        (row.state.as_str(), row.pending.as_deref()),
        ("interrupted", Some("back again"))
    );
    assert!(row.outcome.is_none());

    // One that failed is over for good.
    let failed = live(&fx, &vm.id, "running").await;
    let outcome = json!({"kind": "failed", "reason": "x"});
    store::end(&fx.app.pool, &failed.id, "ended", &outcome, NOW)
        .await
        .unwrap();
    let r = call(&fx, Method::POST, &uri(&failed, "/messages"), msg("hi")).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("session_over"))
    );
}

#[tokio::test]
async fn a_title_is_set_trimmed_cleared_and_bounded_and_only_a_live_session_has_a_turn_to_stop() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = live(&fx, &vm.id, "running").await;
    let r = call(
        &fx,
        Method::PATCH,
        &uri(&s, ""),
        json!({"title": "  Billing fix  "}),
    )
    .await;
    assert_eq!(
        (r.0, r.1["title"].as_str()),
        (StatusCode::OK, Some("Billing fix")),
        "{}",
        r.1
    );
    let r = call(&fx, Method::PATCH, &uri(&s, ""), json!({"title": ""})).await;
    assert!(r.1["title"].is_null(), "{}", r.1);
    let r = call(
        &fx,
        Method::PATCH,
        &uri(&s, ""),
        json!({"title": "x".repeat(61)}),
    )
    .await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST);
    let r = call(&fx, Method::PATCH, &uri(&s, ""), json!({})).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST);
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'agent.renamed'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(audited, 2);
    // A session with a title is not retitled by its first message.
    store::set_title(&fx.app.pool, &s.id, "Mine").await.unwrap();
    store::title_from_first_message(&fx.app.pool, &s.id, "something else")
        .await
        .unwrap();
    assert_eq!(
        store::get(&fx.app.pool, &s.id)
            .await
            .unwrap()
            .unwrap()
            .title
            .as_deref(),
        Some("Mine")
    );

    // A session that is not a live conversation has no answer to stop.
    sqlx::query("UPDATE core_agent_sessions SET live = 0 WHERE id = ?")
        .bind(&s.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let r = call(&fx, Method::POST, &uri(&s, "/interrupt"), Value::Null).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("not_live"))
    );
}

#[test]
fn a_title_is_the_first_line_of_the_first_message_cut_to_sixty_characters() {
    assert_eq!(
        store::title_of("  \n  hello there \nsecond line").as_deref(),
        Some("hello there")
    );
    assert_eq!(
        store::title_of("é".repeat(100).as_str())
            .unwrap()
            .chars()
            .count(),
        60
    );
    assert_eq!(store::title_of(" \n "), None);
}

#[tokio::test]
async fn a_create_may_carry_no_first_message() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    // Neither a missing nor an empty prompt is a bad request: the refusal is the runner's absence.
    for body in [
        json!({"runner": vm.id, "harness": "claude"}),
        json!({"runner": vm.id, "harness": "claude", "prompt": ""}),
        json!({"runner": vm.id, "harness": "claude", "live": true}),
    ] {
        let r = call(&fx, Method::POST, "/api/v1/agent-sessions", body).await;
        assert_eq!(
            (r.0, r.1["code"].as_str()),
            (StatusCode::CONFLICT, Some("runner_offline")),
            "{}",
            r.1
        );
    }
}

#[tokio::test]
async fn a_waiting_session_nobody_comes_back_to_ends_and_can_be_resumed_by_a_message() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = live(&fx, &vm.id, "running").await;
    let idle = answer(&s, AgentState::Waiting, 1, json!({"type": "waiting"}));
    store::apply(&fx.app.pool, &s.id, &idle, NOW).await.unwrap();
    sqlx::query("UPDATE core_agent_sessions SET harness_session = 'h-1' WHERE id = ?")
        .bind(&s.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let row = |fx: &Fx| {
        let pool = fx.app.pool.clone();
        let id = s.id.clone();
        async move { store::get(&pool, &id).await.unwrap().unwrap() }
    };
    // Within the default two hours: still waiting.
    fx.clock.advance(7_199);
    assert!(
        !crate::agents::live::before_read(&fx.app, &row(&fx).await)
            .await
            .unwrap()
    );
    assert_eq!(row(&fx).await.api_state(), "waiting");
    // Past it: ended as a success the user can pick up again.
    fx.clock.advance(2);
    assert!(
        crate::agents::live::before_read(&fx.app, &row(&fx).await)
            .await
            .unwrap()
    );
    let ended = row(&fx).await;
    assert_eq!(ended.state, "ended");
    assert_eq!(ended.outcome.as_ref().unwrap()["kind"], "succeeded");
    assert_eq!(ended.outcome.as_ref().unwrap()["reason"], "idle_timeout");
    assert!(ended.wakeable() && ended.waiting_since.is_none());
    // The device's login lapsed in the two hours: it signs in again.
    let login = fx.app.auth.issue_session(&fx.dev.id, fx.clock.unix());
    fx.app
        .auth
        .elevate(&login.id, &fx.dev.id, fx.clock.unix() + 3_600);
    fx.dev.set_session(Some(login.id));
    let r = call(
        &fx,
        Method::POST,
        &uri(&s, "/messages"),
        json!({"text": "I am back"}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(row(&fx).await.state, "interrupted");
}
