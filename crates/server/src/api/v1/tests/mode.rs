//! AI session modes (E3) at the Core's routes, without a runner: the session info carries its
//! permission mode and Plan mode; a create asks for Plan mode only of claude, and only of a runner
//! that can switch; `setAgentSessionMode` keeps a session off its runner's new mode for its next
//! start, refuses what a mode cannot be, and audits every change. The runner end is
//! `runner::harness::tests::controls` and `runner::v2::agent::tests`.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::store::agents::{self as store, NewSession};

async fn call(fx: &Fx, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(&fx.dev), body)).await
}

/// A session of `harness` under `policy`, in `state`.
async fn session(fx: &Fx, harness: &str, policy: Value, state: &str) -> store::Session {
    let vm = super::secrets::runner(fx, "vm").await;
    let new = NewSession {
        runner: &vm.id,
        harness,
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let sys = ainkrad_core::audit::AuditActor::System;
    let s = store::create(&fx.app.pool, &new, sys, NOW).await.unwrap();
    if state != "starting" {
        store::set_state(&fx.app.pool, &s.id, state, "test", false, NOW)
            .await
            .unwrap();
    }
    store::get(&fx.app.pool, &s.id).await.unwrap().unwrap()
}

fn mode_uri(s: &store::Session) -> String {
    format!("/api/v1/agent-sessions/{}/mode", s.id)
}

async fn policy_of(fx: &Fx, s: &store::Session) -> Value {
    store::get(&fx.app.pool, &s.id)
        .await
        .unwrap()
        .unwrap()
        .policy
}

#[tokio::test]
async fn the_session_info_carries_its_permission_mode_and_plan_mode() {
    let fx = fx().await;
    let edits = json!({"mode": "accept_edits", "allow": ["Read"]});
    let s = session(&fx, "claude", edits, "running").await;
    let shown = fx.ok(&format!("/api/v1/agent-sessions/{}", s.id)).await;
    assert_eq!(
        (&shown["policy"], &shown["plan"]),
        (&json!("accept_edits"), &json!(false))
    );
    let planned = session(
        &fx,
        "claude",
        json!({"mode": "ask", "plan": true}),
        "running",
    )
    .await;
    let listed = fx.ok("/api/v1/agent-sessions").await;
    let row = (listed.as_array().unwrap().iter())
        .find(|r| r["id"] == planned.id.as_str())
        .unwrap();
    assert_eq!(
        (&row["policy"], &row["plan"]),
        (&json!("ask"), &json!(true))
    );
    // A policy stored without a mode reads as the default, `ask`.
    let bare = session(&fx, "codex", json!({}), "running").await;
    let shown = fx.ok(&format!("/api/v1/agent-sessions/{}", bare.id)).await;
    assert_eq!(
        (&shown["policy"], &shown["plan"]),
        (&json!("ask"), &json!(false))
    );
}

#[tokio::test]
async fn plan_mode_at_start_is_claudes_and_needs_a_runner_that_can_switch() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let create = |harness: &str, extra: Value| {
        let mut b = json!({"runner": vm.id, "harness": harness});
        b.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        b
    };
    for (harness, extra) in [
        ("codex", json!({"plan": true})),
        ("opencode", json!({"policy": {"mode": "ask", "plan": true}})),
    ] {
        let uri = "/api/v1/agent-sessions";
        let r = call(&fx, Method::POST, uri, create(harness, extra)).await;
        assert_eq!(
            (r.0, r.1["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("plan_unsupported")),
            "{harness}: {}",
            r.1
        );
    }
    // Claude, on a runner that does not list `agent.mode` (here: not connected at all).
    let body = create("claude", json!({"plan": true}));
    let r = call(&fx, Method::POST, "/api/v1/agent-sessions", body).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("unsupported_command")),
        "{}",
        r.1
    );
    assert!(
        fx.ok("/api/v1/agent-sessions")
            .await
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_mode_change_is_kept_for_the_next_start_and_audited() {
    let fx = fx().await;
    let floor = json!({"mode": "ask", "allow": ["Read"], "min_isolation": "process"});
    let s = session(&fx, "claude", floor, "interrupted").await;
    let r = call(&fx, Method::POST, &mode_uri(&s), json!({"plan": true})).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(
        (&r.1["policy"], &r.1["plan"]),
        (&json!("ask"), &json!(true))
    );
    let body = json!({"policy": "accept_edits", "plan": false});
    let r = call(&fx, Method::POST, &mode_uri(&s), body).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(
        (&r.1["policy"], &r.1["plan"]),
        (&json!("accept_edits"), &json!(false))
    );
    // The rest of the policy stays; Plan mode off is no field at all (an older runner refuses one).
    assert_eq!(
        policy_of(&fx, &s).await,
        json!({"mode": "accept_edits", "allow": ["Read"], "min_isolation": "process"})
    );
    let audited: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'agent.mode_changed' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    let audited: Vec<Value> = (audited.iter())
        .map(|d| serde_json::from_str(d).unwrap())
        .collect();
    assert_eq!(audited.len(), 2);
    assert_eq!(audited[0]["from"], json!({"policy": "ask", "plan": false}));
    assert_eq!(audited[0]["to"], json!({"policy": "ask", "plan": true}));
    assert_eq!(
        audited[1]["to"],
        json!({"policy": "accept_edits", "plan": false})
    );
}

#[tokio::test]
async fn what_a_mode_cannot_be_is_refused_and_changes_nothing() {
    let fx = fx().await;
    let s = session(&fx, "claude", json!({"mode": "ask"}), "interrupted").await;
    let codex = session(&fx, "codex", json!({"mode": "ask"}), "interrupted").await;
    let starting = session(&fx, "claude", json!({"mode": "ask"}), "starting").await;
    let running = session(&fx, "claude", json!({"mode": "ask"}), "running").await;
    for (who, body, status, code) in [
        (&s, json!({}), StatusCode::BAD_REQUEST, "bad_request"),
        (
            &s,
            json!({"policy": "yolo"}),
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            &codex,
            json!({"plan": true}),
            StatusCode::BAD_REQUEST,
            "plan_unsupported",
        ),
        (
            &s,
            json!({"policy": "sandboxed"}),
            StatusCode::CONFLICT,
            "mode_at_start",
        ),
        (
            &starting,
            json!({"plan": true}),
            StatusCode::CONFLICT,
            "session_starting",
        ),
        // On its runner, which is not connected: not told, so not kept.
        (
            &running,
            json!({"plan": true}),
            StatusCode::CONFLICT,
            "runner_offline",
        ),
    ] {
        let r = call(&fx, Method::POST, &mode_uri(who), body.clone()).await;
        assert_eq!(
            (r.0, r.1["code"].as_str()),
            (status, Some(code)),
            "{body}: {}",
            r.1
        );
        assert_eq!(policy_of(&fx, who).await, json!({"mode": "ask"}), "{body}");
    }
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'agent.mode_changed'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(audited, 0);
}
