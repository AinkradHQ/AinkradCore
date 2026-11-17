//! AI session card data (E6) at the Core's routes, without a runner: the running answer's cost
//! appears with its message, follows its `usage_so_far` entries priced from the book, and clears at
//! its end; `stopAgentSubagent` refuses a harness that cannot stop one sub-agent (409) and an id
//! that is no running sub-agent (404). The relayed stop is `tests/hub/subagents.rs`.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::store::agents::{self as store, NewSession};
use ainkrad_proto::v2::{AgentEvents, AgentState, TranscriptEntry};

async fn session(fx: &Fx, harness: &str, model: Option<&str>) -> store::Session {
    let vm = super::secrets::runner(fx, "vm").await;
    let policy = json!({"mode": "ask"});
    let new = NewSession {
        runner: &vm.id,
        harness,
        model,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let sys = ainkrad_core::audit::AuditActor::System;
    let s = store::create(&fx.app.pool, &new, sys, NOW).await.unwrap();
    store::set_state(&fx.app.pool, &s.id, "running", "test", false, NOW)
        .await
        .unwrap();
    s
}

/// Stores the next entries of `s` after `after`, as a runner's answer does.
async fn say(fx: &Fx, s: &store::Session, after: u64, bodies: &[Value]) -> u64 {
    let entries: Vec<TranscriptEntry> = (bodies.iter().enumerate())
        .map(|(i, body)| TranscriptEntry {
            seq: after + 1 + i as u64,
            at: 1,
            body: body.clone(),
        })
        .collect();
    let ev = AgentEvents {
        gateway: vec![],
        session: s.id.clone(),
        state: AgentState::Running,
        last_seq: after + bodies.len() as u64,
        entries,
        harness_session: None,
        usage: None,
        outcome: None,
        plan_limit: None,
        folder: None,
    };
    store::apply(&fx.app.pool, &s.id, &ev, NOW).await.unwrap()
}

async fn post(fx: &Fx, uri: String) -> (StatusCode, Value) {
    send(&fx.app, req(Method::POST, &uri, Some(&fx.dev), None)).await
}

async fn cost(fx: &Fx, s: &store::Session) -> (Value, Value) {
    let got = fx.ok(&format!("/api/v1/agent-sessions/{}", s.id)).await;
    (
        got["turn_cost_usd_micros"].clone(),
        got["turn_cost_approximate"].clone(),
    )
}

fn so_far(input: u64, output: u64, cache_read: u64) -> Value {
    json!({"type": "usage_so_far", "input": input, "output": output,
           "cache_read": cache_read, "cache_write": 0, "cost_usd": null})
}

#[tokio::test]
async fn the_running_answers_cost_appears_moves_and_clears() {
    let fx = fx().await;
    // Sonnet's shipped list price: $2 in, $10 out, $0.10 cache per million tokens.
    let s = session(&fx, "claude", Some("claude-sonnet-5-5")).await;
    assert_eq!(
        cost(&fx, &s).await,
        (Value::Null, json!(false)),
        "no turn yet"
    );
    let at = say(
        &fx,
        &s,
        0,
        &[json!({"type": "user_message", "id": 1, "text": "go"})],
    )
    .await;
    assert_eq!(cost(&fx, &s).await, (json!(0), json!(false)), "started");
    let at = say(&fx, &s, at, &[so_far(1000, 100, 10_000)]).await;
    // 1000 × 2 + 100 × 10 + 10 000 × 0.1 micro-dollars; Claude's mid-turn output undercounts.
    assert_eq!(cost(&fx, &s).await, (json!(4000), json!(true)));
    let at = say(
        &fx,
        &s,
        at,
        &[
            json!({"type": "tool_use", "id": "t", "name": "Bash"}),
            so_far(3000, 200, 10_000),
        ],
    )
    .await;
    assert_eq!(cost(&fx, &s).await, (json!(9000), json!(true)), "it moves");
    let usage = json!({"type": "usage", "input": 3000, "output": 400, "cache_read": 10_000,
                       "cache_write": 0, "cost_usd": 0.01});
    let ended = json!({"type": "turn_ended", "outcome": {"kind": "success"}});
    let at = say(&fx, &s, at, &[usage, ended]).await;
    assert_eq!(
        cost(&fx, &s).await,
        (Value::Null, json!(false)),
        "the turn is over"
    );
    // The next message starts the next turn at 0.
    say(
        &fx,
        &s,
        at,
        &[json!({"type": "user_message", "id": 2, "text": "more"})],
    )
    .await;
    assert_eq!(cost(&fx, &s).await, (json!(0), json!(false)));

    // A model with no price has no cost, a turn or not; a harness that reports steps is exact.
    let unpriced = session(&fx, "claude", Some("claude-unknown")).await;
    say(&fx, &unpriced, 0, &[so_far(1000, 100, 0)]).await;
    assert_eq!(cost(&fx, &unpriced).await, (Value::Null, json!(false)));
    sqlx::query(
        "INSERT INTO core_prices (provider, model, version, input_per_mtok_micro, \
         output_per_mtok_micro, cache_per_mtok_micro, priced_at, created_at) \
         VALUES ('openai', 'gpt-x', 1, 1000000, 4000000, 0, ?1, ?1)",
    )
    .bind(NOW)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let codex = session(&fx, "codex", Some("gpt-x")).await;
    say(&fx, &codex, 0, &[so_far(1000, 100, 0)]).await;
    assert_eq!(cost(&fx, &codex).await, (json!(1400), json!(false)));
}

#[tokio::test]
async fn a_sub_agent_stop_needs_a_harness_that_can_and_a_running_sub_agent() {
    let fx = fx().await;
    let stop = |s: &store::Session, call: &str| {
        format!("/api/v1/agent-sessions/{}/subagents/{call}/stop", s.id)
    };
    let codex = session(&fx, "codex", None).await;
    let r = post(&fx, stop(&codex, "t1")).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("unsupported_command")),
        "{}",
        r.1
    );
    let claude = session(&fx, "claude", None).await;
    let shown = fx
        .ok(&format!("/api/v1/agent-sessions/{}", claude.id))
        .await;
    assert_eq!(
        shown["can_stop_subagents"], false,
        "its runner is not connected"
    );
    say(
        &fx,
        &claude,
        0,
        &[
            json!({"type": "tool_use", "id": "bash1", "name": "Bash", "input": {}}),
            json!({"type": "tool_use", "id": "done1", "name": "Task", "input": {}}),
            json!({"type": "tool_result", "id": "done1", "name": "Task", "status": "ok"}),
        ],
    )
    .await;
    // Not a call at all, not a sub-agent's, one that has its result: none runs.
    for id in ["nope", "bash1", "done1"] {
        let r = post(&fx, stop(&claude, id)).await;
        assert_eq!(
            (r.0, r.1["code"].as_str()),
            (StatusCode::NOT_FOUND, Some("unknown_subagent")),
            "{id}: {}",
            r.1
        );
    }
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'agent.subagent_stopped'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 0, "a refusal stops nothing");
}
