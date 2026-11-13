//! Code Mode writes (E6): risk classes, the Core-held approval of a risky call, idempotency and the
//! operations a session can never reach. Every case goes through `ainkrad.call`; a decision goes
//! through the real signed router (`decideAgentApproval`), so the gate's scope and step-up rules
//! are the ones under test.

use std::time::Duration;

use ainkrad_core::settings::Key;
use ainkrad_proto::v2::ToolCall;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::code_mode::{S, go, ok_result, rows, session, set, sql};
use super::*;
use crate::ops_catalog::{Allowed, Risk, build, call_call, check};

/// The catalogue of this Core made of exactly `rows`, whatever the committed allow-list says.
fn ops(fx: &Fx, rows: &[(&str, Risk)]) {
    let allow: Vec<Allowed> = rows
        .iter()
        .map(|(op, risk)| Allowed {
            op: (*op).to_owned(),
            risk: Some(*risk),
            summary: format!("Does {op}."),
        })
        .collect();
    let spec: Value =
        serde_json::from_str(&crate::api::v1::spec::json_for(&fx.app.modules)).unwrap();
    fx.app.ops.set(build(&spec, &allow)).unwrap();
}

fn rename(s: &S, title: &str) -> Value {
    json!({"op": "titleAgentSession", "args": {"id": s.id, "body": {"title": title}}})
}

async fn title(fx: &Fx, s: &S) -> Value {
    fx.ok(&format!("/api/v1/agent-sessions/{}", s.id)).await["title"].clone()
}

fn call(args: Value) -> ToolCall {
    ToolCall {
        tc_seq: 1,
        id: "c1".to_owned(),
        tool: "ainkrad.call".to_owned(),
        args,
    }
}

/// A call parked in its own task, as the broker runs it.
fn spawn(fx: &Fx, s: &S, args: Value) -> tokio::task::JoinHandle<(bool, String)> {
    let (app, runner, id) = (fx.app.clone(), s.runner.clone(), s.id.clone());
    tokio::spawn(async move {
        let r = call_call(&app, &runner, &id, &call(args)).await;
        (r.ok, r.code.unwrap_or_default())
    })
}

/// The request id of the approval `s` waits on.
async fn parked(fx: &Fx, s: &S) -> String {
    for _ in 0..200 {
        if let Some(p) = crate::ops_catalog::pending(&fx.app, &s.id)
            .await
            .unwrap()
            .pop()
        {
            return p.id;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("nothing is waiting for approval");
}

async fn decide(fx: &Fx, by: &TestDevice, s: &S, request: &str, ok: bool) -> (StatusCode, Value) {
    let uri = format!("/api/v1/agent-sessions/{}/approvals/{request}", s.id);
    send(
        &fx.app,
        req(Method::POST, &uri, Some(by), Some(json!({"approved": ok}))),
    )
    .await
}

async fn done(h: tokio::task::JoinHandle<(bool, String)>) -> (bool, String) {
    tokio::time::timeout(Duration::from_secs(10), h)
        .await
        .expect("the call ends")
        .unwrap()
}

#[tokio::test]
async fn a_write_runs_inside_the_creators_scopes_and_leaves_origin_and_root() {
    let fx = fx().await;
    ops(&fx, &[("titleAgentSession", Risk::Write)]);
    let s = session(&fx, &["read", "agent"]).await;
    let r = ok_result(&fx, &s, rename(&s, "Plan")).await;
    assert_eq!(r["title"], "Plan");
    assert_eq!(title(&fx, &s).await, "Plan");
    // The call row and the handler's own row both say ai_session, rooted in the person.
    let seen: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT action, origin, origin_root FROM audit_events \
         WHERE action IN ('code_mode.call', 'agent.renamed') ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(seen.len(), 2, "{seen:?}");
    for (_, origin, root) in &seen {
        assert_eq!(
            (origin.as_str(), root.as_deref()),
            ("ai_session", Some("person"))
        );
    }
    let d: Value = serde_json::from_str(&rows(&fx).await[0].4).unwrap();
    assert_eq!(
        (d["risk"].as_str(), d["outcome"].as_str()),
        (Some("write"), Some("ok"))
    );
    assert!(
        d.get("project").is_some(),
        "the row names the session's project (null without one)"
    );
    assert!(!d.to_string().contains("Plan"), "no argument in a row");

    // Without the scope the write never runs.
    let weak = session(&fx, &["read"]).await;
    assert_eq!(
        go(&fx, &weak, rename(&weak, "X")).await.1,
        "forbidden_scope"
    );
    // A body that does not fit its schema never reaches the handler.
    for bad in [json!({"title": 5}), json!({"title": ["a"]}), json!(7)] {
        let a = json!({"op": "titleAgentSession", "args": {"id": s.id, "body": bad}});
        let (ok, code) = go(&fx, &s, a).await;
        assert!(!ok && code == "bad_args", "{bad}: {code}");
    }
    let a = json!({"op": "titleAgentSession", "args": {"id": s.id}});
    assert_eq!(go(&fx, &s, a).await.1, "bad_args", "a body is required");
    assert_eq!(title(&fx, &s).await, "Plan");
}

#[tokio::test]
async fn a_write_on_a_step_up_route_is_not_available_unless_it_is_risky() {
    let fx = fx().await;
    ops(&fx, &[("cancelAgentSession", Risk::Write)]);
    let s = session(&fx, &["read", "agent"]).await;
    let a = json!({"op": "cancelAgentSession", "args": {"id": s.id}});
    assert_eq!(go(&fx, &s, a).await, (false, "not_available".to_owned()));
    // The class and the method must agree: a GET is never a write.
    let fx = self::fx().await;
    ops(&fx, &[("getCoreHealth", Risk::Write)]);
    let s = session(&fx, &["read"]).await;
    assert_eq!(
        go(&fx, &s, json!({"op": "getCoreHealth"})).await.1,
        "not_available"
    );
}

#[tokio::test]
async fn a_risky_call_never_runs_without_an_approval_and_a_denial_is_a_plain_refusal() {
    let fx = fx().await;
    ops(&fx, &[("titleAgentSession", Risk::Risky)]);
    let s = session(&fx, &["read", "agent"]).await;
    let approver = fx.enroll("approver", &["read", "agent", "approve"]).await;

    let h = spawn(&fx, &s, rename(&s, "Risky"));
    let id = parked(&fx, &s).await;
    assert!(id.starts_with("cm_"));
    // The card the App shows: tool, plain words, redacted arguments, reason.
    let held = crate::ops_catalog::pending(&fx.app, &s.id).await.unwrap();
    assert_eq!(held[0].tool, "ainkrad.titleAgentSession");
    assert_eq!(held[0].args["body"]["title"], "Risky");
    let list = fx
        .ok(&format!("/api/v1/agent-sessions/{}/approvals", s.id))
        .await;
    assert_eq!(list["approvals"][0]["id"], id.as_str());
    assert_eq!(list["approvals"][0]["risk"], "risky");
    let input = &list["approvals"][0]["input"];
    assert_eq!(input["args"]["body"]["title"], "Risky");
    assert!(input["summary"].is_string() && input["reason"].is_string());
    let ev: String =
        sqlx::query_scalar("SELECT payload FROM events WHERE kind = 'agent.approval_requested'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert!(
        ev.contains("\"input\"") && ev.contains("\"reason\""),
        "{ev}"
    );
    // The request event the phones are pushed for.
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM events WHERE kind = 'agent.approval_requested'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(n, 1);
    assert_eq!(
        title(&fx, &s).await,
        Value::Null,
        "nothing ran while it waited"
    );

    let (st, _) = decide(&fx, &approver, &s, &id, false).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(done(h).await, (false, "approval_denied".to_owned()));
    assert_eq!(title(&fx, &s).await, Value::Null, "a denial runs nothing");
    // Decided already: the same request answers 409, and nothing waits any more.
    assert_eq!(
        decide(&fx, &approver, &s, &id, true).await.0,
        StatusCode::CONFLICT
    );
    assert!(
        crate::ops_catalog::pending(&fx.app, &s.id)
            .await
            .unwrap()
            .is_empty()
    );
    let last: Value = serde_json::from_str(&rows(&fx).await.pop().unwrap().4).unwrap();
    assert_eq!(
        (last["code"].as_str(), last["outcome"].as_str()),
        (Some("approval_denied"), Some("error"))
    );
    assert_eq!(last["approval"]["request"], id.as_str());
    let by: String =
        sqlx::query_scalar("SELECT decided_by FROM core_code_mode_approvals WHERE id = ?")
            .bind(&id)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(by, approver.id);

    // The retry asks again (a denial is not a first result), and an approval runs it exactly once.
    let h = spawn(&fx, &s, rename(&s, "Risky"));
    let id2 = parked(&fx, &s).await;
    assert_ne!(id, id2);
    assert_eq!(
        decide(&fx, &approver, &s, &id2, true).await.0,
        StatusCode::OK
    );
    assert_eq!(done(h).await, (true, String::new()));
    assert_eq!(title(&fx, &s).await, "Risky");
    let d: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'agent.decided' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(d.len(), 2, "each decision is audited: {d:?}");
}

#[tokio::test]
async fn an_approval_is_single_use_and_bound_to_its_arguments() {
    let fx = fx().await;
    ops(&fx, &[("titleAgentSession", Risk::Risky)]);
    let s = session(&fx, &["read", "agent"]).await;
    let approver = fx.enroll("approver", &["read", "agent", "approve"]).await;
    let h = spawn(&fx, &s, rename(&s, "One"));
    let id = parked(&fx, &s).await;
    // Another script's approval is not this call's: its bound hash differs.
    sql(
        &fx,
        "UPDATE core_code_mode_approvals SET args_sha256 = 'other' WHERE id = ?",
        &id,
    )
    .await;
    assert_eq!(
        decide(&fx, &approver, &s, &id, true).await.0,
        StatusCode::OK
    );
    assert_eq!(done(h).await, (false, "approval_used".to_owned()));
    assert_eq!(title(&fx, &s).await, Value::Null);
    let state: String =
        sqlx::query_scalar("SELECT state FROM core_code_mode_approvals WHERE id = ?")
            .bind(&id)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(state, "approved", "never spent");
}

#[tokio::test]
async fn only_a_device_with_approve_and_a_step_up_can_decide() {
    let fx = fx().await;
    ops(&fx, &[("titleAgentSession", Risk::Risky)]);
    let s = session(&fx, &["read", "agent"]).await;
    let viewer = fx.enroll("viewer", &["read", "agent"]).await;
    let cold = TestDevice::enroll(
        &fx.app.pool,
        "cold",
        "device",
        &["read", "agent", "approve"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    cold.set_session(Some(
        fx.app.auth.issue_session(&cold.id, fx.clock.unix()).id,
    ));
    let approver = fx.enroll("approver", &["read", "agent", "approve"]).await;

    let h = spawn(&fx, &s, rename(&s, "Gated"));
    let id = parked(&fx, &s).await;
    let (st, body) = decide(&fx, &viewer, &s, &id, true).await;
    assert_eq!(
        (st, body["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope"))
    );
    let (st, body) = decide(&fx, &cold, &s, &id, true).await;
    assert_eq!(
        (st, body["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("step_up_required"))
    );
    let (st, _) = send(
        &fx.app,
        req(
            Method::POST,
            &format!("/api/v1/agent-sessions/{}/approvals/{id}", s.id),
            None,
            Some(json!({"approved": true})),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(
        title(&fx, &s).await,
        Value::Null,
        "still waiting, nothing ran"
    );
    assert_eq!(
        crate::ops_catalog::pending(&fx.app, &s.id)
            .await
            .unwrap()
            .len(),
        1
    );
    // Unknown request ids of this session are 404.
    assert_eq!(
        decide(&fx, &approver, &s, "cm_nope", true).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        decide(&fx, &approver, &s, &id, true).await.0,
        StatusCode::OK
    );
    assert!(done(h).await.0);
}

#[tokio::test]
async fn an_unanswered_approval_expires_and_nothing_runs() {
    let fx = fx().await;
    ops(&fx, &[("titleAgentSession", Risk::Risky)]);
    set(&fx, Key::CodeModeApprovalSecs, "1").await;
    let s = session(&fx, &["read", "agent"]).await;
    let approver = fx.enroll("approver", &["read", "agent", "approve"]).await;
    let h = spawn(&fx, &s, rename(&s, "Late"));
    let id = parked(&fx, &s).await;
    assert_eq!(done(h).await, (false, "approval_timeout".to_owned()));
    assert_eq!(title(&fx, &s).await, Value::Null);
    assert_eq!(
        decide(&fx, &approver, &s, &id, true).await.0,
        StatusCode::CONFLICT
    );
    let last: Value = serde_json::from_str(&rows(&fx).await.pop().unwrap().4).unwrap();
    assert_eq!(last["code"], "approval_timeout");
}

#[tokio::test]
async fn a_session_that_ends_while_parked_is_refused_and_audited() {
    let fx = fx().await;
    ops(&fx, &[("titleAgentSession", Risk::Risky)]);
    let s = session(&fx, &["read", "agent"]).await;
    let h = spawn(&fx, &s, rename(&s, "Gone"));
    let id = parked(&fx, &s).await;
    sql(
        &fx,
        "UPDATE core_agent_sessions SET state = 'ended' WHERE id = ?",
        &s.id,
    )
    .await;
    assert_eq!(done(h).await, (false, "session_ended".to_owned()));
    let state: String =
        sqlx::query_scalar("SELECT state FROM core_code_mode_approvals WHERE id = ?")
            .bind(&id)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(state, "ended");
    assert!(
        rows(&fx)
            .await
            .iter()
            .any(|r| r.4.contains("session_ended"))
    );
}

#[tokio::test]
async fn a_core_restart_while_parked_never_replays_the_call() {
    let fx = fx().await;
    ops(&fx, &[("titleAgentSession", Risk::Risky)]);
    let s = session(&fx, &["read", "agent"]).await;
    let h = spawn(&fx, &s, rename(&s, "Boot"));
    let id = parked(&fx, &s).await;
    // The restarted Core: the same database, nothing in memory (the parked future above stands
    // for the one the restart dropped).
    let mut after = fx.app.clone();
    after.code_mode = Default::default();
    // Nothing waits for the approval any more: a decision finds it closed and it is never run.
    let found = crate::ops_catalog::decide_approval(&after, &s.id, &id, true, "d_x")
        .await
        .unwrap();
    assert_eq!(found, crate::ops_catalog::Decided::Closed);
    // The script asks again: the claim of the first try has no result and nothing runs it.
    let r = call_call(&after, &s.runner, &s.id, &call(rename(&s, "Boot"))).await;
    assert_eq!(r.code.as_deref(), Some("outcome_unknown"));
    assert!(!done(h).await.0);
    assert_eq!(title(&fx, &s).await, Value::Null, "never replayed");
}

#[tokio::test]
async fn a_scope_taken_away_while_parked_refuses_on_resume() {
    let fx = fx().await;
    ops(&fx, &[("titleAgentSession", Risk::Risky)]);
    let s = session(&fx, &["read", "agent"]).await;
    let approver = fx.enroll("approver", &["read", "agent", "approve"]).await;
    let h = spawn(&fx, &s, rename(&s, "Revoked"));
    let id = parked(&fx, &s).await;
    sql(
        &fx,
        "UPDATE core_devices SET scopes = '[\"read\"]' WHERE id = ?",
        &s.creator,
    )
    .await;
    assert_eq!(
        decide(&fx, &approver, &s, &id, true).await.0,
        StatusCode::OK
    );
    assert_eq!(done(h).await, (false, "forbidden_scope".to_owned()));
    assert_eq!(title(&fx, &s).await, Value::Null);
}

#[tokio::test]
async fn the_same_write_sent_again_returns_the_first_result_and_runs_nothing() {
    let fx = fx().await;
    ops(&fx, &[("titleAgentSession", Risk::Write)]);
    let s = session(&fx, &["read", "agent"]).await;
    let first = ok_result(&fx, &s, rename(&s, "A")).await;
    assert_eq!(first["title"], "A");
    // Someone else changes it; the retry must not write over that.
    sql(
        &fx,
        "UPDATE core_agent_sessions SET title = 'B' WHERE id = ?",
        &s.id,
    )
    .await;
    let again = ok_result(&fx, &s, rename(&s, "A")).await;
    assert_eq!(again, json!({"replayed": true, "result": first}));
    assert_eq!(title(&fx, &s).await, "B");
    // repeat:true is an identical write the script means twice.
    let mut twice = rename(&s, "A");
    twice["repeat"] = json!(true);
    assert_eq!(ok_result(&fx, &s, twice).await["title"], "A");
    assert_eq!(title(&fx, &s).await, "A");
    // Other arguments are another write.
    assert_eq!(ok_result(&fx, &s, rename(&s, "C")).await["title"], "C");
    // A named key stands for the call whatever its arguments.
    let mut k = rename(&s, "D");
    k["key"] = json!("k1");
    assert_eq!(ok_result(&fx, &s, k.clone()).await["title"], "D");
    k["args"]["body"]["title"] = json!("E");
    assert_eq!(ok_result(&fx, &s, k).await["replayed"], true);
    assert_eq!(title(&fx, &s).await, "D");
    // The window ends: it runs again.
    fx.clock.advance(601);
    assert_eq!(ok_result(&fx, &s, rename(&s, "A")).await["title"], "A");
    // Only a hash is stored, never an argument.
    let stored: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT key_hash, result FROM core_code_mode_idem")
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    assert!(
        stored
            .iter()
            .all(|(k, _)| k.len() == 64 && !k.contains("A"))
    );
    // Another session with the same call is its own write.
    let other = session(&fx, &["read", "agent"]).await;
    assert_eq!(
        ok_result(&fx, &other, rename(&other, "A")).await["title"],
        "A"
    );
}

#[tokio::test]
async fn a_write_that_failed_is_not_remembered() {
    let fx = fx().await;
    ops(&fx, &[("titleAgentSession", Risk::Write)]);
    let s = session(&fx, &["read", "agent"]).await;
    let ghost =
        json!({"op": "titleAgentSession", "args": {"id": "as_ghost", "body": {"title": "x"}}});
    for _ in 0..2 {
        assert_eq!(
            go(&fx, &s, ghost.clone()).await,
            (false, "not_found".to_owned())
        );
    }
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM core_code_mode_idem WHERE result IS NOT NULL")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn secrets_and_device_or_runner_admin_are_never_callable() {
    let fx = fx().await;
    let spec: Value =
        serde_json::from_str(&crate::api::v1::spec::json_for(&fx.app.modules)).unwrap();
    // Every operation of those families, allow-listed as risky by mistake.
    let mut hidden = Vec::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        if crate::ops_catalog::exposed(path) {
            continue;
        }
        for op in item.as_object().unwrap().values() {
            if let Some(id) = op["operationId"].as_str() {
                hidden.push(id.to_owned());
            }
        }
    }
    for must in [
        "listSecrets",
        "createSecret",
        "leaseSecret",
        "listDevices",
        "revokeDevice",
        "setDeviceScopes",
        "createPairing",
        "setRunnerPolicy",
        "installRunnerTool",
    ] {
        assert!(
            hidden.iter().any(|h| h == must),
            "{must} is not in the contract's hidden families: {hidden:?}"
        );
    }
    let rows_: Vec<(&str, Risk)> = hidden.iter().map(|h| (h.as_str(), Risk::Risky)).collect();
    let allow: Vec<Allowed> = rows_
        .iter()
        .map(|(op, r)| Allowed {
            op: (*op).to_owned(),
            risk: Some(*r),
            summary: String::new(),
        })
        .collect();
    // The gate test would fail the build for each, and the builder leaves each out.
    let bad = check(&spec, &allow);
    for h in &hidden {
        assert!(
            bad.iter()
                .any(|b| b.starts_with(&format!("{h}:")) && b.contains("not exposed")),
            "{h}"
        );
    }
    ops(&fx, &rows_);
    assert!(fx.app.catalogue().ops.is_empty());
    let s = session(&fx, &["read", "agent", "approve", "terminal", "runner"]).await;
    for op in &hidden {
        let (ok, code) = go(&fx, &s, json!({"op": op, "args": {}})).await;
        assert!(!ok && code == "unknown_op", "{op}: {code}");
    }
    // And the committed allow-list holds none of them.
    for a in crate::ops_catalog::allow_list().unwrap() {
        assert!(!hidden.contains(&a.op), "{} is allow-listed", a.op);
    }
}
