//! Agent sessions' routes (E2-08) without a runner: what is refused before anything reaches
//! one (a bad body, an offline runner, no step-up, the wrong scope, an unknown session), that a
//! refusal never quotes the prompt and grows no audit row, and the transcript and list reads.
//! The runner end to end is `tests/hub/agents.rs`.

use axum::http::{Method, StatusCode};
use serde_json::json;

use super::*;
use crate::store::agents::{self as store, NewSession, SessionSecret};

const PROMPT: &str = "a private prompt 3c9f";

#[tokio::test]
async fn naming_a_secret_requires_admin_even_with_agent_step_up() {
    let fx = fx().await;
    let agent = super::stepup::plain(&fx, "agent-only", &["agent", "read"], true).await;
    assert_eq!(super::stepup::step_up(&fx, &agent).await.0, StatusCode::OK);
    let r = call(
        &fx,
        &agent,
        Method::POST,
        "/api/v1/agent-sessions",
        json!({
            "runner": "d_00000000000000000000000000",
            "harness": "claude",
            "secrets": [{"name": "git.token", "var": "GIT_TOKEN"}]
        }),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope"))
    );
}

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

async fn stored(fx: &Fx, runner: &str) -> store::Session {
    let policy = json!({});
    let secrets = [SessionSecret {
        name: "git.token".into(),
        var: "GIT_TOKEN".into(),
    }];
    let new = NewSession {
        runner,
        harness: "claude",
        model: None,
        prompt: Some(PROMPT),
        workspace: None,
        policy: &policy,
        secrets: &secrets,
        created_by: &fx.dev.id,
    };
    store::create(&fx.app.pool, &new, super::super::BY, NOW)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_create_is_checked_before_any_runner_is_asked() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let ok = json!({"runner": vm.id, "harness": "claude", "prompt": PROMPT});
    for (why, body) in [
        ("runner id", json!({"runner": "vm", "harness": "claude"})),
        (
            "harness",
            json!({"runner": vm.id, "harness": "Claude Code"}),
        ),
        (
            "var",
            json!({"runner": vm.id, "harness": "claude",
                       "secrets": [{"name": "git.token", "var": "LD_PRELOAD"}]}),
        ),
        (
            "reserved run token var",
            json!({"runner": vm.id, "harness": "claude",
                       "secrets": [{"name": "git.token", "var": "CITADEL_RUN_TOKEN"}]}),
        ),
        (
            "name",
            json!({"runner": vm.id, "harness": "claude",
                        "secrets": [{"name": "Git", "var": "T"}]}),
        ),
        (
            "policy",
            json!({"runner": vm.id, "harness": "claude", "policy": {"mode": "yolo"}}),
        ),
        (
            "prompt",
            json!({"runner": vm.id, "harness": "claude", "prompt": "x".repeat(70_000)}),
        ),
    ] {
        let r = call(&fx, &fx.dev, Method::POST, "/api/v1/agent-sessions", body).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{why}: {}", r.1);
    }
    // A runner that is not connected: refused, and no session (nor lease) made.
    let r = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/agent-sessions",
        ok.clone(),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("runner_offline"))
    );
    assert!(!r.1.to_string().contains(PROMPT));
    assert!(
        fx.ok("/api/v1/agent-sessions")
            .await
            .as_array()
            .unwrap()
            .is_empty()
    );
    let leases: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secret_leases")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(leases, 0);
    // A device with `read` only, and one without a step-up.
    let reader = enroll(&fx.app, &fx.clock, "reader", &["read"]).await;
    let r = call(
        &fx,
        &reader,
        Method::POST,
        "/api/v1/agent-sessions",
        ok.clone(),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope"))
    );
    let unelevated = super::stepup::plain(&fx, "plain", &["agent"], false).await;
    let r = call(&fx, &unelevated, Method::POST, "/api/v1/agent-sessions", ok).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("step_up_required"))
    );
    // A runner device reaches none of it.
    let r = call(&fx, &vm, Method::GET, "/api/v1/agent-sessions", Value::Null).await;
    assert_eq!(r.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sessions_list_read_and_replay_their_transcript_by_seq() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = stored(&fx, &vm.id).await;
    let ev = ainkrad_proto::v2::AgentEvents {
        session: s.id.clone(),
        state: ainkrad_proto::v2::AgentState::Running,
        last_seq: 4,
        // 3 comes before 2 is held: only the run continuing the stored one is taken.
        entries: [1, 3]
            .map(|seq| ainkrad_proto::v2::TranscriptEntry {
                seq,
                at: 1,
                body: json!({"type": "line", "n": seq}),
            })
            .into(),
        harness_session: Some("h-1".into()),
        usage: None,
        outcome: None,
    };
    assert_eq!(
        store::apply(&fx.app.pool, &s.id, &ev, NOW).await.unwrap(),
        1
    );
    let full = ainkrad_proto::v2::AgentEvents {
        entries: (1..=4)
            .map(|seq| ainkrad_proto::v2::TranscriptEntry {
                seq,
                at: 1,
                body: json!({"type": if seq == 4 { "approval_request" } else { "line" },
                             "id": "t1", "tool": "Bash", "n": seq}),
            })
            .collect(),
        ..ev
    };
    // A resend of 1 and the rest: each stored once.
    assert_eq!(
        store::apply(&fx.app.pool, &s.id, &full, NOW).await.unwrap(),
        4
    );
    assert_eq!(
        store::apply(&fx.app.pool, &s.id, &full, NOW).await.unwrap(),
        4
    );
    let uri = format!("/api/v1/agent-sessions/{}/transcript?after=2", s.id);
    let t = fx.ok(&uri).await;
    let seqs: Vec<u64> = t["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, [3, 4]);
    let got = fx.ok(&format!("/api/v1/agent-sessions/{}", s.id)).await;
    assert_eq!(
        (got["state"].as_str(), got["last_seq"].as_i64()),
        (Some("starting"), Some(4))
    );
    assert_eq!(got["secrets"], json!(["git.token"]), "names only");
    assert!(!got.to_string().contains(PROMPT));
    assert_eq!(
        fx.ok("/api/v1/agent-sessions")
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // The events: one transcript range per new run, the approval for `approve`.
    let kinds: Vec<String> =
        sqlx::query_scalar("SELECT kind FROM events WHERE kind LIKE 'agent.%' ORDER BY seq")
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(
        kinds,
        [
            "agent.created",
            "agent.transcript",
            "agent.approval_requested",
            "agent.transcript"
        ]
    );
    assert_eq!(
        crate::store::kinds::platform_scope("agent.approval_requested"),
        "approve"
    );
    assert_eq!(
        crate::store::kinds::platform_scope("agent.transcript"),
        "agent"
    );
    let audit: String =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'agent.created'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert!(
        !audit.contains(PROMPT) && audit.contains("git.token"),
        "{audit}"
    );
    // Unknown sessions, and actions on one whose runner is away.
    for uri in [
        "/api/v1/agent-sessions/as_nope",
        "/api/v1/agent-sessions/d_x/transcript",
    ] {
        assert_eq!(
            call(&fx, &fx.dev, Method::GET, uri, Value::Null).await.0,
            StatusCode::NOT_FOUND
        );
    }
    let kill = format!("/api/v1/agent-sessions/{}/kill", s.id);
    let r = call(&fx, &fx.dev, Method::POST, &kill, Value::Null).await;
    assert_eq!(r.1["code"], "runner_offline");
    let resume = format!("/api/v1/agent-sessions/{}/resume", s.id);
    let r = call(&fx, &fx.dev, Method::POST, &resume, Value::Null).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("not_resumable"))
    );
}

/// Review M1's lesson for the new writes: refusals a caller can repeat at will are counted,
/// not written to the permanent audit log.
#[tokio::test]
async fn refused_agent_writes_grow_no_audit_rows() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = stored(&fx, &vm.id).await;
    let rows = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events WHERE action = 'api.refused'",
        )
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
    };
    let before = rows().await;
    let create = json!({"runner": vm.id, "harness": "claude"});
    for _ in 0..20 {
        call(
            &fx,
            &fx.dev,
            Method::POST,
            "/api/v1/agent-sessions",
            create.clone(),
        )
        .await;
        let uri = format!("/api/v1/agent-sessions/{}/approvals/t1", s.id);
        call(&fx, &fx.dev, Method::POST, &uri, json!({"approved": true})).await;
        let uri = format!("/api/v1/agent-sessions/{}/messages", s.id);
        call(&fx, &fx.dev, Method::POST, &uri, json!({"text": "hi"})).await;
    }
    assert_eq!(rows().await, before);
}

/// A module drives only the sessions it created (E2-13 S7): never a client's, never another
/// module's, never a command that starts code, and never one that is over.
#[tokio::test]
async fn a_module_drives_only_its_own_live_sessions() {
    use crate::agents::{ModuleAgents, Refusal};
    use ainkrad_proto::v2::{AgentRead, AgentSend, AgentStop, Command};
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let policy = json!({});
    let new = NewSession {
        runner: &vm.id,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let owned = store::create_owned(
        &fx.app.pool,
        &new,
        Some("citadel"),
        ainkrad_core::audit::AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    let clients = store::create(
        &fx.app.pool,
        &new,
        ainkrad_core::audit::AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(owned.owner_module.as_deref(), Some("citadel"));
    assert_eq!(clients.owner_module, None);
    let stop = |s: &store::Session| {
        Command::AgentStop(AgentStop {
            session: s.id.clone(),
            kill: true,
        })
    };
    let why = |r: Result<(), Refusal>| match r {
        Err(Refusal::Runner(e)) => e.message,
        other => format!("{other:?}"),
    };
    let (citadel, other_module) = (ModuleAgents::named("citadel"), ModuleAgents::named("other"));
    // A client's session, and a session of another module's name.
    assert!(
        why(citadel.instruct(&fx.app, &clients.id, stop(&clients)).await)
            .contains("not this module's")
    );
    assert!(
        why(other_module
            .instruct(&fx.app, &owned.id, stop(&owned))
            .await)
        .contains("not this module's")
    );
    // A command that would start or read, and one about another session.
    let read = Command::AgentRead(AgentRead {
        session: owned.id.clone(),
        after: 0,
        wait_ms: None,
    });
    assert!(why(citadel.instruct(&fx.app, &owned.id, read).await).contains("only stop"));
    let other = Command::AgentSend(AgentSend {
        session: clients.id.clone(),
        text: "x".into(),
    });
    assert!(why(citadel.instruct(&fx.app, &owned.id, other).await).contains("another session"));
    // A session id that does not exist is not this module's either.
    assert!(
        why(citadel.instruct(&fx.app, "as_missing", stop(&owned)).await)
            .contains("not this module's")
    );
    // Over: nothing is sent.
    store::end(
        &fx.app.pool,
        &owned.id,
        "ended",
        &json!({"kind": "done"}),
        NOW,
    )
    .await
    .unwrap();
    let over = store::get(&fx.app.pool, &owned.id).await.unwrap().unwrap();
    assert!(why(citadel.instruct(&fx.app, &over.id, stop(&over)).await).contains("over"));
}

/// A client's write on a session a module drives would bypass the module's own audit and
/// approvals: every client write route refuses it, and the transcript is an `admin` read.
#[tokio::test]
async fn a_client_cannot_drive_or_read_a_session_a_module_owns() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let policy = json!({});
    let new = NewSession {
        runner: &vm.id,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let owned = store::create_owned(
        &fx.app.pool,
        &new,
        Some("citadel"),
        ainkrad_core::audit::AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    let base = format!("/api/v1/agent-sessions/{}", owned.id);
    for (path, body) in [
        ("messages", json!({"text": "hi"})),
        ("cancel", Value::Null),
        ("resume", Value::Null),
        ("wake", json!({})),
        ("approvals/req-1", json!({"approved": true})),
    ] {
        let r = call(&fx, &fx.dev, Method::POST, &format!("{base}/{path}"), body).await;
        assert_eq!(
            (r.0, r.1["code"].as_str()),
            (StatusCode::CONFLICT, Some("module_owned")),
            "{path}"
        );
    }
    // The transcript: an `agent` device is refused, the admin reads it.
    let agent = super::stepup::plain(&fx, "agent-only", &["agent", "read"], true).await;
    let r = call(
        &fx,
        &agent,
        Method::GET,
        &format!("{base}/transcript"),
        Value::Null,
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope"))
    );
    let r = call(
        &fx,
        &fx.dev,
        Method::GET,
        &format!("{base}/transcript"),
        Value::Null,
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{r:?}");
    // A client session that holds secrets is the admin's alone, not the module rule's (B-H1).
    let own = stored(&fx, &vm.id).await;
    let r = call(
        &fx,
        &agent,
        Method::GET,
        &format!("/api/v1/agent-sessions/{}/transcript", own.id),
        Value::Null,
    )
    .await;
    assert_eq!(r.0, StatusCode::FORBIDDEN, "{r:?}");
}

/// What a module's `create` answers (the refusal's message), for these inputs.
async fn module_create(
    fx: &Fx,
    runner: &str,
    by: &str,
    secrets: &[SessionSecret],
    policy: &Value,
    prompt: Option<&str>,
) -> String {
    use crate::agents::{ModuleAgents, Refusal};
    let new = NewSession {
        runner,
        harness: "claude",
        model: None,
        prompt,
        workspace: None,
        policy,
        secrets,
        created_by: by,
    };
    match ModuleAgents::named("citadel").create(&fx.app, &new).await {
        Err(Refusal::Runner(e)) => e.message,
        other => format!("{:?}", other.map(|s| s.id)),
    }
}

/// A module creates a session through the same checks as the client route: naming a broker
/// secret needs `created_by` to be an admin device, and a malformed policy, an oversized prompt
/// or a sandbox mode without the flag is refused (never defaulted).
#[tokio::test]
async fn a_module_create_passes_the_same_checks_as_the_route() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let agent = super::stepup::plain(&fx, "agent-only", &["agent", "read"], true).await;
    let secrets = [SessionSecret {
        name: "git.token".into(),
        var: "GIT_TOKEN".into(),
    }];
    let ask = json!({"mode": "ask"});
    for by in [agent.id.as_str(), "d_00000000000000000000000000"] {
        let why = module_create(&fx, &vm.id, by, &secrets, &ask, None).await;
        assert!(why.contains("admin scope"), "{by}: {why}");
    }
    let (by, admin) = (agent.id.as_str(), fx.dev.id.as_str());
    let bad = [
        (by, json!({"mode": "yolo"}), None, "does not have its shape"),
        (by, ask.clone(), Some("x".repeat(70_000)), "too long"),
        (
            admin,
            json!({"mode": "sandboxed", "sandboxed": false}),
            None,
            "sandbox flag",
        ),
    ];
    for (by, policy, prompt, expect) in bad {
        let why = module_create(&fx, &vm.id, by, &[], &policy, prompt.as_deref()).await;
        assert!(why.contains(expect), "{expect}: {why}");
    }
    // The admin device passes validation and reaches the runner check (not connected here).
    let why = module_create(&fx, &vm.id, &fx.dev.id, &secrets, &ask, None).await;
    assert!(!why.contains("admin scope"), "{why}");
    assert!(
        fx.ok("/api/v1/agent-sessions")
            .await
            .as_array()
            .unwrap()
            .is_empty()
    );
}

/// Break-glass (M3): an `admin` device kills a module's runaway session through the Core;
/// message, cancel and resume stay the module's, and a non-admin cannot kill it.
#[tokio::test]
async fn an_admin_may_kill_a_module_session_and_nobody_else() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let policy = json!({});
    let new = NewSession {
        runner: &vm.id,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let owned = store::create_owned(
        &fx.app.pool,
        &new,
        Some("citadel"),
        ainkrad_core::audit::AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    let uri = format!("/api/v1/agent-sessions/{}/kill", owned.id);
    let agent = super::stepup::plain(&fx, "agent-only", &["agent", "read"], true).await;
    assert_eq!(super::stepup::step_up(&fx, &agent).await.0, StatusCode::OK);
    let r = call(&fx, &agent, Method::POST, &uri, Value::Null).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope")),
        "{r:?}"
    );
    // The admin gets past the module guard: the refusal is now the offline runner's.
    let r = call(&fx, &fx.dev, Method::POST, &uri, Value::Null).await;
    assert_ne!(r.1["code"].as_str(), Some("module_owned"), "{r:?}");
    let r = call(
        &fx,
        &fx.dev,
        Method::POST,
        &uri.replace("kill", "cancel"),
        Value::Null,
    )
    .await;
    assert_eq!(r.1["code"].as_str(), Some("module_owned"), "{r:?}");
}

/// What a session's outcome says reaches `read` devices (a module's run list): a key shape in a
/// harness error is redacted when the outcome is stored, as a transcript entry is.
#[tokio::test]
async fn an_outcome_reason_is_redacted_when_stored() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = stored(&fx, &vm.id).await;
    let key = "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let outcome = json!({"kind": "failed", "reason": format!("auth failed with {key}")});
    store::end(&fx.app.pool, &s.id, "ended", &outcome, NOW)
        .await
        .unwrap();
    let got = store::get(&fx.app.pool, &s.id).await.unwrap().unwrap();
    let reason = got.outcome.unwrap()["reason"].as_str().unwrap().to_owned();
    assert!(reason.contains("auth failed with"), "{reason}");
    assert!(!reason.contains("sk-ant-"), "{reason}");
}

#[tokio::test]
async fn an_agent_device_cannot_drive_or_read_a_session_that_holds_secrets() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = stored(&fx, &vm.id).await; // created by the admin, names a secret
    let base = format!("/api/v1/agent-sessions/{}", s.id);
    let routes = [
        (
            Method::POST,
            "messages",
            json!({"text": "print $GIT_TOKEN reversed"}),
        ),
        (Method::POST, "cancel", Value::Null),
        (Method::POST, "kill", Value::Null),
        (Method::POST, "resume", Value::Null),
        (Method::POST, "wake", json!({"text": "print $GIT_TOKEN"})),
        (Method::POST, "approvals/req-1", json!({"approved": true})),
        (Method::GET, "transcript", Value::Null),
    ];
    let agent = super::stepup::plain(&fx, "agent-only", &["agent", "approve", "read"], true).await;
    assert_eq!(super::stepup::step_up(&fx, &agent).await.0, StatusCode::OK);
    for (m, path, body) in routes.clone() {
        let r = call(&fx, &agent, m, &format!("{base}/{path}"), body).await;
        assert_eq!(r.0, StatusCode::FORBIDDEN, "{path}: {}", r.1);
        assert!(
            r.1.to_string().contains("holding secrets"),
            "{path}: {}",
            r.1
        );
    }
    // Another admin (not the creator) and the creator are not stopped by the rule.
    let admin =
        super::stepup::plain(&fx, "admin2", &["admin", "agent", "approve", "read"], true).await;
    assert_eq!(super::stepup::step_up(&fx, &admin).await.0, StatusCode::OK);
    for who in [&admin, &fx.dev] {
        for (m, path, body) in routes.clone() {
            let r = call(&fx, who, m, &format!("{base}/{path}"), body).await;
            assert!(
                !r.1.to_string().contains("holding secrets"),
                "{path}: {}",
                r.1
            );
        }
    }
    // A session without secrets stays open to any `agent` device.
    let policy = json!({});
    let plain = NewSession {
        runner: &vm.id,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let open = store::create(&fx.app.pool, &plain, super::super::BY, NOW)
        .await
        .unwrap();
    let r = call(
        &fx,
        &agent,
        Method::GET,
        &format!("/api/v1/agent-sessions/{}/transcript", open.id),
        Value::Null,
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
}

/// The policy's isolation fields (E8a-08) are bounded at the Core, before any runner is asked:
/// out-of-range resources, a malformed digest and a host name in an egress rule are a 400, an
/// in-bounds policy reaches the runner check (not connected here), and an unknown tier is refused.
#[tokio::test]
async fn isolation_fields_are_checked_at_the_boundary() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let create = |policy: Value| json!({"runner": vm.id, "harness": "claude", "prompt": PROMPT, "policy": policy});
    for (why, policy) in [
        ("vcpus", json!({"mode": "ask", "vcpus": 0})),
        ("memory", json!({"mode": "ask", "memory_mb": 999_999_999})),
        ("disk", json!({"mode": "ask", "disk_mb": 1})),
        ("wall", json!({"mode": "ask", "wall_secs": 0})),
        ("digest", json!({"mode": "ask", "image": "ubuntu:latest"})),
        (
            "host name",
            json!({"mode": "ask", "egress": {"allow": ["example.com"]}}),
        ),
        (
            "prefix",
            json!({"mode": "ask", "egress": {"deny": ["10.0.0.0/33"]}}),
        ),
        ("tier", json!({"mode": "ask", "min_isolation": "vm"})),
    ] {
        let r = call(
            &fx,
            &fx.dev,
            Method::POST,
            "/api/v1/agent-sessions",
            create(policy),
        )
        .await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{why}: {}", r.1);
    }
    // In bounds: past validation, it reaches the placement check (the runner is not connected).
    let good = json!({"mode": "ask", "min_isolation": "process", "memory_mb": 512,
                      "wall_secs": 60, "egress": {"allow": ["10.0.0.0/8"]}});
    let r = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/agent-sessions",
        create(good),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("runner_offline"))
    );
    // A policy with none of the fields places as before (the runner is not connected here).
    let r = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/agent-sessions",
        create(json!({"mode": "ask"})),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("runner_offline"))
    );
}
