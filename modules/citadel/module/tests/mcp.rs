//! The MCP server (S8) over the Core's token route: the run token is the only credential, a
//! token reaches its own run's issue and nothing else, no tool decides an approval or touches a
//! secret, the token is nowhere the Core keeps text, and the unsigned exemption covers exactly
//! one route. Over HTTP through the real router, with Citadel mounted.

mod common;
mod work_seed;

use std::sync::Arc;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::api::limit::Limiter;
use ainkrad_core_server::api::v1::Limits;
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::gateway::token::unsigned_routes;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use citadel_module::Citadel;
use citadel_module::domain::exec::RunEvent;
use citadel_module::domain::work::{IssueId, ProjectMode, RunId, WakeSource};
use citadel_module::store::exec::{
    self as engine, Host, Instruction, NewWakeRequest, StartFailure, StartSpec,
};
use common::*;
use serde_json::{Value, json};
use tower::ServiceExt;
use work_seed::{Seed, seed};

const MCP: &str = "/token/citadel/v1/mcp";

/// A host that records the session it would start, owned and pointing at its run, as the
/// platform does.
struct Fake(String);

impl Host for Fake {
    async fn runners(&self, _: &App, _: &str) -> Vec<String> {
        vec![self.0.clone()]
    }

    async fn start(&self, app: &App, spec: &StartSpec) -> Result<String, StartFailure> {
        let policy = json!({});
        let new = NewSession {
            runner: &spec.runner,
            harness: &spec.harness,
            model: Some(&spec.model),
            prompt: Some(&spec.prompt),
            workspace: None,
            policy: &policy,
            secrets: &[],
            created_by: &spec.by_device,
        };
        let s = sessions::create_owned_ref(
            &app.pool,
            &new,
            Some("citadel"),
            Some(&format!("run:{}", spec.run.0)),
            AuditActor::System,
            &app.clock.now(),
        )
        .await
        .unwrap();
        Ok(s.id)
    }

    async fn instruct(&self, _: &App, _: &str, _: Instruction) -> Result<(), String> {
        Ok(())
    }
}

/// A company with an agent, an issue waiting on it, and a run on it that has started.
struct Co {
    seed: Seed,
    run: engine::Run,
}

async fn company(fx: &Fx, host: &Fake, name: &str, key: &str) -> Co {
    let seed = seed(&fx.app.pool, name, key, ProjectMode::Kanban).await;
    let wake = NewWakeRequest {
        agent_id: citadel_module::domain::org::AgentId(seed.agent),
        issue_id: Some(IssueId(seed.issue)),
        source: WakeSource::Assignment,
        reason: "test".into(),
        idempotency_key: format!("mcp-{name}"),
        not_before: None,
    };
    engine::enqueue_wake(&fx.app.pool, &wake).await.unwrap();
    let run = engine::dispatch_next(&fx.app, host, &fx.app.clock.now())
        .await
        .unwrap()
        .expect("a run is due");
    Co { seed, run }
}

struct W {
    fx: Fx,
    host: Fake,
}

async fn set(app: &App, name: &str, value: &str) {
    citadel_module::settings::handle()
        .set(&app.pool, name, value, AuditActor::System, &app.clock.now())
        .await
        .unwrap();
}

async fn world() -> W {
    let fx = fx().await;
    let runner = enroll(&fx.app, "vm", &["runner"], false).await;
    engine::set_engine(&fx.app.pool, true, &fx.dev.id, &fx.app.clock.now())
        .await
        .unwrap();
    set(&fx.app, "mcp.enabled", "1").await;
    W {
        fx,
        host: Fake(runner.id),
    }
}

impl W {
    async fn co(&self, name: &str, key: &str) -> Co {
        company(&self.fx, &self.host, name, key).await
    }

    async fn token(&self, run: RunId) -> String {
        engine::issue_run_token(&self.fx.app.pool, run, &self.fx.app.clock.now())
            .await
            .unwrap()
            .expose()
            .to_owned()
    }
}

fn post(token: Option<&str>, uri: &str) -> axum::http::request::Builder {
    let mut req = Request::post(uri)
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    req
}

async fn send(app: &App, req: Request<Body>) -> (StatusCode, Value) {
    let res = router(app.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn rpc(app: &App, token: Option<&str>, body: Value) -> (StatusCode, Value) {
    send(
        app,
        post(token, MCP).body(Body::from(body.to_string())).unwrap(),
    )
    .await
}

fn tool(name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
}

fn list() -> Value {
    json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
}

/// The tool's answer: whether it failed, and its text.
fn answer(reply: &Value) -> (bool, String) {
    (
        reply["result"]["isError"] == true,
        reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    )
}

async fn count(app: &App, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn serves_initialize_tools_list_and_calls_with_a_run_token() {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let t = w.token(a.run.id).await;
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"}}});
    let (status, reply) = rpc(&w.fx.app, Some(&t), init).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["result"]["serverInfo"]["name"], "citadel");
    let (status, reply) = rpc(&w.fx.app, Some(&t), list()).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let names: Vec<&str> = reply["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "get_issue",
            "get_context",
            "comment",
            "transition",
            "create_subtask",
            "report_blocker",
            "request_approval",
            "get_approval"
        ]
    );
    let (status, reply) = rpc(&w.fx.app, Some(&t), tool("get_issue", json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (failed, text) = answer(&reply);
    assert!(!failed, "{text}");
    let issue: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        (issue["key"].as_str(), issue["title"].as_str()),
        (Some("AAA-1"), Some("A work"))
    );
}

#[tokio::test]
async fn a_wrong_expired_revoked_or_unissued_token_is_the_same_401() {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let t = w.token(a.run.id).await;
    let app = &w.fx.app;
    let random = format!("cit_run_{}", "ab".repeat(32));
    for bad in [
        None,
        Some("cit_run_guess"),
        Some(random.as_str()),
        Some(&t[..20]),
    ] {
        let (status, _) = rpc(app, bad, list()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{bad:?}");
    }
    assert_eq!(rpc(app, Some(&t), list()).await.0, StatusCode::OK);
    // Expired.
    sqlx::query("UPDATE citadel_run_tokens SET expires_at = '2000-01-01T00:00:00.000Z'")
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(rpc(app, Some(&t), list()).await.0, StatusCode::UNAUTHORIZED);
    // A newer token revokes the older one; the run ending revokes the newer.
    let t2 = w.token(a.run.id).await;
    assert_eq!(rpc(app, Some(&t), list()).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(rpc(app, Some(&t2), list()).await.0, StatusCode::OK);
    let run = engine::get_run(&app.pool, a.run.id).await.unwrap().unwrap();
    let cancel = RunEvent::Cancel {
        reason: "stopped".into(),
    };
    engine::transition_run(
        &app.pool,
        run.id,
        AuditActor::System,
        &cancel,
        &app.clock.now(),
    )
    .await
    .unwrap();
    assert_eq!(
        rpc(app, Some(&t2), list()).await.0,
        StatusCode::UNAUTHORIZED,
        "revoked"
    );
    // A run that is not running has no token to issue.
    assert!(
        engine::issue_run_token(&app.pool, a.run.id, &app.clock.now())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_token_reaches_only_its_runs_issue_and_company_and_every_call_is_audited() {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let b = w.co("B", "BBB").await;
    let ta = w.token(a.run.id).await;
    let tb = w.token(b.run.id).await;
    let app = &w.fx.app;
    // Another company's issue: read, comment, transition, subtask-of, blocker: the same refusal
    // as an issue that does not exist, and nothing of B in the answer.
    let foreign = b.seed.issue;
    for (name, args) in [
        ("get_issue", json!({"issue_id": foreign})),
        ("comment", json!({"issue_id": foreign, "body": "hi"})),
        (
            "transition",
            json!({"issue_id": foreign, "transition": "start"}),
        ),
        ("report_blocker", json!({"issue_id": foreign, "title": "x"})),
        ("report_blocker", json!({"blocker_issue_id": foreign})),
        (
            "transition",
            json!({"transition": "block", "blocker_issue_id": foreign}),
        ),
        (
            "request_approval",
            json!({"issue_id": foreign, "kind": "pr_merge", "summary": "s"}),
        ),
    ] {
        let (_, reply) = rpc(app, Some(&ta), tool(name, args)).await;
        let (failed, text) = answer(&reply);
        assert!(failed, "{name}: {text}");
        assert!(
            !text.contains("B work") && !text.contains("BBB"),
            "{name}: {text}"
        );
    }
    // Nothing was written to B.
    assert_eq!(
        count(
            app,
            &format!("SELECT count(*) FROM citadel_comments WHERE issue_id = {foreign}")
        )
        .await,
        0
    );
    assert_eq!(
        count(app, "SELECT count(*) FROM citadel_blocker_links").await,
        0
    );
    assert_eq!(
        count(app, "SELECT count(*) FROM citadel_approvals").await,
        0
    );
    // A same-company issue that is neither the run's nor its subtask is refused too.
    let sibling = {
        let (_, r) = rpc(
            app,
            Some(&ta),
            tool("create_subtask", json!({"title": "own"})),
        )
        .await;
        let (failed, text) = answer(&r);
        assert!(!failed, "{text}");
        let sub: Value = serde_json::from_str(&text).unwrap();
        // A subtask is reachable.
        let id = sub["issue_id"].clone();
        let (_, r) = rpc(
            app,
            Some(&ta),
            tool("comment", json!({"issue_id": id, "body": "ok"})),
        )
        .await;
        assert!(!answer(&r).0, "{r}");
        id
    };
    let unrelated = citadel_module::store::work::create_issue(
        &app.pool,
        &citadel_module::domain::work::NewIssue {
            project_id: citadel_module::domain::work::ProjectId(a.seed.project),
            epic_id: None,
            parent_id: None,
            kind: citadel_module::domain::work::IssueKind::Task,
            title: "unrelated".into(),
            body: String::new(),
            state: citadel_module::domain::work::IssueState::Todo,
            owner: None,
            next_actor: Some(citadel_module::domain::work::NextActor::Agent(
                citadel_module::domain::org::AgentId(a.seed.agent),
            )),
            points: None,
            sprint_id: None,
        },
    )
    .await
    .unwrap();
    let (_, r) = rpc(
        app,
        Some(&ta),
        tool("comment", json!({"issue_id": unrelated.id.0, "body": "x"})),
    )
    .await;
    let (failed, text) = answer(&r);
    assert!(failed && text.contains("not this run's issue"), "{text}");
    // B's own token reaches B's issue, and not A's.
    let (_, r) = rpc(app, Some(&tb), tool("get_issue", json!({}))).await;
    assert!(!answer(&r).0);
    let (_, r) = rpc(
        app,
        Some(&tb),
        tool("get_issue", json!({"issue_id": a.seed.issue})),
    )
    .await;
    assert!(answer(&r).0);
    let _ = sibling;
    // Every call is audited as A's run, refused or not.
    let calls = count(
        app,
        &format!(
            "SELECT count(*) FROM audit_events WHERE action LIKE 'citadel.mcp.%' \
             AND json_extract(details, '$.run_id') = {}",
            a.run.id.0
        ),
    )
    .await;
    assert_eq!(calls, 7 + 1 + 1 + 1);
    let refused = count(
        app,
        &format!(
            "SELECT count(*) FROM audit_events WHERE action LIKE 'citadel.mcp.%' \
             AND json_extract(details, '$.run_id') = {} AND json_extract(details, '$.ok') = 0",
            a.run.id.0
        ),
    )
    .await;
    assert_eq!(refused, 7 + 1);
}

#[tokio::test]
async fn no_tool_decides_an_approval_or_touches_a_secret_or_a_run() {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let t = w.token(a.run.id).await;
    let app = &w.fx.app;
    // None is listed, and none is callable.
    let (_, reply) = rpc(app, Some(&t), list()).await;
    let names: Vec<String> = reply["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names.len(), 8, "{names:?}");
    for forbidden in [
        "decide",
        "approve",
        "reject",
        "secret",
        "lease",
        "credential",
        "kill",
        "cancel",
        "engine",
        "setting",
        "device",
        "wake",
        "budget",
        "hire",
        "token",
    ] {
        // `request_approval` and `get_approval` only ask and read.
        let hits: Vec<_> = names.iter().filter(|n| n.contains(forbidden)).collect();
        assert!(
            hits.iter().all(|n| n.ends_with("_approval")),
            "{forbidden}: {hits:?}"
        );
    }
    for name in [
        "decide_approval",
        "decide",
        "approve",
        "decide_repo",
        "create_secret",
        "lease_secret",
        "redeem_lease",
        "kill_run",
        "cancel_run",
        "set_engine",
        "request_hire",
        "set_setting",
        "publish_artifact",
        "plan_sprint",
        "../get_issue",
        "GET_ISSUE",
    ] {
        let (_, reply) = rpc(app, Some(&t), tool(name, json!({}))).await;
        let (failed, text) = answer(&reply);
        assert!(failed && text.contains("no such tool"), "{name:?}: {reply}");
    }
    // Many junk names, one audit row: they cannot grow the trail.
    assert_eq!(
        count(
            app,
            "SELECT count(*) FROM audit_events WHERE action = 'citadel.mcp.unknown_tool'"
        )
        .await,
        1
    );
    // Asking is allowed, deciding is not: the approval stays pending and only the asker reads it.
    let (_, r) = rpc(
        app,
        Some(&t),
        tool(
            "request_approval",
            json!({"kind": "pr_merge", "summary": "merge it"}),
        ),
    )
    .await;
    let (failed, text) = answer(&r);
    assert!(!failed, "{text}");
    let id = serde_json::from_str::<Value>(&text).unwrap()["approval_id"].clone();
    let (_, r) = rpc(
        app,
        Some(&t),
        tool("get_approval", json!({"approval_id": id})),
    )
    .await;
    assert!(answer(&r).1.contains("\"status\":\"pending\""));
    // The kinds a human decides elsewhere (a hire, a sprint commit) cannot even be asked for.
    for kind in [
        "hire_agent",
        "sprint_commit",
        "plan_approval",
        "workflow_push",
        "nope",
    ] {
        let (_, r) = rpc(
            app,
            Some(&t),
            tool("request_approval", json!({"kind": kind, "summary": "s"})),
        )
        .await;
        assert!(answer(&r).0, "{kind}");
    }
    // Another agent's approval looks like none.
    let b = w.co("B", "BBB").await;
    let tb = w.token(b.run.id).await;
    let (_, r) = rpc(
        app,
        Some(&tb),
        tool("get_approval", json!({"approval_id": id})),
    )
    .await;
    assert!(answer(&r).0, "{r}");
    // And the run is not controllable through it: still running after all of the above.
    let run = engine::get_run(&app.pool, a.run.id).await.unwrap().unwrap();
    assert!(!run.state.is_terminal());
}

#[tokio::test]
async fn the_token_is_nowhere_the_core_keeps_text() {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let t = w.token(a.run.id).await;
    let app = &w.fx.app;
    // Use it, including a failing call that echoes its arguments.
    rpc(app, Some(&t), tool("comment", json!({"body": "progress"}))).await;
    rpc(app, Some(&t), tool("nope", json!({"x": 1}))).await;
    // Every column of every table: the raw token is in none of them (only its hash is).
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(&app.pool)
    .await
    .unwrap();
    for table in tables {
        let cols: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT name FROM pragma_table_info('{table}')"
        )))
        .fetch_all(&app.pool)
        .await
        .unwrap();
        let any = cols
            .iter()
            .map(|c| format!("coalesce(CAST(\"{c}\" AS TEXT), '')"))
            .collect::<Vec<_>>()
            .join(" || ' ' || ");
        let n = count(
            app,
            &format!("SELECT count(*) FROM \"{table}\" WHERE ({any}) LIKE '%{t}%'"),
        )
        .await;
        assert_eq!(n, 0, "the raw run token is in {table}");
    }
    let stored = count(
        app,
        &format!(
            "SELECT count(*) FROM citadel_run_tokens WHERE token_hash = '{}'",
            engine::key_hash(&t)
        ),
    )
    .await;
    assert_eq!(stored, 1, "its hash is");
    // The log writer masks its shape wherever it appears.
    let line = ainkrad_core_server::ops::logging::redact(false, &format!("run token {t} refused"));
    assert!(!line.contains(&t), "{line}");
}

#[tokio::test]
async fn a_launch_mints_a_fresh_token_for_the_runs_own_session_only() {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let b = w.co("B", "BBB").await;
    let app = &w.fx.app;
    let session = |run: &engine::Run| {
        let id = run.session_id.clone().unwrap();
        let pool = app.pool.clone();
        async move { sessions::get(&pool, &id).await.unwrap().unwrap() }
    };
    let (sa, sb) = (session(&a.run).await, session(&b.run).await);
    assert_eq!(
        sa.owner_ref.as_deref(),
        Some(format!("run:{}", a.run.id.0).as_str())
    );
    // Off: nothing is minted, nothing is delivered.
    set(app, "mcp.enabled", "0").await;
    assert!(Citadel.credentials(app, &sa).await.unwrap().is_empty());
    citadel_module::settings::handle()
        .set(
            &app.pool,
            "mcp.enabled",
            "1",
            AuditActor::System,
            &app.clock.now(),
        )
        .await
        .unwrap();
    let first = Citadel.credentials(app, &sa).await.unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].var, "CITADEL_RUN_TOKEN");
    assert!(first[0].value.starts_with("cit_run_"));
    assert_eq!(
        rpc(app, Some(&first[0].value), list()).await.0,
        StatusCode::OK
    );
    // A later launch (a resume) mints another and the first dies.
    let second = Citadel.credentials(app, &sa).await.unwrap();
    assert_eq!(
        rpc(app, Some(&first[0].value), list()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        rpc(app, Some(&second[0].value), list()).await.0,
        StatusCode::OK
    );
    // A session that is not the run's own gets nothing: not another run's, not a client's.
    let mut forged = sb.clone();
    forged.owner_ref = sa.owner_ref.clone();
    assert!(
        Citadel.credentials(app, &forged).await.is_err(),
        "run A's pointer on B's session"
    );
    let mut none = sa.clone();
    none.owner_ref = None;
    assert!(Citadel.credentials(app, &none).await.is_err());
    none.owner_ref = Some("run:999999".into());
    assert!(Citadel.credentials(app, &none).await.is_err());
    // A run that has ended gets none.
    let cancel = RunEvent::Cancel {
        reason: "stopped".into(),
    };
    engine::transition_run(
        &app.pool,
        a.run.id,
        AuditActor::System,
        &cancel,
        &app.clock.now(),
    )
    .await
    .unwrap();
    assert!(Citadel.credentials(app, &sa).await.is_err());
    assert_eq!(
        rpc(app, Some(&second[0].value), list()).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_gate_refuses_other_hosts_browsers_cookies_queries_and_big_bodies() {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let t = w.token(a.run.id).await;
    let app = &w.fx.app;
    let body = list().to_string();
    let build = |b: axum::http::request::Builder| b.body(Body::from(body.clone())).unwrap();
    let mut other_host = build(post(Some(&t), MCP));
    other_host
        .headers_mut()
        .insert(header::HOST, "evil.example".parse().unwrap());
    assert_eq!(send(app, other_host).await.0, StatusCode::FORBIDDEN);
    let browser = build(post(Some(&t), MCP).header(header::ORIGIN, "https://evil.example"));
    assert_eq!(send(app, browser).await.0, StatusCode::FORBIDDEN);
    let cookie = build(post(Some(&t), MCP).header(header::COOKIE, "a=b"));
    assert_eq!(send(app, cookie).await.0, StatusCode::BAD_REQUEST);
    let query = build(post(Some(&t), &format!("{MCP}?token={t}")));
    assert_eq!(send(app, query).await.0, StatusCode::BAD_REQUEST);
    // A body past the cap is refused before it is read, with and without a length.
    let huge = "x".repeat(citadel_module::mcp::MAX_BODY + 1);
    let sized = post(Some(&t), MCP)
        .header(header::CONTENT_LENGTH, huge.len())
        .body(Body::from(huge.clone()))
        .unwrap();
    assert_eq!(send(app, sized).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    let unsized_ = post(Some(&t), MCP).body(Body::from(huge)).unwrap();
    assert_eq!(send(app, unsized_).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    // A text field past its cap is refused by the tool.
    let long = "y".repeat(40 * 1024);
    let (_, r) = rpc(app, Some(&t), tool("comment", json!({"body": long}))).await;
    assert!(answer(&r).0);
    // Tokens are never read from a GET (a stateless server has no stream to open).
    let get = Request::get(MCP)
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {t}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(app, get).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn guessing_is_locked_out_and_a_valid_token_is_rate_limited_and_capped() {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let t = w.token(a.run.id).await;
    let mut app = w.fx.app.clone();
    // Per-run call cap, counted atomically.
    citadel_module::settings::handle()
        .set(
            &app.pool,
            "mcp.max_calls_per_run",
            "2",
            AuditActor::System,
            &app.clock.now(),
        )
        .await
        .unwrap();
    for _ in 0..2 {
        assert!(!answer(&rpc(&app, Some(&t), tool("get_issue", json!({}))).await.1).0);
    }
    let (_, r) = rpc(&app, Some(&t), tool("get_issue", json!({}))).await;
    let (failed, text) = answer(&r);
    assert!(failed && text.contains("tool calls"), "{text}");
    // Per-principal rate.
    app.limits = Arc::new(Limits {
        requests: Limiter::new(1, 0.001),
    });
    assert_eq!(rpc(&app, Some(&t), list()).await.0, StatusCode::OK);
    assert_eq!(
        rpc(&app, Some(&t), list()).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    app.limits = Arc::new(Limits::default());
    // A source that keeps guessing is locked out, but a valid token never is: a junk flood
    // cannot switch MCP off for the other runs behind the same address.
    for _ in 0..20 {
        assert_eq!(
            rpc(&app, Some("cit_run_guess"), list()).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        rpc(&app, Some("cit_run_guess"), list()).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(rpc(&app, Some(&t), list()).await.0, StatusCode::OK);
}

#[tokio::test]
async fn unknown_tool_names_count_against_the_cap_and_audit_once() {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let t = w.token(a.run.id).await;
    let app = &w.fx.app;
    set(app, "mcp.max_calls_per_run", "3").await;
    for _ in 0..3 {
        let (_, r) = rpc(app, Some(&t), tool("nope", json!({}))).await;
        assert!(answer(&r).1.contains("no such tool"));
    }
    let (_, r) = rpc(app, Some(&t), tool("get_issue", json!({}))).await;
    let (failed, text) = answer(&r);
    assert!(failed && text.contains("tool calls"), "{text}");
    let (_, r) = rpc(app, Some(&t), tool("nope", json!({}))).await;
    assert!(answer(&r).1.contains("tool calls"));
    assert_eq!(
        count(
            app,
            "SELECT count(*) FROM audit_events WHERE action = 'citadel.mcp.unknown_tool'"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn turning_mcp_off_stops_tokens_already_issued() {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let t = w.token(a.run.id).await;
    let app = &w.fx.app;
    assert_eq!(rpc(app, Some(&t), list()).await.0, StatusCode::OK);
    set(app, "mcp.enabled", "0").await;
    assert_eq!(rpc(app, Some(&t), list()).await.0, StatusCode::UNAUTHORIZED);
    set(app, "mcp.enabled", "1").await;
    assert_eq!(rpc(app, Some(&t), list()).await.0, StatusCode::OK);
}

/// The exemption from the signature covers one route of this module and nothing else: the list
/// of everything unsigned is this, a token opens no signed route, and a signature opens no token
/// route.
#[tokio::test]
async fn the_unsigned_exemption_is_one_route() {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let t = w.token(a.run.id).await;
    let app = &w.fx.app;
    let mut got = unsigned_routes(&app.modules);
    got.sort();
    let mut want: Vec<(String, String)> = [
        ("ANY", "/handshake"),
        ("ANY", "/pair"),
        ("ANY", "/healthz"),
        ("ANY", "/runner/v2/connect"),
        ("POST", "/token/citadel/v1/mcp"),
    ]
    .iter()
    .map(|(m, p)| ((*m).to_owned(), (*p).to_owned()))
    .collect();
    want.sort();
    assert_eq!(got, want);
    // Every documented route of the module, signed ones and the engine's, refuses the token ...
    let doc = Citadel.openapi();
    let mut n = 0;
    for (path, item) in doc["paths"].as_object().unwrap() {
        let uri = format!("{BASE}{}", path.replace("{id}", "1"));
        for method in item.as_object().unwrap().keys() {
            let m: Method = method.to_uppercase().parse().unwrap();
            let r = Request::builder()
                .method(m)
                .uri(&uri)
                .header(header::HOST, HOST)
                .header(header::AUTHORIZATION, format!("Bearer {t}"))
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                send(app, r).await.0,
                StatusCode::BAD_REQUEST,
                "{method} {uri}"
            );
            // ... and the same path under the token prefix is not a route at all.
            let r = Request::builder()
                .method(method.to_uppercase().parse::<Method>().unwrap())
                .uri(format!("/token/citadel/v1{}", path.replace("{id}", "1")))
                .header(header::HOST, HOST)
                .header(header::AUTHORIZATION, format!("Bearer {t}"))
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                send(app, r).await.0,
                StatusCode::UNAUTHORIZED,
                "token prefix {uri}"
            );
            n += 1;
        }
    }
    assert!(n > 50, "{n} routes walked");
    // The platform's secret and approval routes too.
    for uri in [
        "/api/v1/secrets",
        "/api/v1/secret-leases/redeem",
        "/api/v1/agent-sessions",
    ] {
        let r = Request::builder()
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::AUTHORIZATION, format!("Bearer {t}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(app, r).await.0, StatusCode::BAD_REQUEST, "{uri}");
    }
    // A signature alone opens no token route.
    let (status, _) = call_at(&w.fx, "/token/citadel/v1/mcp").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

async fn call_at(fx: &Fx, uri: &str) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::HOST, HOST);
    for (name, value) in fx.dev.headers("POST", uri, b"") {
        b = b.header(name, value);
    }
    send(&fx.app, b.body(Body::empty()).unwrap()).await
}

/// F-05: a credential an agent pastes into a comment is redacted before it is stored, because a
/// `read` device (a phone) reads comments back.
#[tokio::test]
async fn an_agents_comment_is_redacted_before_it_is_stored() {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let t = w.token(a.run.id).await;
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let (_, reply) = rpc(
        &w.fx.app,
        Some(&t),
        tool(
            "comment",
            json!({"issue_id": a.seed.issue, "body": format!("token is {secret}")}),
        ),
    )
    .await;
    let (failed, text) = answer(&reply);
    assert!(!failed, "{text}");
    let stored: String =
        sqlx::query_scalar("SELECT group_concat(body) FROM citadel_comments WHERE issue_id = ?")
            .bind(a.seed.issue)
            .fetch_one(&w.fx.app.pool)
            .await
            .unwrap();
    assert!(
        stored.contains("token is") && !stored.contains(secret),
        "{stored}"
    );
}
