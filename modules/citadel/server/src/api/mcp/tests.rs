//! The MCP server over HTTP: the gate, the run token, the protocol. The tools themselves are
//! tested in `tools`, on the same fixtures.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use citadel_core::audit::{AuditActor, AuditFilter};
use citadel_core::auth::{RUN_TOKEN_TTL_SECS, RunScope, RunToken};
use citadel_core::exec::{NewRunner, NewWakeRequest, Run, RunEvent, WakeSource};
use citadel_core::org::{AgentId, AgentStatus, CompanyId, Harness, NewAgent, OrgRole};
use citadel_core::work::{
    IssueId, IssueKind, IssueState, NewIssue, NewProject, NextActor, ProjectMode, SprintApproval,
};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use tower::ServiceExt;

use crate::api::{App, router};
use crate::scheduler::Clock;
use crate::store::exec::{
    authorize_run_token, dispatch_next, enqueue_wake, register_runner, start_run, transition_run,
};
use crate::store::org::{create_agent, create_company};
use crate::store::work::{create_issue, create_project};
use crate::store::{audit, connect};

mod apply_plan;
mod artifacts;
mod cli;
mod empty_done;
mod forge;
mod knowledge;
mod org;
mod plan;
mod planner_tools;
mod requirements;
mod roles;
mod tools;

pub(super) const NOW: &str = "2026-10-21T10:00:00.000Z";
const HOST: &str = "citadel.test";

pub(super) struct FixedClock(pub Mutex<String>);

impl Clock for FixedClock {
    fn now(&self) -> String {
        self.0.lock().unwrap().clone()
    }
}

/// A migrated database in its own temp dir, removed on drop, and an app on it.
pub(super) struct Fx {
    pub app: App,
    pub clock: std::sync::Arc<FixedClock>,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A company's running run on its own issue, waiting on its agent.
pub(super) struct Company {
    pub company: CompanyId,
    pub agent: AgentId,
    pub issue: IssueId,
    pub run: Run,
    pub token: RunToken,
}

impl Company {
    pub fn scope(&self) -> RunScope {
        RunScope {
            run_id: self.run.id,
            agent_id: self.agent,
            issue_id: Some(self.issue),
            company_id: self.company,
        }
    }
}

pub(super) async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("citadel-mcp-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("citadel.db")).await.unwrap();
    let clock = std::sync::Arc::new(FixedClock(Mutex::new(NOW.to_owned())));
    let app = App::new(pool, clock.clone(), HOST.to_owned());
    Fx { app, clock, dir }
}

/// Company `name` (project key `key`) with an agent, an issue waiting on it, and a run on it
/// started with its token.
pub(super) async fn company(pool: &SqlitePool, name: &str, key: &str) -> Company {
    let company = create_company(pool, name).await.unwrap().id;
    let a = NewAgent {
        company_id: company,
        name: format!("{name} dev"),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Opencode,
        model: String::new(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    let agent = create_agent(pool, &a).await.unwrap().id;
    let p = NewProject {
        company_id: company,
        team_id: None,
        name: format!("{name} project"),
        key: key.to_owned(),
        mode: ProjectMode::Kanban,
        sprint_approval: SprintApproval::Owner,
    };
    let project = create_project(pool, &p).await.unwrap().id;
    let i = NewIssue {
        project_id: project,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: format!("{name} work"),
        body: "Do the thing.".to_owned(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Agent(agent)),
        points: None,
        sprint_id: None,
    };
    let issue = create_issue(pool, &i).await.unwrap().id;
    let wake = NewWakeRequest {
        agent_id: agent,
        issue_id: Some(issue),
        source: WakeSource::Assignment,
        reason: "test".to_owned(),
        idempotency_key: format!("mcp-test-{name}"),
        not_before: None,
    };
    enqueue_wake(pool, &wake).await.unwrap();
    let runner = NewRunner {
        name: format!("{name}-runner"),
        tags: vec![],
    };
    let (runner, _) = register_runner(pool, &runner).await.unwrap();
    let run = dispatch_next(pool, runner.id, &[], &Harness::ALL, NOW)
        .await
        .unwrap()
        .expect("a run is due");
    let (run, token) = start_run(pool, run.id, AuditActor::Runner(runner.id), None, NOW)
        .await
        .unwrap();
    Company {
        company,
        agent,
        issue,
        run,
        token,
    }
}

/// A JSON-RPC POST to `/mcp/v1`, as a harness's MCP client sends it.
fn post(token: Option<&str>) -> axum::http::request::Builder {
    let mut req = Request::post("/mcp/v1")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    req
}

/// Sends `body` and returns the status and the JSON reply (`Null` when there is none).
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
    let req = post(token).body(Body::from(body.to_string())).unwrap();
    send(app, req).await
}

pub(super) fn tool_names(reply: &Value) -> Vec<&str> {
    reply["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect()
}

fn call(name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
}

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2025-06-18","capabilities":{},
    "clientInfo":{"name":"test","version":"1"}}}"#;

#[tokio::test]
async fn serves_initialize_tools_list_and_calls_with_a_run_token() {
    let fx = fx().await;
    let a = company(&fx.app.pool, "A", "AAA").await;
    let t = Some(a.token.expose());

    let init: Value = serde_json::from_str(INITIALIZE).unwrap();
    let (status, reply) = rpc(&fx.app, t, init).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["result"]["serverInfo"]["name"], "citadel");
    assert!(reply["result"]["capabilities"]["tools"].is_object());

    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let (status, reply) = rpc(&fx.app, t, list).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    // A developer's run lists its role's tools (E15.18); the rest are found by search.
    assert_eq!(
        tool_names(&reply),
        [
            "get_issue",
            "get_context",
            "comment",
            "transition",
            "create_subtask",
            "report_blocker",
            "open_pr",
            "request_repo",
            "request_approval",
            "get_approval",
            "propose_knowledge",
            "search_tools",
            "describe_tool",
            "ask_human",
            "publish_artifact",
            "get_artifact",
        ]
    );
    // Unscoped, every tool.
    let by = AuditActor::User(citadel_core::work::UserId(1));
    let (key, at) = (
        citadel_core::settings::Key::McpRoleScopedTools,
        citadel_core::settings::Scope::Company(a.company),
    );
    crate::store::settings::set(&fx.app.pool, key, at, "0", by, NOW)
        .await
        .unwrap();
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let (_, reply) = rpc(&fx.app, t, list).await;
    assert_eq!(
        tool_names(&reply),
        [
            "get_issue",
            "get_context",
            "list_backlog",
            "comment",
            "transition",
            "create_subtask",
            "report_blocker",
            "open_pr",
            "request_repo",
            "decide_repo",
            "set_repos",
            "qa_verdict",
            "request_approval",
            "get_approval",
            "propose_knowledge",
            "review_knowledge",
            "plan_sprint",
            "sprint_add_issue",
            "sprint_remove_issue",
            "set_sprint_issues",
            "estimate_issue",
            "assign_issue",
            "commit_sprint",
            "close_sprint",
            "propose_retro_items",
            "sprint_report",
            "org_chart",
            "route_intake",
            "plan_requirement",
            "apply_plan",
            "search_tools",
            "describe_tool",
            "ask_human",
            "post_to_requirement",
            "publish_artifact",
            "get_artifact",
            "request_hire",
        ]
    );

    let (status, reply) = rpc(&fx.app, t, call("get_issue", json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    let issue: Value = serde_json::from_str(text).unwrap();
    assert_eq!(issue["key"], "AAA-1");
    assert_eq!(issue["title"], "A work");
}

#[tokio::test]
async fn refuses_requests_without_a_live_run_token() {
    let fx = fx().await;
    let a = company(&fx.app.pool, "A", "AAA").await;
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});

    for token in [None, Some("cit_run_guess")] {
        let (status, _) = rpc(&fx.app, token, list.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?}");
    }
    // Past its expiry.
    const { assert!(RUN_TOKEN_TTL_SECS <= 24 * 60 * 60) };
    *fx.clock.0.lock().unwrap() = "2026-10-22T10:00:00.001Z".to_owned();
    let (status, _) = rpc(&fx.app, Some(a.token.expose()), list.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "expired");
    *fx.clock.0.lock().unwrap() = NOW.to_owned();
    let (status, _) = rpc(&fx.app, Some(a.token.expose()), list.clone()).await;
    assert_eq!(status, StatusCode::OK, "live again at NOW");
    // Revoked: its run ended.
    let by = AuditActor::Runner(a.run.runner_id.unwrap());
    transition_run(&fx.app.pool, a.run.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap();
    let (status, _) = rpc(&fx.app, Some(a.token.expose()), list).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked");
}

#[tokio::test]
async fn the_gate_refuses_other_hosts_browsers_and_query_strings() {
    let fx = fx().await;
    let a = company(&fx.app.pool, "A", "AAA").await;
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let t = Some(a.token.expose());
    let build = |req: axum::http::request::Builder| req.body(Body::from(body.to_string())).unwrap();

    let mut other_host = build(post(t));
    let evil = "evil.example".parse().unwrap();
    other_host.headers_mut().insert(header::HOST, evil);
    let browser = build(post(t).header(header::ORIGIN, "https://evil.example"));
    let mut query = build(post(t));
    *query.uri_mut() = "/mcp/v1?token=x".parse().unwrap();
    assert_eq!(send(&fx.app, other_host).await.0, StatusCode::FORBIDDEN);
    assert_eq!(send(&fx.app, browser).await.0, StatusCode::FORBIDDEN);
    assert_eq!(send(&fx.app, query).await.0, StatusCode::BAD_REQUEST);
}

/// Over HTTP, run A's token reaches A's issue and never B's, and every call is audited as
/// A's agent on A's run.
#[tokio::test]
async fn a_token_reaches_only_its_runs_issue_and_every_call_is_audited() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = company(pool, "A", "AAA").await;
    let b = company(pool, "B", "BBB").await;
    let t = Some(a.token.expose());

    let (_, reply) = rpc(
        &fx.app,
        t,
        call("get_issue", json!({"issue_id": b.issue.0})),
    )
    .await;
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("not this run's issue"), "{text}");
    assert!(!text.contains("B work"), "nothing of B leaks: {text}");

    let (_, reply) = rpc(&fx.app, t, call("comment", json!({"body": "hi"}))).await;
    assert_ne!(reply["result"]["isError"], true, "{reply}");

    let filter = AuditFilter {
        run_id: Some(a.run.id),
        ..AuditFilter::default()
    };
    let events = audit::list(pool, &filter, None, 100).await.unwrap();
    let calls: Vec<_> = events
        .iter()
        .filter(|e| e.action.starts_with("mcp."))
        .collect();
    assert_eq!(calls.len(), 2, "{events:?}");
    assert!(calls.iter().all(|e| e.actor == AuditActor::Agent(a.agent)));
    assert_eq!(calls[0].action, "mcp.get_issue");
    assert!(calls[0].details.contains("\"ok\":false"));
    assert_eq!(calls[1].action, "mcp.comment");
    assert!(calls[1].details.contains("\"ok\":true"));
    // The scope comes from the stored run, not from anything the agent says.
    let scope = authorize_run_token(pool, a.token.expose(), NOW)
        .await
        .unwrap();
    assert_eq!(scope, a.scope());
}
