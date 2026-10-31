//! Shared fixtures of the MCP tests: a Core with Citadel mounted, companies with a started run,
//! run tokens and JSON-RPC helpers.
#![allow(dead_code, unused_imports)]

use std::sync::Arc;

use crate::common::*;
use crate::work_seed::{Seed, seed};
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
use serde_json::{Value, json};
use tower::ServiceExt;

pub const MCP: &str = "/token/citadel/v1/mcp";

/// A host that records the session it would start, owned and pointing at its run, as the
/// platform does.
pub struct Fake(String);

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
pub struct Co {
    pub seed: Seed,
    pub run: engine::Run,
}

pub async fn company(fx: &Fx, host: &Fake, name: &str, key: &str) -> Co {
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

pub struct W {
    pub fx: Fx,
    pub host: Fake,
}

pub async fn set(app: &App, name: &str, value: &str) {
    citadel_module::settings::handle()
        .set(&app.pool, name, value, AuditActor::System, &app.clock.now())
        .await
        .unwrap();
}

pub async fn world() -> W {
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
    pub async fn co(&self, name: &str, key: &str) -> Co {
        company(&self.fx, &self.host, name, key).await
    }

    pub async fn token(&self, run: RunId) -> String {
        engine::issue_run_token(&self.fx.app.pool, run, &self.fx.app.clock.now())
            .await
            .unwrap()
            .expose()
            .to_owned()
    }
}

pub fn post(token: Option<&str>, uri: &str) -> axum::http::request::Builder {
    let mut req = Request::post(uri)
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    req
}

pub async fn send(app: &App, req: Request<Body>) -> (StatusCode, Value) {
    let res = router(app.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

pub async fn rpc(app: &App, token: Option<&str>, body: Value) -> (StatusCode, Value) {
    send(
        app,
        post(token, MCP).body(Body::from(body.to_string())).unwrap(),
    )
    .await
}

pub fn tool(name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
}

pub fn list() -> Value {
    json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
}

/// The tool's answer: whether it failed, and its text.
pub fn answer(reply: &Value) -> (bool, String) {
    (
        reply["result"]["isError"] == true,
        reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    )
}

pub async fn count(app: &App, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&app.pool)
        .await
        .unwrap()
}
