//! Runner control from the App: the policy a runner runs with (`PUT /runners/{id}/policy`) and the
//! install of a tool on a runner's host (`POST /runners/{id}/tools`, polled at
//! `GET /runners/{id}/tools/operations/{op}`). Both are admin plus a step-up: they change what runs
//! on a machine. The commands go to the runner over its proven channel (`runner.policy`,
//! `tools.install`, `tools.status`; `ainkrad_proto::v2::control`).
//!
//! An install is followed by one task per operation, which polls the runner's `tools.status` once a
//! second and writes a `runner.tool_install` event each time the percent, the step or the state
//! changes. Operations live in memory (a Core restart forgets them; the runner keeps its last 16).

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ainkrad_core::audit::{AuditEntity, NewAuditEvent};
use ainkrad_proto::v2::{
    Body, Command, ErrorCode, MAX_AGENT_CAPACITY, Reply, RunnerPolicy, StreamError, Tool,
    ToolOpState, ToolsInstall, ToolsStatus, ToolsStatusReq,
};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;

use super::runners::{failed, one};
use super::types::{Timestamp, ts};
use super::{ApiError, BY, Caller};
use crate::api::App;
use crate::auth::crypto::{is_id, random_id};
use crate::hub::Elevated;
use crate::scheduler::iso_of_unix;

/// Audit actions and event kinds (`store::kinds`).
pub const POLICY_SET: &str = "runner.policy_set";
pub const TOOL_INSTALL: &str = "runner.tool_install";
pub const POLICY_EVENT: &str = "runner.policy";

/// How long the runner gets to check and save a policy (its agent check runs a self-test).
const POLICY_WAIT: Duration = Duration::from_secs(60);
/// How long a runner may be unreachable while it installs before the operation is given up.
const LOST_AFTER: Duration = Duration::from_secs(120);
/// No install runs longer than this, whatever the runner says.
const OP_LIMIT: Duration = Duration::from_secs(35 * 60);
const POLL: Duration = Duration::from_secs(1);
/// Operations kept for polling.
const KEEP: usize = 64;

/// What a runner offers: terminals, agents, and how many agent sessions at once.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RunnerPolicyBody {
    /// Terminals are offered on the runner.
    pub terminals: bool,
    /// Agent sessions are offered. Refused (409 `policy_refused`, with the reason) when the
    /// runner cannot run them: no process sandbox, no proven egress filter, or no agent tool installed.
    pub agents: bool,
    /// How many agent sessions run at once, 1 to 8.
    pub agent_capacity: u32,
}

impl From<RunnerPolicy> for RunnerPolicyBody {
    fn from(p: RunnerPolicy) -> Self {
        Self {
            terminals: p.terminals,
            agents: p.agents,
            agent_capacity: p.agent_capacity,
        }
    }
}

/// The answer to a policy change.
#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyResult {
    /// The policy now saved on the runner.
    pub policy: Option<RunnerPolicyBody>,
    /// The runner is restarting to apply it: it is offline for a few seconds and then reports the
    /// new policy in `GET /runners` (`policy`). False when nothing it runs changed.
    pub restarting: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InstallToolBody {
    /// `claude`, `codex`, `node`, `git`, `python`, `go`, `rust` or `docker`.
    pub tool: String,
}

/// One tool install, from start to its end.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ToolOperation {
    /// The operation's id, `op_…`.
    pub op: Option<String>,
    /// The runner's device id.
    pub runner: Option<String>,
    pub tool: Option<String>,
    /// `running`, `done` or `failed`.
    pub state: Option<String>,
    /// 0 to 100.
    pub percent: Option<u8>,
    /// What it is doing now, a short sentence.
    pub step: Option<String>,
    /// Why it failed (`state` `failed`).
    pub reason: Option<String>,
    /// When `done`: the tools the runner found after the install, name to version.
    pub tools: Option<BTreeMap<String, String>>,
    pub started_at: Option<Timestamp>,
}

#[derive(Debug, Clone)]
struct Op {
    runner: String,
    started: i64,
    status: ToolsStatus,
    reason: Option<String>,
}

impl Op {
    fn state(&self) -> &'static str {
        match self.status.state {
            ToolOpState::Running => "running",
            ToolOpState::Done => "done",
            ToolOpState::Failed => "failed",
        }
    }

    fn view(&self) -> ToolOperation {
        ToolOperation {
            op: Some(self.status.operation.clone()),
            runner: Some(self.runner.clone()),
            tool: Some(self.status.tool.name().to_owned()),
            state: Some(self.state().to_owned()),
            percent: Some(self.status.percent),
            step: Some(self.status.step.clone()),
            reason: self.reason.clone(),
            tools: (!self.status.tools.is_empty()).then(|| self.status.tools.clone()),
            started_at: Some(ts(&iso_of_unix(self.started))),
        }
    }

    fn event(&self) -> Value {
        let mut v = serde_json::to_value(self.view()).unwrap_or_default();
        if let Some(o) = v.as_object_mut() {
            o.remove("started_at");
        }
        v
    }
}

/// The operations in flight and the last ones.
#[derive(Default)]
pub struct ToolOps(Mutex<HashMap<String, Op>>);

impl ToolOps {
    fn running_on(&self, runner: &str) -> bool {
        let ops = self.0.lock().unwrap();
        ops.values()
            .any(|o| o.runner == runner && o.status.state == ToolOpState::Running)
    }

    fn put(&self, op: Op) {
        let mut ops = self.0.lock().unwrap();
        if ops.len() >= KEEP
            && let Some(oldest) = ops
                .iter()
                .filter(|(_, o)| o.status.state != ToolOpState::Running)
                .min_by_key(|(_, o)| o.started)
                .map(|(k, _)| k.clone())
        {
            ops.remove(&oldest);
        }
        ops.insert(op.status.operation.clone(), op);
    }

    fn get(&self, id: &str) -> Option<Op> {
        self.0.lock().unwrap().get(id).cloned()
    }
}

async fn emit(app: &App, kind: &str, payload: Value) {
    let written = async {
        let mut tx = crate::store::begin_write(&app.pool).await?;
        crate::store::events::append(&mut tx, kind, &payload).await?;
        tx.commit().await
    };
    if let Err(e) = written.await {
        tracing::error!(error = %e, kind, "writing a runner event failed");
    }
}

async fn audit(
    app: &App,
    me: &Caller,
    device_seq: i64,
    action: &str,
    details: Value,
) -> Result<(), ApiError> {
    let event = NewAuditEvent {
        actor: BY,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "device".to_owned(),
            id: device_seq,
        }),
        details: json!({"by_device": me.device.id, "detail": details}).to_string(),
    };
    crate::store::audit::append_one(&app.pool, &event).await?;
    Ok(())
}

/// Sends `command` and waits for its answer.
async fn ask(
    app: &App,
    runner: &str,
    command: Command,
    proof: Elevated,
    wait: Duration,
) -> Result<Reply, StreamError> {
    let sent = app.hub.dispatch_elevated(runner, command, proof)?;
    match tokio::time::timeout(wait, sent.outcome()).await {
        Ok(Ok(Body::Result(r))) => Ok(r),
        Ok(Ok(other)) => Err(StreamError::new(
            ErrorCode::BadFrame,
            format!("unexpected answer {other:?}"),
        )),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(StreamError::new(
            ErrorCode::Lost,
            "the runner did not answer in time",
        )),
    }
}

#[utoipa::path(put, path = "/api/v1/runners/{id}/policy", operation_id = "setRunnerPolicy",
    tag = "runners",
    params(("id" = String, Path, description = "The runner's device id, `d_…`")),
    request_body = RunnerPolicyBody,
    responses((status = 200, description = "The runner saved the policy (audited as \
        `runner.policy_set`, and a `runner.policy` event) and restarts itself to apply it when it \
        changes what runs; `GET /runners` then reports it in `policy` once it is back. It \
        interrupts the agent sessions and, when terminals go off, closes the terminals running on that runner. 400 for \
        an `agent_capacity` outside 1 to 8; 409 `policy_refused` (the reason is the message) when \
        `agents` is true and the runner cannot run them, `runner_offline`, `unsupported_command` \
        (a runner without runner control), 502 `runner_failed`, 504 `runner_lost`. Needs `admin` and a \
        step-up", body = PolicyResult)))]
pub async fn set_policy(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<RunnerPolicyBody>,
) -> Result<Json<PolicyResult>, ApiError> {
    let d = one(&app, &id).await?;
    if !(1..=MAX_AGENT_CAPACITY).contains(&b.agent_capacity) {
        return Err(ApiError::bad_request(format!(
            "agent_capacity must be from 1 to {MAX_AGENT_CAPACITY}"
        )));
    }
    let policy = RunnerPolicy {
        terminals: b.terminals,
        agents: b.agents,
        agent_capacity: b.agent_capacity,
    };
    let proof = app.hub.admin_elevation(&me);
    let applied = match ask(&app, &id, Command::RunnerPolicy(policy), proof, POLICY_WAIT).await {
        Ok(Reply::RunnerPolicy(a)) => a,
        Ok(_) => {
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                "runner_failed",
                "unexpected answer",
            ));
        }
        Err(e) if e.code == ErrorCode::InvalidArgs => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "policy_refused",
                e.message,
            ));
        }
        Err(e) => return Err(failed(&e)),
    };
    let body = RunnerPolicyBody::from(applied.policy);
    audit(
        &app,
        &me,
        d.seq,
        POLICY_SET,
        json!({"runner": id, "terminals": body.terminals, "agents": body.agents,
            "agent_capacity": body.agent_capacity, "restarting": applied.restarting}),
    )
    .await?;
    emit(
        &app,
        POLICY_EVENT,
        json!({"runner": id, "terminals": body.terminals, "agents": body.agents,
            "agent_capacity": body.agent_capacity, "restarting": applied.restarting}),
    )
    .await;
    Ok(Json(PolicyResult {
        policy: Some(body),
        restarting: Some(applied.restarting),
    }))
}

#[utoipa::path(post, path = "/api/v1/runners/{id}/tools", operation_id = "installRunnerTool",
    tag = "runners",
    params(("id" = String, Path, description = "The runner's device id, `d_…`")),
    request_body = InstallToolBody,
    responses((status = 202, description = "The install started on the runner's host (audited as \
        `runner.tool_install`). Follow it with `runner.tool_install` events (`op`, `runner`, \
        `tool`, `state` `running`/`done`/`failed`, `percent`, `step`, `reason`, and on `done` the \
        `tools` the runner found) or by polling `GET /runners/{id}/tools/operations/{op}`. A tool \
        installs one at a time per runner; the runner reports it in `tools` when done. Linux runners set up \
        by the installer only. 400 for a tool that is not listed; 409 `install_running`, \
        `runner_offline`, `unsupported_command`; 503 `runner_busy`. Needs `admin` and a step-up",
        body = ToolOperation)))]
pub async fn install_tool(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<InstallToolBody>,
) -> Result<(StatusCode, Json<ToolOperation>), ApiError> {
    let d = one(&app, &id).await?;
    let tool = Tool::ALL
        .into_iter()
        .find(|t| t.name() == b.tool)
        .ok_or_else(|| {
            ApiError::bad_request(
                "tool must be claude, codex, node, git, python, go, rust or docker",
            )
        })?;
    if app.hub.runners().get(&id).and_then(|r| r.os.as_deref()) == Some("macos") {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "unsupported_command",
            "tools are installed on Linux runners only",
        ));
    }
    if app.tool_ops.running_on(&id) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "install_running",
            "another install is running on this runner",
        ));
    }
    let op = random_id("op_");
    let proof = app.hub.admin_elevation(&me);
    let first = match ask(
        &app,
        &id,
        Command::ToolsInstall(ToolsInstall {
            operation: op.clone(),
            tool,
        }),
        proof,
        Duration::from_secs(20),
    )
    .await
    {
        Ok(Reply::ToolsStatus(s)) => s,
        Ok(_) => {
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                "runner_failed",
                "unexpected answer",
            ));
        }
        Err(e) if e.code == ErrorCode::Busy && e.message.contains("install") => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "install_running",
                e.message,
            ));
        }
        Err(e) => return Err(failed(&e)),
    };
    let record = Op {
        runner: id.clone(),
        started: app.clock.unix(),
        status: first,
        reason: None,
    };
    app.tool_ops.put(record.clone());
    audit(
        &app,
        &me,
        d.seq,
        TOOL_INSTALL,
        json!({"runner": id, "tool": tool.name(), "op": op}),
    )
    .await?;
    emit(&app, TOOL_INSTALL, record.event()).await;
    let view = record.view();
    tokio::spawn(follow(app.clone(), op, record, proof));
    Ok((StatusCode::ACCEPTED, Json(view)))
}

/// Polls the runner until the install ends, keeping the record and writing the events.
async fn follow(app: App, op: String, mut rec: Op, proof: Elevated) {
    let began = Instant::now();
    let mut lost_since: Option<Instant> = None;
    let mut shown = (
        rec.status.percent,
        rec.status.step.clone(),
        rec.status.state,
    );
    while rec.status.state == ToolOpState::Running {
        tokio::time::sleep(POLL).await;
        let asked = ask(
            &app,
            &rec.runner,
            Command::ToolsStatus(ToolsStatusReq {
                operation: op.clone(),
            }),
            proof,
            Duration::from_secs(15),
        )
        .await;
        match asked {
            Ok(Reply::ToolsStatus(s)) => {
                lost_since = None;
                rec.reason = s.reason.clone();
                rec.status = s;
            }
            // The runner restarted and forgot the operation, or the Core cannot reach it for too long.
            Err(e) if e.code == ErrorCode::InvalidArgs => {
                fail(&mut rec, "the runner restarted during the install");
            }
            Ok(_) | Err(_) => {
                let since = *lost_since.get_or_insert_with(Instant::now);
                if since.elapsed() > LOST_AFTER {
                    fail(&mut rec, "lost contact with the runner during the install");
                }
            }
        }
        if began.elapsed() > OP_LIMIT && rec.status.state == ToolOpState::Running {
            fail(&mut rec, "the install took too long");
        }
        app.tool_ops.put(rec.clone());
        let now = (
            rec.status.percent,
            rec.status.step.clone(),
            rec.status.state,
        );
        if now != shown {
            shown = now;
            emit(&app, TOOL_INSTALL, rec.event()).await;
        }
    }
    if rec.status.state == ToolOpState::Done {
        app.hub.merge_tools(&rec.runner, &rec.status.tools);
    }
}

fn fail(rec: &mut Op, why: &str) {
    rec.status.state = ToolOpState::Failed;
    rec.reason = Some(why.to_owned());
    rec.status.reason = rec.reason.clone();
}

#[utoipa::path(get, path = "/api/v1/runners/{id}/tools/operations/{op}",
    operation_id = "getRunnerToolOperation", tag = "runners",
    params(("id" = String, Path, description = "The runner's device id, `d_…`"),
        ("op" = String, Path, description = "The operation id, `op_…`")),
    responses((status = 200, description = "The install's state now. The Core keeps the last 64 \
        operations in memory (a Core restart forgets them: 404)", body = ToolOperation)))]
pub async fn get_operation(
    State(app): State<App>,
    Path((id, op)): Path<(String, String)>,
) -> Result<Json<ToolOperation>, ApiError> {
    one(&app, &id).await?;
    let found = is_id(&op, "op_").then(|| app.tool_ops.get(&op)).flatten();
    found
        .filter(|o| o.runner == id)
        .map(|o| Json(o.view()))
        .ok_or_else(|| ApiError::not_found("no such operation"))
}
