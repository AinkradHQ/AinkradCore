//! Agent sessions (E2-08, `crate::agents`): create, list, read, transcript, message, decide a
//! tool approval, cancel, kill and resume. Scope `agent` (a decision `approve`); everything that
//! runs code or hands out secrets (create, message, resume) and everything that stops one
//! (cancel, kill) needs a step-up (`scopes::DESTRUCTIVE`).
//!
//! No route returns a lease or a value: a session's secrets are listed by name. The prompt and
//! messages are the caller's own and go to the runner; audit rows name the session, never them.
//! Bodies are parsed here, like the secrets', so a refusal never quotes one.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::agents::{self, Refusal};
use crate::api::App;
use crate::auth::crypto::is_id;
use crate::store::agents::{self as store, Session, SessionSecret};
use ainkrad_proto::v2::{AgentDecide, AgentSend, AgentStop, Command};

const MAX_PROMPT: usize = 64 * 1024;
const MAX_MESSAGE: usize = 16 * 1024;
const MAX_SECRETS: usize = 16;

/// Tokens used, as the harness reported them.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentUsage {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    /// Millionths of a US dollar, when the harness says.
    pub cost_usd_micros: Option<u64>,
}

/// An agent session: a harness on a runner.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentSession {
    /// `as_…`.
    pub id: String,
    /// The runner's device id, `d_…`.
    pub runner: String,
    pub harness: String,
    pub model: Option<String>,
    /// `starting`, `running`, `interrupted` (its runner restarted; it is resumed), `ended`,
    /// `lost`.
    pub state: String,
    /// The harness's own session id, what a resume continues.
    pub harness_session: Option<String>,
    /// The newest transcript `seq` stored.
    pub last_seq: i64,
    /// Once over: `{"kind": "succeeded" | "failed" | "cancelled" | "token_cap" | "stalled" |
    /// "lost", "reason": …}`.
    #[schema(value_type = Option<Object>)]
    pub outcome: Option<Value>,
    pub usage: Option<AgentUsage>,
    /// How many times it was resumed.
    pub resumes: Option<i64>,
    /// The secrets it is leased at each start, by name.
    pub secrets: Option<Vec<String>>,
    /// Its row: page `listAgentSessions` with `before`.
    pub index: Option<i64>,
    pub created_by: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub ended_at: Option<Timestamp>,
}

impl From<Session> for AgentSession {
    fn from(s: Session) -> Self {
        Self {
            id: s.id,
            runner: s.runner,
            harness: s.harness,
            model: s.model,
            state: s.state,
            harness_session: s.harness_session,
            last_seq: s.last_seq,
            outcome: s.outcome,
            usage: Some(AgentUsage {
                input: s.usage.input,
                output: s.usage.output,
                cache_read: s.usage.cache_read,
                cache_write: s.usage.cache_write,
                cost_usd_micros: s.usage.cost_usd_micros,
            }),
            resumes: Some(s.resumes),
            secrets: Some(s.secrets.into_iter().map(|x| x.name).collect()),
            index: Some(s.n),
            created_by: s.created_by,
            created_at: ts(&s.created_at),
            updated_at: ts(&s.updated_at),
            ended_at: s.ended_at.as_deref().map(ts),
        }
    }
}

/// A secret for the session: the broker's secret `name`, delivered under `var`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AgentSecret {
    pub name: String,
    /// `[A-Z_][A-Z0-9_]*`, not `PATH`, `HOME` or a loader's: the value (`env` delivery), the
    /// path of a 0600 file holding it (`file`), or of an askpass helper (`askpass`).
    pub var: String,
}

/// A session to start. No `Debug`: the prompt is the caller's.
#[derive(Deserialize, ToSchema)]
pub struct NewAgentSession {
    /// The runner's device id, `d_…`.
    pub runner: String,
    /// `claude`, `codex`, `opencode`, `agy` (what the runner's `agent` driver takes).
    pub harness: String,
    pub model: Option<String>,
    pub prompt: Option<String>,
    /// The repo and worktree to work in (`{"repo_url", "base_branch", "branch", …}`); absent, a
    /// scratch dir.
    #[schema(value_type = Option<Object>)]
    pub workspace: Option<Value>,
    /// `{"mode": "ask" | "accept_edits" | "sandboxed", "allow": […]}`; default `ask`.
    #[schema(value_type = Option<Object>)]
    pub policy: Option<Value>,
    /// At most 16. Each is leased to the runner at each start (secrets broker, gate G-SEC).
    pub secrets: Option<Vec<AgentSecret>>,
}

#[derive(Deserialize, ToSchema)]
pub struct AgentMessage {
    pub text: String,
}

#[derive(Deserialize, ToSchema)]
pub struct AgentDecision {
    pub approved: bool,
    /// Told to the agent; a denial's reason.
    pub reply: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AgentTranscriptEntry {
    /// From 1, by one: replay from any `seq` with `after`.
    pub seq: u64,
    /// Unix milliseconds, on the runner.
    pub at_ms: i64,
    /// A harness event, or the session's own (`started`, `message`, `approval_request`,
    /// `approval_decided`, `interrupted`, `gap`, `ended`), redacted.
    #[schema(value_type = Object)]
    pub body: Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AgentTranscript {
    pub session: String,
    pub state: String,
    pub last_seq: i64,
    pub entries: Vec<AgentTranscriptEntry>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct Before {
    /// Sessions with an `index` below this; absent, from the newest.
    pub before: Option<i64>,
    pub limit: Option<u32>,
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|_| ApiError::bad_request("the body is not a valid request for this route"))
}

impl From<Refusal> for ApiError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::Runner(e) => super::runners::failed(&e),
            Refusal::Secrets(e) => e.into(),
            Refusal::Db(e) => e.into(),
        }
    }
}

async fn one(app: &App, id: &str) -> Result<Session, ApiError> {
    let found = match is_id(id, "as_") {
        true => store::get(&app.pool, id).await?,
        false => None,
    };
    found.ok_or_else(|| ApiError::not_found("no such agent session"))
}

fn harness_ok(h: &str) -> bool {
    (1..=32).contains(&h.len())
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

#[utoipa::path(post, path = "/api/v1/agent-sessions", operation_id = "createAgentSession",
    tag = "agents",
    request_body = NewAgentSession,
    responses((status = 200, description = "Started on the runner (`running`), or `starting` \
        while the runner is away (audited as `agent.created`). 409 `runner_offline` or \
        `unsupported_command` (no agent driver), 503 `runner_busy` (its capacity or the \
        harness's slot is full), the secrets broker's refusals (`secrets_disabled`, \
        `limit_reached`, 400 when the runner is not in a secret's scope)", body = AgentSession)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<AgentSession> {
    let b: NewAgentSession = parse(&body)?;
    if !is_id(&b.runner, "d_") {
        return Err(ApiError::bad_request("runner is a runner's device id, d_…"));
    }
    if !harness_ok(&b.harness) {
        return Err(ApiError::bad_request("harness is [a-z0-9_-]{1,32}"));
    }
    if b.prompt.as_ref().is_some_and(|p| p.len() > MAX_PROMPT)
        || b.model.as_ref().is_some_and(|m| m.len() > 128)
    {
        return Err(ApiError::bad_request(
            "the prompt (64 KiB) or model is too long",
        ));
    }
    let secrets: Vec<SessionSecret> = b
        .secrets
        .unwrap_or_default()
        .into_iter()
        .map(|s| SessionSecret {
            name: s.name,
            var: s.var,
        })
        .collect();
    if secrets.len() > MAX_SECRETS
        || secrets.iter().any(|s| {
            !crate::store::secrets::valid_name(&s.name)
                || !ainkrad_proto::v2::valid_secret_var(&s.var)
        })
    {
        return Err(ApiError::bad_request(
            "at most 16 secrets, each a secret's name and a variable [A-Z_][A-Z0-9_]* the runner \
             does not set itself",
        ));
    }
    if !secrets.is_empty() && !me.device.scopes.iter().any(|scope| scope == "admin") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "naming broker secrets requires the admin scope",
        ));
    }
    let workspace_ok = b.workspace.as_ref().is_none_or(|w| {
        serde_json::from_value::<ainkrad_proto::runner::Workspace>(w.clone())
            .is_ok_and(|workspace| workspace.problem().is_none())
    });
    let policy = b.policy.unwrap_or_else(|| {
        serde_json::to_value(ainkrad_proto::runner::Policy::default()).expect("a policy serializes")
    });
    if !workspace_ok
        || serde_json::from_value::<ainkrad_proto::runner::Policy>(policy.clone()).is_err()
    {
        return Err(ApiError::bad_request(
            "workspace or policy does not have its shape",
        ));
    }
    agents::admit(&app, &b.runner, &b.harness).await?;
    let new = store::NewSession {
        runner: &b.runner,
        harness: &b.harness,
        model: b.model.as_deref(),
        prompt: b.prompt.as_deref(),
        workspace: b.workspace.as_ref(),
        policy: &policy,
        secrets: &secrets,
        created_by: &me.device.id,
    };
    let s = store::create(&app.pool, &new, BY, &app.clock.now()).await?;
    agents::authorize_create(&app, &me, &s.id);
    agents::start(&app, &s).await?;
    Ok(Json(one(&app, &s.id).await?.into()))
}

#[utoipa::path(get, path = "/api/v1/agent-sessions", operation_id = "listAgentSessions",
    tag = "agents", params(Before),
    responses((status = 200, description = "Sessions, newest first (at most `limit`, 50 by \
        default, 200 at most)", body = Vec<AgentSession>)))]
pub async fn list(State(app): State<App>, Query(q): Query<Before>) -> ApiResult<Vec<AgentSession>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let all = store::list(&app.pool, q.before, limit).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(get, path = "/api/v1/agent-sessions/{id}", operation_id = "getAgentSession",
    tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`")),
    responses((status = 200, description = "One session", body = AgentSession)))]
pub async fn get(State(app): State<App>, Path(id): Path<String>) -> ApiResult<AgentSession> {
    Ok(Json(one(&app, &id).await?.into()))
}

#[utoipa::path(get, path = "/api/v1/agent-sessions/{id}/transcript",
    operation_id = "getAgentTranscript", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`"), super::Paging),
    responses((status = 200, description = "Entries with `seq` above `after`, oldest first, at \
        most `limit` (500 by default, 1000 at most); the `agent.transcript` events say when \
        there are more", body = AgentTranscript)))]
pub async fn transcript(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(p): Query<super::Paging>,
) -> ApiResult<AgentTranscript> {
    let s = one(&app, &id).await?;
    let limit = p.limit.unwrap_or(500).clamp(1, 1000);
    let entries = store::transcript(&app.pool, &s.id, p.after.unwrap_or(0), limit).await?;
    Ok(Json(AgentTranscript {
        session: s.id,
        state: s.state,
        last_seq: s.last_seq,
        entries: entries
            .into_iter()
            .map(|e| AgentTranscriptEntry {
                seq: e.seq,
                at_ms: e.at,
                body: e.body,
            })
            .collect(),
    }))
}

/// Sends `command` about `s` to its runner (answer within the service's wait).
async fn tell(app: &App, s: &Session, command: Command, caller: &Caller) -> Result<(), ApiError> {
    if !s.live() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "session_over",
            "the session is over",
        ));
    }
    let ev = agents::ask(
        app,
        &s.runner,
        command,
        app.agents.config.answer,
        Some(app.hub.agent_elevation(caller)),
    )
    .await
    .map_err(|e| super::runners::failed(&e))?;
    store::apply(&app.pool, &s.id, &ev, &app.clock.now()).await?;
    Ok(())
}

#[utoipa::path(post, path = "/api/v1/agent-sessions/{id}/messages",
    operation_id = "sendAgentMessage", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`")),
    request_body = AgentMessage,
    responses((status = 200, description = "Given to the harness as its next turn (audited as \
        `agent.messaged`, its length only). 409 `session_over`, 502 `runner_failed` when it \
        is not running", body = AgentSession)))]
pub async fn message(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<AgentSession> {
    let s = one(&app, &id).await?;
    let b: AgentMessage = parse(&body)?;
    if b.text.is_empty() || b.text.len() > MAX_MESSAGE {
        return Err(ApiError::bad_request("a message is 1 byte to 16 KiB"));
    }
    let bytes = b.text.len();
    tell(
        &app,
        &s,
        Command::AgentSend(AgentSend {
            session: s.id.clone(),
            text: b.text,
        }),
        &me,
    )
    .await?;
    let details = json!({"bytes": bytes});
    store::action(
        &app.pool,
        &s,
        BY,
        "agent.messaged",
        Some("agent.message"),
        details,
        &me.device.id,
    )
    .await?;
    Ok(Json(one(&app, &id).await?.into()))
}

/// A tool request id as harnesses make them.
fn request_ok(r: &str) -> bool {
    (1..=128).contains(&r.len())
        && r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

#[utoipa::path(post, path = "/api/v1/agent-sessions/{id}/approvals/{request}",
    operation_id = "decideAgentApproval", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`"),
        ("request" = String, Path, description = "The `id` of its `approval_request` entry")),
    request_body = AgentDecision,
    responses((status = 200, description = "The waiting tool call is allowed or denied, from any \
        device with `approve` (audited as `agent.decided`). 502 `runner_failed` when no such \
        request waits", body = AgentSession)))]
pub async fn decide(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, request)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<AgentSession> {
    let s = one(&app, &id).await?;
    if !request_ok(&request) {
        return Err(ApiError::not_found("no such tool request"));
    }
    let b: AgentDecision = parse(&body)?;
    let cmd = Command::AgentDecide(AgentDecide {
        session: s.id.clone(),
        request: request.clone(),
        approved: b.approved,
        reply: b.reply,
    });
    tell(&app, &s, cmd, &me).await?;
    let details = json!({"request": request, "approved": b.approved});
    let kind = Some("agent.approval_decided");
    store::action(
        &app.pool,
        &s,
        BY,
        "agent.decided",
        kind,
        details,
        &me.device.id,
    )
    .await?;
    Ok(Json(one(&app, &id).await?.into()))
}

async fn stop(app: App, me: Caller, id: String, kill: bool) -> ApiResult<AgentSession> {
    let s = one(&app, &id).await?;
    tell(
        &app,
        &s,
        Command::AgentStop(AgentStop {
            session: s.id.clone(),
            kill,
        }),
        &me,
    )
    .await?;
    let action = if kill {
        "agent.killed"
    } else {
        "agent.cancelled"
    };
    store::action(&app.pool, &s, BY, action, None, json!({}), &me.device.id).await?;
    Ok(Json(one(&app, &id).await?.into()))
}

#[utoipa::path(post, path = "/api/v1/agent-sessions/{id}/cancel",
    operation_id = "cancelAgentSession", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`")),
    responses((status = 200, description = "Its tool call in flight finishes, then it ends \
        (killed after the runner's grace; audited as `agent.cancelled`)", body = AgentSession)))]
pub async fn cancel(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AgentSession> {
    stop(app, me, id, false).await
}

#[utoipa::path(post, path = "/api/v1/agent-sessions/{id}/kill",
    operation_id = "killAgentSession", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`")),
    responses((status = 200, description = "Its harness is killed now and its delivered secrets \
        removed (audited as `agent.killed`)", body = AgentSession)))]
pub async fn kill(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AgentSession> {
    stop(app, me, id, true).await
}

#[utoipa::path(post, path = "/api/v1/agent-sessions/{id}/resume",
    operation_id = "resumeAgentSession", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`")),
    responses((status = 200, description = "A `lost` or `interrupted` session is started again \
        on its runner, continuing the harness's own session, with fresh leases (audited as \
        `agent.resumed`). 409 `not_resumable` otherwise", body = AgentSession)))]
pub async fn resume(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AgentSession> {
    let s = one(&app, &id).await?;
    if !store::reopen(&app.pool, &s.id, &app.clock.now()).await? {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "not_resumable",
            "only a lost or interrupted session is resumed",
        ));
    }
    store::action(
        &app.pool,
        &s,
        BY,
        "agent.resumed",
        None,
        json!({}),
        &me.device.id,
    )
    .await?;
    agents::supervise(&app, &s.id);
    Ok(Json(one(&app, &id).await?.into()))
}
