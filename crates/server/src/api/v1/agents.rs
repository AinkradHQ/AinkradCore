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
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use utoipa::ToSchema;

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::agents;
use crate::api::App;
use crate::auth::crypto::is_id;
use crate::store::agents::{self as store, Session, SessionSecret};
use ainkrad_proto::v2::{AgentDecide, AgentSend, AgentStop, Command};

pub(super) mod access;
pub(in crate::api::v1) mod sched;
mod types;
use sched::{AgentWaiting, create_named, listed, page, shown};
use types::*;

const MAX_MESSAGE: usize = 16 * 1024;

/// An agent session: a harness on a runner.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentSession {
    /// `as_…`.
    pub id: String,
    /// The runner's device id, `d_…`.
    pub runner: String,
    pub harness: String,
    pub model: Option<String>,
    /// `starting`, `running` (working), `waiting` (a live session finished its answer and waits
    /// for the user's next message; it still holds its runner slot), `interrupted` (its runner
    /// restarted; it is resumed), `ended`, `lost`.
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
    /// The opaque agent id the create named (the key of its chain binding).
    pub agent: Option<String>,
    /// The chain the run draws its accounts from; absent for a session that names its account
    /// itself or uses the runner's own login.
    pub chain_id: Option<i64>,
    /// The chain as it was when the session began (an edit never moves a running run).
    pub chain: Option<Vec<super::chains::ChainEntry>>,
    /// The entry of `chain` the run sits on, from 0.
    pub chain_pos: Option<i64>,
    /// The account the session holds, whatever its delivery (an API key or a subscription).
    pub account: Option<i64>,
    /// Set while a chain session waits for an account: it stays `starting` until `until`, or
    /// until `scheduler.wait_max_secs` ends the run.
    pub waiting: Option<AgentWaiting>,
    /// How many accounts a launch refused after the pick before the one it holds (at most 2).
    pub repicked: Option<i64>,
    /// The last status class its own gateway reported: `ok`, `rate_limited`, `quota`,
    /// `server_error`, `auth_failed`, …
    pub upstream_class: Option<String>,
    /// The run it belongs to: its first attempt's id. A failover is a new session (an attempt) of
    /// the same run; filter `listAgentSessions` with `run`.
    pub run: Option<String>,
    /// Which attempt of its run it is, from 0.
    pub attempt: Option<i64>,
    /// The attempt this one replaced.
    pub failover_of: Option<String>,
    /// The attempt that replaced this one.
    pub failed_over_to: Option<String>,
    /// Why the run was moved off this attempt (`rate_limited`, `quota`, `auth`, `budget_pool`, …).
    /// An ended run's last attempt says in `outcome.failover` (`{result, why, reasons}`) why it
    /// could not move on. Admin only.
    pub failover_class: Option<String>,
    /// The pools a budget stop took out of the run's chain. Admin only.
    pub skip_pools: Option<Vec<i64>>,
    /// A live conversation (`createAgentSession`'s `live`): the state is `waiting` between answers.
    pub live: Option<bool>,
    /// While `waiting`: since when.
    pub idle_since: Option<Timestamp>,
    /// A short name: the first message's start, or the one `titleAgentSession` set.
    pub title: Option<String>,
}

impl From<Session> for AgentSession {
    fn from(s: Session) -> Self {
        let state = s.api_state().to_owned();
        Self {
            live: Some(s.conversation),
            idle_since: s
                .waiting_since
                .filter(|_| s.state == "running")
                .map(|t| ts(&crate::scheduler::iso_of_unix(t))),
            title: s.title,
            id: s.id,
            runner: s.runner,
            harness: s.harness,
            model: s.model,
            state,
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
            agent: None,
            chain_id: None,
            chain: None,
            chain_pos: None,
            account: None,
            waiting: None,
            repicked: None,
            upstream_class: None,
            run: None,
            attempt: None,
            failover_of: None,
            failed_over_to: None,
            failover_class: None,
            skip_pools: None,
        }
    }
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|_| ApiError::bad_request("the body is not a valid request for this route"))
}

async fn one(app: &App, me: &Caller, id: &str) -> Result<Session, ApiError> {
    let found = match is_id(id, "as_") {
        true => store::get(&app.pool, id).await?,
        false => None,
    };
    let s = found.ok_or_else(|| ApiError::not_found("no such agent session"))?;
    // Another user's session is no such session, on every route (a read, a write, a stop).
    sched::of_user(app, me, &s).await?;
    Ok(s)
}

/// A session a module drives answers to that module's own routes (its audit, its approvals, its
/// run state): a client's write on it would bypass them, so it is refused.
fn not_a_modules(s: &Session) -> Result<(), ApiError> {
    match &s.owner_module {
        Some(m) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "module_owned",
            format!("the session belongs to the {m} module: use its routes"),
        )),
        None => Ok(()),
    }
}

/// A session that holds leased secrets answers only to its creator or an `admin` device: any
/// other `agent` device could message it into printing the value (B-H1), read what it printed,
/// or resume it to lease the secrets again. The POST routes are step-up routes already.
fn owns_secrets(s: &Session, me: &Caller) -> Result<(), ApiError> {
    let admin = me.device.scopes.iter().any(|scope| scope == "admin");
    if s.secrets.is_empty() || s.created_by == me.device.id || admin {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::FORBIDDEN,
        "forbidden_scope",
        "a session holding secrets answers only to its creator or an admin device",
    ))
}

#[utoipa::path(post, path = "/api/v1/agent-sessions", operation_id = "createAgentSession",
    tag = "agents",
    request_body = NewAgentSession,
    responses((status = 200, description = "Started on the runner (`running`), or `starting` \
        while the runner is away (audited as `agent.created`). 409 `runner_offline` or \
        `unsupported_command` (no agent driver), 503 `runner_busy` (its capacity or the \
        harness's slot is full), the secrets broker's refusals (`secrets_disabled`, \
        `limit_reached`, 400 when the runner is not in a secret's scope). With `chain` or \
        `agent` (admin only, else 403): the session starts with no account and the allocator \
        picks one from the chain (`waiting` while every account cools); 404 for no such chain, \
        400 for a harness, a model or an `acct.*` secret beside a chain. 409 `no_account` for a \
        plain create of claude, codex or agy that names no `acct.*` secret and no credential \
        variable of its own (it would answer \"Not logged in\"). A chain create \
        passes a plain create's checks for the harness of every entry, and the runner must be \
        online with room for at least one entry (else its refusal, 409 or 503), all before \
        any row; an entry the runner cannot serve is skipped at the pick", body = AgentSession)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<AgentSession> {
    let b: NewAgentSession = parse(&body)?;
    let secrets: Vec<SessionSecret> = b
        .secrets
        .unwrap_or_default()
        .into_iter()
        .map(|s| SessionSecret {
            name: s.name,
            var: s.var,
        })
        .collect();
    let policy = b.policy.unwrap_or_else(|| {
        serde_json::to_value(ainkrad_proto::runner::Policy::default()).expect("a policy serializes")
    });
    // An account session (an `acct.*` secret, or a chain/agent the allocator draws one from) runs
    // sandboxed: the Core adds the floor instead of refusing a client that left it out.
    let draws_account = b.chain.is_some() || b.agent.is_some();
    let policy =
        agents::with_account_floor(policy, draws_account || agents::holds_account(&secrets));
    let new = store::NewSession {
        runner: &b.runner,
        harness: &b.harness,
        model: b.model.as_deref(),
        // No first message (absent or empty): the session starts waiting for one.
        prompt: b.prompt.as_deref().filter(|p| !p.is_empty()),
        workspace: b.workspace.as_ref(),
        policy: &policy,
        secrets: &secrets,
        created_by: &me.device.id,
    };
    let admin = me.device.scopes.iter().any(|scope| scope == "admin");
    let access = access::checked(&app, admin, b.connection_access.as_deref())?;
    let s = if b.chain.is_some() || b.agent.is_some() {
        create_named(&app, &me, &new, admin, b.chain, b.agent.as_deref()).await?
    } else {
        agents::validate_new(&new, admin).map_err(|e| match e {
            agents::Invalid::Bad(why) => ApiError::bad_request(why),
            agents::Invalid::Forbidden(why) => {
                ApiError::new(StatusCode::FORBIDDEN, "forbidden_scope", why)
            }
        })?;
        agents::admit_holding(&app, &b.runner, &b.harness, &policy, &secrets).await?;
        if let Some(e) = sched::no_account(&new, sched::own_login(&app, &b.runner, &b.harness)) {
            return Err(e);
        }
        store::create(&app.pool, &new, BY, &app.clock.now()).await?
    };
    // A live conversation, where the runner offers it; titled by its first message.
    let live = b.live.unwrap_or(true) && agents::offers_live(&app, &s.runner);
    let title = s.prompt.as_deref().and_then(store::title_of);
    store::configure(&app.pool, &s.id, live, title.as_deref()).await?;
    let s = Session {
        conversation: live,
        title,
        ..s
    };
    access::apply(&app, &s.id, &access).await?;
    agents::authorize_create(&app, &me, &s.id);
    agents::start(&app, &s).await?;
    shown(&app, &me, &s.id).await
}

#[utoipa::path(get, path = "/api/v1/agent-sessions", operation_id = "listAgentSessions",
    tag = "agents", params(Before),
    responses((status = 200, description = "Sessions, newest first (at most `limit`, 50 by \
        default, 200 at most)", body = Vec<AgentSession>)))]
pub async fn list(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Query(q): Query<Before>,
) -> ApiResult<Vec<AgentSession>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let all = page(&app, q.before, limit, q.run.as_deref()).await?;
    Ok(Json(listed(&app, &me, all).await?))
}

#[utoipa::path(get, path = "/api/v1/agent-sessions/{id}", operation_id = "getAgentSession",
    tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`")),
    responses((status = 200, description = "One session", body = AgentSession)))]
pub async fn get(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AgentSession> {
    shown(&app, &me, &id).await
}

#[utoipa::path(get, path = "/api/v1/agent-sessions/{id}/transcript",
    operation_id = "getAgentTranscript", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`"), super::Paging),
    responses((status = 200, description = "Entries with `seq` above `after`, oldest first, at \
        most `limit` (500 by default, 1000 at most); the `agent.transcript` events say when \
        there are more", body = AgentTranscript)))]
pub async fn transcript(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Query(p): Query<super::Paging>,
) -> ApiResult<AgentTranscript> {
    let s = one(&app, &me, &id).await?;
    owns_secrets(&s, &me)?;
    // What a module's agent saw and did is the module's `admin` read, not an `agent` device's.
    if s.owner_module.is_some() && !me.device.scopes.iter().any(|scope| scope == "admin") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "a module's session transcript requires the admin scope",
        ));
    }
    let limit = p.limit.unwrap_or(500).clamp(1, 1000);
    let entries = store::transcript(&app.pool, &s.id, p.after.unwrap_or(0), limit).await?;
    Ok(Json(AgentTranscript {
        state: s.api_state().to_owned(),
        session: s.id,
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
    not_a_modules(s)?;
    owns_secrets(s, caller)?;
    send(app, s, command, caller).await
}

async fn send(app: &App, s: &Session, command: Command, caller: &Caller) -> Result<(), ApiError> {
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
        `agent.messaged`, its length only). A live session takes it in its running process: \
        `waiting` becomes `running`, and a message sent while an answer runs is queued behind \
        it. A live session whose process is gone (a runner restart, a lost runner, an idle end) \
        is started again with the harness's own resume in the same folder and gets it there, so \
        the conversation goes on. A first message gives an untitled session its `title`. 409 \
        `session_over`, `session_starting` (not on its runner yet), 502 `runner_failed` when it \
        is not running", body = AgentSession)))]
pub async fn message(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<AgentSession> {
    let s = one(&app, &me, &id).await?;
    let b: AgentMessage = parse(&body)?;
    if b.text.is_empty() || b.text.len() > MAX_MESSAGE {
        return Err(ApiError::bad_request("a message is 1 byte to 16 KiB"));
    }
    let bytes = b.text.len();
    let text = b.text;
    store::title_from_first_message(&app.pool, &s.id, &text).await?;
    if s.conversation && s.state != "running" {
        restart_with(&app, &s, &me, &text).await?;
    } else {
        let send = Command::AgentSend(AgentSend {
            session: s.id.clone(),
            text,
        });
        tell(&app, &s, send, &me).await?;
    }
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
    shown(&app, &me, &id).await
}

/// A message for a live session that is not on its runner: kept as `pending` and delivered by its
/// supervisor once the harness runs again (resumed by its own session id, in the session's folder).
async fn restart_with(app: &App, s: &Session, me: &Caller, text: &str) -> Result<(), ApiError> {
    not_a_modules(s)?;
    owns_secrets(s, me)?;
    let conflict =
        |code: &'static str, why: &'static str| Err(ApiError::new(StatusCode::CONFLICT, code, why));
    if s.state == "starting" {
        return conflict("session_starting", "the session is not on its runner yet");
    }
    let over = matches!(s.state.as_str(), "ended" | "lost");
    if over && agents::supervised(app).contains(&s.id) {
        return conflict("session_busy", "the session is still finishing: try again");
    }
    match store::wake(&app.pool, &s.id, Some(text), &app.clock.now()).await? {
        store::Woken::Reopened => {
            agents::authorize_message(app, me, &s.id);
            agents::supervise(app, &s.id);
            Ok(())
        }
        store::Woken::Busy => conflict(
            "account_full",
            "the session's account is full: send again when one of its sessions ends",
        ),
        store::Woken::Gone => conflict("session_over", "the session is over"),
    }
}

#[utoipa::path(post, path = "/api/v1/agent-sessions/{id}/interrupt",
    operation_id = "interruptAgentSession", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`")),
    responses((status = 200, description = "Stops the running answer of a live session, like Esc \
        in the CLI (audited as `agent.interrupted`): a tool call waiting for approval is denied, \
        the session goes on and becomes `waiting` (a message queued behind the answer is taken \
        next). Nothing happens while it waits. 409 `not_live` for a session that is not a live \
        conversation, `session_over`; `cancel` ends the session", body = AgentSession)))]
pub async fn interrupt(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AgentSession> {
    let s = one(&app, &me, &id).await?;
    if !s.conversation {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "not_live",
            "only a live session has an answer to stop: use cancel",
        ));
    }
    let stop = Command::AgentStop(AgentStop {
        session: s.id.clone(),
        kill: false,
        turn: true,
    });
    tell(&app, &s, stop, &me).await?;
    let action = "agent.interrupted";
    store::action(&app.pool, &s, BY, action, None, json!({}), &me.device.id).await?;
    shown(&app, &me, &id).await
}

#[utoipa::path(patch, path = "/api/v1/agent-sessions/{id}",
    operation_id = "titleAgentSession", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`")),
    request_body = AgentTitle,
    responses((status = 200, description = "Sets the session's short `title` (at most 60 \
        characters, trimmed; empty clears it; audited as `agent.renamed`)", body = AgentSession)))]
pub async fn title(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<AgentSession> {
    let s = one(&app, &me, &id).await?;
    let b: AgentTitle = parse(&body)?;
    if b.title.chars().count() > store::MAX_TITLE {
        return Err(ApiError::bad_request("a title is at most 60 characters"));
    }
    not_a_modules(&s)?;
    owns_secrets(&s, &me)?;
    store::set_title(&app.pool, &s.id, &b.title).await?;
    let details = json!({"chars": b.title.chars().count()});
    store::action(
        &app.pool,
        &s,
        BY,
        "agent.renamed",
        None,
        details,
        &me.device.id,
    )
    .await?;
    shown(&app, &me, &id).await
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
    let s = one(&app, &me, &id).await?;
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
    shown(&app, &me, &id).await
}

async fn stop(app: App, me: Caller, id: String, kill: bool) -> ApiResult<AgentSession> {
    let mut s = one(&app, &me, &id).await?;
    let command = |s: &Session| {
        Command::AgentStop(AgentStop {
            session: s.id.clone(),
            kill,
            turn: false,
        })
    };
    if s.owner_module.is_some() && kill {
        // Break-glass: a runaway harness of a module whose own routes cannot stop it (the module
        // is gone, its run row lost). Kill only, and only an admin.
        if !me.device.scopes.iter().any(|scope| scope == "admin") {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "forbidden_scope",
                "killing a module's session requires the admin scope",
            ));
        }
        send(&app, &s, command(&s), &me).await?;
    } else {
        not_a_modules(&s)?;
        owns_secrets(&s, &me)?;
        // A person's stop ends the run, and the one to stop is its newest attempt (a failover may have
        // replaced the one the person knows): found without writing, checked, and only then is the
        // whole run settled so no attempt of it moves on.
        let newest = crate::store::failover::newest(&app.pool, &s.id).await?;
        if newest != s.id {
            s = one(&app, &me, &newest).await?;
            owns_secrets(&s, &me)?;
        }
        // Settled before the stop so no move slips in; opened again if the stop never reaches the
        // runner (it is offline): the run is then no more cancelled than it was.
        let cancelled = crate::store::failover::cancel_run(&app.pool, &s.id).await?;
        let moved = cancelled.newest != s.id;
        if moved {
            s = one(&app, &me, &cancelled.newest).await?;
        }
        let stopped = async {
            if moved {
                owns_secrets(&s, &me)?;
            }
            // An attempt that is over has nothing to stop: the cancel stands (the run is settled).
            if !s.live() {
                return Ok::<(), ApiError>(());
            }
            // A chain session that never reached its runner (waiting for an account, or picked and not
            // started) is ended here: the runner has nothing to stop.
            if !crate::store::alloc::end_unstarted(&app.pool, &s.id, &app.clock.now()).await? {
                send(&app, &s, command(&s), &me).await?;
            }
            Ok(())
        }
        .await;
        if let Err(e) = stopped {
            // Opened again only when a stop to a harness that is still live did not get through; one
            // that ended meanwhile is as cancelled as it was.
            let live = one(&app, &me, &s.id).await.map_or(true, |x| x.live());
            if live {
                let over =
                    crate::store::failover::restore_run(&app.pool, &cancelled.settled).await?;
                agents::drive_failover(&app, &over);
                return Err(e);
            }
        }
    }
    let action = if kill {
        "agent.killed"
    } else {
        "agent.cancelled"
    };
    store::action(&app.pool, &s, BY, action, None, json!({}), &me.device.id).await?;
    shown(&app, &me, &id).await
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
        removed (audited as `agent.killed`). A module's session: `admin` only, the break-glass \
        stop when the module's own routes cannot", body = AgentSession)))]
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
    let s = one(&app, &me, &id).await?;
    not_a_modules(&s)?;
    owns_secrets(&s, &me)?;
    if !store::reopen(&app.pool, &s.id, &app.clock.now()).await? {
        let full = crate::store::alloc::account_full(&app.pool, &s.id).await?;
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "not_resumable",
            if full {
                "the session's account is full: resume again when one of its sessions ends"
            } else {
                "only a lost or interrupted session is resumed"
            },
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
    shown(&app, &me, &id).await
}

#[utoipa::path(post, path = "/api/v1/agent-sessions/{id}/wake",
    operation_id = "wakeAgentSession", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`")),
    request_body = AgentWakeRequest,
    responses((status = 200, description = "Queued on the scheduler (audited as \
        `agent.wake_queued`): once the session is idle it is resumed on its runner, continuing \
        the harness's own session with `text` as its next turn (`agent.woken`). A session that \
        is still running is retried for a while, then the wake is dropped (a wake queued for an \
        attempt a failover replaced goes to its run's newest). 409 `failed_over` (the session was \
        replaced: the message names the attempt to wake), 409 `not_wakeable` (failed, cancelled, \
        a module's), 409 `limit_reached` (too many wakes waiting), 503 \
        `scheduler_unavailable`", body = AgentWake)))]
pub async fn wake(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<AgentWake> {
    let s = one(&app, &me, &id).await?;
    let b: AgentWakeRequest = parse(&body)?;
    let key = match b.key {
        Some(k) if request_ok(&k) => k,
        Some(_) => {
            return Err(ApiError::bad_request(
                "a wake key is 1 to 128 of A-Za-z0-9_.:-",
            ));
        }
        None => crate::auth::crypto::random_id("w_"),
    };
    let long = |t: &String| t.is_empty() || t.len() > crate::agents::wake::MAX_TEXT;
    if b.text.as_ref().is_some_and(long) {
        return Err(ApiError::bad_request("a wake text is 1 byte to 16 KiB"));
    }
    not_a_modules(&s)?;
    owns_secrets(&s, &me)?;
    // A wake queued earlier follows its run to the newest attempt; a new one names it instead.
    let newest = crate::store::failover::newest(&app.pool, &s.id).await?;
    if newest != s.id {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "failed_over",
            format!("a failover replaced this session: wake {newest}"),
        ));
    }
    if !s.wakeable() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "not_wakeable",
            "only a session that is not over, was lost, or finished a turn can be woken",
        ));
    }
    let payload = json!({"session": s.id, "by": me.device.id, "text": b.text});
    let name = crate::agents::wake::JOB;
    let cap = crate::agents::wake::CAP;
    let queued = crate::jobs::wake_platform(&app.pool, &app.clock.now(), name, &key, &payload, cap)
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(_) => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "scheduler_unavailable",
                "the scheduler does not run the wake queue",
            ),
            e => e.into(),
        })?;
    if queued == crate::jobs::Queued::Full {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "limit_reached",
            "too many wakes are waiting",
        ));
    }
    let details =
        json!({"queued": queued == crate::jobs::Queued::New, "bytes": b.text.map(|t| t.len())});
    let action = "agent.wake_queued";
    store::action(&app.pool, &s, BY, action, None, details, &me.device.id).await?;
    Ok(Json(AgentWake {
        session: s.id,
        key,
        queued: queued == crate::jobs::Queued::New,
    }))
}
