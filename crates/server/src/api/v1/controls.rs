//! The admin's controls (E11.3–E11.8, decision #34): pause and resume an agent or a whole
//! company, stop a run now, message a run, wake a sleeping runner, and the actions of the "needs
//! you" and "why stuck" lists: nudge an issue's next actor, reassign it to a team member, and
//! allow an escalated call for the rest of its issue. Each goes through the engine as the admin
//! and is audited (`store::exec::controls`, `store::gov::allow_for_issue`).

use ainkrad_core::exec::{RunId, RunnerId};
use ainkrad_core::gov::ApprovalId;
use ainkrad_core::org::{AgentId, AgentStatus};
use ainkrad_core::work::{IssueId, IssueTransition, NextActor};
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::model::{Agent, Approval, Issue, Run, Runner};
use super::org::{agent_out, company};
use super::{ADMIN, ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::exec::{self, Delivery, MessageError, TransitionError};
use crate::store::{gov, org, work};

impl From<TransitionError> for ApiError {
    fn from(e: TransitionError) -> Self {
        match e {
            TransitionError::NotFound => Self::not_found(e.to_string()),
            TransitionError::Db(e) => e.into(),
            e => Self::conflict(e.to_string()),
        }
    }
}

async fn agent(app: &App, id: i64) -> Result<ainkrad_core::org::Agent, ApiError> {
    org::get_agent(&app.pool, AgentId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no agent {id}")))
}

#[utoipa::path(post, path = "/api/v1/agents/{id}/pause", operation_id = "pauseAgent",
    tag = "controls", params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The paused agent. Its running run finishes the tool \
        call in flight, then ends `cancelled` (\"paused by admin\"); it gets no new run and its \
        wakes wait until it is resumed", body = Agent)))]
pub async fn pause_agent(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Agent> {
    let a = agent(&app, id).await?;
    if !exec::pause_agent(&app.pool, a.id, BY, &app.clock.now()).await? {
        let status = a.status.as_str();
        return Err(ApiError::conflict(format!(
            "agent {id} is {status}, not active"
        )));
    }
    agent_out(&app, agent(&app, id).await?).await.map(Json)
}

#[utoipa::path(post, path = "/api/v1/agents/{id}/resume", operation_id = "resumeAgent",
    tag = "controls", params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The active agent, woken on every open issue waiting \
        on it", body = Agent)))]
pub async fn resume_agent(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Agent> {
    let a = agent(&app, id).await?;
    if !exec::resume_agent(&app.pool, a.id, BY, &app.clock.now()).await? {
        let status = a.status.as_str();
        return Err(ApiError::conflict(format!(
            "agent {id} is {status}, not paused"
        )));
    }
    agent_out(&app, agent(&app, id).await?).await.map(Json)
}

/// The agents a company-wide pause or resume changed.
#[derive(Debug, Serialize, ToSchema)]
pub struct Changed {
    pub agent_ids: Vec<i64>,
}

#[utoipa::path(post, path = "/api/v1/companies/{id}/pause", operation_id = "pauseCompany",
    tag = "controls", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "Every active agent of the company, paused as \
        `pauseAgent` does", body = Changed)))]
pub async fn pause_company(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Changed> {
    switch_company(&app, id, true).await
}

#[utoipa::path(post, path = "/api/v1/companies/{id}/resume", operation_id = "resumeCompany",
    tag = "controls", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "Every paused agent of the company, resumed as \
        `resumeAgent` does", body = Changed)))]
pub async fn resume_company(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Changed> {
    switch_company(&app, id, false).await
}

async fn switch_company(app: &App, id: i64, pause: bool) -> ApiResult<Changed> {
    let c = company(app, id).await?;
    let changed = exec::pause_company(&app.pool, c.id, pause, BY, &app.clock.now()).await?;
    let agent_ids = changed.into_iter().map(|a| a.0).collect();
    Ok(Json(Changed { agent_ids }))
}

#[utoipa::path(post, path = "/api/v1/runs/{id}/stop", operation_id = "stopRun", tag = "controls",
    params(("id" = i64, Path, description = "Run id")),
    responses((status = 200, description = "The run, ended `cancelled` (\"stopped by admin\") at \
        once; its runner kills the harness", body = Run)))]
pub async fn stop_run(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Run> {
    let r = exec::stop_run(&app.pool, RunId(id), BY, &app.clock.now()).await?;
    Ok(Json(r.into()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewMessage {
    pub body: String,
    /// Makes a retry safe: the same key on the same run is taken once.
    pub idempotency_key: Option<String>,
}

/// Where a message to a run went: to the run (`message_id`; its harness gets it at its next
/// turn, shown in the transcript as a `user_message` chunk with that id), or, the run not live,
/// a comment on its issue waking the run's agent (`comment_id`). A message the run ends before
/// taking becomes such a comment too.
#[derive(Debug, Serialize, ToSchema)]
pub struct MessageDelivery {
    /// `run` or `comment`.
    pub delivered_as: String,
    pub message_id: Option<i64>,
    pub comment_id: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/runs/{id}/messages", operation_id = "messageRun",
    tag = "controls", params(("id" = i64, Path, description = "Run id")), request_body = NewMessage,
    responses((status = 200, description = "Where the message went", body = MessageDelivery)))]
pub async fn message_run(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(m): Json<NewMessage>,
) -> ApiResult<MessageDelivery> {
    let key = m.idempotency_key.as_deref();
    let now = app.clock.now();
    let delivery = exec::message_run(&app.pool, RunId(id), ADMIN, &m.body, key, &now)
        .await
        .map_err(|e| match e {
            MessageError::NotFound => ApiError::not_found(format!("no run {id}")),
            MessageError::NoIssue => ApiError::conflict(e.to_string()),
            MessageError::Db(sqlx::Error::InvalidArgument(why)) => ApiError::bad_request(why),
            MessageError::Db(e) => e.into(),
        })?;
    Ok(Json(match delivery {
        Delivery::Run(id) => MessageDelivery {
            delivered_as: "run".to_owned(),
            message_id: Some(id),
            comment_id: None,
        },
        Delivery::Comment(id) => MessageDelivery {
            delivered_as: "comment".to_owned(),
            message_id: None,
            comment_id: Some(id),
        },
    }))
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct WakeBody {
    /// `now` ("Wake my Mac": pushed to the Mac app at once; the default) or `when_back` ("Run
    /// when I'm back": nothing pushed until it reconnects; its work waits).
    #[serde(default)]
    pub when: Option<String>,
}

#[utoipa::path(post, path = "/api/v1/runners/{id}/wake", operation_id = "wakeRunner",
    tag = "controls", params(("id" = i64, Path, description = "Runner id")),
    request_body = WakeBody,
    responses((status = 200, description = "The runner, its wake requested until it next \
        connects. The server cannot wake a sleeping machine: the request is pushed to the admin's \
        devices (`runner.wake_requested`), and the Mac app keeps its machine awake", body = Runner)))]
pub async fn wake_runner(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<WakeBody>,
) -> ApiResult<Runner> {
    let when = b.when.as_deref().unwrap_or("now");
    let r = exec::request_wake(&app.pool, RunnerId(id), when, BY, &app.clock.now())
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
            e => e.into(),
        })?
        .ok_or_else(|| ApiError::not_found(format!("no runner {id}")))?;
    Ok(Json(super::runners::shown(&app, r).await?))
}

/// The wake a nudge made.
#[derive(Debug, Serialize, ToSchema)]
pub struct Nudged {
    pub agent_id: i64,
    pub wake_id: i64,
    /// `pending`, or `coalesced` into the wake already waiting.
    pub wake_status: String,
}

#[utoipa::path(post, path = "/api/v1/issues/{id}/nudge", operation_id = "nudgeIssue",
    tag = "controls", params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issue's next actor, an agent, woken again",
        body = Nudged)))]
pub async fn nudge_issue(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Nudged> {
    let w = exec::nudge_issue(&app.pool, IssueId(id), BY, &app.clock.now())
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => ApiError::conflict(why),
            e => e.into(),
        })?
        .ok_or_else(|| ApiError::not_found(format!("no open issue {id}")))?;
    Ok(Json(Nudged {
        agent_id: w.agent_id.0,
        wake_id: w.id.0,
        wake_status: w.status.as_str().to_owned(),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReassignBody {
    /// An active member of the issue's project's team (any active agent of its company when the
    /// project has no team).
    pub agent_id: i64,
}

#[utoipa::path(post, path = "/api/v1/issues/{id}/reassign", operation_id = "reassignIssue",
    tag = "controls", params(("id" = i64, Path, description = "Issue id")),
    request_body = ReassignBody,
    responses((status = 200, description = "The issue, waiting on that agent, which is woken",
        body = Issue)))]
pub async fn reassign_issue(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<ReassignBody>,
) -> ApiResult<Issue> {
    let i = super::issues::issue(&app, id).await?;
    let p = work::get_project(&app.pool, i.project_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no issue {id}")))?;
    let to = agent(&app, b.agent_id).await?;
    let member: bool =
        match p.team_id {
            Some(team) => sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM team_memberships WHERE team_id = ? AND agent_id = ?)",
            )
            .bind(team.0)
            .bind(to.id.0)
            .fetch_one(&app.pool)
            .await?,
            None => to.company_id == p.company_id,
        };
    if !member || to.status != AgentStatus::Active {
        let why = format!(
            "agent {} is not an active member of the issue's team",
            b.agent_id
        );
        return Err(ApiError::bad_request(why));
    }
    let next = NextActor::Agent(to.id);
    let i =
        work::transition_issue(&app.pool, i.id, &IssueTransition::Reassign { next }, BY).await?;
    super::issues::issue_out(&app, i).await.map(Json)
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct AllowBody {
    /// Goes back to the agent, as with any approval.
    pub reply: Option<String>,
    /// The allowlist entry: `<tool>` or `<tool>:<command prefix>`. Absent: the escalated call's
    /// tool and its command's first two words (`Bash:cargo add`), or the tool alone.
    pub rule: Option<String>,
}

#[utoipa::path(post, path = "/api/v1/approvals/{id}/allow-for-issue",
    operation_id = "allowForIssue", tag = "controls",
    params(("id" = i64, Path, description = "Approval id")), request_body = AllowBody,
    responses((status = 200, description = "The permission escalation, approved; the same call \
        goes ahead on its issue's runs without asking until `approval.issue_allow_secs` from \
        now (audited as `approval.allowed_for_issue`)", body = Approval)))]
pub async fn allow_for_issue(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<AllowBody>,
) -> ApiResult<Approval> {
    let (reply, rule, now) = (b.reply.as_deref(), b.rule.as_deref(), app.clock.now());
    let a = gov::allow_for_issue(&app.pool, ApprovalId(id), ADMIN, reply, rule, &now).await?;
    Ok(Json(a.into()))
}

#[utoipa::path(post, path = "/api/v1/issues/{id}/backlog", operation_id = "moveToBacklog",
    tag = "controls", params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issue set aside in the backlog (the `shelve` \
        transition), waiting on the admin; nobody is woken. Refused while a run works on it: \
        stop the run first", body = Issue)))]
pub async fn move_to_backlog(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Issue> {
    let i = super::issues::issue(&app, id).await?;
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM runs WHERE issue_id = ? \
         AND state IN ('queued', 'claimed', 'running'))",
    )
    .bind(i.id.0)
    .fetch_one(&app.pool)
    .await?;
    if live {
        return Err(ApiError::conflict("a run works on it; stop the run first"));
    }
    let next = NextActor::Human(ADMIN);
    let i = work::transition_issue(&app.pool, i.id, &IssueTransition::Shelve { next }, BY).await?;
    super::issues::issue_out(&app, i).await.map(Json)
}
