//! Editing and ending an agent (API minor 17): `updateAgent` changes its role, profile, harness,
//! model, runner tags and reporting line, `wakeAgent` wakes it now, `terminateAgent` lets it go.
//! Each goes through the store as the admin and is audited (`agent.updated`, `agent.woken`,
//! `agent.terminated`; every audited change is also an event on the stream).

use citadel_core::org::{AgentChange, AgentId, AgentStatus};
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use utoipa::ToSchema;

use super::hire::refused;
use super::model::Agent;
use super::org::agent_out;
use super::quest::serde_with_none;
use super::types::{Effort, Harness, Sandbox};
use super::{ADMIN, ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::org;

/// What to change about an agent; absent fields stay, `null` clears `effort`, `sandbox` and
/// `reports_to`. At least one field is needed.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AgentUpdate {
    /// Free-text job title, 1-100 characters.
    pub role: Option<String>,
    /// At most 4000 characters.
    pub description: Option<String>,
    pub harness: Option<Harness>,
    /// 1-200 characters.
    pub model: Option<String>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<Effort>)]
    pub effort: Option<Option<Effort>>,
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<Sandbox>)]
    pub sandbox: Option<Option<Sandbox>>,
    /// At most 20 tags, each 1-64 characters without spaces.
    pub runner_tags: Option<Vec<String>>,
    /// An agent of the company that does not report to this one; `null`: nobody.
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<i64>)]
    pub reports_to: Option<Option<i64>>,
    /// At most 20000 characters.
    pub instructions: Option<String>,
    /// At most 50, each 1-500 characters; replaces the list.
    pub guidelines: Option<Vec<String>>,
}

#[utoipa::path(patch, path = "/api/v1/agents/{id}", operation_id = "updateAgent", tag = "org",
    params(("id" = i64, Path, description = "Agent id")), request_body = AgentUpdate,
    responses(
        (status = 200, description = "The agent as changed (audited as `agent.updated`, naming the \
            `fields` changed); 400 for an invalid value or an empty change", body = Agent),
        (status = 409, description = "The agent is terminated, or the reporting line would loop \
            or leave the company", body = super::types::ErrorBody)))]
pub async fn update(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(u): Json<AgentUpdate>,
) -> ApiResult<Agent> {
    let change = AgentChange {
        role: u.role,
        description: u.description,
        harness: u.harness.map(Into::into),
        model: u.model,
        effort: u.effort.map(|e| e.map(Into::into)),
        sandbox: u.sandbox.map(|s| s.map(Into::into)),
        runner_tags: u.runner_tags,
        reports_to: u.reports_to.map(|m| m.map(AgentId)),
        instructions: u.instructions,
        guidelines: u.guidelines,
    };
    let a = org::edit_agent(&app.pool, AgentId(id), &change, BY)
        .await
        .map_err(refused)?;
    agent_out(&app, a).await.map(Json)
}

async fn current(app: &App, id: i64) -> Result<citadel_core::org::Agent, ApiError> {
    org::get_agent(&app.pool, AgentId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no agent {id}")))
}

#[utoipa::path(post, path = "/api/v1/agents/{id}/wake", operation_id = "wakeAgent", tag = "controls",
    params(("id" = i64, Path, description = "Agent id")),
    responses(
        (status = 200, description = "The active agent, woken now (audited as `agent.woken`): on \
            each open issue waiting on it, else once to look at its inbox", body = Agent),
        (status = 409, description = "The agent is not active", body = super::types::ErrorBody)))]
pub async fn wake(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Agent> {
    let a = current(&app, id).await?;
    if crate::store::exec::wake_agent(&app.pool, a.id, BY, &app.clock.now())
        .await?
        .is_none()
    {
        let status = a.status.as_str();
        return Err(ApiError::conflict(format!(
            "agent {id} is {status}, not active"
        )));
    }
    agent_out(&app, current(&app, id).await?).await.map(Json)
}

/// Why an agent is let go.
#[derive(Debug, Deserialize, ToSchema)]
pub struct Termination {
    /// Kept in the audit trail; required.
    pub reason: String,
}

#[utoipa::path(post, path = "/api/v1/agents/{id}/terminate", operation_id = "terminateAgent",
    tag = "controls", params(("id" = i64, Path, description = "Agent id")),
    request_body = Termination,
    responses(
        (status = 200, description = "The agent, `terminated` for good (audited as \
            `agent.terminated`, listing what it undid): its live runs end `cancelled`, its pending \
            wakes are dropped, every open issue waiting on it goes to the admin and its ownership \
            is cleared; it is never woken again", body = Agent),
        (status = 409, description = "Already terminated", body = super::types::ErrorBody)))]
pub async fn terminate(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(t): Json<Termination>,
) -> ApiResult<Agent> {
    let a = current(&app, id).await?;
    if t.reason.trim().is_empty() {
        return Err(ApiError::bad_request("terminating needs a reason"));
    }
    let now = app.clock.now();
    if !crate::store::exec::terminate_agent(&app.pool, a.id, &t.reason, ADMIN, BY, &now).await? {
        debug_assert_eq!(a.status, AgentStatus::Terminated);
        return Err(ApiError::conflict(format!(
            "agent {id} is terminated already"
        )));
    }
    agent_out(&app, current(&app, id).await?).await.map(Json)
}
