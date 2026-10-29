//! Per-task model routing (E15.5): an agent's model per tier, a project's routing rules, and
//! the per-task cost report (09-cost "Per task").

use ainkrad_core::org::{AgentId, ModelRoute};
use ainkrad_core::work::ProjectId;
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::org::company;
use super::types::{Harness, Tier};
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::{exec, gov, org, work};

/// The (harness, model) an agent's tasks of `tier` start on. Its own harness and model are
/// its standard tier, so only `small` and `large` are set here.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ModelTier {
    pub tier: Tier,
    pub harness: Harness,
    pub model: String,
}

async fn tiers(app: &App, id: i64) -> Result<Vec<ModelTier>, ApiError> {
    if org::get_agent(&app.pool, AgentId(id)).await?.is_none() {
        return Err(ApiError::not_found(format!("no agent {id}")));
    }
    let all = org::list_tiers(&app.pool, AgentId(id)).await?;
    Ok(all
        .into_iter()
        .map(|(tier, r)| ModelTier {
            tier: tier.into(),
            harness: r.harness.into(),
            model: r.model,
        })
        .collect())
}

#[utoipa::path(get, path = "/api/v1/agents/{id}/tiers", operation_id = "listModelTiers",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The agent's small and large models", body = Vec<ModelTier>)))]
pub async fn list_tiers(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<ModelTier>> {
    Ok(Json(tiers(&app, id).await?))
}

#[utoipa::path(put, path = "/api/v1/agents/{id}/tiers", operation_id = "setModelTiers",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    request_body = Vec<ModelTier>,
    responses((status = 200, description = "The new tiers; empty clears them", body = Vec<ModelTier>)))]
pub async fn set_tiers(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(entries): Json<Vec<ModelTier>>,
) -> ApiResult<Vec<ModelTier>> {
    let set: Vec<_> = entries
        .into_iter()
        .map(|t| {
            let route = ModelRoute {
                harness: t.harness.into(),
                model: t.model,
            };
            (t.tier.into(), route)
        })
        .collect();
    match org::set_tiers(&app.pool, AgentId(id), &set, BY).await {
        Ok(true) => Ok(Json(tiers(&app, id).await?)),
        Ok(false) => Err(ApiError::not_found(format!("no agent {id}"))),
        Err(sqlx::Error::InvalidArgument(why)) => Err(ApiError::bad_request(why)),
        Err(e) => Err(e.into()),
    }
}

/// One routing rule: issues with this label (`label:chore`) or kind (`kind:subtask`) run on
/// `tier`. A matching rule wins over points.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TierRule {
    pub rule: String,
    pub tier: Tier,
}

/// A project's routing rules; `defaults` when it has set none and the built-in ones apply.
#[derive(Debug, Serialize, ToSchema)]
pub struct TierRules {
    pub rules: Vec<TierRule>,
    pub defaults: bool,
}

async fn rules(app: &App, id: i64) -> Result<TierRules, ApiError> {
    if work::get_project(&app.pool, ProjectId(id)).await?.is_none() {
        return Err(ApiError::not_found(format!("no project {id}")));
    }
    let (rules, defaults) = exec::list_tier_rules(&app.pool, ProjectId(id)).await?;
    let rules = rules
        .into_iter()
        .map(|(rule, tier)| TierRule {
            rule,
            tier: tier.into(),
        })
        .collect();
    Ok(TierRules { rules, defaults })
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/tier-rules", operation_id = "getTierRules",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project's routing rules", body = TierRules)))]
pub async fn get_rules(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<TierRules> {
    Ok(Json(rules(&app, id).await?))
}

#[utoipa::path(put, path = "/api/v1/projects/{id}/tier-rules", operation_id = "setTierRules",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    request_body = Vec<TierRule>,
    responses((status = 200, description = "The new rules; empty restores the defaults", body = TierRules)))]
pub async fn set_rules(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(set): Json<Vec<TierRule>>,
) -> ApiResult<TierRules> {
    let set: Vec<_> = set.into_iter().map(|r| (r.rule, r.tier.into())).collect();
    match exec::set_tier_rules(&app.pool, ProjectId(id), &set, BY).await {
        Ok(true) => Ok(Json(rules(&app, id).await?)),
        Ok(false) => Err(ApiError::not_found(format!("no project {id}"))),
        Err(sqlx::Error::InvalidArgument(why)) => Err(ApiError::bad_request(why)),
        Err(e) => Err(e.into()),
    }
}

/// One issue's runs and what they used. Dollars are the priced runs' only; unpriced and
/// subscription runs are counted in tokens, never as $0.
#[derive(Debug, Serialize, ToSchema)]
pub struct TaskCost {
    pub issue_id: i64,
    /// `CIT-42`.
    pub key: String,
    pub title: String,
    pub points: Option<i64>,
    /// The tier its latest run was routed to.
    pub tier: Option<Tier>,
    pub runs: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    pub cost_usd_micros: i64,
    pub priced_runs: i64,
    pub unpriced_runs: i64,
    pub subscription_runs: i64,
    pub unpriced_tokens: i64,
    pub subscription_tokens: i64,
    /// The largest context a run started with.
    pub context_tokens: Option<i64>,
    /// Seconds its runs worked.
    pub secs: i64,
}

impl From<gov::TaskCost> for TaskCost {
    fn from(t: gov::TaskCost) -> Self {
        Self {
            issue_id: t.issue_id,
            key: t.key,
            title: t.title,
            points: t.points,
            tier: t
                .tier
                .and_then(|t| t.parse::<ainkrad_core::org::Tier>().ok())
                .map(Into::into),
            runs: t.runs,
            input_tokens: t.input_tokens,
            output_tokens: t.output_tokens,
            cache_tokens: t.cache_tokens,
            cost_usd_micros: t.cost_usd_micros,
            priced_runs: t.priced_runs,
            unpriced_runs: t.unpriced_runs,
            subscription_runs: t.subscription_runs,
            unpriced_tokens: t.unpriced_tokens,
            subscription_tokens: t.subscription_tokens,
            context_tokens: t.context_tokens,
            secs: t.secs,
        }
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct Since {
    /// Only runs queued at or after this time (RFC 3339); all runs without it.
    pub since: Option<String>,
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/costs/tasks", operation_id = "getTaskCosts",
    tag = "costs", params(("id" = i64, Path, description = "Company id"), Since),
    responses((status = 200, description = "What each issue's runs used, most tokens first", body = Vec<TaskCost>)))]
pub async fn task_costs(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(q): Query<Since>,
) -> ApiResult<Vec<TaskCost>> {
    let c = company(&app, id).await?;
    let now = app.clock.now();
    match gov::task_costs(&app.pool, c.id, q.since.as_deref(), &now).await {
        Ok(tasks) => Ok(Json(tasks.into_iter().map(Into::into).collect())),
        Err(sqlx::Error::InvalidArgument(why)) => Err(ApiError::bad_request(why)),
        Err(e) => Err(e.into()),
    }
}
