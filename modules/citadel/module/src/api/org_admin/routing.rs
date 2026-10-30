//! Per-task model routing (E15.5): an agent's model per tier and a project's routing rules.
//! (The per-task cost report reads runs: with the run engine, S7.)

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, State};

use super::{failed, parse};
use crate::api::error::found;
use crate::api::model::org_admin::{ModelTier, TierRule, TierRules};
use crate::api::scope::Acting;
use crate::domain::org::{AgentId, ModelRoute, Tier};
use crate::domain::work::ProjectId;
use crate::store::org;

async fn tiers(app: &App, id: i64) -> Result<Vec<ModelTier>, ApiError> {
    found(org::get_agent(&app.pool, AgentId(id)).await?, "agent")?;
    let all = org::list_tiers(&app.pool, AgentId(id)).await?;
    Ok(all
        .into_iter()
        .map(|(tier, r)| ModelTier {
            tier: tier.as_str().to_owned(),
            harness: r.harness.as_str().to_owned(),
            model: r.model,
        })
        .collect())
}

#[utoipa::path(get, path = "/agents/{id}/tiers", operation_id = "listModelTiers",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The agent's small and large models",
        body = Vec<ModelTier>)))]
pub async fn list_tiers(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Vec<ModelTier>> {
    Ok(Json(tiers(&app, id).await?))
}

#[utoipa::path(put, path = "/agents/{id}/tiers", operation_id = "setModelTiers",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    request_body = Vec<ModelTier>,
    responses((status = 200, description = "The new tiers; empty clears them",
        body = Vec<ModelTier>)))]
pub async fn set_tiers(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(entries): Json<Vec<ModelTier>>,
) -> ApiResult<Vec<ModelTier>> {
    let mut set = vec![];
    for t in entries {
        let route = ModelRoute {
            harness: parse("harness", &t.harness)?,
            model: t.model,
        };
        set.push((parse::<Tier>("tier", &t.tier)?, route));
    }
    match org::set_tiers(&app.pool, AgentId(id), &set, BY).await {
        Ok(true) => Ok(Json(tiers(&app, id).await?)),
        Ok(false) => Err(ApiError::not_found(format!("no agent {id}"))),
        Err(e) => Err(failed(e)),
    }
}

async fn rules(app: &App, id: i64) -> Result<TierRules, ApiError> {
    let known: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM citadel_projects WHERE id = ?)")
            .bind(id)
            .fetch_one(&app.pool)
            .await?;
    if !known {
        return Err(ApiError::not_found(format!("no project {id}")));
    }
    let (rules, defaults) = org::list_tier_rules(&app.pool, ProjectId(id)).await?;
    let rules = rules
        .into_iter()
        .map(|(rule, tier)| TierRule {
            rule,
            tier: tier.as_str().to_owned(),
        })
        .collect();
    Ok(TierRules { rules, defaults })
}

#[utoipa::path(get, path = "/projects/{id}/tier-rules", operation_id = "getTierRules",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project's routing rules", body = TierRules)))]
pub async fn get_rules(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<TierRules> {
    Ok(Json(rules(&app, id).await?))
}

#[utoipa::path(put, path = "/projects/{id}/tier-rules", operation_id = "setTierRules",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    request_body = Vec<TierRule>,
    responses((status = 200, description = "The new rules; empty restores the defaults",
        body = TierRules)))]
pub async fn set_rules(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(set): Json<Vec<TierRule>>,
) -> ApiResult<TierRules> {
    let mut parsed = vec![];
    for r in set {
        parsed.push((r.rule, parse::<Tier>("tier", &r.tier)?));
    }
    match org::set_tier_rules(&app.pool, ProjectId(id), &parsed, BY).await {
        Ok(true) => Ok(Json(rules(&app, id).await?)),
        Ok(false) => Err(ApiError::not_found(format!("no project {id}"))),
        Err(e) => Err(failed(e)),
    }
}
