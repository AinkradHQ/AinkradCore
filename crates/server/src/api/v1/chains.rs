//! Chain presets and an agent's chain (API minor 18): a company's named chains of (harness,
//! model, account) entries, and `PUT /agents/{id}/chain` to give an agent a preset or a chain of
//! its own. A preset's entries replace the agent's fallbacks while it has one; an agent with
//! neither uses the company's default preset (`is_default`). Audited as `chain_preset.created`,
//! `.updated`, `.deleted` and `agent.chain_set`, each an event on the stream.

use ainkrad_core::ops::{ChainEntry, ChainPreset, NewChainPreset};
use ainkrad_core::org::{AgentId, ModelRoute};
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::org::company;
use super::types::Harness;
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::org::{self, AgentChain};

/// One entry of a chain, tried in order.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ChainEntryBody {
    pub harness: Harness,
    pub model: String,
    /// Pin the entry to one account of the company's pool; absent: any.
    pub account_id: Option<i64>,
}

impl From<ChainEntry> for ChainEntryBody {
    fn from(e: ChainEntry) -> Self {
        Self {
            harness: e.harness.into(),
            model: e.model,
            account_id: e.account_id,
        }
    }
}

impl From<ChainEntryBody> for ChainEntry {
    fn from(e: ChainEntryBody) -> Self {
        Self {
            harness: e.harness.into(),
            model: e.model,
            account_id: e.account_id,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChainPresetOut {
    pub id: i64,
    pub company_id: i64,
    pub name: String,
    /// `#rrggbb`.
    pub color: Option<String>,
    pub description: String,
    /// The chain agents with no chain of their own use.
    pub is_default: bool,
    pub entries: Vec<ChainEntryBody>,
}

impl From<ChainPreset> for ChainPresetOut {
    fn from(p: ChainPreset) -> Self {
        Self {
            id: p.id,
            company_id: p.company_id,
            name: p.name,
            color: p.color,
            description: p.description,
            is_default: p.is_default,
            entries: p.entries.into_iter().map(Into::into).collect(),
        }
    }
}

/// A preset to store; `PUT` replaces all of it.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ChainPresetBody {
    /// 1-100 characters, unique within the company.
    pub name: String,
    /// `#rrggbb`.
    pub color: Option<String>,
    /// At most 2000 characters.
    #[serde(default)]
    pub description: String,
    /// Make it the company's default chain (the old default stops being it).
    #[serde(default)]
    pub is_default: bool,
    /// At most 20; an account pin must be in the company's pool.
    pub entries: Vec<ChainEntryBody>,
}

impl From<ChainPresetBody> for NewChainPreset {
    fn from(b: ChainPresetBody) -> Self {
        Self {
            name: b.name,
            color: b.color,
            description: b.description,
            is_default: b.is_default,
            entries: b.entries.into_iter().map(Into::into).collect(),
        }
    }
}

fn failed(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
        sqlx::Error::Database(d) if d.message().contains("UNIQUE") => {
            ApiError::conflict("the company has a preset of that name already")
        }
        e => e.into(),
    }
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/chain-presets", operation_id = "listChainPresets",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company's chain presets, by name", body = Vec<ChainPresetOut>)))]
pub async fn list(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<ChainPresetOut>> {
    let c = company(&app, id).await?;
    let all = org::list_presets(&app.pool, c.id).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(post, path = "/api/v1/companies/{id}/chain-presets", operation_id = "createChainPreset",
    tag = "org", params(("id" = i64, Path, description = "Company id")), request_body = ChainPresetBody,
    responses((status = 200, description = "The preset (audited as `chain_preset.created`); 409 \
        for a name the company has, 400 for an invalid preset or a pin outside the pool",
        body = ChainPresetOut)))]
pub async fn create(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<ChainPresetBody>,
) -> ApiResult<ChainPresetOut> {
    let c = company(&app, id).await?;
    let made = org::create_preset(&app.pool, c.id, &b.into(), BY)
        .await
        .map_err(failed)?;
    Ok(Json(made.into()))
}

#[utoipa::path(put, path = "/api/v1/chain-presets/{id}", operation_id = "updateChainPreset",
    tag = "org", params(("id" = i64, Path, description = "Chain preset id")), request_body = ChainPresetBody,
    responses((status = 200, description = "The preset as replaced (audited as \
        `chain_preset.updated`)", body = ChainPresetOut)))]
pub async fn update(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<ChainPresetBody>,
) -> ApiResult<ChainPresetOut> {
    let made = org::update_preset(&app.pool, id, &b.into(), BY)
        .await
        .map_err(failed)?
        .ok_or_else(|| ApiError::not_found(format!("no chain preset {id}")))?;
    Ok(Json(made.into()))
}

/// What a delete removed.
#[derive(Debug, Serialize, ToSchema)]
pub struct Deleted {
    pub id: i64,
}

#[utoipa::path(delete, path = "/api/v1/chain-presets/{id}", operation_id = "deleteChainPreset",
    tag = "org", params(("id" = i64, Path, description = "Chain preset id")),
    responses((status = 200, description = "Deleted (audited as `chain_preset.deleted`); the \
        agents using it go back to their own chain", body = Deleted)))]
pub async fn delete(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Deleted> {
    match org::delete_preset(&app.pool, id, BY).await? {
        true => Ok(Json(Deleted { id })),
        false => Err(ApiError::not_found(format!("no chain preset {id}"))),
    }
}

/// How an agent gets its chain: a preset, or entries of its own. Exactly one.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AgentChainBody {
    /// Use this preset of the agent's company.
    pub preset_id: Option<i64>,
    /// Use these fallbacks of its own and no preset (no account pins: pin in a preset); an empty
    /// list clears them.
    pub entries: Option<Vec<ChainEntryBody>>,
}

/// The agent's effective chain after its own entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentChainOut {
    /// The preset the agent has set; absent when it uses its own entries (or the default).
    pub preset_id: Option<i64>,
    pub entries: Vec<ChainEntryBody>,
}

#[utoipa::path(put, path = "/api/v1/agents/{id}/chain", operation_id = "setAgentChain",
    tag = "org", params(("id" = i64, Path, description = "Agent id")), request_body = AgentChainBody,
    responses((status = 200, description = "The chain the agent has now (audited as \
        `agent.chain_set`); 400 unless exactly one of `preset_id` and `entries` is given or for \
        a preset of another company", body = AgentChainOut)))]
pub async fn set_chain(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<AgentChainBody>,
) -> ApiResult<AgentChainOut> {
    let chain = match (b.preset_id, b.entries) {
        (Some(p), None) => AgentChain::Preset(Some(p)),
        (None, Some(entries)) => {
            if entries.iter().any(|e| e.account_id.is_some()) {
                return Err(ApiError::bad_request(
                    "pin accounts in a preset, not on an agent",
                ));
            }
            let routes = entries.into_iter().map(|e| ModelRoute {
                harness: e.harness.into(),
                model: e.model,
            });
            AgentChain::Entries(routes.collect())
        }
        _ => {
            return Err(ApiError::bad_request(
                "give exactly one of preset_id and entries",
            ));
        }
    };
    match org::set_agent_chain(&app.pool, AgentId(id), &chain, BY).await {
        Ok(true) => {}
        Ok(false) => return Err(ApiError::not_found(format!("no agent {id}"))),
        Err(e) => return Err(failed(e)),
    }
    let (preset_id, entries) = org::effective_chain(&app.pool, AgentId(id)).await?;
    Ok(Json(AgentChainOut {
        preset_id,
        entries: entries.into_iter().map(Into::into).collect(),
    }))
}
