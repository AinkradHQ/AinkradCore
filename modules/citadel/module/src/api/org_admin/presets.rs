//! Chain presets and an agent's chain (API minor 18), and roles: a company's named chains of
//! (harness, model, account) entries, `PUT /agents/{id}/chain` to give an agent a preset or a
//! chain of its own, and what a company hires for. Audited as `chain_preset.*`,
//! `agent.chain_set` and `role.*`.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, State};

use super::{company, failed, parse};
use crate::api::model::org_admin::{
    AgentChainBody, AgentChainOut, ChainEntryBody, ChainPresetBody, ChainPresetOut, OrgRemoved,
    RoleBody, RoleOut,
};
use crate::api::scope::Acting;
use crate::domain::ops::{ChainEntry, ChainPreset, NewChainPreset, NewRole, Role};
use crate::domain::org::{AgentId, ModelRoute};
use crate::store::org::{self, AgentChain};

fn entry_out(e: ChainEntry) -> ChainEntryBody {
    ChainEntryBody {
        harness: e.harness.as_str().to_owned(),
        model: e.model,
        account_id: e.account_id,
    }
}

fn entry_in(e: ChainEntryBody) -> Result<ChainEntry, ApiError> {
    Ok(ChainEntry {
        harness: parse("harness", &e.harness)?,
        model: e.model,
        account_id: e.account_id,
    })
}

fn preset_out(p: ChainPreset) -> ChainPresetOut {
    ChainPresetOut {
        id: p.id,
        company_id: p.company_id,
        name: p.name,
        color: p.color,
        description: p.description,
        is_default: p.is_default,
        entries: p.entries.into_iter().map(entry_out).collect(),
    }
}

fn preset_in(b: ChainPresetBody) -> Result<NewChainPreset, ApiError> {
    Ok(NewChainPreset {
        name: b.name,
        color: b.color,
        description: b.description,
        is_default: b.is_default,
        entries: b
            .entries
            .into_iter()
            .map(entry_in)
            .collect::<Result<_, _>>()?,
    })
}

fn role_out(r: Role) -> RoleOut {
    RoleOut {
        id: r.id,
        company_id: r.company_id,
        name: r.name,
        purpose: r.purpose,
        icon: r.icon,
        harness: r.harness.map(Into::into),
        model: r.model,
        budget_tokens: r.budget_tokens,
        skills: r.skills,
        instructions: r.instructions,
    }
}

fn role_in(b: RoleBody) -> Result<NewRole, ApiError> {
    Ok(NewRole {
        name: b.name,
        purpose: b.purpose,
        icon: b.icon,
        harness: b
            .harness
            .as_deref()
            .map(|h| parse("harness", h))
            .transpose()?,
        model: b.model,
        budget_tokens: b.budget_tokens,
        skills: b.skills,
        instructions: b.instructions,
    })
}

/// `failed`, with the message a duplicate preset name has.
fn preset_failed(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.message().contains("UNIQUE") => {
            ApiError::conflict("the company has a preset of that name already")
        }
        e => failed(e),
    }
}

#[utoipa::path(get, path = "/companies/{id}/chain-presets", operation_id = "listChainPresets",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company's chain presets, by name",
        body = Vec<ChainPresetOut>)))]
pub async fn list_presets(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Vec<ChainPresetOut>> {
    let c = company(&app, id).await?;
    let all = org::list_presets(&app.pool, c.id).await?;
    Ok(Json(all.into_iter().map(preset_out).collect()))
}

#[utoipa::path(post, path = "/companies/{id}/chain-presets", operation_id = "createChainPreset",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    request_body = ChainPresetBody,
    responses((status = 200, description = "The preset (audited as `chain_preset.created`); 409 \
        for a name the company has, 400 for an invalid preset or a pin outside the pool",
        body = ChainPresetOut)))]
pub async fn create_preset(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(b): Json<ChainPresetBody>,
) -> ApiResult<ChainPresetOut> {
    let c = company(&app, id).await?;
    let made = org::create_preset(&app.pool, c.id, &preset_in(b)?, BY)
        .await
        .map_err(preset_failed)?;
    Ok(Json(preset_out(made)))
}

#[utoipa::path(put, path = "/chain-presets/{id}", operation_id = "updateChainPreset",
    tag = "org", params(("id" = i64, Path, description = "Chain preset id")),
    request_body = ChainPresetBody,
    responses((status = 200, description = "The preset as replaced (audited as \
        `chain_preset.updated`)", body = ChainPresetOut)))]
pub async fn update_preset(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(b): Json<ChainPresetBody>,
) -> ApiResult<ChainPresetOut> {
    let made = org::update_preset(&app.pool, id, &preset_in(b)?, BY)
        .await
        .map_err(preset_failed)?
        .ok_or_else(|| ApiError::not_found(format!("no chain preset {id}")))?;
    Ok(Json(preset_out(made)))
}

#[utoipa::path(delete, path = "/chain-presets/{id}", operation_id = "deleteChainPreset",
    tag = "org", params(("id" = i64, Path, description = "Chain preset id")),
    responses((status = 200, description = "Deleted (audited as `chain_preset.deleted`); the \
        agents using it go back to their own chain; needs a step-up", body = OrgRemoved)))]
pub async fn delete_preset(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<OrgRemoved> {
    match org::delete_preset(&app.pool, id, BY).await? {
        true => Ok(Json(OrgRemoved { id })),
        false => Err(ApiError::not_found(format!("no chain preset {id}"))),
    }
}

#[utoipa::path(put, path = "/agents/{id}/chain", operation_id = "setAgentChain",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    request_body = AgentChainBody,
    responses((status = 200, description = "The chain the agent has now (audited as \
        `agent.chain_set`); 400 unless exactly one of `preset_id` and `entries` is given or for \
        a preset of another company", body = AgentChainOut)))]
pub async fn set_chain(
    State(app): State<App>,
    _: Acting,
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
            let mut routes = vec![];
            for e in entries {
                routes.push(ModelRoute {
                    harness: parse("harness", &e.harness)?,
                    model: e.model,
                });
            }
            AgentChain::Entries(routes)
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
        entries: entries.into_iter().map(entry_out).collect(),
    }))
}

/// `failed`, with the message a duplicate role name has.
fn role_failed(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.message().contains("UNIQUE") => {
            ApiError::conflict("the company has a role of that name already")
        }
        e => failed(e),
    }
}

#[utoipa::path(get, path = "/companies/{id}/roles", operation_id = "listRoles", tag = "org",
    params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company's roles, by name",
        body = Vec<RoleOut>)))]
pub async fn list_roles(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Vec<RoleOut>> {
    let c = company(&app, id).await?;
    let all = org::list_roles(&app.pool, c.id).await?;
    Ok(Json(all.into_iter().map(role_out).collect()))
}

#[utoipa::path(post, path = "/companies/{id}/roles", operation_id = "createRole", tag = "org",
    params(("id" = i64, Path, description = "Company id")), request_body = RoleBody,
    responses((status = 200, description = "The role (audited as `role.created`); 409 for a \
        name the company has, 400 for an invalid role", body = RoleOut)))]
pub async fn create_role(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(b): Json<RoleBody>,
) -> ApiResult<RoleOut> {
    let c = company(&app, id).await?;
    let made = org::create_role(&app.pool, c.id, &role_in(b)?, BY)
        .await
        .map_err(role_failed)?;
    Ok(Json(role_out(made)))
}

#[utoipa::path(put, path = "/roles/{id}", operation_id = "updateRole", tag = "org",
    params(("id" = i64, Path, description = "Role id")), request_body = RoleBody,
    responses((status = 200, description = "The role as replaced (audited as `role.updated`)",
        body = RoleOut)))]
pub async fn update_role(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(b): Json<RoleBody>,
) -> ApiResult<RoleOut> {
    let made = org::update_role(&app.pool, id, &role_in(b)?, BY)
        .await
        .map_err(role_failed)?
        .ok_or_else(|| ApiError::not_found(format!("no role {id}")))?;
    Ok(Json(role_out(made)))
}

#[utoipa::path(delete, path = "/roles/{id}", operation_id = "deleteRole", tag = "org",
    params(("id" = i64, Path, description = "Role id")),
    responses((status = 200, description = "Deleted (audited as `role.deleted`); agents keep \
        their role title; needs a step-up", body = OrgRemoved)))]
pub async fn delete_role(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<OrgRemoved> {
    match org::delete_role(&app.pool, id, BY).await? {
        true => Ok(Json(OrgRemoved { id })),
        false => Err(ApiError::not_found(format!("no role {id}"))),
    }
}
