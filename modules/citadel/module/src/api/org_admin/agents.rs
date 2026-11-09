//! Editing an agent (API minor 17): `updateAgent` changes its role, profile, harness, model,
//! runner tags and reporting line; the figure's palette, the avatar reset and the model
//! fallbacks. Each goes through the store as the admin and is audited (`agent.updated`,
//! `agent.appearance_set`, `agent.avatar_reset`, `agent.fallbacks_set`).

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, State};

use super::{agent_out, failed, org_refused, parse};
use crate::api::error::found;
use crate::api::model::Agent;
use crate::api::model::org_admin::{AgentUpdate, AppearanceChange, ModelFallback, Palette};
use crate::api::scope::Acting;
use crate::domain::org::{AgentChange, AgentId, ModelRoute};
use crate::store::org::{self, avatars};

/// The avatar errors the routes here can meet, as the client sees them.
fn avatar_failed(e: avatars::AvatarError) -> ApiError {
    use avatars::AvatarError as E;
    let why = e.to_string();
    match e {
        E::NoAgent(_) | E::NoCompany(_) | E::NoProject(_) => ApiError::not_found(why),
        E::UnknownPalette(_) | E::UnknownFigure(_) | E::NotAnImage | E::TooLarge { .. } => {
            ApiError::bad_request(why)
        }
        E::Io(_) => ApiError::bad_request(why),
        E::Db(e) => e.into(),
    }
}

#[utoipa::path(patch, path = "/agents/{id}", operation_id = "updateAgent", tag = "org",
    params(("id" = i64, Path, description = "Agent id")), request_body = AgentUpdate,
    responses(
        (status = 200, description = "The agent as changed (audited as `agent.updated`, naming \
            the `fields` changed); 400 for an invalid value or an empty change", body = Agent),
        (status = 409, description = "The agent is terminated, or the reporting line would loop \
            or leave the company")))]
pub async fn update_agent(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(u): Json<AgentUpdate>,
) -> ApiResult<Agent> {
    let change = AgentChange {
        role: u.role,
        description: u.description,
        harness: u
            .harness
            .as_deref()
            .map(|v| parse("harness", v))
            .transpose()?,
        model: u.model,
        effort: u
            .effort
            .map(|e| e.as_deref().map(|v| parse("effort", v)).transpose())
            .transpose()?,
        sandbox: u
            .sandbox
            .map(|s| s.as_deref().map(|v| parse("sandbox", v)).transpose())
            .transpose()?,
        runner_tags: u.runner_tags,
        reports_to: u.reports_to.map(|m| m.map(AgentId)),
        instructions: u.instructions,
        guidelines: u.guidelines,
    };
    let a = org::edit_agent(&app.pool, AgentId(id), &change, BY)
        .await
        .map_err(|e| match e {
            org::OrgError::Db(sqlx::Error::Database(d)) if d.message().contains("UNIQUE") => {
                ApiError::conflict("that name or seat is taken already")
            }
            e => org_refused(e),
        })?;
    agent_out(&app, a).await.map(Json)
}

#[utoipa::path(get, path = "/avatars/palettes", operation_id = "listPalettes", tag = "org",
    responses((status = 200, description = "Every palette, in the figure design's order; the \
        colours live in the client", body = Vec<Palette>)))]
pub async fn palettes(State(app): State<App>, _: Acting) -> ApiResult<Vec<Palette>> {
    let all = avatars::list_palettes(&app.pool).await?;
    Ok(Json(
        all.into_iter()
            .map(|(id, name)| Palette { id, name })
            .collect(),
    ))
}

#[utoipa::path(put, path = "/agents/{id}/appearance", operation_id = "setAppearance",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    request_body = AppearanceChange,
    responses((status = 200, description = "The agent, in its new palette", body = Agent)))]
pub async fn set_appearance(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(c): Json<AppearanceChange>,
) -> ApiResult<Agent> {
    let v = c.figure_version.as_deref();
    let a = avatars::set_appearance(&app.pool, AgentId(id), &c.palette_id, v, BY)
        .await
        .map_err(avatar_failed)?;
    agent_out(&app, a).await.map(Json)
}

#[utoipa::path(delete, path = "/agents/{id}/avatar", operation_id = "resetAvatar",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The agent, its figure shown again", body = Agent)))]
pub async fn reset_avatar(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Agent> {
    let a = avatars::reset_avatar(&app.pool, AgentId(id), BY)
        .await
        .map_err(avatar_failed)?;
    agent_out(&app, a).await.map(Json)
}

async fn chain(app: &App, id: i64) -> Result<Vec<ModelFallback>, ApiError> {
    found(org::get_agent(&app.pool, AgentId(id)).await?, "agent")?;
    let all = org::list_fallbacks(&app.pool, AgentId(id)).await?;
    Ok(all
        .into_iter()
        .map(|r| ModelFallback {
            harness: r.harness.as_str().to_owned(),
            model: r.model,
        })
        .collect())
}

#[utoipa::path(get, path = "/agents/{id}/fallbacks", operation_id = "listFallbacks",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The agent's fallback chain, in order",
        body = Vec<ModelFallback>)))]
pub async fn list_fallbacks(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Vec<ModelFallback>> {
    Ok(Json(chain(&app, id).await?))
}

#[utoipa::path(put, path = "/agents/{id}/fallbacks", operation_id = "setFallbacks",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    request_body = Vec<ModelFallback>,
    responses((status = 200, description = "The new chain; empty clears it",
        body = Vec<ModelFallback>)))]
pub async fn set_fallbacks(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(entries): Json<Vec<ModelFallback>>,
) -> ApiResult<Vec<ModelFallback>> {
    let mut routes = vec![];
    for f in entries {
        routes.push(ModelRoute {
            harness: parse("harness", &f.harness)?,
            model: f.model,
        });
    }
    match org::set_fallbacks(&app.pool, AgentId(id), &routes, BY).await {
        Ok(true) => Ok(Json(chain(&app, id).await?)),
        Ok(false) => Err(ApiError::not_found(format!("no agent {id}"))),
        Err(e) => Err(failed(e)),
    }
}
