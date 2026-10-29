//! An agent's model fallback chain (E15.3): read it, or replace it as a whole.

use ainkrad_core::org::{AgentId, ModelRoute};
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::types::Harness;
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::org;

/// One entry of the chain, tried in order after the agent's own harness and model.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Fallback {
    pub harness: Harness,
    pub model: String,
}

impl From<ModelRoute> for Fallback {
    fn from(r: ModelRoute) -> Self {
        Self {
            harness: r.harness.into(),
            model: r.model,
        }
    }
}

async fn chain(app: &App, id: i64) -> Result<Vec<Fallback>, ApiError> {
    if org::get_agent(&app.pool, AgentId(id)).await?.is_none() {
        return Err(ApiError::not_found(format!("no agent {id}")));
    }
    let all = org::list_fallbacks(&app.pool, AgentId(id)).await?;
    Ok(all.into_iter().map(Into::into).collect())
}

#[utoipa::path(get, path = "/api/v1/agents/{id}/fallbacks", operation_id = "listFallbacks",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The agent's fallback chain, in order", body = Vec<Fallback>)))]
pub async fn list(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<Fallback>> {
    Ok(Json(chain(&app, id).await?))
}

#[utoipa::path(put, path = "/api/v1/agents/{id}/fallbacks", operation_id = "setFallbacks",
    tag = "org", params(("id" = i64, Path, description = "Agent id")),
    request_body = Vec<Fallback>,
    responses((status = 200, description = "The new chain; empty clears it", body = Vec<Fallback>)))]
pub async fn set(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(entries): Json<Vec<Fallback>>,
) -> ApiResult<Vec<Fallback>> {
    let routes: Vec<ModelRoute> = entries
        .into_iter()
        .map(|f| ModelRoute {
            harness: f.harness.into(),
            model: f.model,
        })
        .collect();
    match org::set_fallbacks(&app.pool, AgentId(id), &routes, BY).await {
        Ok(true) => Ok(Json(chain(&app, id).await?)),
        Ok(false) => Err(ApiError::not_found(format!("no agent {id}"))),
        Err(sqlx::Error::InvalidArgument(why)) => Err(ApiError::bad_request(why)),
        Err(e) => Err(e.into()),
    }
}
