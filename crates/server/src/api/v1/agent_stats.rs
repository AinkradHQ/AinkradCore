//! An agent's stats (API minor 18): `GET /agents/{id}/stats`, read from its runs and the cost
//! ledger as of now (UTC); nothing is stored.

use ainkrad_core::org::AgentId;
use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use utoipa::ToSchema;

use super::{ApiError, ApiResult};
use crate::api::App;
use crate::store::org;

#[derive(Debug, Serialize, ToSchema)]
pub struct DayRuns {
    /// `2026-10-22`.
    pub day: String,
    pub runs: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WeekSuccess {
    /// The week's Monday.
    pub week: String,
    /// Runs that finished that week, and how many of them succeeded.
    pub runs: i64,
    pub succeeded: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DaySpend {
    pub day: String,
    /// Priced dollars, in millionths; unpriced spend is in `tokens` only.
    pub cost_usd_micros: i64,
    pub tokens: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AgentStats {
    /// The last 7 days, oldest first.
    pub runs_by_day: Vec<DayRuns>,
    /// The last 8 weeks, oldest first.
    pub success_by_week: Vec<WeekSuccess>,
    /// The mean dollars of a priced run over the last 8 weeks; absent when none is priced.
    pub avg_cost_micros: Option<i64>,
    /// Runs started in the last 28 days: 7 rows, Monday first, of 6 four-hour slots (00, 04 … 20 UTC).
    pub heatmap: Vec<Vec<i64>>,
    /// Each day of the current month so far.
    pub daily_spend: Vec<DaySpend>,
}

#[utoipa::path(get, path = "/api/v1/agents/{id}/stats", operation_id = "getAgentStats", tag = "org",
    params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The agent's runs, success, cost, working hours and \
        spend (API minor 18)", body = AgentStats)))]
pub async fn get(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<AgentStats> {
    org::get_agent(&app.pool, AgentId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no agent {id}")))?;
    let s = org::agent_stats(&app.pool, AgentId(id), &app.clock.now()).await?;
    Ok(Json(AgentStats {
        runs_by_day: s
            .runs_by_day
            .into_iter()
            .map(|(day, runs)| DayRuns { day, runs })
            .collect(),
        success_by_week: s
            .success_by_week
            .into_iter()
            .map(|(week, runs, succeeded)| WeekSuccess {
                week,
                runs,
                succeeded,
            })
            .collect(),
        avg_cost_micros: s.avg_cost_micros,
        heatmap: s.heatmap.iter().map(|r| r.to_vec()).collect(),
        daily_spend: s
            .daily_spend
            .into_iter()
            .map(|(day, cost_usd_micros, tokens)| DaySpend {
                day,
                cost_usd_micros,
                tokens,
            })
            .collect(),
    }))
}
