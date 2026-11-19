//! The AI order over the API (E7-1, D-18): one ordered list of the user's accounts, each with an
//! optional model. The first account that is ready serves a new session, the next takes over when it
//! fails. Underneath are hidden single-account pools and a hidden chain (`store::chains::order`).
//!
//! - **Admin, and a write is destructive** (a step-up): the order decides which key a run spends next.
//! - **Per-agent overrides** are the Advanced part: an agent with one walks its own list.
//! - **Refusals** are the chain rules (`bad_request` 400, `not_found` 404 for a missing account or an
//!   agent without an override, `conflict`/`limit_reached` 409). Every write is audited `chain.*`,
//!   never a value.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::accounts::AccountsDeleted;
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::store::chains::{self as ch, order};

/// One account of an order.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrderItem {
    /// The account's id.
    pub account: i64,
    pub provider: String,
    /// `claude`, `codex` or `agy`.
    pub harness: String,
    /// The model to run; absent, the harness's default.
    pub model: Option<String>,
}

impl From<order::Item> for OrderItem {
    fn from(i: order::Item) -> Self {
        Self {
            account: i.account,
            provider: i.provider,
            harness: i.harness,
            model: i.model,
        }
    }
}

/// An agent's own order.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentOrder {
    pub agent: String,
    pub items: Vec<OrderItem>,
}

/// The default order and the per-agent overrides.
#[derive(Debug, Serialize, ToSchema)]
pub struct AiOrder {
    /// Empty until the first account is added.
    pub items: Vec<OrderItem>,
    pub overrides: Vec<AgentOrder>,
}

impl From<order::Order> for AiOrder {
    fn from(o: order::Order) -> Self {
        Self {
            items: o.items.into_iter().map(Into::into).collect(),
            overrides: o
                .overrides
                .into_iter()
                .map(|o| AgentOrder {
                    agent: o.agent,
                    items: o.items.into_iter().map(Into::into).collect(),
                })
                .collect(),
        }
    }
}

/// An account to write into an order.
#[derive(Deserialize, ToSchema)]
pub struct NewOrderItem {
    pub account: i64,
    /// A valid model id; an API-key account's must be priced. Absent, the harness's default.
    pub model: Option<String>,
}

/// A whole order to write: 1 to 16 accounts, none twice.
#[derive(Deserialize, ToSchema)]
pub struct NewOrder {
    pub items: Vec<NewOrderItem>,
}

fn parse(body: &[u8]) -> Result<NewOrder, ApiError> {
    serde_json::from_slice(body)
        .map_err(|_| ApiError::bad_request("the body is not a valid request for this route"))
}

fn specs(b: &NewOrder) -> Vec<order::Spec<'_>> {
    b.items
        .iter()
        .map(|i| order::Spec {
            account: i.account,
            model: i.model.as_deref(),
        })
        .collect()
}

#[utoipa::path(get, path = "/api/v1/ai-order", operation_id = "getAiOrder", tag = "accounts",
    responses((status = 200, description = "The caller's user's AI order and per-agent overrides", body = AiOrder)))]
pub async fn get(State(app): State<App>, Extension(me): Extension<Caller>) -> ApiResult<AiOrder> {
    let user = ch::user_of(&app.pool, &me.device.id).await?;
    Ok(Json(order::get(&app.pool, user).await?.into()))
}

#[utoipa::path(put, path = "/api/v1/ai-order", operation_id = "setAiOrder", tag = "accounts",
    request_body = NewOrder,
    responses((status = 200, description = "The order replaced as a whole (audited as \
        `chain.created` or `chain.updated`); a run already walking it keeps its snapshot. 400 for \
        0 or more than 16 accounts, an account twice, a harness a chain does not run or an \
        unpriced API-key model; 404 for no such account", body = AiOrder)))]
pub async fn set(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<AiOrder> {
    let b = parse(&body)?;
    let user = ch::user_of(&app.pool, &me.device.id).await?;
    order::set(
        &app.pool,
        user,
        None,
        &specs(&b),
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await?;
    Ok(Json(order::get(&app.pool, user).await?.into()))
}

#[utoipa::path(put, path = "/api/v1/ai-order/agents/{agent}", operation_id = "setAgentAiOrder",
    tag = "accounts", params(("agent" = String, Path, description = "The agent's id")),
    request_body = NewOrder,
    responses((status = 200, description = "The agent's own order; its sessions walk it instead of \
        the default one. The refusals of `setAiOrder`; 400 for a bad agent id", body = AiOrder)))]
pub async fn set_agent(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(agent): Path<String>,
    body: Bytes,
) -> ApiResult<AiOrder> {
    let b = parse(&body)?;
    let user = ch::user_of(&app.pool, &me.device.id).await?;
    order::set(
        &app.pool,
        user,
        Some(&agent),
        &specs(&b),
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await?;
    Ok(Json(order::get(&app.pool, user).await?.into()))
}

#[utoipa::path(delete, path = "/api/v1/ai-order/agents/{agent}",
    operation_id = "clearAgentAiOrder", tag = "accounts",
    params(("agent" = String, Path, description = "The agent's id")),
    responses((status = 200, description = "The agent walks the default order again (audited as \
        `chain.unbound`); 404 when it had no override", body = AccountsDeleted)))]
pub async fn clear_agent(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(agent): Path<String>,
) -> ApiResult<AccountsDeleted> {
    let user = ch::user_of(&app.pool, &me.device.id).await?;
    order::clear_agent(&app.pool, user, &agent, &me.device.id, BY).await?;
    Ok(Json(AccountsDeleted {
        deleted: true,
        undo_until: None,
    }))
}
