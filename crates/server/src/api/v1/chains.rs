//! Fallback chains over the API (design `2026-11-06-core-account-scheduler` §13, S7). Every route
//! is `admin`: reading a chain says which accounts a run may walk. Every write is also
//! destructive (a step-up), like pool membership: a chain decides which key a run spends next.
//!
//! - **One user's.** A chain, its bindings and the pools its entries name belong to the user of
//!   the calling device (`core_devices.user_id`), never to one a body names. Another user's chain
//!   does not exist for a caller (404), whatever the verb; a list shows the caller's own.
//! - **Writes.** `POST` makes a chain, `PUT /chains/{id}` replaces its name and WHOLE entry list,
//!   `DELETE` removes it (409 while a live session walks it), `PUT …/default` makes it the user's
//!   default, and an agent's binding says which chain its sessions get. Every write is audited
//!   `chain.*` with ids, names and models, never a value.
//! - **Refusals.** `bad_request` is 400, `not_found` 404, `conflict` and `limit_reached` 409
//!   (the store's own codes, as every other route maps them).

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::accounts::AccountsDeleted;
use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::store::chains::{self as ch, EntrySpec};

/// One step of a chain: the pool tried at this position, and the harness and model its accounts
/// run. The harness is the pool's provider's own.
#[derive(Debug, Serialize, ToSchema)]
pub struct ChainEntry {
    /// The pool's id.
    pub pool: i64,
    pub provider: String,
    /// `claude`, `codex` or `agy`.
    pub harness: String,
    /// The model for that harness; absent, the harness's default.
    pub model: Option<String>,
}

impl From<ch::ChainEntry> for ChainEntry {
    fn from(e: ch::ChainEntry) -> Self {
        Self {
            pool: e.pool,
            provider: e.provider,
            harness: e.harness,
            model: e.model,
        }
    }
}

/// An ordered fallback chain of 1 to 4 pools. A new session draws an account from the first
/// entry that has one to give.
#[derive(Debug, Serialize, ToSchema)]
pub struct Chain {
    pub id: i64,
    pub name: String,
    /// The user's default chain serves an agent bound to none.
    pub is_default: bool,
    /// In fallback order.
    pub entries: Vec<ChainEntry>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<ch::Chain> for Chain {
    fn from(c: ch::Chain) -> Self {
        Self {
            id: c.id,
            name: c.name,
            is_default: c.is_default,
            entries: c.entries.into_iter().map(Into::into).collect(),
            created_at: ts(&c.created_at),
            updated_at: ts(&c.updated_at),
        }
    }
}

/// An entry to write: a pool and the model its accounts run.
#[derive(Deserialize, ToSchema)]
pub struct NewChainEntry {
    /// The pool's id; it must be the caller's user's, of a `claude`, `codex` or `agy` provider,
    /// and in the chain once.
    pub pool: i64,
    /// A valid model id; an API-key pool's must be priced. Absent, the harness's default.
    pub model: Option<String>,
}

/// A chain to write: `[a-z][a-z0-9._-]{0,63}` and 1 to 4 entries, at most one of them a
/// subscription. For an edit this replaces the name and the whole list.
#[derive(Deserialize, ToSchema)]
pub struct NewChain {
    pub name: String,
    pub entries: Vec<NewChainEntry>,
}

/// An agent's binding: its sessions get this chain.
#[derive(Debug, Serialize, ToSchema)]
pub struct ChainBinding {
    /// The opaque agent id, 1 to 64 of `[A-Za-z0-9._:-]`.
    pub agent: String,
    /// The chain's id.
    pub chain: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct BindChain {
    /// The chain's id.
    pub chain: i64,
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|_| ApiError::bad_request("the body is not a valid request for this route"))
}

/// A numeric path id; anything else is no such chain.
fn num(s: &str) -> Result<i64, ApiError> {
    s.parse::<u64>()
        .ok()
        .and_then(|n| i64::try_from(n).ok())
        .ok_or_else(|| ApiError::not_found("no such chain"))
}

/// The user the caller's device acts as.
async fn user(app: &App, me: &Caller) -> Result<i64, ApiError> {
    Ok(ch::user_of(&app.pool, &me.device.id).await?)
}

/// The chain `id`, if it is `user`'s: another user's is no such chain.
async fn owned(app: &App, user: i64, id: i64) -> Result<ch::Chain, ApiError> {
    let c = ch::get(&app.pool, id).await?;
    match c.user_id == user {
        true => Ok(c),
        false => Err(ApiError::not_found("no such chain")),
    }
}

fn specs(b: &NewChain) -> Vec<EntrySpec<'_>> {
    b.entries
        .iter()
        .map(|e| EntrySpec {
            pool: e.pool,
            model: e.model.as_deref(),
            harness: None,
        })
        .collect()
}

#[utoipa::path(get, path = "/api/v1/chains", operation_id = "listChains", tag = "chains",
    responses((status = 200, description = "The caller's user's chains, each with its entries in \
        fallback order", body = Vec<Chain>)))]
pub async fn list(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> ApiResult<Vec<Chain>> {
    let user = user(&app, &me).await?;
    let all = ch::list(&app.pool).await?;
    Ok(Json(
        all.into_iter()
            .filter(|c| c.user_id == user)
            .map(Into::into)
            .collect(),
    ))
}

#[utoipa::path(get, path = "/api/v1/chains/{id}", operation_id = "getChain", tag = "chains",
    params(("id" = String, Path, description = "The chain's id")),
    responses((status = 200, description = "One chain; 404 for another user's", body = Chain)))]
pub async fn get(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<Chain> {
    let user = user(&app, &me).await?;
    Ok(Json(owned(&app, user, num(&id)?).await?.into()))
}

#[utoipa::path(post, path = "/api/v1/chains", operation_id = "createChain", tag = "chains",
    request_body = NewChain,
    responses((status = 200, description = "Stored for the caller's user (audited as \
        `chain.created`). 400 for a bad name, 1 to 4 entries, a pool twice, another user's pool, \
        a pool that is not a `claude`, `codex` or `agy` one, an unpriced API-key model, or two \
        subscriptions; 404 for no such pool; 409 `conflict` (the name is taken) or \
        `limit_reached`", body = Chain)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<Chain> {
    let b: NewChain = parse(&body)?;
    let user = user(&app, &me).await?;
    let c = ch::create(
        &app.pool,
        user,
        &b.name,
        &specs(&b),
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await?;
    Ok(Json(c.into()))
}

#[utoipa::path(put, path = "/api/v1/chains/{id}", operation_id = "replaceChain", tag = "chains",
    params(("id" = String, Path, description = "The chain's id")),
    request_body = NewChain,
    responses((status = 200, description = "The name and the whole entry list replaced (audited \
        as `chain.updated`); a run already walking the chain keeps its snapshot. The refusals of \
        `createChain`; 404 for another user's chain", body = Chain)))]
pub async fn replace(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<Chain> {
    let b: NewChain = parse(&body)?;
    let user = user(&app, &me).await?;
    let id = owned(&app, user, num(&id)?).await?.id;
    let c = ch::update(
        &app.pool,
        id,
        &b.name,
        &specs(&b),
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await?;
    Ok(Json(c.into()))
}

#[utoipa::path(delete, path = "/api/v1/chains/{id}", operation_id = "deleteChain", tag = "chains",
    params(("id" = String, Path, description = "The chain's id")),
    responses((status = 200, description = "Deleted with its entries and bindings (audited as \
        `chain.deleted`); 409 `conflict` while a live session walks it, 404 for another \
        user's", body = AccountsDeleted)))]
pub async fn delete(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AccountsDeleted> {
    let user = user(&app, &me).await?;
    let id = owned(&app, user, num(&id)?).await?.id;
    ch::delete(&app.pool, id, &me.device.id, BY).await?;
    Ok(Json(AccountsDeleted { deleted: true }))
}

#[utoipa::path(put, path = "/api/v1/chains/{id}/default", operation_id = "setDefaultChain",
    tag = "chains", params(("id" = String, Path, description = "The chain's id")),
    responses((status = 200, description = "The user's default chain from now on, the previous \
        one no longer (audited as `chain.default_set`); it serves a session that names an agent \
        bound to none", body = Chain)))]
pub async fn set_default(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<Chain> {
    let user = user(&app, &me).await?;
    let id = owned(&app, user, num(&id)?).await?.id;
    let c = ch::set_default(&app.pool, id, &me.device.id, BY, &app.clock.now()).await?;
    Ok(Json(c.into()))
}

#[utoipa::path(get, path = "/api/v1/chains/bindings", operation_id = "listChainBindings",
    tag = "chains",
    responses((status = 200, description = "The caller's user's agent bindings, by agent", body = Vec<ChainBinding>)))]
pub async fn list_bindings(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> ApiResult<Vec<ChainBinding>> {
    let user = user(&app, &me).await?;
    let all = ch::list_bindings(&app.pool).await?;
    Ok(Json(
        all.into_iter()
            .filter(|b| b.user_id == user)
            .map(|b| ChainBinding {
                agent: b.agent,
                chain: b.chain_id,
            })
            .collect(),
    ))
}

#[utoipa::path(put, path = "/api/v1/chains/bindings/{agent}", operation_id = "bindAgentChain",
    tag = "chains", params(("agent" = String, Path, description = "The agent's id")),
    request_body = BindChain,
    responses((status = 200, description = "The agent's sessions get this chain, replacing an \
        earlier binding (audited as `chain.bound`); 400 for a bad agent id, 404 for no such \
        chain", body = ChainBinding)))]
pub async fn bind(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(agent): Path<String>,
    body: Bytes,
) -> ApiResult<ChainBinding> {
    let b: BindChain = parse(&body)?;
    let user = user(&app, &me).await?;
    let id = owned(&app, user, b.chain).await?.id;
    ch::bind(&app.pool, &agent, id, &me.device.id, BY, &app.clock.now()).await?;
    Ok(Json(ChainBinding { agent, chain: id }))
}

#[utoipa::path(delete, path = "/api/v1/chains/bindings/{agent}",
    operation_id = "unbindAgentChain", tag = "chains",
    params(("agent" = String, Path, description = "The agent's id")),
    responses((status = 200, description = "The agent's sessions fall back to the default chain \
        (audited as `chain.unbound`); 404 when it had no binding", body = AccountsDeleted)))]
pub async fn unbind(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(agent): Path<String>,
) -> ApiResult<AccountsDeleted> {
    let user = user(&app, &me).await?;
    ch::unbind(&app.pool, user, &agent, &me.device.id, BY).await?;
    Ok(Json(AccountsDeleted { deleted: true }))
}
