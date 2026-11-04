//! AI provider accounts, pools and bindings over the API (KAN-432; design
//! `2026-11-02-ai-provider-accounts` §10, §11b). Reading is `read` and shows only what a phone
//! may see: no secret name, no runner scope, never a value. Every write is `admin` and
//! destructive (a step-up): storing or replacing a key, enabling or disabling an account, its
//! cap, a pool's members, a binding, the default, a provider definition's edit.
//!
//! A key is written, never read: [`NewProviderAccount`] and [`ReplaceKey`] parse their own body (a
//! serde error could quote the key) and have no `Debug`; nothing returns it.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use super::types::{Timestamp, opt_ts, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::ops::secretbox::SecretBox;
use crate::store::providers::{Definition, Model};
use crate::store::secrets::Error as StoreError;
use crate::store::{accounts as acc, pools as pl, providers as prov};

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|_| ApiError::bad_request("the body is not a valid request for this route"))
}

/// A numeric path id; anything else is no such row.
fn num(s: &str, what: &str) -> Result<i64, ApiError> {
    s.parse::<u64>()
        .ok()
        .and_then(|n| i64::try_from(n).ok())
        .ok_or_else(|| ApiError::not_found(format!("no such {what}")))
}

fn sealer(app: &App) -> Result<&SecretBox, ApiError> {
    app.secrets.as_deref().ok_or_else(|| {
        ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "secrets_unavailable",
            "this Core has no master key loaded",
        )
    })
}

fn err(e: StoreError) -> ApiError {
    e.into()
}

// ----- providers --------------------------------------------------------------------------

#[utoipa::path(get, path = "/api/v1/accounts/providers", operation_id = "listProviders",
    tag = "accounts",
    responses((status = 200, description = "The built-in providers, then the user definitions", body = Vec<Provider>)))]
pub async fn list_providers(State(app): State<App>) -> ApiResult<Vec<Provider>> {
    let all = prov::list(&app.pool).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(post, path = "/api/v1/accounts/providers", operation_id = "createProvider",
    tag = "accounts", request_body = Provider,
    responses((status = 200, description = "Stored (audited as `provider.created`). 400 for a \
        definition that fails validation (https DNS base URL, the harness's own variable); 409 \
        `conflict` or `limit_reached`", body = Provider)))]
pub async fn create_provider(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<Provider> {
    let p: Provider = parse(&body)?;
    let d = prov::create(&app.pool, &p.into(), &me.device.id, BY, &app.clock.now())
        .await
        .map_err(err)?;
    Ok(Json(d.into()))
}

#[utoipa::path(put, path = "/api/v1/accounts/providers/{id}", operation_id = "replaceProvider",
    tag = "accounts", params(("id" = String, Path, description = "The provider's id")),
    request_body = Provider,
    responses((status = 200, description = "A new version (audited as `provider.updated`). \
        Accounts already stored keep the base URL they were bound to", body = Provider)))]
pub async fn replace_provider(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<Provider> {
    let mut p: Provider = parse(&body)?;
    if p.id != id {
        return Err(ApiError::bad_request("the body's id is not the path's"));
    }
    p.id = id;
    let d = prov::replace(&app.pool, &p.into(), &me.device.id, BY, &app.clock.now())
        .await
        .map_err(err)?;
    Ok(Json(d.into()))
}

#[utoipa::path(delete, path = "/api/v1/accounts/providers/{id}", operation_id = "deleteProvider",
    tag = "accounts", params(("id" = String, Path, description = "The provider's id")),
    responses((status = 200, description = "Deleted (audited as `provider.deleted`); a built-in \
        or one an account uses is refused", body = AccountsDeleted)))]
pub async fn delete_provider(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AccountsDeleted> {
    prov::delete(&app.pool, &id, &me.device.id, BY)
        .await
        .map_err(err)?;
    Ok(Json(AccountsDeleted { deleted: true }))
}

// ----- accounts ---------------------------------------------------------------------------

#[utoipa::path(get, path = "/api/v1/accounts", operation_id = "listAccounts", tag = "accounts",
    responses((status = 200, description = "Every account: its key's last four characters, \
        never the key, its secret's name or its runner scope", body = Vec<ProviderAccount>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<ProviderAccount>> {
    Ok(Json(
        acc::list(&app.pool)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

#[utoipa::path(get, path = "/api/v1/accounts/{id}", operation_id = "getAccount", tag = "accounts",
    params(("id" = String, Path, description = "The account's id")),
    responses((status = 200, description = "One account", body = ProviderAccount)))]
pub async fn get(State(app): State<App>, Path(id): Path<String>) -> ApiResult<ProviderAccount> {
    Ok(Json(
        acc::get(&app.pool, num(&id, "account")?)
            .await
            .map_err(err)?
            .into(),
    ))
}

#[utoipa::path(post, path = "/api/v1/accounts", operation_id = "createAccount", tag = "accounts",
    request_body = NewProviderAccount,
    responses((status = 200, description = "Stored with its key in the secrets broker (audited \
        as `account.created`, and the broker's own `secret.created`). 409 `secrets_disabled` \
        (`secrets.mode` 0), `real_secret_refused` (a real key shape while \
        `secrets.provider_accounts` is off), `conflict` or `limit_reached`; 400 for a bad \
        provider, label, cap or runner; 503 `secrets_unavailable`", body = AccountDetail)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<AccountDetail> {
    let b: NewProviderAccount = parse(&body)?;
    let new = acc::NewAccount {
        provider: &b.provider,
        label: &b.label,
        value: &b.value,
        runners: b.runners.as_deref().unwrap_or_default(),
        cap: b.cap,
    };
    let a = acc::create(
        &app.pool,
        sealer(&app)?,
        &new,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(a.into()))
}

#[utoipa::path(put, path = "/api/v1/accounts/{id}/secret", operation_id = "replaceAccountSecret",
    tag = "accounts", params(("id" = String, Path, description = "The account's id")),
    request_body = ReplaceKey,
    responses((status = 200, description = "A new key version, its last four characters cut \
        again, every outstanding lease on the old one dropped (audited as \
        `account.secret_replaced`); the refusals of `createAccount`", body = AccountDetail)))]
pub async fn replace_secret(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<AccountDetail> {
    let id = num(&id, "account")?;
    let b: ReplaceKey = parse(&body)?;
    let a = acc::replace_secret(
        &app.pool,
        sealer(&app)?,
        id,
        &b.value,
        b.runners.as_deref(),
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(a.into()))
}

#[utoipa::path(put, path = "/api/v1/accounts/{id}/state", operation_id = "setAccountState",
    tag = "accounts", params(("id" = String, Path, description = "The account's id")),
    request_body = SetState,
    responses((status = 200, description = "Enables (`active`) or disables the account, or \
        marks it cooling, limited or unhealthy (audited as `account.state_set`)",
        body = ProviderAccount)))]
pub async fn set_state(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<SetState>,
) -> ApiResult<ProviderAccount> {
    let a = acc::set_state(
        &app.pool,
        num(&id, "account")?,
        &b.state,
        b.reason.as_deref(),
        b.until.as_deref(),
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(a.into()))
}

#[utoipa::path(put, path = "/api/v1/accounts/{id}/cap", operation_id = "setAccountCap",
    tag = "accounts", params(("id" = String, Path, description = "The account's id")),
    request_body = SetCap,
    responses((status = 200, description = "The concurrency cap, 0 (no cap) to 64 (audited as \
        `account.cap_set`)", body = ProviderAccount)))]
pub async fn set_cap(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<SetCap>,
) -> ApiResult<ProviderAccount> {
    let a = acc::set_cap(
        &app.pool,
        num(&id, "account")?,
        b.cap,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(a.into()))
}

#[utoipa::path(delete, path = "/api/v1/accounts/{id}", operation_id = "deleteAccount",
    tag = "accounts", params(("id" = String, Path, description = "The account's id")),
    responses((status = 200, description = "Deleted with its key, its leases and its pool \
        seats (audited as `account.deleted`)", body = AccountsDeleted)))]
pub async fn delete(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AccountsDeleted> {
    acc::delete(&app.pool, num(&id, "account")?, &me.device.id, BY)
        .await
        .map_err(err)?;
    Ok(Json(AccountsDeleted { deleted: true }))
}

mod pools;
mod types;

pub use pools::*;
pub use types::*;
