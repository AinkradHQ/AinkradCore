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
use crate::store::placement::Placement;
use crate::store::providers::{Definition, Model};
use crate::store::secrets::Error as StoreError;
use crate::store::{account_keys, accounts as acc, pools as pl, providers as prov};

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

/// The accounts' load and health, for an `admin` device only: how many sessions hold an account
/// says what other users are running.
async fn statuses_for(
    app: &App,
    me: &Caller,
) -> Result<std::collections::HashMap<i64, crate::store::health::Status>, ApiError> {
    match me.device.scopes.iter().any(|s| s == "admin") {
        true => Ok(crate::store::health::statuses(&app.pool).await?),
        false => Ok(Default::default()),
    }
}

// ----- accounts ---------------------------------------------------------------------------

#[utoipa::path(get, path = "/api/v1/accounts", operation_id = "listAccounts", tag = "accounts",
    responses((status = 200, description = "Every account: its key's last four characters, \
        never the key, its secret's name or its runner scope; with its `live` session count and \
        `health` (`admin` devices only)", body = Vec<ProviderAccount>)))]
pub async fn list(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> ApiResult<Vec<ProviderAccount>> {
    let status = statuses_for(&app, &me).await?;
    Ok(Json(
        acc::list(&app.pool)
            .await?
            .into_iter()
            .map(|a| {
                let st = status.get(&a.id);
                ProviderAccount::from(a).with_status(st)
            })
            .collect(),
    ))
}

#[utoipa::path(get, path = "/api/v1/accounts/{id}", operation_id = "getAccount", tag = "accounts",
    params(("id" = String, Path, description = "The account's id")),
    responses((status = 200, description = "One account, with its `live` session count and \
        `health` (`admin` devices only)", body = ProviderAccount)))]
pub async fn get(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<ProviderAccount> {
    let a = acc::get(&app.pool, num(&id, "account")?)
        .await
        .map_err(err)?;
    let status = statuses_for(&app, &me).await?;
    let st = status.get(&a.id);
    Ok(Json(ProviderAccount::from(a).with_status(st)))
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
    // A subscription's token never comes in a body: only a sign-in (`startAccountLogin`) makes one.
    if account_keys::subscription_provider(&b.provider) {
        return Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "login_required",
            "a subscription account is made by signing in (POST /api/v1/accounts/logins), not by a key",
        ));
    }
    let new = acc::NewAccount {
        provider: &b.provider,
        label: &b.label,
        value: &b.value,
        runners: b.runners.as_deref().unwrap_or_default(),
        cap: b.cap,
    };
    let user = crate::store::chains::user_of(&app.pool, &me.device.id).await?;
    let place = Placement {
        user,
        pool: b.pool,
        chain: b.chain,
        position: b.position.map(|p| p as usize),
        monthly_usd_micros: b.monthly_limit_usd_micros,
    };
    let (a, (pool, chain)) = acc::create_placed(
        &app.pool,
        sealer(&app)?,
        &new,
        "key",
        &me.device.id,
        BY,
        &app.clock.now(),
        &place,
    )
    .await
    .map_err(err)?;
    let mut d = AccountDetail::from(a);
    (d.pool, d.chain) = (Some(pool), chain);
    Ok(Json(d))
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
    let a = crate::agents::subscription::set_state(
        &app,
        num(&id, "account")?,
        &b.state,
        b.reason.as_deref(),
        b.until.as_deref(),
        &me.device.id,
        BY,
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

#[utoipa::path(put, path = "/api/v1/accounts/{id}/session-limits",
    operation_id = "setAccountSessionLimits", tag = "accounts",
    params(("id" = String, Path, description = "The account's id")),
    request_body = SessionLimits,
    responses((status = 200, description = "What one session may spend through this account \
        (audited as `account.session_limits_set`); a dimension left out is cleared. The Core's \
        ceiling for a gateway session honours it beside the budgets, from the next time a \
        ceiling is set (a session's start, its resume, or the top-up of its ceiling): a session \
        that is running keeps the ceiling it holds until then. It raises what a session may \
        spend, so it needs a step-up", body = ProviderAccount)))]
pub async fn set_session_limits(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<SessionLimits>,
) -> ApiResult<ProviderAccount> {
    let a = account_keys::set_session_limits(
        &app.pool,
        num(&id, "account")?,
        b.max_tokens,
        b.max_usd_micros,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(a.into()))
}

#[utoipa::path(post, path = "/api/v1/accounts/{id}/test", operation_id = "testAccount",
    tag = "accounts", params(("id" = String, Path, description = "The account's id")),
    responses((status = 200, description = "One free request (a model list) made through the \
        gateway of a runner that is online, in the key's scope and offers it: the status class \
        and the latency, never a body. Stored on the account and audited as `account.tested`. 409 \
        `no_runner` when none is ready; 429 when the account was tested within a minute or a \
        test is running. A provider whose model list needs no key and that declares no \
        `test_path` answers `inconclusive` (nothing is sent), never `ok`", body = AccountTested),
        (status = 502, description = "The runner failed or did not answer the test (code \
        `runner_failed`); the attempt is recorded as `failed` and counts for the rate limit")))]
pub async fn test_account(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AccountTested> {
    use crate::agents::gateway::test::{Failed, run};
    let id = num(&id, "account")?;
    match run(&app, &me, id).await {
        Ok(t) => Ok(Json(AccountTested {
            result: t.result,
            latency_ms: t.latency_ms,
            runner: t.runner,
        })),
        Err(Failed::Gone) => Err(ApiError::not_found("no such account")),
        Err(Failed::Soon(why)) => Err(ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            why,
        )),
        Err(Failed::NoRunner) => Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "no_runner",
            "no runner in this key's scope is online and offers the gateway",
        )),
        Err(Failed::Refused(why)) => Err(ApiError::conflict(why)),
        Err(Failed::Runner(why)) => Err(ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "runner_failed",
            why,
        )),
        Err(Failed::Db(e)) => Err(e.into()),
    }
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
    crate::agents::subscription::delete(&app, num(&id, "account")?, &me.device.id, BY)
        .await
        .map_err(err)?;
    Ok(Json(AccountsDeleted { deleted: true }))
}

mod logins;
mod pools;
mod types;

pub use logins::*;
pub use pools::*;
pub use types::*;
