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

/// An account as a `read` device sees it: its key's last four characters, never the key, the
/// broker secret's name or the runners it may be leased to.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderAccount {
    pub id: i64,
    /// `anthropic`, `openai` or `google`.
    pub provider: String,
    pub label: String,
    /// The key's last four characters; empty for a key too short to show any.
    pub masked_tail: String,
    /// The provider's base URL when the account was stored.
    pub base_url: String,
    /// `active`, `cooling`, `limited`, `unhealthy` or `disabled`.
    pub state: String,
    pub state_reason: Option<String>,
    pub state_until: Option<Timestamp>,
    /// Sessions that may hold the account at once; 0 is no cap.
    pub cap: i64,
    pub last_used_at: Option<Timestamp>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<acc::Account> for ProviderAccount {
    fn from(a: acc::Account) -> Self {
        Self {
            id: a.id,
            provider: a.provider,
            label: a.label,
            masked_tail: a.masked_tail,
            base_url: a.base_url,
            state: a.state,
            state_reason: a.state_reason,
            state_until: opt_ts(a.state_until.as_deref()),
            cap: a.cap,
            last_used_at: opt_ts(a.last_used_at.as_deref()),
            created_at: ts(&a.created_at),
            updated_at: ts(&a.updated_at),
        }
    }
}

/// What an `admin` write answers: the account and the runners its key may be leased to.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountDetail {
    pub account: ProviderAccount,
    /// Runner device ids, explicit (never a wildcard).
    pub runners: Vec<String>,
}

impl From<acc::Account> for AccountDetail {
    fn from(a: acc::Account) -> Self {
        let runners = a.runners.clone();
        Self {
            account: a.into(),
            runners,
        }
    }
}

/// A new account. Deliberately no `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct NewProviderAccount {
    pub provider: String,
    pub label: String,
    /// The API key; written, never read back.
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    /// Runner device ids it may be leased to; default none.
    pub runners: Option<Vec<String>>,
    /// Default 4; 0 is no cap.
    pub cap: Option<i64>,
}

/// A replacement key, and optionally a new runner scope. No `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct ReplaceKey {
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    pub runners: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetState {
    /// `active`, `cooling`, `limited`, `unhealthy` or `disabled`.
    pub state: String,
    pub reason: Option<String>,
    pub until: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetCap {
    pub cap: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountsDeleted {
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ModelPrice {
    pub id: String,
    /// List price per million input tokens, in millionths of a dollar.
    pub input_per_mtok_micro: i64,
    pub output_per_mtok_micro: i64,
}

/// A provider definition: a built-in, or user data validated before it is stored.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Provider {
    pub id: String,
    pub name: String,
    /// `claude`, `codex` or `agy`.
    pub harness: String,
    /// The harness's own authentication variable.
    pub auth_var: String,
    /// `https://`, a public DNS name.
    pub base_url: String,
    pub usage_parser: String,
    /// `env` and/or `gateway`.
    pub delivery: Vec<String>,
    /// `paste`.
    pub login_methods: Vec<String>,
    pub models: Vec<ModelPrice>,
    /// When the models' list prices were read.
    pub priced_at: Option<String>,
    /// Read-only: built-ins cannot be edited.
    #[serde(default)]
    pub builtin: bool,
    #[serde(default)]
    pub version: i64,
}

impl From<Definition> for Provider {
    fn from(d: Definition) -> Self {
        Self {
            id: d.id,
            name: d.name,
            harness: d.harness,
            auth_var: d.auth_var,
            base_url: d.base_url,
            usage_parser: d.usage_parser,
            delivery: d.delivery,
            login_methods: d.login_methods,
            models: d
                .models
                .into_iter()
                .map(|m| ModelPrice {
                    id: m.id,
                    input_per_mtok_micro: m.input_per_mtok_micro,
                    output_per_mtok_micro: m.output_per_mtok_micro,
                })
                .collect(),
            priced_at: d.priced_at,
            builtin: d.builtin,
            version: d.version,
        }
    }
}

impl From<Provider> for Definition {
    fn from(p: Provider) -> Self {
        Self {
            id: p.id,
            name: p.name,
            harness: p.harness,
            auth_var: p.auth_var,
            base_url: p.base_url,
            usage_parser: p.usage_parser,
            delivery: p.delivery,
            login_methods: p.login_methods,
            models: p
                .models
                .into_iter()
                .map(|m| Model {
                    id: m.id,
                    input_per_mtok_micro: m.input_per_mtok_micro,
                    output_per_mtok_micro: m.output_per_mtok_micro,
                })
                .collect(),
            priced_at: p.priced_at,
            builtin: false,
            version: 0,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Pool {
    pub id: i64,
    pub name: String,
    pub provider: String,
    /// The provider's default pool serves an agent bound to none.
    pub is_default: bool,
    /// ProviderAccount ids, in fallback order.
    pub members: Vec<i64>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<pl::Pool> for Pool {
    fn from(p: pl::Pool) -> Self {
        Self {
            id: p.id,
            name: p.name,
            provider: p.provider,
            is_default: p.is_default,
            members: p.members,
            created_at: ts(&p.created_at),
            updated_at: ts(&p.updated_at),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewPool {
    pub name: String,
    /// `anthropic`, `openai` or `google`.
    pub provider: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Binding {
    pub agent: String,
    pub provider: String,
    pub pool_id: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewBinding {
    /// An agent id: 1 to 64 of `[A-Za-z0-9._:-]`.
    pub agent: String,
    pub pool_id: i64,
}

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

// ----- pools and bindings -----------------------------------------------------------------

#[utoipa::path(get, path = "/api/v1/pools", operation_id = "listPools", tag = "accounts",
    responses((status = 200, description = "Every pool, its members in fallback order", body = Vec<Pool>)))]
pub async fn list_pools(State(app): State<App>) -> ApiResult<Vec<Pool>> {
    Ok(Json(
        pl::list(&app.pool)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

#[utoipa::path(post, path = "/api/v1/pools", operation_id = "createPool", tag = "accounts",
    request_body = NewPool,
    responses((status = 200, description = "Created, empty (audited as `pool.created`)", body = Pool)))]
pub async fn create_pool(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(b): Json<NewPool>,
) -> ApiResult<Pool> {
    let p = pl::create(
        &app.pool,
        &b.name,
        &b.provider,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(p.into()))
}

#[utoipa::path(delete, path = "/api/v1/pools/{id}", operation_id = "deletePool", tag = "accounts",
    params(("id" = String, Path, description = "The pool's id")),
    responses((status = 200, description = "Deleted with its bindings (audited as \
        `pool.deleted`); the default pool is refused (409)", body = AccountsDeleted)))]
pub async fn delete_pool(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AccountsDeleted> {
    pl::delete(&app.pool, num(&id, "pool")?, &me.device.id, BY)
        .await
        .map_err(err)?;
    Ok(Json(AccountsDeleted { deleted: true }))
}

#[utoipa::path(put, path = "/api/v1/pools/{id}/members/{account}", operation_id = "addPoolMember",
    tag = "accounts",
    params(("id" = String, Path, description = "The pool's id"),
           ("account" = String, Path, description = "The account's id")),
    responses((status = 200, description = "Appended to the pool's fallback order (audited as \
        `pool.member_added`); an account of another provider is refused (400)", body = Pool)))]
pub async fn add_member(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, account)): Path<(String, String)>,
) -> ApiResult<Pool> {
    let p = pl::add_member(
        &app.pool,
        num(&id, "pool")?,
        num(&account, "account")?,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(p.into()))
}

#[utoipa::path(delete, path = "/api/v1/pools/{id}/members/{account}",
    operation_id = "removePoolMember", tag = "accounts",
    params(("id" = String, Path, description = "The pool's id"),
           ("account" = String, Path, description = "The account's id")),
    responses((status = 200, description = "Removed (audited as `pool.member_removed`)", body = Pool)))]
pub async fn remove_member(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, account)): Path<(String, String)>,
) -> ApiResult<Pool> {
    let p = pl::remove_member(
        &app.pool,
        num(&id, "pool")?,
        num(&account, "account")?,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(p.into()))
}

#[utoipa::path(put, path = "/api/v1/pools/{id}/default", operation_id = "setDefaultPool",
    tag = "accounts", params(("id" = String, Path, description = "The pool's id")),
    responses((status = 200, description = "Its provider's default pool from now on (audited \
        as `pool.default_set`)", body = Pool)))]
pub async fn set_default(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<Pool> {
    let p = pl::set_default(
        &app.pool,
        num(&id, "pool")?,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(p.into()))
}

#[utoipa::path(get, path = "/api/v1/bindings", operation_id = "listBindings", tag = "accounts",
    responses((status = 200, description = "Every agent's binding to a pool", body = Vec<Binding>)))]
pub async fn list_bindings(State(app): State<App>) -> ApiResult<Vec<Binding>> {
    let all = pl::list_bindings(&app.pool).await?;
    Ok(Json(
        all.into_iter()
            .map(|b| Binding {
                agent: b.agent,
                provider: b.provider,
                pool_id: b.pool_id,
            })
            .collect(),
    ))
}

#[utoipa::path(put, path = "/api/v1/bindings", operation_id = "bindAgent", tag = "accounts",
    request_body = NewBinding,
    responses((status = 200, description = "The agent draws its pool's provider from this pool, \
        replacing an earlier binding for that provider (audited as `pool.bound`)",
        body = Binding)))]
pub async fn bind(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(b): Json<NewBinding>,
) -> ApiResult<Binding> {
    pl::bind(
        &app.pool,
        &b.agent,
        b.pool_id,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    let p = pl::get(&app.pool, b.pool_id).await.map_err(err)?;
    Ok(Json(Binding {
        agent: b.agent,
        provider: p.provider,
        pool_id: p.id,
    }))
}

#[utoipa::path(delete, path = "/api/v1/bindings/{agent}/{provider}", operation_id = "unbindAgent",
    tag = "accounts",
    params(("agent" = String, Path, description = "The agent's id"),
           ("provider" = String, Path, description = "`anthropic`, `openai` or `google`")),
    responses((status = 200, description = "The agent falls back to the provider's default \
        pool (audited as `pool.unbound`)", body = AccountsDeleted)))]
pub async fn unbind(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((agent, provider)): Path<(String, String)>,
) -> ApiResult<AccountsDeleted> {
    pl::unbind(&app.pool, &agent, &provider, &me.device.id, BY)
        .await
        .map_err(err)?;
    Ok(Json(AccountsDeleted { deleted: true }))
}
