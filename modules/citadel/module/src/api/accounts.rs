//! Provider account pool API (S9, E15.1–E15.2): accounts, company assignments, cooldown/disabled
//! status, plan tiers, rolling usage limits, and 5-hour / 7-day usage reports.
//!
//! Each account maps to at most ONE broker secret (`secret_name`, `delivery`, `runners`) in the
//! Core secrets broker (`ainkrad_core_server::store::secrets`). No handler accepts or returns a
//! credential value, file path, or environment variable name.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::extract::{Path, State};
use axum::routing::{delete, get, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use super::error::{found, refused};
use super::model::Deleted;
use super::scope::Acting;
use super::types::{Billing as BillingModel, Harness, Timestamp, opt_ts, ts};
use crate::domain::gov::{AccountId, AccountStatus, Billing, LimitUnit, PlanTier};
use crate::domain::org::{CompanyId, Harness as DomainHarness};
use crate::store::accounts::{self as store, AccountLimit, AccountSignal, NewAccount};
use crate::store::org;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatusApi {
    Active,
    Cooling,
    Disabled,
}

impl From<AccountStatus> for AccountStatusApi {
    fn from(s: AccountStatus) -> Self {
        match s {
            AccountStatus::Active => Self::Active,
            AccountStatus::Cooling => Self::Cooling,
            AccountStatus::Disabled => Self::Disabled,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanTierApi {
    Pro,
    Max5x,
    Max20x,
    Plus,
    Api,
}

impl From<PlanTier> for PlanTierApi {
    fn from(p: PlanTier) -> Self {
        match p {
            PlanTier::Pro => Self::Pro,
            PlanTier::Max5x => Self::Max5x,
            PlanTier::Max20x => Self::Max20x,
            PlanTier::Plus => Self::Plus,
            PlanTier::Api => Self::Api,
        }
    }
}

impl From<PlanTierApi> for PlanTier {
    fn from(p: PlanTierApi) -> Self {
        match p {
            PlanTierApi::Pro => Self::Pro,
            PlanTierApi::Max5x => Self::Max5x,
            PlanTierApi::Max20x => Self::Max20x,
            PlanTierApi::Plus => Self::Plus,
            PlanTierApi::Api => Self::Api,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LimitUnitApi {
    Tokens,
    Messages,
}

impl From<LimitUnit> for LimitUnitApi {
    fn from(u: LimitUnit) -> Self {
        match u {
            LimitUnit::Tokens => Self::Tokens,
            LimitUnit::Messages => Self::Messages,
        }
    }
}

impl From<LimitUnitApi> for LimitUnit {
    fn from(u: LimitUnitApi) -> Self {
        match u {
            LimitUnitApi::Tokens => Self::Tokens,
            LimitUnitApi::Messages => Self::Messages,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AccountSignalOut {
    pub plan_tier: Option<PlanTierApi>,
    pub used_percent: Option<u8>,
    pub reset_at: Option<Timestamp>,
    pub at: Timestamp,
}

impl From<AccountSignal> for AccountSignalOut {
    fn from(s: AccountSignal) -> Self {
        Self {
            plan_tier: s.plan_tier.map(Into::into),
            used_percent: s.used_percent,
            reset_at: opt_ts(s.reset_at.as_deref()),
            at: ts(&s.at),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Account {
    pub id: i64,
    pub harness: Harness,
    pub label: String,
    pub secret_name: String,
    pub delivery: String,
    pub runners: Vec<String>,
    pub billing: BillingModel,
    pub config_dir: String,
    pub status: AccountStatusApi,
    pub status_reason: Option<String>,
    pub status_until: Option<Timestamp>,
    pub last_used_at: Option<Timestamp>,
    pub plan_tier: Option<PlanTierApi>,
    pub signal: Option<AccountSignalOut>,
    pub created_at: Timestamp,
    pub company_ids: Vec<i64>,
}

impl From<store::Account> for Account {
    fn from(a: store::Account) -> Self {
        Self {
            id: a.id.0,
            harness: a.harness.into(),
            label: a.label,
            secret_name: a.secret_name,
            delivery: a.delivery,
            runners: a.runners,
            billing: a.billing.into(),
            config_dir: a.config_dir,
            status: a.status.into(),
            status_reason: a.status_reason,
            status_until: opt_ts(a.status_until.as_deref()),
            last_used_at: opt_ts(a.last_used_at.as_deref()),
            plan_tier: a.plan_tier.map(Into::into),
            signal: a.signal.map(Into::into),
            created_at: ts(&a.created_at),
            company_ids: a.company_ids.into_iter().map(|c| c.0).collect(),
        }
    }
}

/// Request body to create an account. `deny_unknown_fields` refuses any attempt to send a raw
/// credential value, token, or host file path.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateAccount {
    pub harness: Harness,
    pub label: String,
    pub billing: Option<BillingModel>,
    pub config_dir: Option<String>,
    /// Name of the broker secret in `core_secrets`; defaults to `label`.
    pub secret_name: Option<String>,
    /// Delivery type (`env`, `file`, `askpass`); read from `core_secrets` when the secret exists.
    pub delivery: Option<String>,
    /// Runner ids allowed to lease the secret; read from `core_secrets` when the secret exists.
    pub runners: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusBody {
    pub status: AccountStatusApi,
    pub reason: Option<String>,
    pub until: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountPlanBody {
    pub plan_tier: Option<PlanTierApi>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountLimitBody {
    pub unit: LimitUnitApi,
    pub window_secs: i64,
    pub cap: i64,
    pub warn_percent: Option<u8>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LimitStandingOut {
    pub unit: LimitUnitApi,
    pub window_secs: i64,
    pub cap: i64,
    pub used: i64,
    pub warn_percent: u8,
    pub exhausted: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WindowUsageOut {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    pub total_tokens: i64,
    pub messages: i64,
    pub cost_usd_micros: i64,
}

impl From<store::WindowUsage> for WindowUsageOut {
    fn from(w: store::WindowUsage) -> Self {
        Self {
            input_tokens: w.input_tokens,
            output_tokens: w.output_tokens,
            cache_tokens: w.cache_tokens,
            total_tokens: w.total_tokens,
            messages: w.messages,
            cost_usd_micros: w.cost_usd_micros,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CompanyAccountSliceOut {
    pub company_id: i64,
    pub five_hours: WindowUsageOut,
    pub seven_days: WindowUsageOut,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountUsageReport {
    pub id: i64,
    pub harness: Harness,
    pub label: String,
    pub billing: BillingModel,
    pub status: AccountStatusApi,
    pub status_reason: Option<String>,
    pub status_until: Option<Timestamp>,
    pub last_used_at: Option<Timestamp>,
    pub plan_tier: Option<PlanTierApi>,
    pub signal: Option<AccountSignalOut>,
    pub company_ids: Vec<i64>,
    pub five_hours: WindowUsageOut,
    pub seven_days: WindowUsageOut,
    pub max_utilisation_bps: u32,
    pub recent_drops: i64,
    pub limits: Vec<LimitStandingOut>,
    pub by_company: Vec<CompanyAccountSliceOut>,
}

impl From<store::AccountUsage> for AccountUsageReport {
    fn from(u: store::AccountUsage) -> Self {
        let a = u.account;
        Self {
            id: a.id.0,
            harness: a.harness.into(),
            label: a.label,
            billing: a.billing.into(),
            status: a.status.into(),
            status_reason: a.status_reason,
            status_until: opt_ts(a.status_until.as_deref()),
            last_used_at: opt_ts(a.last_used_at.as_deref()),
            plan_tier: a.plan_tier.map(Into::into),
            signal: a.signal.map(Into::into),
            company_ids: a.company_ids.into_iter().map(|c| c.0).collect(),
            five_hours: u.five_hours.into(),
            seven_days: u.seven_days.into(),
            max_utilisation_bps: u.max_utilisation_bps,
            recent_drops: u.recent_drops,
            limits: u
                .limits
                .into_iter()
                .map(|l| LimitStandingOut {
                    unit: l.unit.into(),
                    window_secs: l.window_secs,
                    cap: l.cap,
                    used: l.used,
                    warn_percent: l.warn_percent,
                    exhausted: l.exhausted,
                })
                .collect(),
            by_company: u
                .by_company
                .into_iter()
                .map(|s| CompanyAccountSliceOut {
                    company_id: s.company_id.0,
                    five_hours: s.five_hours.into(),
                    seven_days: s.seven_days.into(),
                })
                .collect(),
        }
    }
}

#[utoipa::path(get, path = "/accounts", operation_id = "listAccounts", tag = "governance",
    responses((status = 200, description = "Every provider account in the pool (never a token)",
        body = Vec<Account>)))]
pub async fn list_accounts(State(app): State<App>, acting: Acting) -> ApiResult<Vec<Account>> {
    let all = store::list_accounts(&app.pool).await?;
    let visible = all.into_iter().filter(|a| match acting.0 {
        Some(c) => a.company_ids.contains(&c),
        None => true,
    });
    Ok(Json(visible.map(Into::into).collect()))
}

#[utoipa::path(post, path = "/accounts", operation_id = "createAccount", tag = "governance",
    request_body = CreateAccount,
    responses((status = 200, description = "The new account", body = Account)))]
pub async fn create_account(
    State(app): State<App>,
    _: Acting,
    Json(body): Json<CreateAccount>,
) -> ApiResult<Account> {
    let require_broker =
        body.secret_name.is_some() && body.delivery.is_none() && body.runners.is_none();
    let new = NewAccount {
        harness: DomainHarness::from(body.harness),
        label: body.label,
        billing: body
            .billing
            .map(Billing::from)
            .unwrap_or(Billing::Subscription),
        config_dir: body.config_dir,
        secret_name: body.secret_name,
        delivery: body.delivery,
        runners: body.runners,
        require_broker_secret: require_broker,
    };
    let created = store::create_account(&app.pool, &new, BY)
        .await
        .map_err(refused)?;
    Ok(Json(created.into()))
}

#[utoipa::path(delete, path = "/accounts/{id}", operation_id = "deleteAccount", tag = "governance",
    params(("id" = i64, Path, description = "Account id")),
    responses((status = 200, description = "Deleted when unused by the ledger; 409 otherwise",
        body = Deleted)))]
pub async fn delete_account(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Deleted> {
    let deleted = match store::delete_account(&app.pool, AccountId(id), BY).await {
        Ok(d) => d,
        Err(sqlx::Error::InvalidArgument(why)) => return Err(ApiError::conflict(why)),
        Err(e) => return Err(refused(e)),
    };
    found(deleted.then_some(()), "account")?;
    Ok(Json(Deleted { deleted: id }))
}

#[utoipa::path(put, path = "/accounts/{id}/companies/{cid}", operation_id = "assignAccount",
    tag = "governance",
    params(("id" = i64, Path, description = "Account id"),
           ("cid" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The account with `cid` in its `company_ids`",
        body = Account)))]
pub async fn assign_account(
    State(app): State<App>,
    _: Acting,
    Path((id, cid)): Path<(i64, i64)>,
) -> ApiResult<Account> {
    found(
        store::get_account(&app.pool, AccountId(id)).await?,
        "account",
    )?;
    found(
        org::get_company(&app.pool, CompanyId(cid)).await?,
        "company",
    )?;
    store::assign_account(&app.pool, AccountId(id), CompanyId(cid), true, BY)
        .await
        .map_err(refused)?;
    let updated = found(
        store::get_account(&app.pool, AccountId(id)).await?,
        "account",
    )?;
    Ok(Json(updated.into()))
}

#[utoipa::path(delete, path = "/accounts/{id}/companies/{cid}", operation_id = "unassignAccount",
    tag = "governance",
    params(("id" = i64, Path, description = "Account id"),
           ("cid" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The account without `cid` in its `company_ids`",
        body = Account)))]
pub async fn unassign_account(
    State(app): State<App>,
    _: Acting,
    Path((id, cid)): Path<(i64, i64)>,
) -> ApiResult<Account> {
    found(
        store::get_account(&app.pool, AccountId(id)).await?,
        "account",
    )?;
    found(
        org::get_company(&app.pool, CompanyId(cid)).await?,
        "company",
    )?;
    store::assign_account(&app.pool, AccountId(id), CompanyId(cid), false, BY)
        .await
        .map_err(refused)?;
    let updated = found(
        store::get_account(&app.pool, AccountId(id)).await?,
        "account",
    )?;
    Ok(Json(updated.into()))
}

#[utoipa::path(put, path = "/accounts/{id}/status", operation_id = "setAccountStatus",
    tag = "governance",
    params(("id" = i64, Path, description = "Account id")), request_body = AccountStatusBody,
    responses((status = 200, description = "The account after the status change", body = Account)))]
pub async fn set_account_status(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(body): Json<AccountStatusBody>,
) -> ApiResult<Account> {
    let status = match body.status {
        AccountStatusApi::Active => AccountStatus::Active,
        AccountStatusApi::Cooling => AccountStatus::Cooling,
        AccountStatusApi::Disabled => AccountStatus::Disabled,
    };
    let updated = store::set_account_status(
        &app.pool,
        AccountId(id),
        status,
        body.reason.as_deref(),
        body.until.as_deref(),
        BY,
    )
    .await
    .map_err(refused)?;
    Ok(Json(found(updated, "account")?.into()))
}

#[utoipa::path(put, path = "/accounts/{id}/plan", operation_id = "setAccountPlan",
    tag = "governance",
    params(("id" = i64, Path, description = "Account id")), request_body = AccountPlanBody,
    responses((status = 200, description = "The account with its new plan tier", body = Account)))]
pub async fn set_account_plan(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(body): Json<AccountPlanBody>,
) -> ApiResult<Account> {
    let tier = body.plan_tier.map(PlanTier::from);
    let updated = store::set_account_plan(&app.pool, AccountId(id), tier, BY)
        .await
        .map_err(refused)?;
    Ok(Json(found(updated, "account")?.into()))
}

#[utoipa::path(put, path = "/accounts/{id}/limits", operation_id = "setAccountLimit",
    tag = "governance",
    params(("id" = i64, Path, description = "Account id")), request_body = AccountLimitBody,
    responses((status = 200, description = "The configured limit", body = AccountLimitBody)))]
pub async fn set_account_limit(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(body): Json<AccountLimitBody>,
) -> ApiResult<AccountLimitBody> {
    found(
        store::get_account(&app.pool, AccountId(id)).await?,
        "account",
    )?;
    let limit = AccountLimit {
        id: 0,
        account_id: AccountId(id),
        unit: LimitUnit::from(body.unit),
        window_secs: body.window_secs,
        cap: body.cap,
        warn_percent: body.warn_percent,
    };
    let saved = store::set_account_limit(&app.pool, &limit, BY)
        .await
        .map_err(refused)?;
    Ok(Json(AccountLimitBody {
        unit: saved.unit.into(),
        window_secs: saved.window_secs,
        cap: saved.cap,
        warn_percent: saved.warn_percent,
    }))
}

#[utoipa::path(delete, path = "/accounts/{id}/limits/{unit}/{window_secs}",
    operation_id = "clearAccountLimit", tag = "governance",
    params(("id" = i64, Path, description = "Account id"),
           ("unit" = LimitUnitApi, Path, description = "`tokens` or `messages`"),
           ("window_secs" = i64, Path, description = "Window in seconds")),
    responses((status = 200, description = "Cleared", body = Deleted)))]
pub async fn clear_account_limit(
    State(app): State<App>,
    _: Acting,
    Path((id, unit_raw, window_secs)): Path<(i64, String, i64)>,
) -> ApiResult<Deleted> {
    let unit: LimitUnit = unit_raw
        .parse()
        .map_err(|_| ApiError::bad_request("unit is `tokens` or `messages`"))?;
    let cleared = store::clear_account_limit(&app.pool, AccountId(id), unit, window_secs, BY)
        .await
        .map_err(refused)?;
    found(cleared.then_some(()), "account limit")?;
    Ok(Json(Deleted { deleted: id }))
}

#[utoipa::path(get, path = "/accounts/usage", operation_id = "getAccountUsage", tag = "governance",
    responses((status = 200, description = "Rolling 5-hour and 7-day usage for every account",
        body = Vec<AccountUsageReport>)))]
pub async fn get_account_usage(
    State(app): State<App>,
    acting: Acting,
) -> ApiResult<Vec<AccountUsageReport>> {
    let now = app.clock.now();
    let usage = store::account_usage(&app.pool, acting.0, &now).await?;
    Ok(Json(usage.into_iter().map(Into::into).collect()))
}

#[utoipa::path(get, path = "/companies/{id}/account-usage",
    operation_id = "getCompanyAccountUsage", tag = "governance",
    params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "Rolling usage of accounts assigned to or used by the company",
        body = Vec<AccountUsageReport>)))]
pub async fn get_company_account_usage(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Vec<AccountUsageReport>> {
    found(org::get_company(&app.pool, CompanyId(id)).await?, "company")?;
    let now = app.clock.now();
    let usage = store::account_usage(&app.pool, Some(CompanyId(id)), &now).await?;
    Ok(Json(usage.into_iter().map(Into::into).collect()))
}

pub fn routes() -> Router<App> {
    Router::new()
        .route("/accounts", get(list_accounts).post(create_account))
        .route("/accounts/usage", get(get_account_usage))
        .route("/accounts/{id}", delete(delete_account))
        .route(
            "/accounts/{id}/companies/{cid}",
            put(assign_account).delete(unassign_account),
        )
        .route("/accounts/{id}/status", put(set_account_status))
        .route("/accounts/{id}/plan", put(set_account_plan))
        .route("/accounts/{id}/limits", put(set_account_limit))
        .route(
            "/accounts/{id}/limits/{unit}/{window_secs}",
            delete(clear_account_limit),
        )
        .route(
            "/companies/{id}/account-usage",
            get(get_company_account_usage),
        )
}

pub const SCOPES: &[(&str, &str, &str)] = &[
    ("GET", "/accounts/usage", "read"),
    ("GET", "/companies/{id}/account-usage", "read"),
];

/// The full account list names broker secrets and runners: `admin`, not a phone read.
pub const ADMIN_READS: &[&str] = &["/accounts"];

pub const DESTRUCTIVE: &[(&str, &str)] = &[
    ("POST", "/accounts"),
    ("DELETE", "/accounts/{id}"),
    ("PUT", "/accounts/{id}/companies/{cid}"),
    ("DELETE", "/accounts/{id}/companies/{cid}"),
    ("PUT", "/accounts/{id}/status"),
    ("PUT", "/accounts/{id}/plan"),
    ("PUT", "/accounts/{id}/limits"),
    ("DELETE", "/accounts/{id}/limits/{unit}/{window_secs}"),
];

#[derive(OpenApi)]
#[openapi(
    paths(
        list_accounts,
        create_account,
        delete_account,
        assign_account,
        unassign_account,
        set_account_status,
        set_account_plan,
        set_account_limit,
        clear_account_limit,
        get_account_usage,
        get_company_account_usage,
    ),
    components(schemas(
        Account,
        AccountStatusApi,
        PlanTierApi,
        LimitUnitApi,
        AccountSignalOut,
        CreateAccount,
        AccountStatusBody,
        AccountPlanBody,
        AccountLimitBody,
        LimitStandingOut,
        WindowUsageOut,
        CompanyAccountSliceOut,
        AccountUsageReport,
    ))
)]
pub struct Doc;
