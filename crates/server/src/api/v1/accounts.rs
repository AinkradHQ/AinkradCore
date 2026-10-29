//! The provider account pool (E15.1), for the admin: list, add, assign to companies, disable
//! or enable. No secret goes in or comes out: an account names a token file on the runner
//! hosts, never the token.

use ainkrad_core::gov::AccountId;
use ainkrad_core::org::CompanyId;
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::org::company;
use super::types::{AccountStatus, Billing, Harness, Timestamp, opt_ts};
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::gov;

/// A provider account, by reference only.
#[derive(Debug, Serialize, ToSchema)]
pub struct Account {
    pub id: i64,
    pub harness: Harness,
    pub label: String,
    /// The token file's name under each runner's credentials dir; absent when the account
    /// logs in through its config dir.
    pub credential_ref: Option<String>,
    /// The harness variable the token goes in.
    pub credential_env: Option<String>,
    /// The account's harness config dir, under each runner's config root.
    pub config_dir: String,
    pub billing: Billing,
    pub status: AccountStatus,
    /// Why it is not active.
    pub status_reason: Option<String>,
    /// When a `limited` or `unhealthy` status ends by itself, if known.
    pub status_until: Option<Timestamp>,
    pub last_used_at: Option<Timestamp>,
    /// The companies whose runs may use it.
    pub company_ids: Vec<i64>,
    /// Its plan tier as the admin wrote it (`Max 20x`, `Pro`); shown, never enforced.
    pub plan_tier: Option<String>,
}

impl From<ainkrad_core::gov::Account> for Account {
    fn from(a: ainkrad_core::gov::Account) -> Self {
        Self {
            id: a.id.0,
            harness: a.harness.into(),
            label: a.label,
            credential_ref: a.credential_ref,
            credential_env: a.credential_env,
            config_dir: a.config_dir,
            billing: a.billing.into(),
            status: a.status.into(),
            status_reason: a.status_reason,
            status_until: opt_ts(a.status_until.as_deref()),
            last_used_at: opt_ts(a.last_used_at.as_deref()),
            company_ids: a.companies,
            plan_tier: a.plan_tier,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewAccount {
    pub harness: Harness,
    /// Unique, `[a-z0-9][a-z0-9._-]*`.
    pub label: String,
    /// A file name under each runner's credentials dir; never the token itself.
    pub credential_ref: Option<String>,
    /// Default: the harness's first auth variable, e.g. `CLAUDE_CODE_OAUTH_TOKEN`.
    pub credential_env: Option<String>,
    /// Default: `accounts/<label>`.
    pub config_dir: Option<String>,
    /// Default: the harness's billing.
    pub billing: Option<Billing>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct StatusChange {
    /// `active` or `disabled`; the others are the server's to set.
    pub status: AccountStatus,
    pub reason: Option<String>,
}

pub(super) async fn found(app: &App, id: i64) -> Result<ainkrad_core::gov::Account, ApiError> {
    gov::get_account(&app.pool, AccountId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no account {id}")))
}

#[utoipa::path(get, path = "/api/v1/accounts", operation_id = "listAccounts", tag = "accounts",
    responses((status = 200, description = "The whole pool; in a company (`X-Citadel-Company`), \
        the accounts its runs may use", body = Vec<Account>)))]
pub async fn list(
    State(app): State<App>,
    axum::Extension(acting): axum::Extension<super::scope::Acting>,
) -> ApiResult<Vec<Account>> {
    let all = gov::list_accounts(&app.pool).await?;
    // In a company (E15.14): the accounts its runs may use.
    let mine = all
        .into_iter()
        .filter(|a| acting.0.is_none_or(|c| a.companies.contains(&c.0)));
    Ok(Json(mine.map(Into::into).collect()))
}

#[utoipa::path(post, path = "/api/v1/accounts", operation_id = "createAccount", tag = "accounts",
    request_body = NewAccount,
    responses((status = 200, description = "The new account, active and assigned to no company", body = Account)))]
pub async fn create(State(app): State<App>, Json(n): Json<NewAccount>) -> ApiResult<Account> {
    let new = gov::new_account(
        &app.pool,
        n.harness.into(),
        &n.label,
        n.credential_ref,
        n.credential_env,
        n.config_dir,
        n.billing.map(Into::into),
    )
    .await?;
    match gov::create_account(&app.pool, &new, BY).await {
        Ok(a) => Ok(Json(a.into())),
        Err(sqlx::Error::InvalidArgument(why)) => Err(ApiError::bad_request(why)),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(ApiError::conflict(
            format!("label {:?} is taken", new.label),
        )),
        Err(e) => Err(e.into()),
    }
}

/// What a delete removed.
#[derive(Debug, Serialize, ToSchema)]
pub struct RemovedAccount {
    pub id: i64,
}

#[utoipa::path(delete, path = "/api/v1/accounts/{id}", operation_id = "deleteAccount",
    tag = "accounts", params(("id" = i64, Path, description = "Account id")),
    responses(
        (status = 200, description = "The account is gone with its company assignments and \
            limits (audited as `account.deleted`)", body = RemovedAccount),
        (status = 409, description = "Live runs use it, or it has run or been billed (the cost \
            ledger keeps its name: disable it instead)", body = super::types::ErrorBody)))]
pub async fn delete(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<RemovedAccount> {
    match gov::delete_account(&app.pool, AccountId(id), BY).await {
        Ok(true) => Ok(Json(RemovedAccount { id })),
        Ok(false) => Err(ApiError::not_found(format!("no account {id}"))),
        Err(gov::DeleteAccountError::Db(e)) => Err(e.into()),
        Err(e) => Err(ApiError::conflict(format!("account {id}: {e}"))),
    }
}

#[utoipa::path(put, path = "/api/v1/accounts/{id}/companies/{company_id}",
    operation_id = "assignAccount", tag = "accounts",
    params(("id" = i64, Path, description = "Account id"),
           ("company_id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The account, now assigned", body = Account)))]
pub async fn assign(
    State(app): State<App>,
    Path((id, company_id)): Path<(i64, i64)>,
) -> ApiResult<Account> {
    let (a, c) = (found(&app, id).await?, company(&app, company_id).await?);
    gov::assign_account(&app.pool, a.id, c.id, true, BY).await?;
    Ok(Json(found(&app, id).await?.into()))
}

#[utoipa::path(delete, path = "/api/v1/accounts/{id}/companies/{company_id}",
    operation_id = "unassignAccount", tag = "accounts",
    params(("id" = i64, Path, description = "Account id"),
           ("company_id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The account; runs already on it keep it", body = Account)))]
pub async fn unassign(
    State(app): State<App>,
    Path((id, company_id)): Path<(i64, i64)>,
) -> ApiResult<Account> {
    let a = found(&app, id).await?;
    gov::assign_account(&app.pool, a.id, CompanyId(company_id), false, BY).await?;
    Ok(Json(found(&app, id).await?.into()))
}

#[utoipa::path(post, path = "/api/v1/accounts/{id}/status", operation_id = "setAccountStatus",
    tag = "accounts", params(("id" = i64, Path, description = "Account id")),
    request_body = StatusChange,
    responses((status = 200, description = "The account", body = Account)))]
pub async fn set_status(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(change): Json<StatusChange>,
) -> ApiResult<Account> {
    let a = found(&app, id).await?;
    let status: ainkrad_core::gov::AccountStatus = change.status.into();
    use ainkrad_core::gov::AccountStatus as S;
    if !matches!(status, S::Active | S::Disabled) {
        return Err(ApiError::bad_request(
            "only active or disabled is set by hand",
        ));
    }
    gov::set_account_status(&app.pool, a.id, status, change.reason.as_deref(), BY).await?;
    Ok(Json(found(&app, id).await?.into()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PlanBody {
    /// 1–64 characters, e.g. `Max 20x`; absent or empty clears it.
    pub plan_tier: Option<String>,
}

#[utoipa::path(put, path = "/api/v1/accounts/{id}/plan", operation_id = "setAccountPlan",
    tag = "accounts", params(("id" = i64, Path, description = "Account id")),
    request_body = PlanBody,
    responses((status = 200, description = "The account with its plan tier (audited as \
        `account.plan_set`)", body = Account)))]
pub async fn set_plan(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<PlanBody>,
) -> ApiResult<Account> {
    let a = found(&app, id).await?;
    let tier = b
        .plan_tier
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    if tier.is_some_and(|t| t.chars().count() > 64) {
        return Err(ApiError::bad_request(
            "a plan tier is at most 64 characters",
        ));
    }
    gov::set_account_plan(&app.pool, a.id, tier, BY).await?;
    Ok(Json(found(&app, id).await?.into()))
}
