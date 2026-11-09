//! Account usage limits and the usage report (E15.2): set or clear a limit, read each
//! account's use per window and per company, or one company's use of every account.

use citadel_core::gov::NewAccountLimit;
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::accounts::{Account, found};
use super::org::company;
use super::types::LimitUnit;
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::gov;

/// A cap on an account's use over a rolling window.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountLimit {
    pub id: i64,
    pub window_secs: i64,
    pub unit: LimitUnit,
    pub max: i64,
    /// The admin is warned once per window at this share of `max`.
    pub warn_percent: i64,
}

impl From<citadel_core::gov::AccountLimit> for AccountLimit {
    fn from(l: citadel_core::gov::AccountLimit) -> Self {
        Self {
            id: l.id,
            window_secs: l.window_secs,
            unit: l.unit.into(),
            max: l.max,
            warn_percent: l.warn_percent,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewLimit {
    /// E.g. 18000 for 5 h.
    pub window_secs: i64,
    pub unit: LimitUnit,
    pub max: i64,
    /// Default: the account's `account.warn_percent` setting (80 unless set).
    pub warn_percent: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LimitUsage {
    pub limit: AccountLimit,
    /// Used in the window ending now.
    pub used: i64,
}

/// What one company used of one account, all time.
#[derive(Debug, Serialize, ToSchema)]
pub struct CompanyUsage {
    pub company_id: i64,
    pub tokens: i64,
    pub messages: i64,
    pub runs: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountUsage {
    pub account: Account,
    pub limits: Vec<LimitUsage>,
    pub companies: Vec<CompanyUsage>,
    /// The harness's latest plan-limit report (Claude's windows), as it sent it.
    #[schema(value_type = Option<Object>)]
    pub signal: Option<serde_json::Value>,
    /// Provider drops in the last `drops_window_secs` (`account.drop_window_secs`); enough of
    /// them (`account.drop_threshold`) make the account unhealthy.
    pub drops: i64,
    pub drops_window_secs: i64,
    /// Provider drops in the last `recent_drops_window_secs`
    /// (`account.drop_display_window_secs`, a day by default), for display.
    pub recent_drops: i64,
    pub recent_drops_window_secs: i64,
}

impl From<gov::AccountUsage> for AccountUsage {
    fn from(u: gov::AccountUsage) -> Self {
        Self {
            account: u.account.into(),
            limits: u
                .limits
                .into_iter()
                .map(|l| LimitUsage {
                    limit: l.limit.into(),
                    used: l.used,
                })
                .collect(),
            companies: u
                .companies
                .into_iter()
                .map(|c| CompanyUsage {
                    company_id: c.company_id,
                    tokens: c.tokens,
                    messages: c.messages,
                    runs: c.runs,
                })
                .collect(),
            signal: u.signal,
            drops: u.drops,
            drops_window_secs: u.drops_window_secs,
            recent_drops: u.recent_drops,
            recent_drops_window_secs: u.recent_drops_window_secs,
        }
    }
}

#[utoipa::path(post, path = "/api/v1/accounts/{id}/limits", operation_id = "setAccountLimit",
    tag = "accounts", params(("id" = i64, Path, description = "Account id")),
    request_body = NewLimit,
    responses((status = 200, description = "The limit, replacing one of the same window and unit", body = AccountLimit)))]
pub async fn set_limit(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(n): Json<NewLimit>,
) -> ApiResult<AccountLimit> {
    let a = found(&app, id).await?;
    let new = NewAccountLimit {
        window_secs: n.window_secs,
        unit: n.unit.into(),
        max: n.max,
        warn_percent: n.warn_percent,
    };
    match gov::set_account_limit(&app.pool, a.id, new, BY, &app.clock.now()).await {
        Ok(l) => Ok(Json(l.into())),
        Err(sqlx::Error::InvalidArgument(why)) => Err(ApiError::bad_request(why)),
        Err(e) => Err(e.into()),
    }
}

#[utoipa::path(delete, path = "/api/v1/accounts/{id}/limits/{unit}/{window_secs}",
    operation_id = "clearAccountLimit", tag = "accounts",
    params(("id" = i64, Path, description = "Account id"),
           ("unit" = LimitUnit, Path, description = "tokens or messages"),
           ("window_secs" = i64, Path, description = "The limit's window")),
    responses((status = 200, description = "The account, without that limit", body = Account)))]
pub async fn clear_limit(
    State(app): State<App>,
    Path((id, unit, window)): Path<(i64, LimitUnit, i64)>,
) -> ApiResult<Account> {
    let a = found(&app, id).await?;
    if !gov::clear_account_limit(&app.pool, a.id, window, unit.into(), BY).await? {
        return Err(ApiError::not_found("no such limit"));
    }
    Ok(Json(a.into()))
}

#[utoipa::path(get, path = "/api/v1/accounts/usage", operation_id = "accountUsage",
    tag = "accounts",
    responses((status = 200, description = "Every account's limits, use and use per company: the \
        whole pool, the admin's; a 404 in a company (`X-Citadel-Company`), which reads its own \
        with `/companies/{id}/account-usage`", body = Vec<AccountUsage>)))]
pub async fn usage(
    State(app): State<App>,
    axum::Extension(acting): axum::Extension<super::scope::Acting>,
) -> ApiResult<Vec<AccountUsage>> {
    if let Some(c) = acting.0 {
        let why = format!(
            "the whole pool is not company {}'s; read /companies/{}/account-usage",
            c.0, c.0
        );
        return Err(super::ApiError::not_found(why));
    }
    let all = gov::account_usage(&app.pool, &app.clock.now()).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

/// What a company used of one account.
#[derive(Debug, Serialize, ToSchema)]
pub struct CompanyAccountUsage {
    pub account_id: i64,
    pub label: String,
    pub tokens: i64,
    pub messages: i64,
    pub runs: i64,
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/account-usage",
    operation_id = "companyAccountUsage", tag = "accounts",
    params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "What the company used of each account it used", body = Vec<CompanyAccountUsage>)))]
pub async fn company_usage(
    State(app): State<App>,
    Path(id): Path<i64>,
) -> ApiResult<Vec<CompanyAccountUsage>> {
    let c = company(&app, id).await?;
    let all = gov::account_usage(&app.pool, &app.clock.now()).await?;
    let used = all.into_iter().filter_map(|u| {
        let mine = u.companies.into_iter().find(|cu| cu.company_id == c.id.0)?;
        Some(CompanyAccountUsage {
            account_id: u.account.id.0,
            label: u.account.label,
            tokens: mine.tokens,
            messages: mine.messages,
            runs: mine.runs,
        })
    });
    Ok(Json(used.collect()))
}
