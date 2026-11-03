//! The cost ledger, prices and account usage over the API (KAN-449; design
//! `2026-11-02-ai-provider-accounts` §7, §10, §12d). Reading is `read`: the ledger and a usage report
//! name no key, no secret and no runner. Changing a price or an account's limit is `admin` and
//! destructive (a step-up). There is NO route that writes the ledger: the run engine and Citadel
//! record through `store::costs`, so a device cannot forge a cost.

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::types::{Timestamp, opt_ts, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::store::{costs, prices, usage};

/// Default and most cost events on a page.
const PAGE: i64 = 100;

#[derive(Debug, Serialize, ToSchema)]
pub struct CostEvent {
    pub id: i64,
    pub session: String,
    /// The attempt of the session (a restart or a failover starts a new epoch).
    pub epoch: i64,
    /// The Core account the attempt used, if it was one of Core's.
    pub account_id: Option<i64>,
    pub provider: String,
    pub harness: String,
    pub model: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    /// Millionths of a dollar; absent when the event is `unpriced` (never 0).
    pub cost_usd_micros: Option<i64>,
    /// `list_price`, `provider_reported`, `billing_corrected` or `unpriced`.
    pub basis: String,
    /// The turn was interrupted: the tokens are the meter's last reading.
    pub approximate: bool,
    /// When the list price that priced a `list_price` event was read.
    pub priced_at: Option<Timestamp>,
    /// The event a `billing_corrected` row corrects.
    pub corrects_id: Option<i64>,
    pub occurred_at: Timestamp,
}

impl From<costs::CostEvent> for CostEvent {
    fn from(e: costs::CostEvent) -> Self {
        Self {
            id: e.id,
            session: e.session,
            epoch: e.epoch,
            account_id: e.account_id,
            provider: e.provider,
            harness: e.harness,
            model: e.model,
            input_tokens: e.input_tokens,
            output_tokens: e.output_tokens,
            cache_tokens: e.cache_tokens,
            cost_usd_micros: e.cost_usd_micros,
            basis: e.basis,
            approximate: e.approximate,
            priced_at: opt_ts(e.priced_at.as_deref()),
            corrects_id: e.corrects_id,
            occurred_at: ts(&e.occurred_at),
        }
    }
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CostQuery {
    /// Only this session's events.
    pub session: Option<String>,
    /// Only this account's events.
    pub account: Option<i64>,
    /// At most this many, newest first (default and most 100).
    pub limit: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/costs", operation_id = "listCosts", tag = "costs",
    params(CostQuery),
    responses((status = 200, description = "Cost events, newest first. One event is one attempt of a \
        session: a delta, never a running total", body = Vec<CostEvent>)))]
pub async fn list(State(app): State<App>, Query(q): Query<CostQuery>) -> ApiResult<Vec<CostEvent>> {
    let limit = q.limit.unwrap_or(PAGE).clamp(1, PAGE);
    let all = costs::list(&app.pool, q.session.as_deref(), q.account, limit).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

/// A price: millionths of a dollar per million tokens, and when the provider's list price was read.
#[derive(Debug, Serialize, ToSchema)]
pub struct PriceBookEntry {
    pub provider: String,
    pub model: String,
    pub version: i64,
    pub input_per_mtok_micro: i64,
    pub output_per_mtok_micro: i64,
    pub cache_per_mtok_micro: i64,
    pub priced_at: Timestamp,
    pub created_at: Timestamp,
}

impl From<prices::Price> for PriceBookEntry {
    fn from(p: prices::Price) -> Self {
        Self {
            provider: p.provider,
            model: p.model,
            version: p.version,
            input_per_mtok_micro: p.input_per_mtok_micro,
            output_per_mtok_micro: p.output_per_mtok_micro,
            cache_per_mtok_micro: p.cache_per_mtok_micro,
            priced_at: ts(&p.priced_at),
            created_at: ts(&p.created_at),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetPrice {
    pub provider: String,
    pub model: String,
    pub input_per_mtok_micro: i64,
    pub output_per_mtok_micro: i64,
    pub cache_per_mtok_micro: i64,
    /// When the provider's list price was read: a UTC timestamp.
    pub priced_at: String,
}

#[utoipa::path(get, path = "/api/v1/prices", operation_id = "listPrices", tag = "costs",
    responses((status = 200, description = "The newest price of every provider and model. There is \
        no built-in rate card: a model with no price here (or in its definition) is unpriced",
        body = Vec<PriceBookEntry>)))]
pub async fn list_prices(State(app): State<App>) -> ApiResult<Vec<PriceBookEntry>> {
    Ok(Json(
        prices::list(&app.pool)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

#[utoipa::path(put, path = "/api/v1/prices", operation_id = "setPrice", tag = "costs",
    request_body = SetPrice,
    responses((status = 200, description = "The next version of the price, in force from now on \
        (audited as `price.set`). Events already recorded keep the rates that priced them. 400 for \
        a bad provider, model, rate or timestamp", body = PriceBookEntry)))]
pub async fn set_price(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(b): Json<SetPrice>,
) -> ApiResult<PriceBookEntry> {
    let p = prices::set(
        &app.pool,
        &b.provider,
        &b.model,
        [
            b.input_per_mtok_micro,
            b.output_per_mtok_micro,
            b.cache_per_mtok_micro,
        ],
        &b.priced_at,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(ApiError::from)?;
    Ok(Json(p.into()))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UsageWindow {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    pub total_tokens: i64,
    /// Messages counted in the window (an account-wide figure; 0 in a company's slice).
    pub messages: i64,
    pub cost_usd_micros: i64,
}

impl From<usage::Window> for UsageWindow {
    fn from(w: usage::Window) -> Self {
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
pub struct UsageByCompany {
    pub company: String,
    pub five_hours: UsageWindow,
    pub seven_days: UsageWindow,
}

/// A limit and how much of it is used.
#[derive(Debug, Serialize, ToSchema)]
pub struct LimitStanding {
    /// `tokens` or `messages`.
    pub unit: String,
    pub window_secs: i64,
    pub cap: i64,
    pub used: i64,
    pub warn_percent: i64,
    pub exhausted: bool,
}

/// One account's usage. No key, secret name, delivery or runner: it is for a `read` device.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountUsageReport {
    pub account_id: i64,
    pub five_hours: UsageWindow,
    pub seven_days: UsageWindow,
    pub limits: Vec<LimitStanding>,
    /// The highest used/cap of any limit, in basis points (10000 is at the cap).
    pub max_utilisation_bps: i64,
    /// Provider drops in the last hour.
    pub recent_drops: i64,
    pub by_company: Vec<UsageByCompany>,
}

impl From<usage::AccountUsage> for AccountUsageReport {
    fn from(u: usage::AccountUsage) -> Self {
        Self {
            account_id: u.account_id,
            five_hours: u.five_hours.into(),
            seven_days: u.seven_days.into(),
            limits: u
                .limits
                .into_iter()
                .map(|s| LimitStanding {
                    unit: s.unit,
                    window_secs: s.window_secs,
                    cap: s.cap,
                    used: s.used,
                    warn_percent: s.warn_percent,
                    exhausted: s.exhausted,
                })
                .collect(),
            max_utilisation_bps: u.max_utilisation_bps,
            recent_drops: u.recent_drops,
            by_company: u
                .by_company
                .into_iter()
                .map(|c| UsageByCompany {
                    company: c.company,
                    five_hours: c.five_hours.into(),
                    seven_days: c.seven_days.into(),
                })
                .collect(),
        }
    }
}

#[utoipa::path(get, path = "/api/v1/accounts/usage", operation_id = "accountsUsage", tag = "costs",
    responses((status = 200, description = "Every account's tokens, messages and dollars over the \
        last five hours and seven days, its limits with their use, and its recent drops", body = Vec<AccountUsageReport>)))]
pub async fn accounts_usage(State(app): State<App>) -> ApiResult<Vec<AccountUsageReport>> {
    let all = usage::report(&app.pool, None, &app.clock.now()).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetLimit {
    /// `tokens` or `messages`.
    pub unit: String,
    /// 1 to 31622400 seconds.
    pub window_secs: i64,
    pub cap: i64,
    /// Warn at this percent of the cap (1 to 100); default 80.
    pub warn_percent: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LimitSet {
    pub account_id: i64,
    pub unit: String,
    pub window_secs: i64,
    pub cap: i64,
    pub warn_percent: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LimitCleared {
    pub cleared: bool,
}

fn account_id(s: &str) -> Result<i64, ApiError> {
    s.parse::<u64>()
        .ok()
        .and_then(|n| i64::try_from(n).ok())
        .ok_or_else(|| ApiError::not_found("no such account"))
}

#[utoipa::path(put, path = "/api/v1/accounts/{id}/limits", operation_id = "setAccountLimit",
    tag = "costs", params(("id" = String, Path, description = "The account's id")),
    request_body = SetLimit,
    responses((status = 200, description = "The limit set or changed (audited as \
        `account.limit_set`); 404 for no such account", body = LimitSet)))]
pub async fn set_limit(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<SetLimit>,
) -> ApiResult<LimitSet> {
    let l = usage::set_limit(
        &app.pool,
        account_id(&id)?,
        &b.unit,
        b.window_secs,
        b.cap,
        b.warn_percent,
        &me.device.id,
        BY,
    )
    .await
    .map_err(ApiError::from)?;
    Ok(Json(LimitSet {
        account_id: l.account_id,
        unit: l.unit,
        window_secs: l.window_secs,
        cap: l.cap,
        warn_percent: l.warn_percent,
    }))
}

#[utoipa::path(delete, path = "/api/v1/accounts/{id}/limits/{unit}/{window_secs}",
    operation_id = "clearAccountLimit", tag = "costs",
    params(("id" = String, Path, description = "The account's id"),
           ("unit" = String, Path, description = "`tokens` or `messages`"),
           ("window_secs" = i64, Path, description = "The limit's window")),
    responses((status = 200, description = "Cleared (audited as `account.limit_cleared`); \
        `cleared` is false when there was no such limit", body = LimitCleared)))]
pub async fn clear_limit(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, unit, window)): Path<(String, String, i64)>,
) -> ApiResult<LimitCleared> {
    let cleared = usage::clear_limit(
        &app.pool,
        account_id(&id)?,
        &unit,
        window,
        &me.device.id,
        BY,
    )
    .await
    .map_err(ApiError::from)?;
    Ok(Json(LimitCleared { cleared }))
}
