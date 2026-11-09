//! Money from the app (E11.7, the Cost screen): model prices (decision #37: "Set a price…") and
//! budget caps, through the same store calls as the CLI's `price set` and `budget set`, with
//! their rules, audited as the admin.

use citadel_core::gov::{BudgetId, BudgetScope as CoreScope, NewBudget};
use citadel_core::org::{AgentId, CompanyId, DepartmentId};
use citadel_core::work::{IssueId, ProjectId, SprintId};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::gov::{BudgetScope, BudgetStanding};
use super::org::company;
use super::types::{BudgetPeriod, Harness, Timestamp, ts};
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::gov;

/// A harness and model's price, US dollars per million tokens; each set is a new version, and
/// earlier spend keeps the version that priced it.
#[derive(Debug, Serialize, ToSchema)]
pub struct Price {
    pub harness: Harness,
    pub model: String,
    pub version: i64,
    pub input_usd_per_mtok: f64,
    pub output_usd_per_mtok: f64,
    pub cache_usd_per_mtok: f64,
}

impl From<gov::Price> for Price {
    fn from(p: gov::Price) -> Self {
        let usd = |micros: i64| micros as f64 / 1e6;
        Self {
            harness: p.harness.into(),
            model: p.model,
            version: p.version,
            input_usd_per_mtok: usd(p.input_micros_per_mtok),
            output_usd_per_mtok: usd(p.output_micros_per_mtok),
            cache_usd_per_mtok: usd(p.cache_micros_per_mtok),
        }
    }
}

#[utoipa::path(get, path = "/api/v1/prices", operation_id = "listPrices", tag = "money",
    responses((status = 200, description = "The latest version of every harness and model's \
        price; a model with none is unpriced", body = Vec<Price>)))]
pub async fn list_prices(State(app): State<App>) -> ApiResult<Vec<Price>> {
    let all = gov::list_prices(&app.pool).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewPrice {
    pub harness: Harness,
    pub model: String,
    /// Dollars per million tokens, 0 or more (as `citadel-server price set`).
    pub input_usd_per_mtok: f64,
    pub output_usd_per_mtok: f64,
    pub cache_usd_per_mtok: f64,
    /// `now` (the default): from the next cost event on. `past`: also price the metered cost
    /// events of this harness and model that have no dollars yet (API minor 18).
    pub apply_from: Option<ApplyFrom>,
}

/// From when a new price applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplyFrom {
    Past,
    Now,
}

#[utoipa::path(post, path = "/api/v1/prices", operation_id = "setPrice", tag = "money",
    request_body = NewPrice,
    responses((status = 200, description = "The new version of the price, from now on or, with \
        `apply_from: past`, also on the past runs it fits (audited as `price.set`)", body = Price)))]
pub async fn set_price(State(app): State<App>, Json(p): Json<NewPrice>) -> ApiResult<Price> {
    let micros = |usd: f64| -> Result<i64, ApiError> {
        match usd.is_finite() && usd >= 0.0 {
            true => Ok((usd * 1e6).round() as i64),
            false => Err(ApiError::bad_request(
                "a rate is dollars per million tokens, 0 or more",
            )),
        }
    };
    let rates = [
        micros(p.input_usd_per_mtok)?,
        micros(p.output_usd_per_mtok)?,
        micros(p.cache_usd_per_mtok)?,
    ];
    let now = app.clock.now();
    let past = p.apply_from == Some(ApplyFrom::Past);
    let (set, _) =
        gov::set_price_from(&app.pool, p.harness.into(), &p.model, rates, past, BY, &now)
            .await
            .map_err(|e| match e {
                sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
                e => e.into(),
            })?;
    Ok(Json(set.into()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BudgetBody {
    /// The company itself, or one of its departments, projects, agents, sprints or issues.
    pub scope: BudgetScope,
    pub period: BudgetPeriod,
    /// Tokens, 0 or more; 0 with a `usd_cap_micros` is a dollars-only budget.
    pub token_cap: i64,
    /// Millionths of a dollar, 0 or more, enforced beside the tokens when set (API minor 18);
    /// absent clears it. The dollars counted are the priced ones.
    pub usd_cap_micros: Option<i64>,
    /// 1–100; absent: the `budget.warn_percent` setting.
    pub warn_at_percent: Option<u8>,
    /// Runs stop at the cap (the default), or it only warns.
    pub hard_stop: Option<bool>,
}

#[utoipa::path(put, path = "/api/v1/companies/{id}/budgets", operation_id = "setBudget",
    tag = "money", params(("id" = i64, Path, description = "Company id")), request_body = BudgetBody,
    responses((status = 200, description = "The budget for its scope and period, created or \
        changed (audited as `budget.set`), with its spend so far", body = BudgetStanding)))]
pub async fn set_budget(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<BudgetBody>,
) -> ApiResult<BudgetStanding> {
    write_budget(&app, id, b, true).await
}

#[utoipa::path(post, path = "/api/v1/companies/{id}/budgets", operation_id = "createBudget",
    tag = "money", params(("id" = i64, Path, description = "Company id")), request_body = BudgetBody,
    responses((status = 200, description = "A new budget (audited as `budget.created`), with its \
        spend so far; 409 when its scope already has one for the period (`setBudget` changes it)",
        body = BudgetStanding)))]
pub async fn create_budget(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<BudgetBody>,
) -> ApiResult<BudgetStanding> {
    write_budget(&app, id, b, false).await
}

async fn write_budget(
    app: &App,
    id: i64,
    b: BudgetBody,
    replace: bool,
) -> ApiResult<BudgetStanding> {
    let c = company(app, id).await?;
    let scope = match b.scope {
        BudgetScope::Company { company_id } => CoreScope::Company(CompanyId(company_id)),
        BudgetScope::Department { department_id } => {
            CoreScope::Department(DepartmentId(department_id))
        }
        BudgetScope::Project { project_id } => CoreScope::Project(ProjectId(project_id)),
        BudgetScope::Agent { agent_id } => CoreScope::Agent(AgentId(agent_id)),
        BudgetScope::Sprint { sprint_id } => CoreScope::Sprint(SprintId(sprint_id)),
        BudgetScope::Issue { issue_id } => CoreScope::Issue(IssueId(issue_id)),
    };
    if gov::scope_company(&app.pool, &scope).await? != Some(c.id.0) {
        return Err(ApiError::not_found(format!(
            "no such budget scope in company {id}"
        )));
    }
    let warn = match b.warn_at_percent {
        Some(w) => w,
        None => gov::default_warn_percent(&app.pool, &scope).await?,
    };
    let new = NewBudget {
        scope,
        period: b.period.into(),
        token_cap: b.token_cap,
        usd_cap_micros: b.usd_cap_micros,
        warn_at_percent: warn,
        hard_stop: b.hard_stop.unwrap_or(true),
    };
    let invalid = |e| match e {
        sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
        e => e.into(),
    };
    let set = match replace {
        true => gov::set_budget(&app.pool, &new, BY)
            .await
            .map_err(invalid)?,
        false => gov::add_budget(&app.pool, &new, BY)
            .await
            .map_err(invalid)?
            .ok_or_else(|| {
                ApiError::conflict("its scope already has a budget for the period; change that one")
            })?,
    };
    let now = app.clock.now();
    let standing = gov::company_budgets(&app.pool, c.id, &now)
        .await?
        .into_iter()
        .find(|s| s.budget.id == set.id)
        .ok_or_else(|| ApiError::not_found("the budget is gone"))?;
    Ok(Json(standing.into()))
}

#[utoipa::path(delete, path = "/api/v1/budgets/{id}", operation_id = "deleteBudget", tag = "money",
    params(("id" = i64, Path, description = "Budget id")),
    responses((status = 200, description = "Deleted (audited as `budget.deleted`; its spend \
        counters go with it, the ledger stays): the company's budgets left", body = Vec<BudgetStanding>)))]
pub async fn delete_budget(
    State(app): State<App>,
    Path(id): Path<i64>,
) -> ApiResult<Vec<BudgetStanding>> {
    let company: Option<i64> = sqlx::query_scalar(gov::BUDGET_COMPANY)
        .bind(id)
        .fetch_optional(&app.pool)
        .await?
        .flatten();
    let Some(company) = company else {
        return Err(ApiError::not_found(format!("no budget {id}")));
    };
    if !gov::remove_budget(&app.pool, BudgetId(id), BY).await? {
        return Err(ApiError::not_found(format!("no budget {id}")));
    }
    let left = gov::company_budgets(&app.pool, CompanyId(company), &app.clock.now()).await?;
    Ok(Json(left.into_iter().map(Into::into).collect()))
}

/// One version of a price, from when it took effect.
#[derive(Debug, Serialize, ToSchema)]
pub struct PriceVersion {
    #[serde(flatten)]
    pub price: Price,
    pub set_at: Timestamp,
}

/// Which harness and model's price history.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PriceOf {
    pub harness: Harness,
    pub model: String,
}

#[utoipa::path(get, path = "/api/v1/prices/history", operation_id = "priceHistory", tag = "money",
    params(PriceOf),
    responses((status = 200, description = "Every version of the harness and model's price, newest \
        first; empty when it was never priced", body = Vec<PriceVersion>)))]
pub async fn price_history(
    State(app): State<App>,
    Query(q): Query<PriceOf>,
) -> ApiResult<Vec<PriceVersion>> {
    let all = gov::price_history(&app.pool, q.harness.into(), &q.model).await?;
    let out = all.into_iter().map(|(p, at)| PriceVersion {
        price: p.into(),
        set_at: ts(&at),
    });
    Ok(Json(out.collect()))
}

/// Metered spend that has no dollars, for one harness, model and account (API minor 18).
#[derive(Debug, Serialize, ToSchema)]
pub struct UnpricedModel {
    pub harness: Harness,
    pub model: String,
    /// The account the runs used; absent when they had none.
    pub account_id: Option<i64>,
    pub runs: i64,
    pub tokens: i64,
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/costs/unpriced", operation_id = "listUnpriced",
    tag = "money", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The harnesses and models whose metered spend has no \
        dollars, per account, most tokens first; setting a price with `apply_from: past` prices \
        it", body = Vec<UnpricedModel>)))]
pub async fn list_unpriced(
    State(app): State<App>,
    Path(id): Path<i64>,
) -> ApiResult<Vec<UnpricedModel>> {
    let c = company(&app, id).await?;
    let all = gov::unpriced(&app.pool, c.id).await?;
    let out = all.into_iter().map(|u| UnpricedModel {
        harness: u.harness.into(),
        model: u.model,
        account_id: u.account_id,
        runs: u.runs,
        tokens: u.tokens,
    });
    Ok(Json(out.collect()))
}
