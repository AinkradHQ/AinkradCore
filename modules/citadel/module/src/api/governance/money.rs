//! Money from the app (E11.7, the Cost screen): model prices (decision #37: "Set a price...") and
//! budget caps, through the same store calls as the CLI's `price set` and `budget set`, with
//! their rules, audited as the admin.
//!
//! Not here (they read the run table, S7): `getCompanyCosts`, `getSprintCosts`,
//! `listUnpriced`; a price set with `apply_from: past` is refused until then.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde::Serialize;
use utoipa::{IntoParams, ToSchema};

use crate::api::error::found;
use crate::api::model::governance::{BudgetScope, BudgetStanding, Price, PriceVersion};
use crate::api::scope::Acting;
use crate::api::types::{BudgetPeriod, Harness, ts};
use crate::domain::gov::{BudgetId, BudgetScope as CoreScope, NewBudget};
use crate::domain::org::{AgentId, CompanyId, DepartmentId, Harness as CoreHarness};
use crate::domain::work::{IssueId, ProjectId, SprintId};
use crate::store::gov;
use crate::store::org;

#[derive(Debug, Serialize, ToSchema)]
pub struct CostReport {
    pub company_id: i64,
    pub runs: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    pub cost_usd_micros: i64,
    pub unpriced_tokens: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LedgerEntry {
    pub id: i64,
    pub agent_id: i64,
    pub issue_id: Option<i64>,
    pub account_id: Option<i64>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    pub cost_usd_micros: Option<i64>,
    pub priced: bool,
    pub created_at: String,
}

fn invalid(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
        e => e.into(),
    }
}

fn harness(text: &str) -> Result<CoreHarness, ApiError> {
    text.parse()
        .map_err(|_| ApiError::bad_request("harness is `claude`, `codex`, `opencode` or `agy`"))
}

#[utoipa::path(get, path = "/prices", operation_id = "listPrices", tag = "money",
    responses((status = 200, description = "The latest version of every harness and model's \
        price; a model with none is unpriced", body = Vec<Price>)))]
pub async fn list_prices(State(app): State<App>, _: Acting) -> ApiResult<Vec<Price>> {
    let all = gov::list_prices(&app.pool).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewPrice {
    /// `claude`, `codex`, `opencode` or `agy`; anything else is a 400.
    #[schema(value_type = Harness)]
    pub harness: String,
    pub model: String,
    /// Dollars per million tokens, 0 or more (as `citadel-server price set`).
    pub input_usd_per_mtok: f64,
    pub output_usd_per_mtok: f64,
    pub cache_usd_per_mtok: f64,
    /// `now` (the default): from the next cost event on. `past`: also price the metered cost
    /// events of this harness and model that have no dollars yet (API minor 18); refused
    /// until the run engine is ported.
    pub apply_from: Option<String>,
}

#[utoipa::path(post, path = "/prices", operation_id = "setPrice", tag = "money",
    request_body = NewPrice,
    responses((status = 200, description = "The new version of the price, from now on \
        (audited as `price.set`)", body = Price)))]
pub async fn set_price(
    State(app): State<App>,
    _: Acting,
    Json(p): Json<NewPrice>,
) -> ApiResult<Price> {
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
    let past = match p.apply_from.as_deref() {
        None | Some("now") => false,
        Some("past") => true,
        Some(_) => return Err(ApiError::bad_request("apply_from is `now` or `past`")),
    };
    let now = app.clock.now();
    let (set, _) = gov::set_price_from(
        &app.pool,
        harness(&p.harness)?,
        &p.model,
        rates,
        past,
        BY,
        &now,
    )
    .await
    .map_err(invalid)?;
    Ok(Json(set.into()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BudgetBody {
    /// The company itself, or one of its departments, projects, agents, sprints or issues.
    pub scope: BudgetScope,
    /// `day`, `week`, `month` or `total`; anything else is a 400.
    #[schema(value_type = BudgetPeriod)]
    pub period: String,
    /// Tokens, 0 or more; 0 with a `usd_cap_micros` is a dollars-only budget.
    pub token_cap: i64,
    /// Millionths of a dollar, 0 or more, enforced beside the tokens when set (API minor 18);
    /// absent clears it. The dollars counted are the priced ones.
    pub usd_cap_micros: Option<i64>,
    /// 1-100; absent: the `budget.warn_percent` setting.
    pub warn_at_percent: Option<u8>,
    /// Runs stop at the cap (the default), or it only warns.
    pub hard_stop: Option<bool>,
}

#[utoipa::path(put, path = "/companies/{id}/budgets", operation_id = "setBudget",
    tag = "money", params(("id" = i64, Path, description = "Company id")), request_body = BudgetBody,
    responses((status = 200, description = "The budget for its scope and period, created or \
        changed (audited as `budget.set`), with its spend so far; needs a step-up (it may raise \
        a cap)", body = BudgetStanding)))]
pub async fn set_budget(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(b): Json<BudgetBody>,
) -> ApiResult<BudgetStanding> {
    write_budget(&app, id, b, true).await
}

#[utoipa::path(post, path = "/companies/{id}/budgets", operation_id = "createBudget",
    tag = "money", params(("id" = i64, Path, description = "Company id")), request_body = BudgetBody,
    responses((status = 200, description = "A new budget (audited as `budget.created`), with its \
        spend so far; 409 when its scope already has one for the period (`setBudget` changes it)",
        body = BudgetStanding)))]
pub async fn create_budget(
    State(app): State<App>,
    _: Acting,
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
    let c = found(org::get_company(&app.pool, CompanyId(id)).await?, "company")?;
    let period = b
        .period
        .parse()
        .map_err(|_| ApiError::bad_request("period is `day`, `week`, `month` or `total`"))?;
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
        period,
        token_cap: b.token_cap,
        usd_cap_micros: b.usd_cap_micros,
        warn_at_percent: warn,
        hard_stop: b.hard_stop.unwrap_or(true),
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

#[utoipa::path(delete, path = "/budgets/{id}", operation_id = "deleteBudget", tag = "money",
    params(("id" = i64, Path, description = "Budget id")),
    responses((status = 200, description = "Deleted (audited as `budget.deleted`; its spend \
        counters go with it, the ledger stays): the company's budgets left; needs a step-up",
        body = Vec<BudgetStanding>)))]
pub async fn delete_budget(
    State(app): State<App>,
    _: Acting,
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

/// Which harness and model's price history.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PriceOf {
    /// `claude`, `codex`, `opencode` or `agy`.
    #[param(value_type = Harness)]
    pub harness: String,
    pub model: String,
}

#[utoipa::path(get, path = "/prices/history", operation_id = "priceHistory", tag = "money",
    params(PriceOf),
    responses((status = 200, description = "Every version of the harness and model's price, newest \
        first; empty when it was never priced", body = Vec<PriceVersion>)))]
pub async fn price_history(
    State(app): State<App>,
    _: Acting,
    Query(q): Query<PriceOf>,
) -> ApiResult<Vec<PriceVersion>> {
    let all = gov::price_history(&app.pool, harness(&q.harness)?, &q.model).await?;
    let out = all.into_iter().map(|(p, at)| PriceVersion {
        price: p.into(),
        set_at: ts(&at),
    });
    Ok(Json(out.collect()))
}

#[utoipa::path(get, path = "/companies/{id}/costs", operation_id = "getCompanyCosts", tag = "money",
    params(("id" = i64, Path, description = "Company id")), responses((status = 200, body = CostReport)))]
pub async fn company_costs(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<CostReport> {
    found(org::get_company(&app.pool, CompanyId(id)).await?, "company")?;
    let r = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(
        "SELECT count(*), coalesce(sum(c.input_tokens),0), coalesce(sum(c.output_tokens),0), \
         coalesce(sum(c.cache_tokens),0), coalesce(sum(c.cost_usd_micros),0), \
         coalesce(sum(CASE WHEN c.priced = 0 THEN c.input_tokens + c.output_tokens + c.cache_tokens ELSE 0 END),0) \
         FROM citadel_cost_events c JOIN citadel_agents a ON a.id = c.agent_id WHERE a.company_id = ?",
    ).bind(id).fetch_one(&app.pool).await?;
    Ok(Json(CostReport {
        company_id: id,
        runs: r.0,
        input_tokens: r.1,
        output_tokens: r.2,
        cache_tokens: r.3,
        cost_usd_micros: r.4,
        unpriced_tokens: r.5,
    }))
}

#[utoipa::path(get, path = "/companies/{id}/ledger", operation_id = "listCompanyLedger", tag = "money",
    params(("id" = i64, Path, description = "Company id")), responses((status = 200, body = Vec<LedgerEntry>)))]
pub async fn company_ledger(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Vec<LedgerEntry>> {
    found(org::get_company(&app.pool, CompanyId(id)).await?, "company")?;
    let rows = sqlx::query(
        "SELECT c.id, c.agent_id, c.issue_id, c.account_id, c.input_tokens, c.output_tokens, \
         c.cache_tokens, c.cost_usd_micros, c.priced, c.created_at FROM citadel_cost_events c \
         JOIN citadel_agents a ON a.id = c.agent_id WHERE a.company_id = ? ORDER BY c.id DESC LIMIT 500",
    ).bind(id).fetch_all(&app.pool).await?;
    use sqlx::Row;
    Ok(Json(
        rows.into_iter()
            .map(|r| LedgerEntry {
                id: r.get("id"),
                agent_id: r.get("agent_id"),
                issue_id: r.get("issue_id"),
                account_id: r.get("account_id"),
                input_tokens: r.get("input_tokens"),
                output_tokens: r.get("output_tokens"),
                cache_tokens: r.get("cache_tokens"),
                cost_usd_micros: r.get("cost_usd_micros"),
                priced: r.get::<i64, _>("priced") != 0,
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}
