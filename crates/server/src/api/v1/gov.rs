//! Approvals with a reply (E11.5) and the cost dashboard (E11.7).

use ainkrad_core::gov::{ApprovalId, BudgetScope as CoreScope};
use ainkrad_core::work::SprintId;
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::model::Approval;
use super::org::company;
use super::types::BudgetPeriod;
use super::{ADMIN, ApiError, ApiResult};
use crate::api::App;
use crate::store::gov::{self, CostScope, DecideError};

impl From<DecideError> for ApiError {
    fn from(e: DecideError) -> Self {
        match e {
            DecideError::NotFound => Self::not_found(e.to_string()),
            DecideError::Raise => Self::bad_request(e.to_string()),
            DecideError::Db(e) => e.into(),
            e => Self::conflict(e.to_string()),
        }
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ApprovalFilter {
    /// Only those waiting on a decision.
    pub pending: Option<bool>,
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/approvals", operation_id = "listApprovals",
    tag = "approvals", params(("id" = i64, Path, description = "Company id"), ApprovalFilter),
    responses((status = 200, description = "The company's approvals, oldest first", body = Vec<Approval>)))]
pub async fn list_approvals(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(f): Query<ApprovalFilter>,
) -> ApiResult<Vec<Approval>> {
    let c = company(&app, id).await?;
    let all = gov::list_approvals(&app.pool, c.id).await?;
    let pending = f.pending.unwrap_or(false);
    let all = all
        .into_iter()
        .filter(|a| !pending || a.status == ainkrad_core::gov::ApprovalStatus::Pending);
    Ok(Json(all.map(Into::into).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct Decision {
    pub approve: bool,
    /// Goes back to the agent that asked, and wakes it.
    pub reply: Option<String>,
    /// A `budget_overrun` is approved with this many more tokens for the period (millionths of
    /// a dollar when the approval's payload `unit` is `usd_micros`).
    pub raise_tokens: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/approvals/{id}/decision", operation_id = "decideApproval",
    tag = "approvals", params(("id" = i64, Path, description = "Approval id")),
    request_body = Decision,
    responses((status = 200, description = "The decided approval", body = Approval)))]
pub async fn decide(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(d): Json<Decision>,
) -> ApiResult<Approval> {
    let (id, now, reply) = (ApprovalId(id), app.clock.now(), d.reply.as_deref());
    let a = match d.raise_tokens {
        Some(raise) if d.approve => {
            gov::approve_budget_raise(&app.pool, id, raise, ADMIN, reply, &now).await?
        }
        Some(_) => return Err(ApiError::bad_request("a raise only goes with approve")),
        None => gov::decide_approval(&app.pool, id, d.approve, ADMIN, reply, &now).await?,
    };
    Ok(Json(a.into()))
}

/// Runs that used tokens, and what they cost. Dollars are the priced runs' only: an unpriced
/// run is counted, with its tokens, never as $0.
#[derive(Debug, Serialize, ToSchema)]
pub struct CostReport {
    pub runs: i64,
    pub priced_runs: i64,
    pub unpriced_runs: i64,
    pub subscription_runs: i64,
    pub cost_usd_micros: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    pub unpriced_tokens: i64,
    pub subscription_tokens: i64,
}

impl From<gov::CostReport> for CostReport {
    fn from(r: gov::CostReport) -> Self {
        Self {
            runs: r.runs,
            priced_runs: r.priced_runs,
            unpriced_runs: r.unpriced_runs,
            subscription_runs: r.subscription_runs,
            cost_usd_micros: r.cost_usd_micros,
            input_tokens: r.input_tokens,
            output_tokens: r.output_tokens,
            cache_tokens: r.cache_tokens,
            unpriced_tokens: r.unpriced_tokens,
            subscription_tokens: r.subscription_tokens,
        }
    }
}

/// What a budget caps.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BudgetScope {
    Company {
        company_id: i64,
    },
    Department {
        department_id: i64,
    },
    Project {
        project_id: i64,
    },
    Agent {
        agent_id: i64,
    },
    Sprint {
        sprint_id: i64,
    },
    /// API minor 18.
    Issue {
        issue_id: i64,
    },
}

/// A budget and its spend in the current period.
#[derive(Debug, Serialize, ToSchema)]
pub struct BudgetStanding {
    pub budget_id: i64,
    pub scope: BudgetScope,
    pub period: BudgetPeriod,
    pub token_cap: i64,
    /// Millionths of a dollar beside the tokens, when set; with `token_cap` 0, dollars only
    /// (API minor 18).
    pub usd_cap_micros: Option<i64>,
    pub warn_at_percent: u8,
    pub hard_stop: bool,
    /// `2026-10-22`, a week's Monday, `2026-10` or `total`.
    pub period_key: String,
    pub spent: i64,
    /// Tokens added for the period by approved overruns.
    pub raised: i64,
    /// Priced dollars spent in the period, in millionths (API minor 18).
    #[schema(required = false)]
    pub usd_spent_micros: i64,
    /// Dollars added for the period by approved overruns, in millionths (API minor 18).
    #[schema(required = false)]
    pub raised_usd_micros: i64,
}

impl From<gov::Standing> for BudgetStanding {
    fn from(s: gov::Standing) -> Self {
        let b = s.budget;
        Self {
            budget_id: b.id.0,
            scope: match b.scope {
                CoreScope::Company(c) => BudgetScope::Company { company_id: c.0 },
                CoreScope::Department(d) => BudgetScope::Department { department_id: d.0 },
                CoreScope::Project(p) => BudgetScope::Project { project_id: p.0 },
                CoreScope::Agent(a) => BudgetScope::Agent { agent_id: a.0 },
                CoreScope::Sprint(s) => BudgetScope::Sprint { sprint_id: s.0 },
                CoreScope::Issue(i) => BudgetScope::Issue { issue_id: i.0 },
            },
            period: b.period.into(),
            token_cap: b.token_cap,
            usd_cap_micros: b.usd_cap_micros,
            warn_at_percent: b.warn_at_percent,
            hard_stop: b.hard_stop,
            period_key: s.period_key,
            spent: s.spent,
            raised: s.raised,
            usd_spent_micros: s.usd_spent,
            raised_usd_micros: s.raised_usd,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CompanyCosts {
    pub report: CostReport,
    pub budgets: Vec<BudgetStanding>,
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/costs", operation_id = "getCompanyCosts",
    tag = "costs", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company's spend and its budgets' standing", body = CompanyCosts)))]
pub async fn company_costs(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<CompanyCosts> {
    let c = company(&app, id).await?;
    let report = gov::cost_report(&app.pool, CostScope::Company(c.id)).await?;
    let budgets = gov::company_budgets(&app.pool, c.id, &app.clock.now()).await?;
    Ok(Json(CompanyCosts {
        report: report.into(),
        budgets: budgets.into_iter().map(Into::into).collect(),
    }))
}

#[utoipa::path(get, path = "/api/v1/sprints/{id}/costs", operation_id = "getSprintCosts",
    tag = "costs", params(("id" = i64, Path, description = "Sprint id")),
    responses((status = 200, description = "The spend on the sprint's issues", body = CostReport)))]
pub async fn sprint_costs(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<CostReport> {
    crate::store::work::get_sprint(&app.pool, SprintId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no sprint {id}")))?;
    let r = gov::cost_report(&app.pool, CostScope::Sprint(SprintId(id))).await?;
    Ok(Json(r.into()))
}
