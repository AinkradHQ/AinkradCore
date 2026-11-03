//! Budgets over the API (KAN-448; design `2026-11-02-ai-provider-accounts` §10, §12d). Reading is `read`;
//! setting, deleting or raising a budget is `admin` and destructive (a step-up): it decides what may be
//! spent. A list can be filtered by the budget's company binding (`company`), which is how a company's
//! screens ask for theirs (KAN-294). Reserving and releasing are not routes: the scheduler calls them
//! inside the Core, so a device cannot hold or free someone's headroom.

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::store::budgets::{self, guard};

/// A budget and where it stands in the period containing now.
#[derive(Debug, Serialize, ToSchema)]
pub struct SubjectBudget {
    pub id: i64,
    /// `account`, `pool`, `agent`, `company`, `department`, `project`, `sprint` or `issue`.
    pub kind: String,
    /// The subject's id: an account or pool id, or the owning module's opaque id.
    pub subject: String,
    /// The owner's company binding (a company budget's is its subject).
    pub company: Option<String>,
    /// `day`, `week` (from Monday), `month` or `total`.
    pub period: String,
    /// Tokens per period; 0 with a dollar cap is a dollars-only budget.
    pub token_cap: i64,
    /// Millionths of a dollar per period.
    pub usd_cap_micros: Option<i64>,
    pub warn_at_percent: i64,
    /// Stops new sessions, and a running one, at the cap; else it only warns.
    pub hard_stop: bool,
    /// The period this standing is for: `2026-10-22`, a week's Monday, `2026-10` or `total`.
    pub period_key: String,
    pub spent: i64,
    /// Tokens added for the period by approved overruns.
    pub raised: i64,
    pub usd_spent: i64,
    pub raised_usd: i64,
    /// Tokens held by sessions that reserved them and have not spent them yet.
    pub held: i64,
    pub held_usd: i64,
    /// Nothing left in tokens or dollars.
    pub exhausted: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<budgets::Standing> for SubjectBudget {
    fn from(s: budgets::Standing) -> Self {
        let exhausted = s.exhausted();
        let b = s.budget;
        Self {
            id: b.id,
            kind: b.kind,
            subject: b.subject,
            company: b.company,
            period: b.period,
            token_cap: b.token_cap,
            usd_cap_micros: b.usd_cap_micros,
            warn_at_percent: b.warn_at_percent,
            hard_stop: b.hard_stop,
            period_key: s.period_key,
            spent: s.spent,
            raised: s.raised,
            usd_spent: s.usd_spent,
            raised_usd: s.raised_usd,
            held: s.held,
            held_usd: s.held_usd,
            exhausted,
            created_at: ts(&b.created_at),
            updated_at: ts(&b.updated_at),
        }
    }
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct BudgetQuery {
    /// Only this kind of subject.
    pub kind: Option<String>,
    /// Only this subject (with `kind`).
    pub subject: Option<String>,
    /// Only budgets bound to this company.
    pub company: Option<String>,
}

#[utoipa::path(get, path = "/api/v1/budgets", operation_id = "listBudgets", tag = "budgets",
    params(BudgetQuery),
    responses((status = 200, description = "Every budget with its standing in the current period, by id",
        body = Vec<SubjectBudget>)))]
pub async fn list(
    State(app): State<App>,
    Query(q): Query<BudgetQuery>,
) -> ApiResult<Vec<SubjectBudget>> {
    let all = budgets::list(
        &app.pool,
        q.kind.as_deref(),
        q.subject.as_deref(),
        q.company.as_deref(),
        &app.clock.now(),
    )
    .await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetSubjectBudget {
    pub kind: String,
    pub subject: String,
    /// The owner's company binding; for a company budget it must be the subject (or absent).
    pub company: Option<String>,
    pub period: String,
    pub token_cap: i64,
    pub usd_cap_micros: Option<i64>,
    /// Default 80.
    pub warn_at_percent: Option<i64>,
    /// Default true.
    pub hard_stop: Option<bool>,
}

#[utoipa::path(put, path = "/api/v1/budgets", operation_id = "setBudget", tag = "budgets",
    request_body = SetSubjectBudget,
    responses((status = 200, description = "Created, or its caps changed (audited as `budget.created` \
        or `budget.set`), with the period's spend counted from the ledger. 404 for an account or pool \
        that does not exist; 400 for a bad kind, subject, period or cap", body = SubjectBudget)))]
pub async fn set(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(b): Json<SetSubjectBudget>,
) -> ApiResult<SubjectBudget> {
    let new = budgets::NewBudget {
        kind: &b.kind,
        subject: &b.subject,
        company: b.company.as_deref(),
        period: &b.period,
        token_cap: b.token_cap,
        usd_cap_micros: b.usd_cap_micros,
        warn_at_percent: b.warn_at_percent,
        hard_stop: b.hard_stop.unwrap_or(true),
    };
    let now = app.clock.now();
    let set = budgets::set(&app.pool, &new, &me.device.id, BY, &now)
        .await
        .map_err(ApiError::from)?;
    let standing = budgets::standing_of(&app.pool, set.id, &now)
        .await?
        .ok_or_else(|| ApiError::not_found("no such budget"))?;
    Ok(Json(standing.into()))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BudgetDeleted {
    pub deleted: bool,
}

fn num(s: &str) -> Result<i64, ApiError> {
    s.parse::<u64>()
        .ok()
        .and_then(|n| i64::try_from(n).ok())
        .ok_or_else(|| ApiError::not_found("no such budget"))
}

#[utoipa::path(delete, path = "/api/v1/budgets/{id}", operation_id = "deleteBudget", tag = "budgets",
    params(("id" = String, Path, description = "The budget's id")),
    responses((status = 200, description = "Deleted with its counters and holds (audited as \
        `budget.deleted`); `deleted` is false when there was no such budget", body = BudgetDeleted)))]
pub async fn delete(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<BudgetDeleted> {
    let deleted = budgets::remove(&app.pool, num(&id)?, &me.device.id, BY)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(BudgetDeleted { deleted }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RaiseBudget {
    /// The period that ran out: `2026-10-22`, a week's Monday, `2026-10` or `total`.
    pub period_key: String,
    /// Tokens to add (0 when raising dollars).
    pub tokens: Option<i64>,
    /// Millionths of a dollar to add.
    pub usd_micros: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/budgets/{id}/raise", operation_id = "raiseBudget",
    tag = "budgets", params(("id" = String, Path, description = "The budget's id")),
    request_body = RaiseBudget,
    responses((status = 200, description = "That period's headroom raised and its exhaustion alert \
        cleared (audited as `budget.raised`); the body is the budget's standing for the raised period. 404 for no such budget; 400 for an amount of 0 or a \
        bad period key", body = SubjectBudget)))]
pub async fn raise(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<RaiseBudget>,
) -> ApiResult<SubjectBudget> {
    let id = num(&id)?;
    let mut tx = crate::store::begin_write(&app.pool).await?;
    guard::raise_in(
        &mut tx,
        id,
        &b.period_key,
        b.tokens.unwrap_or(0),
        b.usd_micros.unwrap_or(0),
        &me.device.id,
        BY,
    )
    .await
    .map_err(ApiError::from)?;
    tx.commit().await?;
    let standing = budgets::standing_for(&app.pool, id, &b.period_key, &app.clock.now())
        .await?
        .ok_or_else(|| ApiError::not_found("no such budget"))?;
    Ok(Json(standing.into()))
}
