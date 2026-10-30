//! Approvals with a reply (E11.5): the company's list and the decision, as the admin.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ADMIN, ApiError, ApiResult};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::api::error::found;
use crate::api::model::governance::Approval;
use crate::api::scope::Acting;
use crate::domain::gov::{ApprovalId, ApprovalStatus};
use crate::domain::org::CompanyId;
use crate::domain::work::UserId;
use crate::store::gov::{self, DecideError};
use crate::store::org;

fn decided(e: DecideError) -> ApiError {
    match e {
        DecideError::NotFound => ApiError::not_found(e.to_string()),
        DecideError::Raise => ApiError::bad_request(e.to_string()),
        DecideError::Db(e) => e.into(),
        e => ApiError::conflict(e.to_string()),
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ApprovalFilter {
    /// Only those waiting on a decision.
    pub pending: Option<bool>,
}

#[utoipa::path(get, path = "/companies/{id}/approvals", operation_id = "listApprovals",
    tag = "approvals", params(("id" = i64, Path, description = "Company id"), ApprovalFilter),
    responses((status = 200, description = "The company's approvals, oldest first",
        body = Vec<Approval>)))]
pub async fn list_approvals(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Query(f): Query<ApprovalFilter>,
) -> ApiResult<Vec<Approval>> {
    let c = found(org::get_company(&app.pool, CompanyId(id)).await?, "company")?;
    let all = gov::list_approvals(&app.pool, c.id).await?;
    let pending = f.pending.unwrap_or(false);
    let all = all
        .into_iter()
        .filter(|a| !pending || a.status == ApprovalStatus::Pending);
    Ok(Json(all.map(Into::into).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct Decision {
    pub approve: bool,
    /// Goes back to the agent that asked.
    pub reply: Option<String>,
    /// Refused here: a raise widens spend and has its own step-up route (`raiseApproval`).
    pub raise_tokens: Option<i64>,
}

#[utoipa::path(post, path = "/approvals/{id}/decide", operation_id = "decideApproval",
    tag = "approvals", params(("id" = i64, Path, description = "Approval id")),
    request_body = Decision,
    responses((status = 200, description = "The decided approval", body = Approval)))]
pub async fn decide(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(d): Json<Decision>,
) -> ApiResult<Approval> {
    if d.raise_tokens.is_some() {
        return Err(ApiError::bad_request(
            "a raise goes through POST /approvals/{id}/raise",
        ));
    }
    let (id, now, reply) = (ApprovalId(id), app.clock.now(), d.reply.as_deref());
    let by = UserId(ADMIN.0);
    let a = gov::decide_approval(&app.pool, id, d.approve, by, reply, &now)
        .await
        .map_err(decided)?;
    Ok(Json(a.into()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct Raise {
    /// More tokens for the period (millionths of a dollar when the approval's payload `unit`
    /// is `usd_micros`); more than 0.
    pub raise_tokens: i64,
    pub reply: Option<String>,
}

#[utoipa::path(post, path = "/approvals/{id}/raise", operation_id = "raiseApproval",
    tag = "approvals", params(("id" = i64, Path, description = "Approval id")),
    request_body = Raise,
    responses((status = 200, description = "The budget overrun approved with a raise; needs a \
        step-up", body = Approval)))]
pub async fn raise(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(r): Json<Raise>,
) -> ApiResult<Approval> {
    let (id, now) = (ApprovalId(id), app.clock.now());
    let by = UserId(ADMIN.0);
    let a = gov::approve_budget_raise(&app.pool, id, r.raise_tokens, by, r.reply.as_deref(), &now)
        .await
        .map_err(decided)?;
    Ok(Json(a.into()))
}
