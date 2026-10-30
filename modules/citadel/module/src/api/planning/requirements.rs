//! Requirements (E15.10, pain #10): what the admin asked for, and its plan, live. The list keeps
//! to the company a client works in (`X-Citadel-Company`), else spans every company; the tree is
//! the plan rail of screen 12: epics → tasks, % done by points, burndown, ETA, and the scope
//! added or removed since the approved plan.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::api::model::planning::{Requirement, RequirementTree};
use crate::api::scope::Acting;
use crate::domain::work::RequirementId;
use crate::store::work::{self, RequirementError};

async fn find(app: &App, id: i64) -> Result<work::Requirement, ApiError> {
    work::get_requirement(&app.pool, RequirementId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no requirement {id}")))
}

#[utoipa::path(get, path = "/requirements", operation_id = "listRequirements",
    tag = "requirements",
    responses((status = 200, description = "Requirements, newest first: the acting company's, \
        else every company's", body = [Requirement])))]
pub async fn list(State(app): State<App>, acting: Acting) -> ApiResult<Vec<Requirement>> {
    let all = work::list_requirements(&app.pool, acting.0).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(get, path = "/requirements/{id}", operation_id = "getRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    responses((status = 200, description = "The requirement", body = Requirement)))]
pub async fn get(State(app): State<App>, _: Acting, Path(id): Path<i64>) -> ApiResult<Requirement> {
    find(&app, id).await.map(|r| Json(r.into()))
}

#[utoipa::path(get, path = "/requirements/{id}/tree", operation_id = "getRequirementTree",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    responses((status = 200, description = "Its plan, live: epics and tasks with their numbers, \
        % done, burndown, ETA, and the diff against the approved plan",
        body = RequirementTree)))]
pub async fn tree(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<RequirementTree> {
    let t = work::requirement_tree(&app.pool, RequirementId(id), &app.clock.now())
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no requirement {id}")))?;
    Ok(Json(t.into()))
}

fn refused(e: RequirementError) -> ApiError {
    match e {
        RequirementError::NotFound => ApiError::not_found(e.to_string()),
        RequirementError::Db(sqlx::Error::Protocol(why)) => ApiError::bad_request(why),
        RequirementError::Db(e) => e.into(),
        e => ApiError::conflict(e.to_string()),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RequirementRename {
    /// One line, not empty.
    pub title: String,
}

#[utoipa::path(put, path = "/requirements/{id}", operation_id = "renameRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    request_body = RequirementRename,
    responses((status = 200, description = "The requirement under its new title (audited as \
        `requirement.renamed`); a cancelled one is a 409", body = Requirement)))]
pub async fn rename(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(r): Json<RequirementRename>,
) -> ApiResult<Requirement> {
    let renamed = work::rename_requirement(&app.pool, RequirementId(id), &r.title, BY)
        .await
        .map_err(refused)?;
    Ok(Json(renamed.into()))
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct RequirementCancel {
    /// Why, for the audit and the thread's readers.
    pub reason: Option<String>,
}

#[utoipa::path(post, path = "/requirements/{id}/cancel", operation_id = "cancelRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    request_body = RequirementCancel,
    responses((status = 200, description = "The cancelled requirement: its open issues are \
        cancelled with it (audited as `requirement.cancelled`, naming them). Done or cancelled \
        already is a 409; needs a step-up", body = Requirement)))]
pub async fn cancel(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(c): Json<RequirementCancel>,
) -> ApiResult<Requirement> {
    let cancelled = work::cancel_requirement(&app.pool, RequirementId(id), c.reason.as_deref(), BY)
        .await
        .map_err(refused)?;
    Ok(Json(cancelled.into()))
}

#[utoipa::path(post, path = "/requirements/{id}/pause", operation_id = "pauseRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    responses((status = 200, description = "The paused requirement (audited as \
        `requirement.paused`; API minor 18): no wake for its issues is dispatched until it is \
        resumed, and runs already working go on. Paused already changes nothing; done or \
        cancelled is a 409", body = Requirement)))]
pub async fn pause(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Requirement> {
    let r = work::pause_requirement(&app.pool, RequirementId(id), BY)
        .await
        .map_err(refused)?;
    Ok(Json(r.into()))
}

#[utoipa::path(post, path = "/requirements/{id}/resume", operation_id = "resumeRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    responses((status = 200, description = "The resumed requirement (audited as \
        `requirement.resumed`): its held wakes are dispatched. Not paused changes nothing; \
        done or cancelled is a 409", body = Requirement)))]
pub async fn resume(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Requirement> {
    let r = work::resume_requirement(&app.pool, RequirementId(id), BY)
        .await
        .map_err(refused)?;
    Ok(Json(r.into()))
}

#[utoipa::path(post, path = "/requirements/{id}/done", operation_id = "finishRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    responses((status = 200, description = "The requirement, done (audited as \
        `requirement.done`; API minor 18). It must be in progress with none of its issues open; \
        anything else is a 409", body = Requirement)))]
pub async fn finish(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Requirement> {
    let r = work::finish_requirement(&app.pool, RequirementId(id), BY)
        .await
        .map_err(refused)?;
    Ok(Json(r.into()))
}
