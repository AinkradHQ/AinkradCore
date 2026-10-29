//! Requirements (E15.10, pain #10): what the admin asked for, and its plan, live. The list keeps
//! to the company a client works in (`X-Citadel-Company`), else spans every company; the tree is
//! the plan rail of screen 12: epics → tasks, % done by points, burndown, ETA, spend, and the
//! scope added or removed since the approved plan.

use ainkrad_core::work::RequirementId;
use axum::Json;
use axum::extract::{Extension, Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::gov::CostReport;
use super::projects::BurndownDay;
use super::scope::Acting;
use super::types::{Actor, IssueState, RequirementState, Timestamp, ts};
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::work;

#[derive(Debug, Serialize, ToSchema)]
pub struct Requirement {
    pub id: i64,
    pub company_id: i64,
    /// `R-12`.
    pub key: String,
    pub number: i64,
    pub title: String,
    pub body: String,
    pub requested_by_user_id: i64,
    /// The intake request; its comments are the requirement's thread.
    pub intake_issue_id: Option<i64>,
    /// Who answers in the thread: the CEO, then the product owner it was handed to.
    pub owner_agent_id: Option<i64>,
    pub state: RequirementState,
    /// The approved plan's version; 0 before the first approval.
    pub plan_version: i64,
    pub created_at: Timestamp,
    /// When the admin paused it (API minor 18); absent unless it is paused.
    pub paused_at: Option<Timestamp>,
    /// The project it was filed for (API minor 18).
    pub project_id: Option<i64>,
    #[schema(required = false)]
    pub priority_level: super::types::PriorityLevel,
    #[schema(required = false)]
    pub criteria: Vec<super::model::Criterion>,
}

impl From<work::Requirement> for Requirement {
    fn from(r: work::Requirement) -> Self {
        Self {
            key: r.key(),
            id: r.id.0,
            company_id: r.company_id.0,
            number: r.number,
            title: r.title,
            body: r.body,
            requested_by_user_id: r.requested_by.0,
            intake_issue_id: r.intake_issue_id.map(|i| i.0),
            owner_agent_id: r.owner_agent_id.map(|a| a.0),
            state: r.state.into(),
            plan_version: r.plan_version,
            created_at: ts(&r.created_at),
            paused_at: super::types::opt_ts(r.paused_at.as_deref()),
            project_id: r.project_id.map(|p| p.0),
            priority_level: r.priority_level.into(),
            criteria: r
                .criteria
                .into_iter()
                .map(|c| super::model::Criterion {
                    text: c.text,
                    done: c.done,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TreeTask {
    pub issue_id: i64,
    /// `CIT-61`.
    pub key: String,
    pub title: String,
    pub state: IssueState,
    pub epic_id: Option<i64>,
    /// Its owner, else the agent it waits on.
    pub assignee: Option<Actor>,
    pub points: Option<u32>,
    pub sprint_id: Option<i64>,
    /// Seconds its ended runs took.
    pub time_secs: i64,
    pub tokens: i64,
    /// Its pull requests, one per repo it touches.
    pub prs: i64,
}

impl From<work::TreeTask> for TreeTask {
    fn from(t: work::TreeTask) -> Self {
        Self {
            issue_id: t.id.0,
            key: t.key,
            title: t.title,
            state: t.state.into(),
            epic_id: t.epic_id.map(|e| e.0),
            assignee: t.assignee.map(Into::into),
            points: t.points,
            sprint_id: t.sprint_id.map(|s| s.0),
            time_secs: t.time_secs,
            tokens: t.tokens,
            prs: t.prs,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TreeEpic {
    pub epic_id: i64,
    pub project_id: i64,
    pub title: String,
    pub status: String,
    pub points: u32,
    pub done_points: u32,
    pub tasks: Vec<TreeTask>,
}

/// A task as a plan version holds it.
#[derive(Debug, Serialize, ToSchema)]
pub struct PlanTask {
    pub issue_id: i64,
    pub key: String,
    pub title: String,
    pub points: Option<i64>,
}

impl From<work::PlannedTaskRef> for PlanTask {
    fn from(t: work::PlannedTaskRef) -> Self {
        Self {
            issue_id: t.id,
            key: t.key,
            title: t.title,
            points: t.points,
        }
    }
}

/// The plan now against its approved version: scope added or removed since.
#[derive(Debug, Serialize, ToSchema)]
pub struct PlanDiff {
    pub version: i64,
    pub approved_at: Timestamp,
    /// `owner`, or `product_owner` under that sprint policy.
    pub approved_by: String,
    pub added: Vec<PlanTask>,
    pub removed: Vec<PlanTask>,
    pub points_approved: i64,
    pub points_now: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RequirementTree {
    pub requirement: Requirement,
    pub epics: Vec<TreeEpic>,
    /// Its issues outside the plan: the intake request, the kickoff.
    pub other: Vec<TreeTask>,
    pub points: u32,
    pub done_points: u32,
    /// By points, rounded; leaf product tasks only (documentation tasks are left out).
    pub percent_done: u32,
    pub tasks: u32,
    pub done_tasks: u32,
    /// Points left at the end of each day since the plan's approval (or the requirement's
    /// creation).
    pub burndown: Vec<BurndownDay>,
    pub points_per_day: f64,
    /// `YYYY-MM-DD` the rest is done at the pace so far; absent before anything is done or
    /// before three days of data.
    pub eta: Option<String>,
    pub cost: CostReport,
    /// Absent before the plan's first approval.
    pub diff: Option<PlanDiff>,
}

async fn find(app: &App, id: i64) -> Result<work::Requirement, ApiError> {
    work::get_requirement(&app.pool, RequirementId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no requirement {id}")))
}

#[utoipa::path(get, path = "/api/v1/requirements", operation_id = "listRequirements",
    tag = "requirements",
    responses((status = 200, description = "Requirements, newest first: the acting company's, \
        else every company's", body = [Requirement])))]
pub async fn list(
    State(app): State<App>,
    Extension(acting): Extension<Acting>,
) -> ApiResult<Vec<Requirement>> {
    let all = work::list_requirements(&app.pool, acting.0).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(get, path = "/api/v1/requirements/{id}", operation_id = "getRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    responses((status = 200, description = "The requirement", body = Requirement)))]
pub async fn get(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Requirement> {
    find(&app, id).await.map(|r| Json(r.into()))
}

#[utoipa::path(get, path = "/api/v1/requirements/{id}/tree", operation_id = "getRequirementTree",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    responses((status = 200, description = "Its plan, live: epics and tasks with their numbers, \
        % done, burndown, ETA, spend, and the diff against the approved plan",
        body = RequirementTree)))]
pub async fn tree(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<RequirementTree> {
    let t = work::requirement_tree(&app.pool, RequirementId(id), &app.clock.now())
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no requirement {id}")))?;
    Ok(Json(RequirementTree {
        requirement: t.requirement.into(),
        epics: t
            .epics
            .into_iter()
            .map(|e| TreeEpic {
                epic_id: e.id.0,
                project_id: e.project_id.0,
                title: e.title,
                status: e.status,
                points: e.points,
                done_points: e.done_points,
                tasks: e.tasks.into_iter().map(Into::into).collect(),
            })
            .collect(),
        other: t.other.into_iter().map(Into::into).collect(),
        points: t.points,
        done_points: t.done_points,
        percent_done: t.percent_done,
        tasks: t.tasks,
        done_tasks: t.done_tasks,
        burndown: t
            .burndown
            .into_iter()
            .map(|(day, left, scope)| BurndownDay {
                day,
                left,
                scope: Some(scope),
            })
            .collect(),
        points_per_day: t.points_per_day,
        eta: t.eta,
        cost: t.cost.into(),
        diff: t.diff.map(|d| PlanDiff {
            version: d.version,
            approved_at: ts(&d.approved_at),
            approved_by: d.approved_by,
            added: d.added.into_iter().map(Into::into).collect(),
            removed: d.removed.into_iter().map(Into::into).collect(),
            points_approved: d.points_approved,
            points_now: d.points_now,
        }),
    }))
}

fn refused(e: work::RequirementError) -> ApiError {
    match e {
        work::RequirementError::NotFound => ApiError::not_found(e.to_string()),
        work::RequirementError::Db(sqlx::Error::InvalidArgument(why)) => ApiError::bad_request(why),
        work::RequirementError::Db(e) => e.into(),
        e => ApiError::conflict(e.to_string()),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RequirementRename {
    /// One line, not empty.
    pub title: String,
}

#[utoipa::path(put, path = "/api/v1/requirements/{id}", operation_id = "renameRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    request_body = RequirementRename,
    responses((status = 200, description = "The requirement under its new title (audited as \
        `requirement.renamed`); a cancelled one is a 409", body = Requirement)))]
pub async fn rename(
    State(app): State<App>,
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

#[utoipa::path(post, path = "/api/v1/requirements/{id}/cancel", operation_id = "cancelRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    request_body = RequirementCancel,
    responses((status = 200, description = "The cancelled requirement: its open issues are \
        cancelled with it (audited as `requirement.cancelled`, naming them). Done or cancelled \
        already, or a run working on one of its issues (stop it first), is a 409",
        body = Requirement)))]
pub async fn cancel(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(c): Json<RequirementCancel>,
) -> ApiResult<Requirement> {
    let cancelled = work::cancel_requirement(&app.pool, RequirementId(id), c.reason.as_deref(), BY)
        .await
        .map_err(refused)?;
    Ok(Json(cancelled.into()))
}

#[utoipa::path(post, path = "/api/v1/requirements/{id}/pause", operation_id = "pauseRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    responses((status = 200, description = "The paused requirement (audited as \
        `requirement.paused`; API minor 18): no wake for its issues is dispatched until it is \
        resumed, and runs already working go on. Paused already changes nothing; done or \
        cancelled is a 409", body = Requirement)))]
pub async fn pause(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Requirement> {
    let r = work::pause_requirement(&app.pool, RequirementId(id), BY)
        .await
        .map_err(refused)?;
    Ok(Json(r.into()))
}

#[utoipa::path(post, path = "/api/v1/requirements/{id}/resume", operation_id = "resumeRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    responses((status = 200, description = "The resumed requirement (audited as \
        `requirement.resumed`): its held wakes are dispatched. Not paused changes nothing; \
        done or cancelled is a 409", body = Requirement)))]
pub async fn resume(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Requirement> {
    let r = work::resume_requirement(&app.pool, RequirementId(id), BY)
        .await
        .map_err(refused)?;
    Ok(Json(r.into()))
}

#[utoipa::path(post, path = "/api/v1/requirements/{id}/done", operation_id = "finishRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    responses((status = 200, description = "The requirement, done (audited as \
        `requirement.done`; API minor 18). It must be in progress with none of its issues open; \
        anything else is a 409", body = Requirement)))]
pub async fn finish(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Requirement> {
    let r = work::finish_requirement(&app.pool, RequirementId(id), BY)
        .await
        .map_err(refused)?;
    Ok(Json(r.into()))
}
