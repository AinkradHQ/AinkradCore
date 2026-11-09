//! Projects for Quest in server mode (E12.1): the backlog, the board, epics, sprints and
//! their reports, velocity, and kanban WIP limits. Writes go through the store's planning
//! rules (E5) as the admin and are audited.

use citadel_core::work::{self as core, BacklogFilter, NewSprint, ProjectId, SprintId};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::model::{Epic, Issue, Project, Sprint};
use super::org::company;
use super::types::{EpicStatus, IssueState, ProjectMode, SprintApproval, SprintState};
use super::{ApiError, ApiResult, BY, Paging};
use crate::api::App;
use crate::store::work::{self, MAX_BACKLOG_PAGE};

pub(super) async fn project(app: &App, id: i64) -> Result<core::Project, ApiError> {
    work::get_project(&app.pool, ProjectId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no project {id}")))
}

async fn sprint(app: &App, id: i64) -> Result<core::Sprint, ApiError> {
    work::get_sprint(&app.pool, SprintId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no sprint {id}")))
}

fn invalid(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
        sqlx::Error::RowNotFound => ApiError::not_found("no such project"),
        e => e.into(),
    }
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/projects", operation_id = "listProjects",
    tag = "projects", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "The company's projects", body = Vec<Project>)))]
pub async fn list_projects(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<Project>> {
    let c = company(&app, id).await?;
    let all = work::list_projects(&app.pool, c.id).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewProject {
    pub name: String,
    /// Issue-number prefix, unique in the company: 1–10 capital letters and digits, starting
    /// with a letter (`CIT` for `CIT-12`).
    pub key: String,
    /// Absent: kanban.
    pub mode: Option<ProjectMode>,
    /// Who approves a sprint commit; absent: the owner.
    pub sprint_approval: Option<SprintApproval>,
    /// The team that owns it, one of the company's.
    pub team_id: Option<i64>,
    /// Every team, the owner first (API minor 18); wins over `team_id`.
    pub team_ids: Option<Vec<i64>>,
    pub icon: Option<String>,
    /// `#rrggbb`.
    pub color: Option<String>,
    /// Runtime limits, as `ProjectSettings` has them.
    pub runner_tags: Option<Vec<String>>,
    pub max_parallel_runs: Option<u32>,
    pub run_timeout_secs: Option<u32>,
    pub worktree_keep_days: Option<u32>,
}

#[utoipa::path(post, path = "/api/v1/companies/{id}/projects", operation_id = "createProject",
    tag = "projects", params(("id" = i64, Path, description = "Company id")),
    request_body = NewProject,
    responses((status = 200, description = "The new project (audited as `project.created`), its \
        permission policy the default (ask); a malformed or taken key is a 409", body = Project)))]
pub async fn create_project(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(new): Json<NewProject>,
) -> ApiResult<Project> {
    let c = company(&app, id).await?;
    let teams = new
        .team_ids
        .clone()
        .map(|all| all.into_iter().map(citadel_core::org::TeamId));
    let extra = work::ProjectChange {
        team_ids: teams.map(Iterator::collect),
        icon: new.icon.clone().map(Some),
        color: new.color.clone().map(Some),
        runner_tags: new.runner_tags.clone(),
        max_parallel_runs: new.max_parallel_runs.map(Some),
        run_timeout_secs: new.run_timeout_secs.map(Some),
        worktree_keep_days: new.worktree_keep_days.map(Some),
        ..Default::default()
    };
    let first = extra.team_ids.as_ref().and_then(|t| t.first().copied());
    let new = core::NewProject {
        company_id: c.id,
        team_id: first.or(new.team_id.map(citadel_core::org::TeamId)),
        name: new.name,
        key: new.key.trim().to_owned(),
        mode: new.mode.map_or(core::ProjectMode::Kanban, Into::into),
        sprint_approval: new
            .sprint_approval
            .map_or(core::SprintApproval::Owner, Into::into),
    };
    let p = work::add_project_with(&app.pool, &new, &extra, BY)
        .await
        .map_err(|e| match e {
            work::IntakeError::Elsewhere => ApiError::not_found("no such team in the company"),
            work::IntakeError::Db(sqlx::Error::InvalidArgument(why)) => ApiError::bad_request(why),
            work::IntakeError::Db(e) => e.into(),
            e => ApiError::conflict(e.to_string()),
        })?;
    Ok(Json(p.into()))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}", operation_id = "getProject", tag = "projects",
    params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project", body = Project)))]
pub async fn get_project(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Project> {
    Ok(Json(project(&app, id).await?.into()))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/issues", operation_id = "listProjectIssues",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "Every issue of the project, by number: the board",
        body = Vec<Issue>)))]
pub async fn list_issues(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<Issue>> {
    let p = project(&app, id).await?;
    let all = work::list_issues(&app.pool, p.id).await?;
    let all = all.into_iter().map(|i| Issue::new(i, &p.key)).collect();
    super::quest::labeled(&app, all).await.map(Json)
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/backlog", operation_id = "getBacklog",
    tag = "projects", params(("id" = i64, Path, description = "Project id"), Paging),
    responses((status = 200, description = "Open top-level issues in no sprint, by rank; `after` \
        is how many to skip, `limit` at most 200", body = Vec<Issue>)))]
pub async fn backlog(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(page): Query<Paging>,
) -> ApiResult<Vec<Issue>> {
    let p = project(&app, id).await?;
    let offset = u32::try_from(page.after.unwrap_or(0).max(0)).unwrap_or(u32::MAX);
    let limit = page.limit.unwrap_or(MAX_BACKLOG_PAGE);
    let all = work::backlog_page(&app.pool, p.id, &BacklogFilter::default(), offset, limit)
        .await
        .map_err(invalid)?;
    let all = all.into_iter().map(|i| Issue::new(i, &p.key)).collect();
    super::quest::labeled(&app, all).await.map(Json)
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/epics", operation_id = "listEpics",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project's epics", body = Vec<Epic>)))]
pub async fn list_epics(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<Epic>> {
    let p = project(&app, id).await?;
    let all = work::list_epics(&app.pool, p.id).await?;
    Ok(Json(
        all.into_iter().map(|e| Epic::new(e, &p.key)).collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewEpic {
    pub title: String,
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/epics", operation_id = "createEpic",
    tag = "projects", params(("id" = i64, Path, description = "Project id")), request_body = NewEpic,
    responses((status = 200, description = "The new, open epic", body = Epic)))]
pub async fn create_epic(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(new): Json<NewEpic>,
) -> ApiResult<Epic> {
    let e = work::create_epic_by(&app.pool, ProjectId(id), &new.title, BY)
        .await
        .map_err(invalid)?
        .ok_or_else(|| ApiError::not_found(format!("no project {id}")))?;
    let p = project(&app, id).await?;
    Ok(Json(Epic::new(e, &p.key)))
}

/// An epic's fields to change (API minor 18); absent fields keep their value, `null` clears an
/// optional one.
#[derive(Debug, Deserialize, ToSchema)]
pub struct EpicPatch {
    pub title: Option<String>,
    pub status: Option<EpicStatus>,
    /// `#rrggbb`.
    #[serde(default, with = "super::quest::serde_with_none")]
    #[schema(value_type = Option<String>)]
    pub color: Option<Option<String>>,
    /// `YYYY-MM-DD`.
    #[serde(default, with = "super::quest::serde_with_none")]
    #[schema(value_type = Option<String>)]
    pub starts_on: Option<Option<String>>,
    /// `YYYY-MM-DD`, not before `starts_on`.
    #[serde(default, with = "super::quest::serde_with_none")]
    #[schema(value_type = Option<String>)]
    pub ends_on: Option<Option<String>>,
    /// One of the project company's requirements.
    #[serde(default, with = "super::quest::serde_with_none")]
    #[schema(value_type = Option<i64>)]
    pub requirement_id: Option<Option<i64>>,
}

#[utoipa::path(patch, path = "/api/v1/epics/{id}", operation_id = "updateEpic", tag = "projects",
    params(("id" = i64, Path, description = "Epic id")), request_body = EpicPatch,
    responses((status = 200, description = "The epic after the change (audited as `epic.updated`, \
        naming the `fields` changed); a bad colour, date, empty title or foreign requirement is a \
        400", body = Epic)))]
pub async fn update_epic(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(p): Json<EpicPatch>,
) -> ApiResult<Epic> {
    let p = work::EpicPatch {
        title: p.title,
        status: p.status.map(Into::into),
        color: p.color,
        starts_on: p.starts_on,
        ends_on: p.ends_on,
        requirement_id: p.requirement_id.map(|r| r.map(core::RequirementId)),
    };
    let e = work::patch_epic(&app.pool, core::EpicId(id), &p, BY)
        .await
        .map_err(invalid)?
        .ok_or_else(|| ApiError::not_found(format!("no epic {id}")))?;
    let p = project(&app, e.project_id.0).await?;
    Ok(Json(Epic::new(e, &p.key)))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/sprints", operation_id = "listSprints",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project's sprints, oldest first", body = Vec<Sprint>)))]
pub async fn list_sprints(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<Sprint>> {
    let p = project(&app, id).await?;
    let all = work::list_sprints(&app.pool, p.id).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewSprintBody {
    pub name: String,
    #[serde(default)]
    pub goal: String,
    /// `YYYY-MM-DD`.
    pub starts_on: String,
    /// `YYYY-MM-DD`, not before `starts_on`.
    pub ends_on: String,
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/sprints", operation_id = "planSprint",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    request_body = NewSprintBody,
    responses((status = 200, description = "The planned sprint; it starts through its commit", body = Sprint)))]
pub async fn plan_sprint(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(new): Json<NewSprintBody>,
) -> ApiResult<Sprint> {
    let p = project(&app, id).await?;
    let s = NewSprint {
        project_id: p.id,
        name: new.name,
        goal: new.goal,
        state: core::SprintState::Planned,
        starts_on: Some(new.starts_on),
        ends_on: Some(new.ends_on),
    };
    let s = work::plan_sprint(&app.pool, &s, BY)
        .await
        .map_err(|e| match e {
            work::SprintError::Db(e) => invalid(e),
            e => e.into(),
        })?;
    Ok(Json(s.into()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CloseSprint {
    /// A planned sprint to carry the unfinished issues to; else they go back to the backlog.
    pub carry_to: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/sprints/{id}/close", operation_id = "closeSprint",
    tag = "projects", params(("id" = i64, Path, description = "Sprint id")),
    request_body = CloseSprint,
    responses((status = 200, description = "The closed sprint", body = Sprint)))]
pub async fn close_sprint(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(c): Json<CloseSprint>,
) -> ApiResult<Sprint> {
    let s = work::close_sprint(&app.pool, SprintId(id), c.carry_to.map(SprintId), BY).await?;
    Ok(Json(s.into()))
}

#[utoipa::path(delete, path = "/api/v1/sprints/{id}", operation_id = "deleteSprint",
    tag = "projects", params(("id" = i64, Path, description = "Sprint id")),
    responses((status = 200, description = "The deleted sprint: a planned one with no issues \
        whose commit is not waiting on an approval (audited as `sprint.deleted`)", body = Sprint)))]
pub async fn delete_sprint(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Sprint> {
    let s = work::delete_empty_sprint(&app.pool, SprintId(id), BY).await?;
    Ok(Json(s.into()))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BurndownDay {
    /// `YYYY-MM-DD`.
    pub day: String,
    /// Points left at the end of the day.
    pub left: u32,
    /// Points in scope that day (API minor 19); absent on a sprint's burndown.
    #[schema(required = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<u32>,
}

/// A sprint's commitment, what got done, and its burndown.
#[derive(Debug, Serialize, ToSchema)]
pub struct SprintReport {
    pub sprint_id: i64,
    pub state: SprintState,
    pub committed: Option<u32>,
    pub completed: u32,
    pub capacity: Option<u32>,
    pub burndown: Vec<BurndownDay>,
}

#[utoipa::path(get, path = "/api/v1/sprints/{id}/report", operation_id = "getSprintReport",
    tag = "projects", params(("id" = i64, Path, description = "Sprint id")),
    responses((status = 200, description = "Commitment, completion and burndown", body = SprintReport)))]
pub async fn sprint_report(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<SprintReport> {
    let s = sprint(&app, id).await?;
    let r = work::sprint_report(&app.pool, s.id, &app.clock.now())
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no sprint {id}")))?;
    Ok(Json(SprintReport {
        sprint_id: r.sprint_id.0,
        state: r.state.into(),
        committed: r.committed,
        completed: r.completed,
        capacity: r.capacity,
        burndown: r
            .burndown
            .into_iter()
            .map(|(day, left)| BurndownDay {
                day,
                left,
                scope: None,
            })
            .collect(),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SprintPoints {
    pub sprint_id: i64,
    pub committed: u32,
    pub completed: u32,
}

/// Points of the last closed sprints, newest first, and their mean completed.
#[derive(Debug, Serialize, ToSchema)]
pub struct Velocity {
    pub sprints: Vec<SprintPoints>,
    pub average: f64,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/velocity", operation_id = "getVelocity",
    tag = "projects", params(("id" = i64, Path, description = "Project id"), Paging),
    responses((status = 200, description = "The last `limit` (default 5) closed sprints", body = Velocity)))]
pub async fn velocity(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(page): Query<Paging>,
) -> ApiResult<Velocity> {
    let p = project(&app, id).await?;
    let v = work::velocity(&app.pool, p.id, page.limit.unwrap_or(5).min(50)).await?;
    Ok(Json(Velocity {
        sprints: v
            .sprints
            .into_iter()
            .map(|(s, committed, completed)| SprintPoints {
                sprint_id: s.0,
                committed,
                completed,
            })
            .collect(),
        average: v.average,
    }))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct WipLimit {
    pub state: IssueState,
    /// Absent (when setting) removes the limit.
    pub limit: Option<u32>,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/wip", operation_id = "listWipLimits",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The kanban columns' WIP limits", body = Vec<WipLimit>)))]
pub async fn wip_limits(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<WipLimit>> {
    let p = project(&app, id).await?;
    let all = work::wip_limits(&app.pool, p.id).await?;
    let all = all.into_iter().map(|(state, limit)| WipLimit {
        state: state.into(),
        limit: Some(limit),
    });
    Ok(Json(all.collect()))
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/wip", operation_id = "setWipLimit",
    tag = "projects", params(("id" = i64, Path, description = "Project id")), request_body = WipLimit,
    responses((status = 200, description = "The kanban columns' WIP limits", body = Vec<WipLimit>)))]
pub async fn set_wip_limit(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(w): Json<WipLimit>,
) -> ApiResult<Vec<WipLimit>> {
    work::set_wip_limit(&app.pool, ProjectId(id), w.state.into(), w.limit, BY)
        .await
        .map_err(invalid)?;
    wip_limits(State(app), Path(id)).await
}
