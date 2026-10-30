//! Quest in server mode (E12) from the app: a project's settings and labels, labels on issues.
//! The team's capacity, flow times, the sprint commit and review are in `flow`. Writes go through
//! the store's rules as the admin and are audited.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::api::model::work::{Issue, Label, Project};
use crate::api::scope::Acting;
use crate::api::types::{ProjectMode, SprintApproval};
use crate::domain::org::TeamId;
use crate::domain::work::{IssueId, LabelId, ProjectId};
use crate::store::work;

pub(super) async fn project(app: &App, id: i64) -> Result<crate::domain::work::Project, ApiError> {
    work::get_project(&app.pool, ProjectId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no project {id}")))
}

pub(super) async fn issue(app: &App, id: i64) -> Result<crate::domain::work::Issue, ApiError> {
    work::get_issue(&app.pool, IssueId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no issue {id}")))
}

/// The issue as the client sees it, keyed by its project.
async fn issue_out(app: &App, i: crate::domain::work::Issue) -> Result<Issue, ApiError> {
    let key = work::get_project(&app.pool, i.project_id)
        .await?
        .map(|p| p.key)
        .unwrap_or_default();
    let id = i.id;
    let mut one = labeled(app, vec![Issue::new(i, &key)]).await?;
    let mut out = one.remove(0);
    out.repo_implicit = work::implicit_primary_repo(&app.pool, id).await?.is_some();
    Ok(out)
}

/// A refused sprint step on the wire.
pub(super) fn sprint_refused(e: work::SprintError) -> ApiError {
    match e {
        work::SprintError::NotFound => ApiError::not_found(e.to_string()),
        work::SprintError::Db(e) => e.into(),
        e => ApiError::conflict(e.to_string()),
    }
}

pub(super) fn refused(e: sqlx::Error, what: &str) -> ApiError {
    match e {
        sqlx::Error::Protocol(why) => ApiError::bad_request(why),
        sqlx::Error::RowNotFound => ApiError::not_found(what.to_owned()),
        e => e.into(),
    }
}

/// `items` with their labels, in one read.
pub(crate) async fn labeled(app: &App, mut items: Vec<Issue>) -> Result<Vec<Issue>, ApiError> {
    let ids: Vec<i64> = items.iter().map(|i| i.id).collect();
    for (issue, l) in work::labels_of(&app.pool, &ids).await? {
        if let Some(i) = items.iter_mut().find(|i| i.id == issue) {
            i.labels.push(l.into());
        }
    }
    Ok(items)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ProjectSettings {
    pub name: Option<String>,
    /// Scrum to kanban only with no planned or active sprint.
    #[schema(value_type = Option<ProjectMode>)]
    pub mode: Option<String>,
    /// `owner` or `product_owner`; anything else is a 400.
    #[schema(value_type = Option<SprintApproval>)]
    pub sprint_approval: Option<String>,
    /// The owning team, one of the company's; `null` clears it, absent keeps it.
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<i64>)]
    pub team_id: Option<Option<i64>>,
    /// Every team, the owner first (API minor 18); wins over `team_id`.
    pub team_ids: Option<Vec<i64>>,
    /// A symbol or emoji; `null` clears it.
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<String>)]
    pub icon: Option<Option<String>>,
    /// `#rrggbb`; `null` clears it.
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<String>)]
    pub color: Option<Option<String>>,
    /// Runtime (API minor 18), stored and shown: the tags a runner needs, replacing the list.
    pub runner_tags: Option<Vec<String>>,
    /// 1 to 64; `null` clears the cap.
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<u32>)]
    pub max_parallel_runs: Option<Option<u32>>,
    /// 1 to 604800 seconds; `null` clears it.
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<u32>)]
    pub run_timeout_secs: Option<Option<u32>>,
    /// 0 to 3650; `null` clears it.
    #[serde(default, with = "serde_with_none")]
    #[schema(value_type = Option<u32>)]
    pub worktree_keep_days: Option<Option<u32>>,
}

impl ProjectSettings {
    pub(crate) fn change(self) -> Result<work::ProjectChange, ApiError> {
        let mode = self
            .mode
            .map(|m| m.parse::<crate::domain::work::ProjectMode>())
            .transpose()
            .map_err(|_| ApiError::bad_request("mode is `scrum` or `kanban`"))?;
        let sprint_approval = self
            .sprint_approval
            .map(|a| a.parse::<crate::domain::work::SprintApproval>())
            .transpose()
            .map_err(|_| ApiError::bad_request("sprint_approval is `owner` or `product_owner`"))?;
        Ok(work::ProjectChange {
            name: self.name,
            mode,
            sprint_approval,
            team_id: self.team_id.map(|t| t.map(TeamId)),
            team_ids: self
                .team_ids
                .map(|all| all.into_iter().map(TeamId).collect()),
            icon: self.icon,
            color: self.color,
            runner_tags: self.runner_tags,
            max_parallel_runs: self.max_parallel_runs,
            run_timeout_secs: self.run_timeout_secs,
            worktree_keep_days: self.worktree_keep_days,
        })
    }
}

/// `Option<Option<T>>` from JSON: absent is `None`, `null` is `Some(None)`.
pub(crate) mod serde_with_none {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        d: D,
    ) -> Result<Option<Option<T>>, D::Error> {
        Option::<T>::deserialize(d).map(Some)
    }
}

#[utoipa::path(put, path = "/projects/{id}", operation_id = "updateProject",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    request_body = ProjectSettings,
    responses((status = 200, description = "The project after the change (audited as \
        `project.updated`); only the fields given change. Its key never changes", body = Project)))]
pub async fn update_project(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(s): Json<ProjectSettings>,
) -> ApiResult<Project> {
    let c = s.change()?;
    let p = work::change_project(&app.pool, ProjectId(id), &c, BY)
        .await
        .map_err(|e| refused(e, &format!("no such project or team for project {id}")))?;
    Ok(Json(p.into()))
}

#[utoipa::path(get, path = "/projects/{id}/labels", operation_id = "listLabels",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project's labels, by name", body = Vec<Label>)))]
pub async fn list_labels(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Vec<Label>> {
    let p = project(&app, id).await?;
    let all = work::list_labels(&app.pool, p.id).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LabelName {
    /// One line, 1–50 characters, unique in the project.
    pub name: String,
}

#[utoipa::path(post, path = "/projects/{id}/labels", operation_id = "createLabel",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    request_body = LabelName,
    responses((status = 200, description = "The new label (audited as `label.created`)",
        body = Label)))]
pub async fn add_label(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(l): Json<LabelName>,
) -> ApiResult<Label> {
    let l = work::add_label(&app.pool, ProjectId(id), &l.name, BY)
        .await
        .map_err(|e| refused(e, &format!("no project {id}")))?;
    Ok(Json(l.into()))
}

#[utoipa::path(put, path = "/projects/{id}/labels/{label_id}", operation_id = "renameLabel",
    tag = "projects", params(("id" = i64, Path, description = "Project id"),
        ("label_id" = i64, Path, description = "Label id")),
    request_body = LabelName,
    responses((status = 200, description = "The label, renamed (audited as `label.renamed`)",
        body = Label)))]
pub async fn rename_label(
    State(app): State<App>,
    _: Acting,
    Path((id, label)): Path<(i64, i64)>,
    Json(l): Json<LabelName>,
) -> ApiResult<Label> {
    let changed = work::change_label(&app.pool, ProjectId(id), LabelId(label), Some(&l.name), BY);
    let l = changed
        .await
        .map_err(|e| refused(e, &format!("no label {label} in project {id}")))?
        .ok_or_else(|| ApiError::not_found("the label is gone"))?;
    Ok(Json(l.into()))
}

#[utoipa::path(delete, path = "/projects/{id}/labels/{label_id}", operation_id = "deleteLabel",
    tag = "projects", params(("id" = i64, Path, description = "Project id"),
        ("label_id" = i64, Path, description = "Label id")),
    responses((status = 200, description = "The project's labels left; the label is gone from \
        every issue (audited as `label.deleted`)", body = Vec<Label>)))]
pub async fn delete_label(
    State(app): State<App>,
    _: Acting,
    Path((id, label)): Path<(i64, i64)>,
) -> ApiResult<Vec<Label>> {
    work::change_label(&app.pool, ProjectId(id), LabelId(label), None, BY)
        .await
        .map_err(|e| refused(e, &format!("no label {label} in project {id}")))?;
    list_labels(State(app), Acting::default(), Path(id)).await
}

async fn issue_with_labels(app: &App, id: i64) -> ApiResult<Issue> {
    let i = issue(app, id).await?;
    issue_out(app, i).await.map(Json)
}

#[utoipa::path(put, path = "/issues/{id}/labels/{label_id}", operation_id = "labelIssue",
    tag = "issues", params(("id" = i64, Path, description = "Issue id"),
        ("label_id" = i64, Path, description = "A label of the issue's project")),
    responses((status = 200, description = "The issue with the label (audited as \
        `issue.labeled` once)", body = Issue)))]
pub async fn label_issue(
    State(app): State<App>,
    _: Acting,
    Path((id, label)): Path<(i64, i64)>,
) -> ApiResult<Issue> {
    let i = issue(&app, id).await?;
    let theirs = work::get_label(&app.pool, LabelId(label)).await?;
    if theirs.is_none_or(|l| l.project_id != i.project_id) {
        return Err(ApiError::not_found(format!(
            "no label {label} in the issue's project"
        )));
    }
    work::add_issue_label(&app.pool, i.id, LabelId(label), BY).await?;
    issue_with_labels(&app, id).await
}

#[utoipa::path(delete, path = "/issues/{id}/labels/{label_id}", operation_id = "unlabelIssue",
    tag = "issues", params(("id" = i64, Path, description = "Issue id"),
        ("label_id" = i64, Path, description = "Label id")),
    responses((status = 200, description = "The issue without the label (audited as \
        `issue.unlabeled` when it had it)", body = Issue)))]
pub async fn unlabel_issue(
    State(app): State<App>,
    _: Acting,
    Path((id, label)): Path<(i64, i64)>,
) -> ApiResult<Issue> {
    let i = issue(&app, id).await?;
    work::remove_issue_label(&app.pool, i.id, LabelId(label), BY).await?;
    issue_with_labels(&app, id).await
}
