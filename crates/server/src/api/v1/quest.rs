//! Quest in server mode (E12) from the app: a project's settings and labels, labels on issues,
//! the team's sprint capacity, flow times (cycle, lead, age, throughput), the owner's sprint
//! commit, and a closed sprint's review and retro proposals. Writes go through the store's
//! rules as the admin and are audited.

use ainkrad_core::org::{AgentId, TeamId};
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core::work::{IssueId, LabelId, ProjectId, SprintId};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::model::{Issue, Label, Project, Sprint};
use super::projects::project;
use super::types::{ProjectMode, SprintApproval, SprintState, TeamRole, Timestamp, opt_ts};
use super::{ADMIN, ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::work;

/// The routes that came with API minor 9 on paths of their own; `PUT /projects/{id}` is in
/// `router`.
pub(super) fn routes() -> Router<App> {
    Router::new()
        .route(
            "/api/v1/projects/{id}/labels",
            get(list_labels).post(add_label),
        )
        .route(
            "/api/v1/projects/{id}/labels/{label_id}",
            put(rename_label).delete(delete_label),
        )
        .route(
            "/api/v1/issues/{id}/labels/{label_id}",
            put(label_issue).delete(unlabel_issue),
        )
        .route("/api/v1/projects/{id}/capacity", get(capacity))
        .route(
            "/api/v1/projects/{id}/capacity/{agent_id}",
            put(set_capacity),
        )
        .route("/api/v1/projects/{id}/flow", get(project_flow))
        .route("/api/v1/issues/{id}/flow", get(issue_flow))
        .route("/api/v1/sprints/{id}/commit", post(commit_sprint))
        .route("/api/v1/sprints/{id}/review", get(sprint_review))
}

fn refused(e: sqlx::Error, what: &str) -> ApiError {
    match e {
        sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
        sqlx::Error::RowNotFound => ApiError::not_found(what.to_owned()),
        e => e.into(),
    }
}

/// `items` with their labels, in one read.
pub(super) async fn labeled(app: &App, mut items: Vec<Issue>) -> Result<Vec<Issue>, ApiError> {
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
    pub mode: Option<ProjectMode>,
    pub sprint_approval: Option<SprintApproval>,
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
    pub(super) fn change(self) -> work::ProjectChange {
        work::ProjectChange {
            name: self.name,
            mode: self.mode.map(Into::into),
            sprint_approval: self.sprint_approval.map(Into::into),
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
        }
    }
}

/// `Option<Option<T>>` from JSON: absent is `None`, `null` is `Some(None)`.
pub(super) mod serde_with_none {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        d: D,
    ) -> Result<Option<Option<T>>, D::Error> {
        Option::<T>::deserialize(d).map(Some)
    }
}

#[utoipa::path(put, path = "/api/v1/projects/{id}", operation_id = "updateProject",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    request_body = ProjectSettings,
    responses((status = 200, description = "The project after the change (audited as \
        `project.updated`); only the fields given change. Its key never changes", body = Project)))]
pub async fn update_project(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(s): Json<ProjectSettings>,
) -> ApiResult<Project> {
    let c = s.change();
    let p = work::change_project(&app.pool, ProjectId(id), &c, BY)
        .await
        .map_err(|e| refused(e, &format!("no such project or team for project {id}")))?;
    Ok(Json(p.into()))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/labels", operation_id = "listLabels",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project's labels, by name", body = Vec<Label>)))]
pub async fn list_labels(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<Label>> {
    let p = project(&app, id).await?;
    let all = work::list_labels(&app.pool, p.id).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LabelName {
    /// One line, 1–50 characters, unique in the project.
    pub name: String,
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/labels", operation_id = "createLabel",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    request_body = LabelName,
    responses((status = 200, description = "The new label (audited as `label.created`)",
        body = Label)))]
pub async fn add_label(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(l): Json<LabelName>,
) -> ApiResult<Label> {
    let l = work::add_label(&app.pool, ProjectId(id), &l.name, BY)
        .await
        .map_err(|e| refused(e, &format!("no project {id}")))?;
    Ok(Json(l.into()))
}

#[utoipa::path(put, path = "/api/v1/projects/{id}/labels/{label_id}", operation_id = "renameLabel",
    tag = "projects", params(("id" = i64, Path, description = "Project id"),
        ("label_id" = i64, Path, description = "Label id")),
    request_body = LabelName,
    responses((status = 200, description = "The label, renamed (audited as `label.renamed`)",
        body = Label)))]
pub async fn rename_label(
    State(app): State<App>,
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

#[utoipa::path(delete, path = "/api/v1/projects/{id}/labels/{label_id}", operation_id = "deleteLabel",
    tag = "projects", params(("id" = i64, Path, description = "Project id"),
        ("label_id" = i64, Path, description = "Label id")),
    responses((status = 200, description = "The project's labels left; the label is gone from \
        every issue (audited as `label.deleted`)", body = Vec<Label>)))]
pub async fn delete_label(
    State(app): State<App>,
    Path((id, label)): Path<(i64, i64)>,
) -> ApiResult<Vec<Label>> {
    work::change_label(&app.pool, ProjectId(id), LabelId(label), None, BY)
        .await
        .map_err(|e| refused(e, &format!("no label {label} in project {id}")))?;
    list_labels(State(app), Path(id)).await
}

async fn issue_with_labels(app: &App, id: i64) -> ApiResult<Issue> {
    let i = super::issues::issue(app, id).await?;
    super::issues::issue_out(app, i).await.map(Json)
}

#[utoipa::path(put, path = "/api/v1/issues/{id}/labels/{label_id}", operation_id = "labelIssue",
    tag = "issues", params(("id" = i64, Path, description = "Issue id"),
        ("label_id" = i64, Path, description = "A label of the issue's project")),
    responses((status = 200, description = "The issue with the label (audited as \
        `issue.labeled` once)", body = Issue)))]
pub async fn label_issue(
    State(app): State<App>,
    Path((id, label)): Path<(i64, i64)>,
) -> ApiResult<Issue> {
    let i = super::issues::issue(&app, id).await?;
    let theirs = work::get_label(&app.pool, LabelId(label)).await?;
    if theirs.is_none_or(|l| l.project_id != i.project_id) {
        return Err(ApiError::not_found(format!(
            "no label {label} in the issue's project"
        )));
    }
    work::add_issue_label(&app.pool, i.id, LabelId(label), BY).await?;
    issue_with_labels(&app, id).await
}

#[utoipa::path(delete, path = "/api/v1/issues/{id}/labels/{label_id}", operation_id = "unlabelIssue",
    tag = "issues", params(("id" = i64, Path, description = "Issue id"),
        ("label_id" = i64, Path, description = "Label id")),
    responses((status = 200, description = "The issue without the label (audited as \
        `issue.unlabeled` when it had it)", body = Issue)))]
pub async fn unlabel_issue(
    State(app): State<App>,
    Path((id, label)): Path<(i64, i64)>,
) -> ApiResult<Issue> {
    let i = super::issues::issue(&app, id).await?;
    work::remove_issue_label(&app.pool, i.id, LabelId(label), BY).await?;
    issue_with_labels(&app, id).await
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MemberCapacity {
    pub agent_id: i64,
    pub team_role: TeamRole,
    /// Points it takes on per sprint; absent when not set.
    pub capacity: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TeamCapacity {
    /// The project's owning team; absent (and no members) when it has none.
    pub team_id: Option<i64>,
    pub members: Vec<MemberCapacity>,
    /// The members' capacity together, what a sprint commit is checked against; absent when
    /// none is set.
    pub total: Option<u32>,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/capacity", operation_id = "getTeamCapacity",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "Each member of the project's team and its points \
        per sprint", body = TeamCapacity)))]
pub async fn capacity(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<TeamCapacity> {
    let p = project(&app, id).await?;
    let Some((team, members)) = work::team_capacity(&app.pool, p.id).await? else {
        let none = TeamCapacity {
            team_id: None,
            members: vec![],
            total: None,
        };
        return Ok(Json(none));
    };
    let set: Vec<u32> = members.iter().filter_map(|m| m.capacity).collect();
    Ok(Json(TeamCapacity {
        team_id: Some(team.0),
        total: (!set.is_empty()).then(|| set.iter().sum()),
        members: members
            .into_iter()
            .map(|m| MemberCapacity {
                agent_id: m.agent_id.0,
                team_role: m.team_role.into(),
                capacity: m.capacity,
            })
            .collect(),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CapacityBody {
    /// Points per sprint; `null` clears it.
    pub capacity: Option<u32>,
}

#[utoipa::path(put, path = "/api/v1/projects/{id}/capacity/{agent_id}",
    operation_id = "setMemberCapacity", tag = "projects",
    params(("id" = i64, Path, description = "Project id"),
        ("agent_id" = i64, Path, description = "A member of the project's team")),
    request_body = CapacityBody,
    responses((status = 200, description = "The team's capacity after the change (audited as \
        `member.capacity_set`)", body = TeamCapacity)))]
pub async fn set_capacity(
    State(app): State<App>,
    Path((id, agent)): Path<(i64, i64)>,
    Json(c): Json<CapacityBody>,
) -> ApiResult<TeamCapacity> {
    work::set_capacity(&app.pool, ProjectId(id), AgentId(agent), c.capacity, BY)
        .await
        .map_err(|e| refused(e, &format!("agent {agent} is not on project {id}'s team")))?;
    capacity(State(app), Path(id)).await
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct Window {
    /// From (inclusive); absent: `flow.window_secs` before `until`.
    pub since: Option<String>,
    /// To (exclusive); absent: now.
    pub until: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IssueTimes {
    pub issue_id: i64,
    pub cycle_secs: Option<i64>,
    pub lead_secs: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectFlow {
    pub since: Timestamp,
    pub until: Timestamp,
    /// Top-level issues done in the window.
    pub throughput: usize,
    pub mean_cycle_secs: Option<f64>,
    pub mean_lead_secs: Option<f64>,
    /// Each done issue, by when it was done.
    pub issues: Vec<IssueTimes>,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/flow", operation_id = "getProjectFlow",
    tag = "projects", params(("id" = i64, Path, description = "Project id"), Window),
    responses((status = 200, description = "Throughput and cycle and lead times of the issues \
        done in the window, from their state history", body = ProjectFlow)))]
pub async fn project_flow(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(w): Query<Window>,
) -> ApiResult<ProjectFlow> {
    let p = project(&app, id).await?;
    let until = w.until.unwrap_or_else(|| app.clock.now());
    let since = match w.since {
        Some(s) => s,
        None => {
            let window =
                crate::store::settings::value(&app.pool, Key::FlowWindowSecs, Scope::Project(p.id))
                    .await?;
            sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?, '-' || ? || ' seconds')")
                .bind(&until)
                .bind(window)
                .fetch_one(&app.pool)
                .await?
        }
    };
    let m = work::flow_metrics(&app.pool, p.id, &since, &until).await?;
    Ok(Json(ProjectFlow {
        since: Timestamp::new(&since),
        until: Timestamp::new(&until),
        throughput: m.issues.len(),
        mean_cycle_secs: m.mean_cycle_secs,
        mean_lead_secs: m.mean_lead_secs,
        issues: m
            .issues
            .into_iter()
            .map(|(i, cycle, lead)| IssueTimes {
                issue_id: i.0,
                cycle_secs: cycle,
                lead_secs: lead,
            })
            .collect(),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IssueFlow {
    pub created_at: Option<Timestamp>,
    /// First moved to `in_progress`.
    pub started_at: Option<Timestamp>,
    /// Last done, while it is done.
    pub done_at: Option<Timestamp>,
    /// In progress → done.
    pub cycle_secs: Option<i64>,
    /// Created → done.
    pub lead_secs: Option<i64>,
    /// Created → done, or → now while open.
    pub age_secs: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/issues/{id}/flow", operation_id = "getIssueFlow",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issue's cycle and lead time and age, from its \
        state history; absent where it has no such step", body = IssueFlow)))]
pub async fn issue_flow(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<IssueFlow> {
    let i = super::issues::issue(&app, id).await?;
    let f = work::issue_flow(&app.pool, IssueId(i.id.0), &app.clock.now()).await?;
    Ok(Json(IssueFlow {
        created_at: opt_ts(f.created_at.as_deref()),
        started_at: opt_ts(f.started_at.as_deref()),
        done_at: opt_ts(f.done_at.as_deref()),
        cycle_secs: f.cycle_secs,
        lead_secs: f.lead_secs,
        age_secs: f.age_secs,
    }))
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct SprintCommit {
    /// Required when the sprint holds more points than the team's capacity.
    pub override_reason: Option<String>,
}

#[utoipa::path(post, path = "/api/v1/sprints/{id}/commit", operation_id = "commitSprint",
    tag = "projects", params(("id" = i64, Path, description = "Sprint id")),
    request_body = SprintCommit,
    responses((status = 200, description = "The sprint, started by the owner (decision #10: the \
        owner the commit gate waits on; audited as `sprint.started`, gate `owner`). A pending \
        commit approval (decide it instead), unpointed issues, an active sprint, or points over \
        capacity without a reason is a 409", body = Sprint)))]
pub async fn commit_sprint(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(c): Json<SprintCommit>,
) -> ApiResult<Sprint> {
    let s = work::owner_commit_sprint(&app.pool, SprintId(id), ADMIN, c.override_reason.as_deref())
        .await?;
    Ok(Json(s.into()))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RetroProposal {
    /// Its knowledge entry.
    pub id: i64,
    /// `decision`, `landmine` or `retro`.
    pub kind: String,
    pub title: String,
    pub body: String,
    /// `proposed`, `accepted` or `rejected`.
    pub status: String,
    pub proposed_by: Option<i64>,
    /// Why it was accepted or rejected.
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SprintReview {
    pub sprint_id: i64,
    pub state: SprintState,
    /// Stored when it closed: committed and completed points, the carried issues, velocity
    /// against the previous sprints, the blocked and escalated issues; absent before.
    #[schema(value_type = Option<Object>)]
    pub review: Option<serde_json::Value>,
    /// What the product owner or team lead proposed from it, oldest first.
    pub retro: Vec<RetroProposal>,
}

#[utoipa::path(get, path = "/api/v1/sprints/{id}/review", operation_id = "getSprintReview",
    tag = "projects", params(("id" = i64, Path, description = "Sprint id")),
    responses((status = 200, description = "The sprint's review and its retro proposals",
        body = SprintReview)))]
pub async fn sprint_review(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<SprintReview> {
    let s = work::get_sprint(&app.pool, SprintId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no sprint {id}")))?;
    let review = work::sprint_review(&app.pool, s.id).await?;
    let retro = work::retro_items(&app.pool, s.id).await?;
    Ok(Json(SprintReview {
        sprint_id: s.id.0,
        state: s.state.into(),
        review,
        retro: retro
            .into_iter()
            .map(|k| RetroProposal {
                id: k.id.0,
                kind: k.kind.as_str().to_owned(),
                title: k.title,
                body: k.body,
                status: k.status.as_str().to_owned(),
                proposed_by: k.proposed_by.map(|a| a.0),
                reason: k.reason,
            })
            .collect(),
    }))
}
