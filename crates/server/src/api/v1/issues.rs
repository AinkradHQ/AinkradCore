//! Issues (E11.4–E11.6, E12.1): read one, create, move through the state machine, rank,
//! estimate, file under an epic or a sprint, and the comment thread, which is how the admin
//! chats with an agent (`store::work::post_comment`). Every write goes through the store's
//! rules as the admin and is audited.

use ainkrad_core::org::AgentId;
use ainkrad_core::work::{
    self as core, BlockerLink, EpicId, IssueId, IssueTransition, NewIssue, Position, ProjectId,
    SprintId,
};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::audit::{AuditPage, page_of};
use super::model::{Comment, Criterion, Issue};
use super::types::{Actor, IssueKind, IssueState, NextActor, PriorityLevel};
use super::{ADMIN, ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::work::{self, IssueTransitionError, SprintError};

/// The issue as the client sees it, keyed by its project.
pub(super) async fn issue_out(app: &App, i: core::Issue) -> Result<Issue, ApiError> {
    let key = work::get_project(&app.pool, i.project_id)
        .await?
        .map(|p| p.key)
        .unwrap_or_default();
    let id = i.id;
    let mut one = super::quest::labeled(app, vec![Issue::new(i, &key)]).await?;
    let mut out = one.remove(0);
    out.repo_implicit = work::implicit_primary_repo(&app.pool, id).await?.is_some();
    Ok(out)
}

pub(super) async fn issue(app: &App, id: i64) -> Result<core::Issue, ApiError> {
    work::get_issue(&app.pool, IssueId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no issue {id}")))
}

impl From<IssueTransitionError> for ApiError {
    fn from(e: IssueTransitionError) -> Self {
        match e {
            IssueTransitionError::NotFound => Self::not_found(e.to_string()),
            IssueTransitionError::Db(e) => e.into(),
            e => Self::conflict(e.to_string()),
        }
    }
}

impl From<SprintError> for ApiError {
    fn from(e: SprintError) -> Self {
        match e {
            SprintError::NotFound => Self::not_found(e.to_string()),
            SprintError::Db(e) => e.into(),
            e => Self::conflict(e.to_string()),
        }
    }
}

#[utoipa::path(get, path = "/api/v1/issues/{id}", operation_id = "getIssue", tag = "issues",
    params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issue", body = Issue)))]
pub async fn get_issue(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Issue> {
    let i = issue(&app, id).await?;
    issue_out(&app, i).await.map(Json)
}

/// The fields of an issue the admin edits (API minor 18); absent fields keep their value.
#[derive(Debug, Deserialize, ToSchema)]
pub struct IssuePatch {
    pub title: Option<String>,
    pub body: Option<String>,
    /// Never to or from `subtask`.
    pub kind: Option<IssueKind>,
    /// `priority` follows it: true from `high` up.
    pub priority_level: Option<PriorityLevel>,
    /// Replaces the whole list.
    pub criteria: Option<Vec<Criterion>>,
}

#[utoipa::path(patch, path = "/api/v1/issues/{id}", operation_id = "updateIssue", tag = "issues",
    params(("id" = i64, Path, description = "Issue id")), request_body = IssuePatch,
    responses((status = 200, description = "The issue after the change (audited as \
        `issue.updated`, naming the `fields` changed, once; nothing changed, nothing audited). \
        An empty title or criterion, or a change to or from `subtask`, is a 400", body = Issue)))]
pub async fn update_issue(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(p): Json<IssuePatch>,
) -> ApiResult<Issue> {
    let p = work::IssuePatch {
        title: p.title,
        body: p.body,
        kind: p.kind.map(Into::into),
        priority_level: p.priority_level.map(Into::into),
        criteria: p.criteria.map(|all| {
            all.into_iter()
                .map(|c| core::Criterion {
                    text: c.text,
                    done: c.done,
                })
                .collect()
        }),
    };
    let i = work::patch_issue(&app.pool, IssueId(id), &p, BY)
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
            e => e.into(),
        })?
        .ok_or_else(|| ApiError::not_found(format!("no issue {id}")))?;
    issue_out(&app, i).await.map(Json)
}

/// Which page of an issue's activity.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ActivityQuery {
    /// Only rows with a `seq` below this (the previous page's `next_before`).
    pub before: Option<i64>,
    /// At most this many (default and most 100).
    pub limit: Option<u32>,
}

#[utoipa::path(get, path = "/api/v1/issues/{id}/activity", operation_id = "listIssueActivity",
    tag = "issues", params(("id" = i64, Path, description = "Issue id"), ActivityQuery),
    responses((status = 200, description = "What was done to the issue (the audit rows about it: \
        created, moved, estimated, labelled, edited, every state change), newest first; \
        `next_before` continues with older rows (API minor 18)", body = AuditPage)))]
pub async fn activity(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(q): Query<ActivityQuery>,
) -> ApiResult<AuditPage> {
    let i = issue(&app, id).await?;
    let limit = q.limit.unwrap_or(100).clamp(1, 100);
    let rows = crate::store::audit::page(
        &app.pool,
        None,
        q.before.map(ainkrad_core::audit::AuditSeq),
        None,
        Some(("issue", Some(i.id.0))),
        None,
        limit + 1,
    )
    .await?;
    Ok(Json(page_of(rows, limit)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewIssueBody {
    pub title: String,
    #[serde(default)]
    pub body: String,
    /// `task` when absent.
    pub kind: Option<IssueKind>,
    /// `backlog` or `todo`; `backlog` when absent, `todo` with an assignee.
    pub state: Option<IssueState>,
    pub epic_id: Option<i64>,
    pub points: Option<u32>,
    /// An agent to hand it to at once, which wakes it.
    pub assignee_agent_id: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/issues", operation_id = "createIssue",
    tag = "issues", params(("id" = i64, Path, description = "Project id")),
    request_body = NewIssueBody,
    responses((status = 200, description = "The new issue, waiting on the admin or the assignee",
        body = Issue)))]
pub async fn create_issue(
    State(app): State<App>,
    Path(project): Path<i64>,
    Json(new): Json<NewIssueBody>,
) -> ApiResult<Issue> {
    if new.title.trim().is_empty() {
        return Err(ApiError::bad_request("an issue needs a title"));
    }
    let p = work::get_project(&app.pool, ProjectId(project))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no project {project}")))?;
    let state = match (new.state, new.assignee_agent_id) {
        (None, None) => core::IssueState::Backlog,
        (None, Some(_)) | (Some(IssueState::Todo), _) => core::IssueState::Todo,
        (Some(IssueState::Backlog), None) => core::IssueState::Backlog,
        _ => {
            return Err(ApiError::bad_request(
                "a new issue starts in backlog or todo, and in todo when assigned",
            ));
        }
    };
    let i = NewIssue {
        project_id: p.id,
        epic_id: new.epic_id.map(EpicId),
        parent_id: None,
        kind: new.kind.map_or(core::IssueKind::Task, Into::into),
        title: new.title.trim().to_owned(),
        body: new.body,
        state,
        owner: None,
        next_actor: Some(core::NextActor::Human(ADMIN)),
        points: new.points,
        sprint_id: None,
    };
    let mut i = work::create_issue_by(&app.pool, &i, BY)
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
            sqlx::Error::Database(d) if d.is_foreign_key_violation() || d.is_check_violation() => {
                ApiError::bad_request("the epic is not in this project")
            }
            e => e.into(),
        })?;
    if let Some(agent) = new.assignee_agent_id {
        let next = core::NextActor::Agent(AgentId(agent));
        i = work::transition_issue(&app.pool, i.id, &IssueTransition::Reassign { next }, BY)
            .await?;
    }
    super::quest::labeled(&app, vec![Issue::new(i, &p.key)])
        .await
        .map(|mut one| Json(one.remove(0)))
}

/// A step of the issue state machine (`ainkrad_core::work::machine`), as the admin.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Transition {
    Start {},
    Ready {},
    SubmitForReview {
        reviewer: Actor,
    },
    Approve {},
    RequestChanges {
        assignee: Actor,
    },
    /// Needs an open blocker: link one first (`PUT /issues/{id}/blockers/{blocker_id}`), or
    /// name it here to link it and block in one step.
    Block {
        blocker_issue_id: Option<i64>,
    },
    Unblock {},
    Done {},
    Cancel {},
    Reassign {
        next: NextActor,
    },
    Reopen {
        next: NextActor,
    },
    Shelve {
        next: NextActor,
    },
}

impl From<Transition> for IssueTransition {
    fn from(t: Transition) -> Self {
        match t {
            Transition::Start {} => Self::Start,
            Transition::Ready {} => Self::Ready,
            Transition::SubmitForReview { reviewer } => Self::SubmitForReview {
                reviewer: reviewer.into(),
            },
            Transition::Approve {} => Self::Approve,
            Transition::RequestChanges { assignee } => Self::RequestChanges {
                assignee: assignee.into(),
            },
            Transition::Block { .. } => Self::Block,
            Transition::Unblock {} => Self::Unblock,
            Transition::Done {} => Self::Done,
            Transition::Cancel {} => Self::Cancel,
            Transition::Reassign { next } => Self::Reassign { next: next.into() },
            Transition::Reopen { next } => Self::Reopen { next: next.into() },
            Transition::Shelve { next } => Self::Shelve { next: next.into() },
        }
    }
}

#[utoipa::path(post, path = "/api/v1/issues/{id}/transition", operation_id = "transitionIssue",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")), request_body = Transition,
    responses((status = 200, description = "The issue after the step", body = Issue)))]
pub async fn transition(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(t): Json<Transition>,
) -> ApiResult<Issue> {
    let i = match t {
        Transition::Block {
            blocker_issue_id: Some(blocker),
        } => link(&app, id, blocker, true).await?,
        t => work::transition_issue(&app.pool, IssueId(id), &t.into(), BY).await?,
    };
    issue_out(&app, i).await.map(Json)
}

/// Links `blocker` before `blocked` as the admin, blocking it too with `block`.
async fn link(app: &App, blocked: i64, blocker: i64, block: bool) -> Result<core::Issue, ApiError> {
    let link = BlockerLink {
        blocker: IssueId(blocker),
        blocked: IssueId(blocked),
    };
    work::link_blocker(&app.pool, link, block, BY)
        .await
        .map_err(|e| match e {
            IssueTransitionError::Db(sqlx::Error::InvalidArgument(why)) => {
                ApiError::bad_request(why)
            }
            e => e.into(),
        })
}

#[utoipa::path(get, path = "/api/v1/issues/{id}/blockers", operation_id = "listBlockers",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issues that block it", body = Vec<Issue>)))]
pub async fn list_blockers(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<Issue>> {
    let i = issue(&app, id).await?;
    let mut all = vec![];
    for b in work::list_blockers(&app.pool, i.id).await? {
        all.push(issue_out(&app, issue(&app, b.0).await?).await?);
    }
    Ok(Json(all))
}

#[utoipa::path(put, path = "/api/v1/issues/{id}/blockers/{blocker_id}",
    operation_id = "linkBlocker", tag = "issues",
    params(("id" = i64, Path, description = "The blocked issue"),
        ("blocker_id" = i64, Path, description = "The issue that blocks it, in the same company")),
    responses((status = 200, description = "The blocked issue, its state unchanged (block it with \
        the `block` transition); an existing link is kept", body = Issue)))]
pub async fn link_blocker(
    State(app): State<App>,
    Path((id, blocker)): Path<(i64, i64)>,
) -> ApiResult<Issue> {
    let i = link(&app, id, blocker, false).await?;
    issue_out(&app, i).await.map(Json)
}

#[utoipa::path(delete, path = "/api/v1/issues/{id}/blockers/{blocker_id}",
    operation_id = "unlinkBlocker", tag = "issues",
    params(("id" = i64, Path, description = "The blocked issue"),
        ("blocker_id" = i64, Path, description = "The issue that blocks it")),
    responses((status = 200, description = "The issue after; unblocked and its next actor woken \
        when that was its last open blocker", body = Issue)))]
pub async fn unlink_blocker(
    State(app): State<App>,
    Path((id, blocker)): Path<(i64, i64)>,
) -> ApiResult<Issue> {
    let link = BlockerLink {
        blocker: IssueId(blocker),
        blocked: IssueId(id),
    };
    if !work::remove_blocker(&app.pool, link, BY).await? {
        return Err(ApiError::not_found(format!(
            "issue {blocker} does not block {id}"
        )));
    }
    let i = issue(&app, id).await?;
    issue_out(&app, i).await.map(Json)
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MoveTo {
    Top,
    Bottom,
    Before,
    After,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MoveBody {
    pub to: MoveTo,
    /// The issue to go before or after.
    pub anchor_issue_id: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/issues/{id}/move", operation_id = "moveIssue",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")), request_body = MoveBody,
    responses((status = 200, description = "The issue at its new rank", body = Issue)))]
pub async fn move_issue(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(m): Json<MoveBody>,
) -> ApiResult<Issue> {
    let anchor = || {
        m.anchor_issue_id
            .map(IssueId)
            .ok_or_else(|| ApiError::bad_request("before and after need anchor_issue_id"))
    };
    let to = match m.to {
        MoveTo::Top => Position::Top,
        MoveTo::Bottom => Position::Bottom,
        MoveTo::Before => Position::Before(anchor()?),
        MoveTo::After => Position::After(anchor()?),
    };
    issue(&app, id).await?;
    let i = work::move_issue(&app.pool, IssueId(id), to, BY)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => ApiError::not_found("no such anchor issue"),
            sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
            e => e.into(),
        })?;
    issue_out(&app, i).await.map(Json)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EstimateBody {
    /// Story points; absent clears the estimate.
    pub points: Option<u32>,
}

#[utoipa::path(post, path = "/api/v1/issues/{id}/estimate", operation_id = "estimateIssue",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")),
    request_body = EstimateBody,
    responses((status = 200, description = "The issue with its estimate", body = Issue)))]
pub async fn estimate(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(e): Json<EstimateBody>,
) -> ApiResult<Issue> {
    let i = work::estimate_issue(&app.pool, IssueId(id), e.points, BY).await?;
    issue_out(&app, i).await.map(Json)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EpicBody {
    /// Absent takes it out of its epic.
    pub epic_id: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/issues/{id}/epic", operation_id = "setIssueEpic",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")), request_body = EpicBody,
    responses((status = 200, description = "The issue under its epic", body = Issue)))]
pub async fn set_epic(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(e): Json<EpicBody>,
) -> ApiResult<Issue> {
    issue(&app, id).await?;
    let set = work::set_issue_epic(&app.pool, IssueId(id), e.epic_id.map(EpicId), BY)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(_) | sqlx::Error::InvalidArgument(_) => {
                ApiError::bad_request("the epic is not in the issue's project")
            }
            e => e.into(),
        })?;
    if !set {
        return Err(ApiError::not_found(format!("no issue {id}")));
    }
    get_issue(State(app), Path(id)).await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SprintBody {
    /// The sprint to join: a planned one, or an active one (a scope change: the issue needs
    /// points, the sprint's committed points move by them, audited as `sprint.scope_added`);
    /// absent takes it out of its planned or active sprint (`sprint.scope_removed` from an
    /// active one). A closed sprint's scope is fixed.
    pub sprint_id: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/issues/{id}/sprint", operation_id = "setIssueSprint",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")), request_body = SprintBody,
    responses((status = 200, description = "The issue in or out of the sprint", body = Issue)))]
pub async fn set_sprint(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(s): Json<SprintBody>,
) -> ApiResult<Issue> {
    let i = match s.sprint_id {
        Some(sprint) => work::add_to_sprint(&app.pool, SprintId(sprint), IssueId(id), BY).await?,
        None => work::remove_from_sprint(&app.pool, IssueId(id), BY).await?,
    };
    issue_out(&app, i).await.map(Json)
}

#[utoipa::path(get, path = "/api/v1/issues/{id}/comments", operation_id = "listComments",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issue's thread, oldest first", body = Vec<Comment>)))]
pub async fn list_comments(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<Comment>> {
    let i = issue(&app, id).await?;
    let all = work::list_comments(&app.pool, i.id).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewComment {
    pub body: String,
    /// Makes a retry safe: the same key on the same issue posts (and wakes) once.
    pub idempotency_key: Option<String>,
    /// The agent to wake (one of the issue's company). Absent: the first agent the body
    /// mentions (`@agent:<id>`, or `@<name>`, any case), else the agent working a `todo` or
    /// `in_progress` issue (its owner), else its next actor. An open question on the issue is
    /// answered by the comment and wakes its asker either way.
    pub wake_agent_id: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Posted {
    pub comment: Comment,
    /// The agent the comment woke (see `NewComment.wake_agent_id`).
    pub woke_agent_id: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/issues/{id}/comments", operation_id = "postComment",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")), request_body = NewComment,
    responses((status = 200, description = "The comment, and the agent it woke", body = Posted)))]
pub async fn post_comment(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(c): Json<NewComment>,
) -> ApiResult<Posted> {
    let key = c.idempotency_key.as_deref();
    let wake = c.wake_agent_id.map(AgentId);
    let (comment, woke) = work::post_comment(&app.pool, IssueId(id), ADMIN, &c.body, key, wake)
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
            e => e.into(),
        })?
        .ok_or_else(|| ApiError::not_found(format!("no issue {id}")))?;
    Ok(Json(Posted {
        comment: comment.into(),
        woke_agent_id: woke.map(|a| a.0),
    }))
}
