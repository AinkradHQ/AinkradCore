//! Issues (E11.4-E11.6, E12.1): read one, create, move through the state machine, rank,
//! estimate, file under an epic or a sprint. Every write goes through the store's rules as the
//! admin and is audited. The comment thread and the activity are in `thread`.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ADMIN, ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use utoipa::ToSchema;

use super::util::{issue, labeled, parse, project, rule, sprint_error, transition_error};
use crate::api::model::work::{Criterion, Issue};
use crate::api::scope::Acting;
use crate::api::types::{Actor, IssueKind, IssueState, NextActor, PriorityLevel};
use crate::domain::org::AgentId;
use crate::domain::work::{
    self as core, BlockerLink, EpicId, IssueId, IssueTransition, NewIssue, Position, SprintId,
};
use crate::store::work::{self, IssueTransitionError};

/// The issue as the client sees it, keyed by its project.
pub(crate) async fn issue_out(app: &App, i: core::Issue) -> Result<Issue, ApiError> {
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

#[utoipa::path(get, path = "/issues/{id}", operation_id = "getIssue", tag = "issues",
    params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issue", body = Issue)))]
pub async fn get_issue(State(app): State<App>, _: Acting, Path(id): Path<i64>) -> ApiResult<Issue> {
    let i = issue(&app, id).await?;
    issue_out(&app, i).await.map(Json)
}

/// The fields of an issue the admin edits (API minor 18); absent fields keep their value.
#[derive(Debug, Deserialize, ToSchema)]
pub struct IssuePatchBody {
    pub title: Option<String>,
    pub body: Option<String>,
    /// Never to or from `subtask`.
    #[schema(value_type = Option<IssueKind>)]
    pub kind: Option<String>,
    /// `priority` follows it: true from `high` up.
    #[schema(value_type = Option<PriorityLevel>)]
    pub priority_level: Option<String>,
    /// Replaces the whole list.
    pub criteria: Option<Vec<Criterion>>,
}

#[utoipa::path(patch, path = "/issues/{id}", operation_id = "updateIssue", tag = "issues",
    params(("id" = i64, Path, description = "Issue id")), request_body = IssuePatchBody,
    responses((status = 200, description = "The issue after the change (audited as \
        `issue.updated`, naming the `fields` changed, once; nothing changed, nothing audited). \
        An empty title or criterion, or a change to or from `subtask`, is a 400", body = Issue)))]
pub async fn update_issue(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(p): Json<IssuePatchBody>,
) -> ApiResult<Issue> {
    let p = work::IssuePatch {
        title: p.title,
        body: p.body,
        kind: p
            .kind
            .as_deref()
            .map(|k| parse::<core::IssueKind>(k, "kind"))
            .transpose()?,
        priority_level: p
            .priority_level
            .as_deref()
            .map(|l| parse::<core::PriorityLevel>(l, "priority_level"))
            .transpose()?,
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
        .map_err(rule)?
        .ok_or_else(|| ApiError::not_found(format!("no issue {id}")))?;
    issue_out(&app, i).await.map(Json)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewIssueBody {
    pub title: String,
    #[serde(default)]
    pub body: String,
    /// `task` when absent.
    #[schema(value_type = Option<IssueKind>)]
    pub kind: Option<String>,
    /// `backlog` or `todo`; `backlog` when absent, `todo` with an assignee.
    #[schema(value_type = Option<IssueState>)]
    pub state: Option<String>,
    pub epic_id: Option<i64>,
    pub points: Option<u32>,
    /// An agent to hand it to at once, which wakes it.
    pub assignee_agent_id: Option<i64>,
}

#[utoipa::path(post, path = "/projects/{id}/issues", operation_id = "createIssue",
    tag = "issues", params(("id" = i64, Path, description = "Project id")),
    request_body = NewIssueBody,
    responses((status = 200, description = "The new issue, waiting on the admin or the assignee",
        body = Issue)))]
pub async fn create_issue(
    State(app): State<App>,
    _: Acting,
    Path(pid): Path<i64>,
    Json(new): Json<NewIssueBody>,
) -> ApiResult<Issue> {
    if new.title.trim().is_empty() {
        return Err(ApiError::bad_request("an issue needs a title"));
    }
    let kind = new
        .kind
        .as_deref()
        .map(|k| parse::<core::IssueKind>(k, "kind"))
        .transpose()?
        .unwrap_or(core::IssueKind::Task);
    let wanted = new
        .state
        .as_deref()
        .map(|s| parse::<core::IssueState>(s, "state"))
        .transpose()?;
    let p = project(&app, pid).await?;
    let state = match (wanted, new.assignee_agent_id) {
        (None, None) => core::IssueState::Backlog,
        (None, Some(_)) | (Some(core::IssueState::Todo), _) => core::IssueState::Todo,
        (Some(core::IssueState::Backlog), None) => core::IssueState::Backlog,
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
        kind,
        title: new.title.trim().to_owned(),
        body: new.body,
        state,
        owner: None,
        next_actor: Some(core::NextActor::Human(core::UserId(ADMIN.0))),
        points: new.points,
        sprint_id: None,
    };
    let mut i = work::create_issue_by(&app.pool, &i, BY)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_foreign_key_violation() || d.is_check_violation() => {
                ApiError::bad_request("the epic is not in this project")
            }
            e => rule(e),
        })?;
    if let Some(agent) = new.assignee_agent_id {
        let next = core::NextActor::Agent(AgentId(agent));
        i = work::transition_issue(&app.pool, i.id, &IssueTransition::Reassign { next }, BY)
            .await
            .map_err(transition_error)?;
    }
    labeled(&app, vec![Issue::new(i, &p.key)])
        .await
        .map(|mut one| Json(one.remove(0)))
}

/// A step of the issue state machine (`domain::work::machine`), as the admin.
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

#[utoipa::path(post, path = "/issues/{id}/transition", operation_id = "transitionIssue",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")), request_body = Transition,
    responses((status = 200, description = "The issue after the step", body = Issue)))]
pub async fn transition(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(t): Json<Transition>,
) -> ApiResult<Issue> {
    let i = match t {
        Transition::Block {
            blocker_issue_id: Some(blocker),
        } => link(&app, id, blocker, true).await?,
        t => work::transition_issue(&app.pool, IssueId(id), &t.into(), BY)
            .await
            .map_err(transition_error)?,
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
            IssueTransitionError::Db(e) => rule(e),
            e => transition_error(e),
        })
}

#[utoipa::path(get, path = "/issues/{id}/blockers", operation_id = "listBlockers",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issues that block it", body = Vec<Issue>)))]
pub async fn list_blockers(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Vec<Issue>> {
    let i = issue(&app, id).await?;
    let mut all = vec![];
    for b in work::list_blockers(&app.pool, i.id).await? {
        all.push(issue_out(&app, issue(&app, b.0).await?).await?);
    }
    Ok(Json(all))
}

#[utoipa::path(put, path = "/issues/{id}/blockers/{blocker_id}",
    operation_id = "linkBlocker", tag = "issues",
    params(("id" = i64, Path, description = "The blocked issue"),
        ("blocker_id" = i64, Path, description = "The issue that blocks it, in the same company")),
    responses((status = 200, description = "The blocked issue, its state unchanged (block it with \
        the `block` transition); an existing link is kept", body = Issue)))]
pub async fn link_blocker(
    State(app): State<App>,
    _: Acting,
    Path((id, blocker)): Path<(i64, i64)>,
) -> ApiResult<Issue> {
    let i = link(&app, id, blocker, false).await?;
    issue_out(&app, i).await.map(Json)
}

#[utoipa::path(delete, path = "/issues/{id}/blockers/{blocker_id}",
    operation_id = "unlinkBlocker", tag = "issues",
    params(("id" = i64, Path, description = "The blocked issue"),
        ("blocker_id" = i64, Path, description = "The issue that blocks it")),
    responses((status = 200, description = "The issue after; unblocked and its next actor woken \
        when that was its last open blocker", body = Issue)))]
pub async fn unlink_blocker(
    State(app): State<App>,
    _: Acting,
    Path((id, blocker)): Path<(i64, i64)>,
) -> ApiResult<Issue> {
    let link = BlockerLink {
        blocker: IssueId(blocker),
        blocked: IssueId(id),
    };
    if !work::remove_blocker(&app.pool, link, BY)
        .await
        .map_err(transition_error)?
    {
        return Err(ApiError::not_found(format!(
            "issue {blocker} does not block {id}"
        )));
    }
    let i = issue(&app, id).await?;
    issue_out(&app, i).await.map(Json)
}

/// Where an issue goes in its project's order.
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
    /// `top`, `bottom`, `before` or `after`; anything else is a 400.
    #[schema(value_type = MoveTo)]
    pub to: String,
    /// The issue to go before or after.
    pub anchor_issue_id: Option<i64>,
}

#[utoipa::path(post, path = "/issues/{id}/move", operation_id = "moveIssue",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")), request_body = MoveBody,
    responses((status = 200, description = "The issue at its new rank", body = Issue)))]
pub async fn move_issue(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(m): Json<MoveBody>,
) -> ApiResult<Issue> {
    let anchor = || {
        m.anchor_issue_id
            .map(IssueId)
            .ok_or_else(|| ApiError::bad_request("before and after need anchor_issue_id"))
    };
    let to = match m.to.as_str() {
        "top" => Position::Top,
        "bottom" => Position::Bottom,
        "before" => Position::Before(anchor()?),
        "after" => Position::After(anchor()?),
        other => {
            return Err(ApiError::bad_request(format!(
                "`to` is top, bottom, before or after, not {other:?}"
            )));
        }
    };
    issue(&app, id).await?;
    let i = work::move_issue(&app.pool, IssueId(id), to, BY)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => ApiError::not_found("no such anchor issue"),
            e => rule(e),
        })?;
    issue_out(&app, i).await.map(Json)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EstimateBody {
    /// Story points; absent clears the estimate.
    pub points: Option<u32>,
}

#[utoipa::path(post, path = "/issues/{id}/estimate", operation_id = "estimateIssue",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")),
    request_body = EstimateBody,
    responses((status = 200, description = "The issue with its estimate", body = Issue)))]
pub async fn estimate(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(e): Json<EstimateBody>,
) -> ApiResult<Issue> {
    let i = work::estimate_issue(&app.pool, IssueId(id), e.points, BY)
        .await
        .map_err(sprint_error)?;
    issue_out(&app, i).await.map(Json)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EpicBody {
    /// Absent takes it out of its epic.
    pub epic_id: Option<i64>,
}

#[utoipa::path(post, path = "/issues/{id}/epic", operation_id = "setIssueEpic",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")), request_body = EpicBody,
    responses((status = 200, description = "The issue under its epic", body = Issue)))]
pub async fn set_epic(
    State(app): State<App>,
    acting: Acting,
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
    get_issue(State(app), acting, Path(id)).await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SprintBody {
    /// The sprint to join: a planned one, or an active one (a scope change: the issue needs
    /// points, the sprint's committed points move by them, audited as `sprint.scope_added`);
    /// absent takes it out of its planned or active sprint (`sprint.scope_removed` from an
    /// active one). A closed sprint's scope is fixed.
    pub sprint_id: Option<i64>,
}

#[utoipa::path(post, path = "/issues/{id}/sprint", operation_id = "setIssueSprint",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")), request_body = SprintBody,
    responses((status = 200, description = "The issue in or out of the sprint", body = Issue)))]
pub async fn set_sprint(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(s): Json<SprintBody>,
) -> ApiResult<Issue> {
    let i = match s.sprint_id {
        Some(sprint) => work::add_to_sprint(&app.pool, SprintId(sprint), IssueId(id), BY).await,
        None => work::remove_from_sprint(&app.pool, IssueId(id), BY).await,
    }
    .map_err(sprint_error)?;
    issue_out(&app, i).await.map(Json)
}
