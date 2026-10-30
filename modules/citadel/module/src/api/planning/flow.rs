//! Quest, the sprint side: the team's capacity, flow times (cycle, lead, age, throughput), the
//! owner's sprint commit, and a closed sprint's review and retro proposals.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ADMIN, ApiError, ApiResult, BY};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::quest::{issue, project, refused, sprint_refused};
use crate::api::model::work::Sprint;
use crate::api::scope::Acting;
use crate::api::types::{SprintState, TeamRole, Timestamp, opt_ts};
use crate::domain::org::AgentId;
use crate::domain::work::{IssueId, ProjectId, SprintId, UserId};
use crate::store::work;

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

#[utoipa::path(get, path = "/projects/{id}/capacity", operation_id = "getTeamCapacity",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "Each member of the project's team and its points \
        per sprint", body = TeamCapacity)))]
pub async fn capacity(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<TeamCapacity> {
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

#[utoipa::path(put, path = "/projects/{id}/capacity/{agent_id}",
    operation_id = "setMemberCapacity", tag = "projects",
    params(("id" = i64, Path, description = "Project id"),
        ("agent_id" = i64, Path, description = "A member of the project's team")),
    request_body = CapacityBody,
    responses((status = 200, description = "The team's capacity after the change (audited as \
        `member.capacity_set`)", body = TeamCapacity)))]
pub async fn set_capacity(
    State(app): State<App>,
    _: Acting,
    Path((id, agent)): Path<(i64, i64)>,
    Json(c): Json<CapacityBody>,
) -> ApiResult<TeamCapacity> {
    work::set_capacity(&app.pool, ProjectId(id), AgentId(agent), c.capacity, BY)
        .await
        .map_err(|e| refused(e, &format!("agent {agent} is not on project {id}'s team")))?;
    capacity(State(app), Acting::default(), Path(id)).await
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

#[utoipa::path(get, path = "/projects/{id}/flow", operation_id = "getProjectFlow",
    tag = "projects", params(("id" = i64, Path, description = "Project id"), Window),
    responses((status = 200, description = "Throughput and cycle and lead times of the issues \
        done in the window, from their state history", body = ProjectFlow)))]
pub async fn project_flow(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Query(w): Query<Window>,
) -> ApiResult<ProjectFlow> {
    let p = project(&app, id).await?;
    let until = w.until.unwrap_or_else(|| app.clock.now());
    let since = match w.since {
        Some(s) => s,
        None => {
            let window =
                // ponytail: server-wide until the Core settings store has company/project scopes
                crate::settings::value(&app.pool, "flow.window_secs").await?;
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

#[utoipa::path(get, path = "/issues/{id}/flow", operation_id = "getIssueFlow",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issue's cycle and lead time and age, from its \
        state history; absent where it has no such step", body = IssueFlow)))]
pub async fn issue_flow(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<IssueFlow> {
    let i = issue(&app, id).await?;
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

#[utoipa::path(post, path = "/sprints/{id}/commit", operation_id = "commitSprint",
    tag = "projects", params(("id" = i64, Path, description = "Sprint id")),
    request_body = SprintCommit,
    responses((status = 200, description = "The sprint, started by the owner (decision #10: the \
        owner the commit gate waits on; audited as `sprint.started`, gate `owner`). A pending \
        commit approval (decide it instead), unpointed issues, an active sprint, or points over \
        capacity without a reason is a 409", body = Sprint)))]
pub async fn commit_sprint(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(c): Json<SprintCommit>,
) -> ApiResult<Sprint> {
    let admin = UserId(ADMIN.0);
    let s = work::owner_commit_sprint(&app.pool, SprintId(id), admin, c.override_reason.as_deref())
        .await
        .map_err(sprint_refused)?;
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

#[utoipa::path(get, path = "/sprints/{id}/review", operation_id = "getSprintReview",
    tag = "projects", params(("id" = i64, Path, description = "Sprint id")),
    responses((status = 200, description = "The sprint's review and its retro proposals",
        body = SprintReview)))]
pub async fn sprint_review(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<SprintReview> {
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
