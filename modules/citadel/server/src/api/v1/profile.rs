//! A project's profile (E15.13): read it with what a run is given of it and the agents'
//! pending proposals to change it, and change it a field at a time, as the admin (audited).

use citadel_core::audit::AuditActor;
use citadel_core::gov::KnowledgeEntryId;
use citadel_core::work::ProjectId;
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::events::EventActor;
use super::types::{PermissionMode, SprintApproval, Timestamp, opt_ts, ts};
use super::{ApiError, ApiResult, BY, Paging};
use crate::api::App;
use crate::profile::{Profile, ProfilePatch};
use crate::store::{gov, work};

/// An agent's pending proposal of a new value for one field.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileProposal {
    /// The knowledge entry; decided with `decideProfileProposal` (a person only, #48).
    pub id: i64,
    pub field: String,
    pub title: String,
    /// The new value: JSON, or plain text for a text field.
    pub body: String,
    pub proposed_by: Option<i64>,
    /// Why the agent proposes it, in one line, when it said.
    pub rationale: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectProfile {
    pub project_id: i64,
    pub profile: Profile,
    pub sprint_approval: SprintApproval,
    pub permission_mode: PermissionMode,
    /// Bytes of the profile a run is given in its instructions, of `budget_bytes` (the
    /// `profile.budget_bytes` setting).
    pub injected_bytes: u64,
    pub budget_bytes: u64,
    /// Sections the budget leaves out of a run's instructions (named there).
    pub dropped: Vec<String>,
    pub proposals: Vec<ProfileProposal>,
    /// Absent while the profile was never changed.
    pub updated_at: Option<Timestamp>,
}

async fn view(app: &App, id: i64) -> Result<ProjectProfile, ApiError> {
    let project = ProjectId(id);
    let p = work::project_profile(&app.pool, project)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no project {id}")))?;
    let (fitted, budget) = work::run_profile(&app.pool, project).await?;
    let proposals = gov::pending_knowledge(&app.pool, project).await?;
    Ok(ProjectProfile {
        project_id: id,
        injected_bytes: fitted.text.as_ref().map_or(0, |t| t.len() as u64),
        budget_bytes: budget,
        dropped: fitted.dropped.iter().map(|d| (*d).to_owned()).collect(),
        proposals: proposals
            .into_iter()
            .filter_map(|k| {
                Some(ProfileProposal {
                    field: k.profile_field?,
                    id: k.id.0,
                    title: k.title,
                    body: k.body,
                    proposed_by: k.proposed_by.map(|a| a.0),
                    rationale: k.rationale,
                })
            })
            .collect(),
        sprint_approval: p.sprint_approval.into(),
        permission_mode: p.permission_mode.into(),
        updated_at: opt_ts(p.updated_at.as_deref()),
        profile: p.profile,
    })
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/profile", operation_id = "getProjectProfile",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project's profile, what a run is given of it, \
        and the agents' pending proposals to change it", body = ProjectProfile)))]
pub async fn get(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<ProjectProfile> {
    view(&app, id).await.map(Json)
}

#[utoipa::path(put, path = "/api/v1/projects/{id}/profile", operation_id = "updateProjectProfile",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    request_body = ProfilePatch,
    responses((status = 200, description = "The profile after the change: only the fields given \
        change; a value it cannot hold is a 400", body = ProjectProfile)))]
pub async fn update(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(patch): Json<ProfilePatch>,
) -> ApiResult<ProjectProfile> {
    work::update_profile(&app.pool, ProjectId(id), &patch, BY)
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
            e => e.into(),
        })?
        .ok_or_else(|| ApiError::not_found(format!("no project {id}")))?;
    view(&app, id).await.map(Json)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ProposalDecision {
    pub accept: bool,
    /// Why; required to reject.
    pub reason: Option<String>,
}

#[utoipa::path(post, path = "/api/v1/projects/{id}/profile/proposals/{proposal_id}/decision",
    operation_id = "decideProfileProposal", tag = "projects",
    params(("id" = i64, Path, description = "Project id"),
        ("proposal_id" = i64, Path, description = "The proposal (its knowledge entry)")),
    request_body = ProposalDecision,
    responses((status = 200, description = "The profile after the decision: accepted, the field \
        has the proposed value (`project.profile_set`); either way the proposal is gone from \
        `proposals` (audited as `knowledge.accepted|rejected`). Decided already is a 409",
        body = ProjectProfile)))]
pub async fn decide(
    State(app): State<App>,
    Path((id, proposal)): Path<(i64, i64)>,
    Json(d): Json<ProposalDecision>,
) -> ApiResult<ProjectProfile> {
    let entry = KnowledgeEntryId(proposal);
    let theirs: Option<(i64, Option<String>)> =
        sqlx::query_as("SELECT project_id, target FROM knowledge_entries WHERE id = ?")
            .bind(entry.0)
            .fetch_optional(&app.pool)
            .await?;
    let is_profile = |t: &Option<String>| t.as_deref().is_some_and(|t| t.starts_with("profile."));
    if !theirs.is_some_and(|(p, t)| p == id && is_profile(&t)) {
        let why = format!("no profile proposal {proposal} on project {id}");
        return Err(ApiError::not_found(why));
    }
    // A person decides (#48): the device acts as the admin user.
    gov::decide_knowledge(&app.pool, entry, d.accept, BY, d.reason.as_deref())
        .await
        .map_err(|e| match e {
            gov::KnowledgeError::NotFound => ApiError::not_found(e.to_string()),
            gov::KnowledgeError::Invalid(why) => ApiError::bad_request(why),
            gov::KnowledgeError::Db(e) => e.into(),
            e => ApiError::conflict(e.to_string()),
        })?;
    view(&app, id).await.map(Json)
}

/// One step of a profile's history.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileChange {
    /// Its audit sequence number: the cursor of the next page.
    pub seq: i64,
    pub at: Timestamp,
    pub actor: EventActor,
    /// `project.profile_set` (a change), or `knowledge.proposed`, `knowledge.accepted` or
    /// `knowledge.rejected` (an agent's proposal of one).
    pub action: String,
    /// A change: `fields` changed and their new `values` (absent on changes made before values
    /// were recorded), `knowledge_entry` when a proposal made it. A proposal step: its
    /// `profile_field`, `title`, `rationale` or decision `reason`.
    #[schema(value_type = Object)]
    pub details: serde_json::Value,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/profile/history",
    operation_id = "getProfileHistory", tag = "projects",
    params(("id" = i64, Path, description = "Project id"), Paging),
    responses((status = 200, description = "The profile's changes and the agents' proposals of \
        them, newest first; `after` is the `seq` to continue below, `limit` at most 200",
        body = Vec<ProfileChange>)))]
pub async fn history(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(page): Query<Paging>,
) -> ApiResult<Vec<ProfileChange>> {
    let project = ProjectId(id);
    if work::get_project(&app.pool, project).await?.is_none() {
        return Err(ApiError::not_found(format!("no project {id}")));
    }
    let limit = page.limit.unwrap_or(50).min(200);
    let steps = work::profile_history(&app.pool, project, page.after, limit).await?;
    Ok(Json(
        steps
            .into_iter()
            .map(|s| ProfileChange {
                seq: s.seq,
                at: ts(&s.at),
                actor: match s.actor {
                    AuditActor::User(u) => EventActor::User { user_id: u.0 },
                    AuditActor::Agent(a) => EventActor::Agent { agent_id: a.0 },
                    AuditActor::Runner(r) => EventActor::Runner { runner_id: r.0 },
                    AuditActor::System => EventActor::System {},
                },
                action: s.action,
                details: s.details,
            })
            .collect(),
    ))
}
