//! Admin paths the dogfood needed before its first sprint (API minor 11): a project's permission
//! policy (E3.10), publishing a company's skills (E4.3) and retiring or superseding accepted
//! knowledge (E8); since minor 16, listing a project's knowledge and a human's accepting or
//! rejecting a proposal, as `citadel-server knowledge` does. Each write goes through the store's
//! rules as the admin and is audited (`project.policy_set`, `skill.published`,
//! `knowledge.retired`, `knowledge.added`, `knowledge.accepted`, `knowledge.rejected`).

use citadel_core::gov::{KnowledgeEntry, KnowledgeEntryId, SkillAttach};
use citadel_core::org::{CompanyId, DepartmentId};
use citadel_core::work::ProjectId;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::reads::{AgentSkill, skill_out};
use super::types::{KnowledgeKind, KnowledgeStatus, PermissionMode, Timestamp, ts};
use super::{ADMIN, ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::{gov, work};

/// The routes that came with API minor 11.
pub(super) fn routes() -> Router<App> {
    Router::new()
        .route(
            "/api/v1/projects/{id}/policy",
            get(get_policy).put(set_policy),
        )
        .route(
            "/api/v1/companies/{id}/skills",
            get(list_skills).post(publish_skill),
        )
        .route("/api/v1/projects/{id}/knowledge", get(list_knowledge))
        .route("/api/v1/knowledge/{id}/accept", post(accept))
        .route("/api/v1/knowledge/{id}/reject", post(reject))
        .route("/api/v1/knowledge/{id}/retire", post(retire))
        .route("/api/v1/knowledge/{id}/supersede", post(supersede))
}

fn bad(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
        e => e.into(),
    }
}

impl From<gov::KnowledgeError> for ApiError {
    fn from(e: gov::KnowledgeError) -> Self {
        match e {
            gov::KnowledgeError::NotFound => Self::not_found(e.to_string()),
            gov::KnowledgeError::Invalid(why) => Self::bad_request(why),
            gov::KnowledgeError::Db(e) => e.into(),
            e => Self::conflict(e.to_string()),
        }
    }
}

/// A project's harness permission policy (E3.10).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ProjectPolicy {
    /// `ask`: everything outside the allowlist asks; `accept_edits`: file edits inside the
    /// run's worktree go ahead too; `sandboxed`: the harness acts without asking, only on a
    /// sandboxed runner.
    pub mode: PermissionMode,
    /// What goes ahead without asking: a tool name (`Edit`), or `<tool>:<command prefix>`
    /// (`Bash:npm run`), which never matches a command with shell operators. A path outside
    /// the worktree always asks.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Runs need a sandboxed runner; implied by the `sandboxed` mode.
    #[serde(default)]
    pub sandboxed: bool,
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/policy", operation_id = "getProjectPolicy",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "The project's permission policy", body = ProjectPolicy)))]
pub async fn get_policy(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<ProjectPolicy> {
    let p = work::project_policy(&app.pool, ProjectId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no project {id}")))?;
    Ok(Json(ProjectPolicy {
        mode: p.mode.into(),
        allow: p.allow,
        sandboxed: p.sandboxed,
    }))
}

#[utoipa::path(put, path = "/api/v1/projects/{id}/policy", operation_id = "setProjectPolicy",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    request_body = ProjectPolicy,
    responses((status = 200, description = "The policy, replaced whole (audited as \
        `project.policy_set`); a blank allowlist entry is a 400", body = ProjectPolicy)))]
pub async fn set_policy(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(p): Json<ProjectPolicy>,
) -> ApiResult<ProjectPolicy> {
    let mode = ainkrad_proto::runner::PermissionMode::from(p.mode);
    let policy = ainkrad_proto::runner::Policy {
        sandboxed: p.sandboxed || mode == ainkrad_proto::runner::PermissionMode::Sandboxed,
        allow: p.allow.iter().map(|a| a.trim().to_owned()).collect(),
        mode,
    };
    if !work::set_project_policy(&app.pool, ProjectId(id), &policy, BY)
        .await
        .map_err(bad)?
    {
        return Err(ApiError::not_found(format!("no project {id}")));
    }
    get_policy(State(app), Path(id)).await
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/skills", operation_id = "listSkills",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "Every version of the company's skills, by name then \
        version; the latest of a name is the one runs are given", body = Vec<AgentSkill>)))]
pub async fn list_skills(
    State(app): State<App>,
    Path(id): Path<i64>,
) -> ApiResult<Vec<AgentSkill>> {
    super::org::company(&app, id).await?;
    let skills = gov::list_skills(&app.pool, CompanyId(id)).await?;
    Ok(Json(skills.into_iter().map(skill_out).collect()))
}

/// A new version of a skill.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewSkillVersion {
    pub name: String,
    /// Markdown; at most the company's `skills.max_bytes`.
    pub body: String,
    /// `company`, `department`, `role` or `project`.
    pub attach_to: String,
    /// The department or project id.
    pub attach_id: Option<i64>,
    /// The role (matched exactly against an agent's role).
    pub attach_role: Option<String>,
}

#[utoipa::path(post, path = "/api/v1/companies/{id}/skills", operation_id = "publishSkill",
    tag = "org", params(("id" = i64, Path, description = "Company id")),
    request_body = NewSkillVersion,
    responses((status = 200, description = "The new version (1 for a new name); an old version \
        is never edited (audited as `skill.published`). A blank name or body, a body over \
        `skills.max_bytes`, or a department or project not of the company is a 400",
        body = AgentSkill)))]
pub async fn publish_skill(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(s): Json<NewSkillVersion>,
) -> ApiResult<AgentSkill> {
    super::org::company(&app, id).await?;
    let attach = match (s.attach_to.as_str(), s.attach_id, s.attach_role) {
        ("company", None, None) => SkillAttach::Company,
        ("role", None, Some(role)) => SkillAttach::Role(role),
        ("department", Some(d), None) => SkillAttach::Department(DepartmentId(d)),
        ("project", Some(p), None) => SkillAttach::Project(ProjectId(p)),
        _ => {
            return Err(ApiError::bad_request(
                "attach_to is company, role (with attach_role), or department or project (with \
                 attach_id)",
            ));
        }
    };
    let name = s.name.trim();
    gov::publish_skill(&app.pool, CompanyId(id), name, &s.body, &attach, BY)
        .await
        .map(|s| Json(skill_out(s)))
        .map_err(bad)
}

/// Most bytes of an entry's body in a list (`body_truncated` when cut).
const LIST_BODY_BYTES: usize = 16 * 1024;

/// A project knowledge entry (E8).
#[derive(Debug, Serialize, ToSchema)]
pub struct Knowledge {
    pub id: i64,
    pub project_id: i64,
    pub kind: KnowledgeKind,
    pub title: String,
    pub body: String,
    /// `retired`: kept for history, never given to a run.
    pub status: KnowledgeStatus,
    pub retired_reason: Option<String>,
    /// The entry this one replaced.
    pub supersedes: Option<i64>,
    /// The entry that replaced this one.
    pub superseded_by: Option<i64>,
    /// Why it was accepted or rejected.
    pub reason: Option<String>,
    /// The proposer's one-line reason for it.
    pub rationale: Option<String>,
    /// What accepting a proposal applies its body to: `spec` or `profile.<field>`.
    pub target: Option<String>,
    /// The agent that proposed it; absent for an entry the admin added.
    pub proposed_by_agent_id: Option<i64>,
    pub created_at: Timestamp,
    /// Its last audited change (`created_at` when none).
    pub updated_at: Timestamp,
    /// The body was cut to 16 KiB in a list.
    pub body_truncated: bool,
}

/// Every entry of `project`, oldest first, bodies whole.
// ponytail: one entry's answer reads its whole project; fine at tens of entries per project.
async fn entries(app: &App, project: ProjectId) -> Result<Vec<Knowledge>, ApiError> {
    let all = gov::list_knowledge_entries(&app.pool, project).await?;
    let times: Vec<(i64, String, Option<String>)> = sqlx::query_as(
        "SELECT k.id, k.created_at, (SELECT max(a.at) FROM audit_events a \
         WHERE a.entity_kind = 'knowledge_entry' AND a.entity_id = k.id) \
         FROM knowledge_entries k WHERE k.project_id = ?",
    )
    .bind(project.0)
    .fetch_all(&app.pool)
    .await?;
    let by = |id: i64| all.iter().find(|n| n.supersedes.map(|s| s.0) == Some(id));
    let superseded_by: Vec<Option<i64>> = all.iter().map(|k| by(k.id.0).map(|n| n.id.0)).collect();
    Ok(all
        .into_iter()
        .zip(superseded_by)
        .map(|(k, superseded_by)| {
            let (created, updated) = times
                .iter()
                .find(|t| t.0 == k.id.0)
                .map(|t| (t.1.as_str(), t.2.as_deref().unwrap_or(&t.1)))
                .unwrap_or_default();
            Knowledge {
                id: k.id.0,
                project_id: k.project_id.0,
                kind: k.kind.into(),
                title: k.title,
                body: k.body,
                status: k.status.into(),
                retired_reason: k.retired_reason,
                supersedes: k.supersedes.map(|s| s.0),
                superseded_by,
                reason: k.reason,
                rationale: k.rationale,
                target: match k.profile_field {
                    Some(field) => Some(format!("profile.{field}")),
                    None => k.targets_spec.then(|| "spec".to_owned()),
                },
                proposed_by_agent_id: k.proposed_by.map(|a| a.0),
                created_at: ts(created),
                updated_at: ts(updated),
                body_truncated: false,
            }
        })
        .collect())
}

/// `k` as the API shows it, body whole.
async fn knowledge(app: &App, k: KnowledgeEntry) -> ApiResult<Knowledge> {
    entries(app, k.project_id)
        .await?
        .into_iter()
        .find(|e| e.id == k.id.0)
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("no knowledge entry {}", k.id.0)))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/knowledge", operation_id = "listKnowledge",
    tag = "projects", params(("id" = i64, Path, description = "Project id")),
    responses((status = 200, description = "Every entry of the project, oldest first, whatever \
        its status; a body over 16 KiB is cut (`body_truncated`)", body = Vec<Knowledge>)))]
pub async fn list_knowledge(
    State(app): State<App>,
    Path(id): Path<i64>,
) -> ApiResult<Vec<Knowledge>> {
    work::get_project(&app.pool, ProjectId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no project {id}")))?;
    let mut all = entries(&app, ProjectId(id)).await?;
    for k in &mut all {
        if k.body.len() > LIST_BODY_BYTES {
            let cut = (0..=LIST_BODY_BYTES)
                .rev()
                .find(|&i| k.body.is_char_boundary(i))
                .unwrap_or(0);
            k.body.truncate(cut);
            k.body_truncated = true;
        }
    }
    Ok(Json(all))
}

/// A human's decision on a proposal.
#[derive(Debug, Deserialize, ToSchema)]
pub struct KnowledgeDecision {
    /// Why; required to reject.
    pub reason: Option<String>,
}

async fn decide(app: App, id: i64, accept: bool, reason: Option<&str>) -> ApiResult<Knowledge> {
    let k = gov::decide_knowledge(&app.pool, KnowledgeEntryId(id), accept, BY, reason).await?;
    knowledge(&app, k).await
}

#[utoipa::path(post, path = "/api/v1/knowledge/{id}/accept", operation_id = "acceptKnowledge",
    tag = "projects", params(("id" = i64, Path, description = "Knowledge entry id")),
    request_body = KnowledgeDecision,
    responses((status = 200, description = "The proposal, accepted: later runs are given it; a \
        spec or profile proposal applies its body (audited as `knowledge.accepted`). An entry \
        not proposed is a 409", body = Knowledge)))]
pub async fn accept(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(d): Json<KnowledgeDecision>,
) -> ApiResult<Knowledge> {
    decide(app, id, true, d.reason.as_deref()).await
}

#[utoipa::path(post, path = "/api/v1/knowledge/{id}/reject", operation_id = "rejectKnowledge",
    tag = "projects", params(("id" = i64, Path, description = "Knowledge entry id")),
    request_body = KnowledgeDecision,
    responses((status = 200, description = "The proposal, rejected (audited as \
        `knowledge.rejected`). A blank reason is a 400; an entry not proposed is a 409",
        body = Knowledge)))]
pub async fn reject(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(d): Json<KnowledgeDecision>,
) -> ApiResult<Knowledge> {
    decide(app, id, false, d.reason.as_deref()).await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct Retirement {
    pub reason: String,
}

#[utoipa::path(post, path = "/api/v1/knowledge/{id}/retire", operation_id = "retireKnowledge",
    tag = "projects", params(("id" = i64, Path, description = "Knowledge entry id")),
    request_body = Retirement,
    responses((status = 200, description = "The entry, retired: kept, no longer given to runs \
        (audited as `knowledge.retired`). A blank reason is a 400; an entry not accepted is a \
        409", body = Knowledge)))]
pub async fn retire(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(r): Json<Retirement>,
) -> ApiResult<Knowledge> {
    let k = gov::retire_knowledge(&app.pool, KnowledgeEntryId(id), &r.reason, ADMIN).await?;
    knowledge(&app, k).await
}

/// A new version of an accepted entry.
#[derive(Debug, Deserialize, ToSchema)]
pub struct Supersession {
    pub body: String,
    /// The old entry's when absent.
    pub title: Option<String>,
    pub kind: Option<KnowledgeKind>,
    /// Why the old one goes; "superseded by #<new>" when absent.
    pub reason: Option<String>,
}

#[utoipa::path(post, path = "/api/v1/knowledge/{id}/supersede",
    operation_id = "supersedeKnowledge", tag = "projects",
    params(("id" = i64, Path, description = "The accepted entry it replaces")),
    request_body = Supersession,
    responses((status = 200, description = "The new entry, accepted, its `supersedes` naming the \
        old one, which is retired (audited as `knowledge.added` and `knowledge.retired`). An \
        entry not accepted is a 409", body = Knowledge)))]
pub async fn supersede(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(s): Json<Supersession>,
) -> ApiResult<Knowledge> {
    let k = gov::supersede_knowledge(
        &app.pool,
        KnowledgeEntryId(id),
        s.kind.map(Into::into),
        s.title.as_deref(),
        &s.body,
        s.reason.as_deref(),
        ADMIN,
    )
    .await?;
    knowledge(&app, k).await
}
