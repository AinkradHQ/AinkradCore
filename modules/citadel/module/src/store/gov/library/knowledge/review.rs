//! Proposals and their review (E8.2). An agent proposes an entry for its project (`propose`);
//! the project's team lead (an agent, never on its own proposal) or a human accepts or rejects
//! it (`decide_knowledge`), with a reason (required to reject). Accepted, it reaches every
//! later run (`project_knowledge`). A `state` proposal may target the project's spec: accepting
//! it replaces the spec with its body, in the same transaction. Every step is audited.
//!
//! A proposal that targets a profile field (`profile.<field>`, E15.13) is not ported: it
//! validates and applies through the project profile, which comes with the work slice (S4); it
//! is refused for now (`KnowledgeError::Invalid`).
//!
//! The Core's audit actor is a user or the system, never an agent: an agent's step is audited as
//! the system with `agent_id` in the details.

use std::fmt;

use super::*;

/// Why a proposal or decision was refused.
#[derive(Debug)]
pub enum KnowledgeError {
    NotFound,
    /// It was decided already.
    NotPending(KnowledgeStatus),
    /// Only the project's team lead, or a human, decides proposals.
    NotLead,
    /// A lead does not decide its own proposal.
    OwnProposal,
    /// A rejection needs a reason; a spec target needs a `state` entry.
    Invalid(String),
    Db(Error),
}

impl From<Error> for KnowledgeError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for KnowledgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such knowledge entry"),
            Self::NotPending(s) => write!(f, "the entry is {} already", s.as_str()),
            Self::NotLead => f.write_str(
                "only the project's team lead, or a human, accepts or rejects its proposals",
            ),
            Self::OwnProposal => f.write_str("a lead does not decide its own proposal"),
            Self::Invalid(why) => f.write_str(why),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for KnowledgeError {}

/// Who decides a proposal: a human, or an agent (which must be the project's team lead).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decider {
    User(UserId),
    Agent(AgentId),
}

/// A proposal before it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub project: ProjectId,
    pub kind: KnowledgeKind,
    pub title: String,
    pub body: String,
    /// The body is a new project spec (a `state` entry only).
    pub spec: bool,
    /// The body is a new value of this profile field (E15.13); not ported yet (S4).
    pub profile_field: Option<String>,
    /// Why, in one line (shown with the proposal); blank is none.
    pub rationale: Option<String>,
}

/// Stores `p` as `proposed` by `by` and appends `knowledge.proposed`, in one transaction. An
/// agent of another company is refused by the schema.
pub async fn propose(
    pool: &SqlitePool,
    p: &Proposal,
    by: AgentId,
) -> Result<KnowledgeEntry, KnowledgeError> {
    if p.spec && p.kind != KnowledgeKind::State {
        let why = "only a state entry targets the spec".to_owned();
        return Err(KnowledgeError::Invalid(why));
    }
    let target = match &p.profile_field {
        Some(_) if p.spec => {
            let why = "a proposal targets the spec or a profile field, not both".to_owned();
            return Err(KnowledgeError::Invalid(why));
        }
        Some(field) => {
            // Checked now so a proposal that could never apply is refused at once.
            let patch =
                crate::profile::field_patch(field, &p.body).map_err(KnowledgeError::Invalid)?;
            let mut check = crate::profile::Profile::default();
            patch.apply(&mut check);
            if let Some(why) = check.problem() {
                return Err(KnowledgeError::Invalid(why));
            }
            Some(format!("profile.{field}"))
        }
        None => p.spec.then(|| "spec".to_owned()),
    };
    let rationale = p
        .rationale
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty());
    if rationale.is_some_and(|r| r.contains('\n')) {
        let why = "a proposal's rationale is one line".to_owned();
        return Err(KnowledgeError::Invalid(why));
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let proposed = sqlx::query(concat!(
        "INSERT INTO citadel_knowledge_entries (project_id, kind, title, body, target, \
         proposed_by_agent_id, rationale) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING ",
        knowledge_columns!()
    ))
    .bind(p.project.0)
    .bind(p.kind.as_str())
    .bind(&p.title)
    .bind(&p.body)
    .bind(&target)
    .bind(by.0)
    .bind(rationale)
    .fetch_one(&mut *tx)
    .await
    .and_then(knowledge_entry)?;
    let details = json!({"kind": p.kind.as_str(), "title": p.title, "spec": p.spec,
                         "profile_field": p.profile_field, "rationale": rationale,
                         "agent_id": by.0});
    append_knowledge_event(
        &mut tx,
        p.project,
        proposed.id.0,
        AuditActor::System,
        "knowledge.proposed",
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(proposed)
}

/// Whether `agent` is the active team lead of the project's owning team.
pub async fn is_project_lead(
    pool: impl sqlx::SqliteExecutor<'_>,
    agent: AgentId,
    project: ProjectId,
) -> Result<bool, Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM citadel_projects p JOIN citadel_team_memberships m \
         ON m.team_id = p.team_id AND m.team_role = 'team_lead' \
         JOIN citadel_agents a ON a.id = m.agent_id \
         WHERE p.id = ? AND a.id = ? AND a.status = 'active')",
    )
    .bind(project.0)
    .bind(agent.0)
    .fetch_one(pool)
    .await
}

/// The project's pending proposals, oldest first.
pub async fn pending_knowledge(
    pool: impl sqlx::SqliteExecutor<'_>,
    project: ProjectId,
) -> Result<Vec<KnowledgeEntry>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        knowledge_columns!(),
        " FROM citadel_knowledge_entries WHERE project_id = ? AND status = 'proposed' ORDER BY id"
    ))
    .bind(project.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(knowledge_entry)
    .collect()
}

/// Accepts or rejects the pending entry `id` as `by` (a human, or an agent that must be the
/// project's team lead and not its proposer), with `reason` (required to reject), and appends
/// `knowledge.accepted` / `knowledge.rejected`, in one `BEGIN IMMEDIATE` transaction. An
/// accepted spec proposal replaces the project's spec with its body (`project.spec_set`).
pub async fn decide_knowledge(
    pool: &SqlitePool,
    id: KnowledgeEntryId,
    accept: bool,
    by: Decider,
    reason: Option<&str>,
) -> Result<KnowledgeEntry, KnowledgeError> {
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    if !accept && reason.is_none() {
        return Err(KnowledgeError::Invalid(
            "a rejection needs a reason".to_owned(),
        ));
    }
    let (user, agent) = match by {
        Decider::User(u) => (Some(u.0), None),
        Decider::Agent(a) => (None, Some(a)),
    };
    let (actor, by_agent) = match by {
        Decider::User(u) => (user_actor(u), None),
        Decider::Agent(a) => (AuditActor::System, Some(a.0)),
    };
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let current = sqlx::query(concat!(
        "SELECT ",
        knowledge_columns!(),
        " FROM citadel_knowledge_entries WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *tx)
    .await?
    .map(knowledge_entry)
    .transpose()?
    .ok_or(KnowledgeError::NotFound)?;
    if current.status != KnowledgeStatus::Proposed {
        return Err(KnowledgeError::NotPending(current.status));
    }
    if let Some(agent) = agent {
        if !is_project_lead(&mut *tx, agent, current.project_id).await? {
            return Err(KnowledgeError::NotLead);
        }
        if current.proposed_by == Some(agent) {
            return Err(KnowledgeError::OwnProposal);
        }
        if current.profile_field.is_some() {
            let why = "only a human accepts or rejects a profile change".to_owned();
            return Err(KnowledgeError::Invalid(why));
        }
    }
    let status = if accept { "accepted" } else { "rejected" };
    let decided = sqlx::query(concat!(
        "UPDATE citadel_knowledge_entries SET status = ?, decided_by_user_id = ?, \
         decided_by_agent_id = ?, reason = ? WHERE id = ? RETURNING ",
        knowledge_columns!()
    ))
    .bind(status)
    .bind(user)
    .bind(agent.map(|a| a.0))
    .bind(reason)
    .bind(id.0)
    .fetch_one(&mut *tx)
    .await
    .and_then(knowledge_entry)?;
    let project = decided.project_id;
    let details = json!({"kind": decided.kind.as_str(), "reason": reason,
                         "spec": decided.targets_spec, "profile_field": decided.profile_field,
                         "agent_id": by_agent});
    let action = format!("knowledge.{status}");
    append_knowledge_event(&mut tx, project, id.0, actor, &action, details).await?;
    if accept && let Some(field) = &decided.profile_field {
        let patch =
            crate::profile::field_patch(field, &decided.body).map_err(KnowledgeError::Invalid)?;
        let details = json!({"knowledge_entry": id.0, "agent_id": by_agent});
        match crate::store::work::update_profile_in(&mut tx, project, &patch, actor, details).await
        {
            Ok(_) => {}
            Err(Error::Protocol(why) | Error::InvalidArgument(why)) => {
                return Err(KnowledgeError::Invalid(why));
            }
            Err(e) => return Err(e.into()),
        }
    }
    if accept && decided.targets_spec {
        sqlx::query("UPDATE citadel_projects SET spec = ? WHERE id = ?")
            .bind(&decided.body)
            .bind(project.0)
            .execute(&mut *tx)
            .await?;
        let company: i64 =
            sqlx::query_scalar("SELECT company_id FROM citadel_projects WHERE id = ?")
                .bind(project.0)
                .fetch_one(&mut *tx)
                .await?;
        let event = Event::new(actor, "project.spec_set")
            .entity("project", project.0)
            .company(company)
            .details(json!({"bytes": decided.body.len(), "knowledge_entry": id.0,
                            "agent_id": by_agent}));
        append(&mut tx, event).await?;
    }
    tx.commit().await?;
    Ok(decided)
}
