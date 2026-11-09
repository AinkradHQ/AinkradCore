//! Project knowledge (E8.1): entries a human writes, and what a run is given of them. Agents'
//! proposals and their review (E8.2) are in `review`.
//!
//! A run is given its project's accepted entries, landmines first, then decisions, state and
//! retro notes, newest first within a kind, fitted to the `knowledge.budget_bytes` setting;
//! what does not fit is listed (`RunKnowledge::dropped`), never left out silently. The same set
//! goes into the run's instructions at dispatch and comes back from `get_context`.

use ainkrad_core::audit::AuditActor;
use serde_json::json;

use super::*;
use crate::domain::gov::{KnowledgeKind, KnowledgeStatus, RunKnowledge, fit_knowledge};
use crate::store::audit::{Event, append};
use crate::store::gov::user_actor;

/// Stores an entry a human wrote: accepted at once, decided by `by`, and audited as
/// `knowledge.added` in the same transaction.
pub async fn add_knowledge(
    pool: &SqlitePool,
    project: ProjectId,
    kind: KnowledgeKind,
    title: &str,
    body: &str,
    by: UserId,
) -> Result<KnowledgeEntry, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let added = add_in(&mut tx, project, kind, title, body, by, None).await?;
    tx.commit().await?;
    Ok(added)
}

async fn add_in(
    conn: &mut sqlx::SqliteConnection,
    project: ProjectId,
    kind: KnowledgeKind,
    title: &str,
    body: &str,
    by: UserId,
    supersedes: Option<KnowledgeEntryId>,
) -> Result<KnowledgeEntry, Error> {
    let added = sqlx::query(concat!(
        "INSERT INTO citadel_knowledge_entries (project_id, kind, title, body, status, \
         decided_by_user_id, supersedes_id) VALUES (?, ?, ?, ?, 'accepted', ?, ?) RETURNING ",
        knowledge_columns!()
    ))
    .bind(project.0)
    .bind(kind.as_str())
    .bind(title)
    .bind(body)
    .bind(by.0)
    .bind(supersedes.map(|s| s.0))
    .fetch_one(&mut *conn)
    .await
    .and_then(knowledge_entry)?;
    let mut details = json!({"project": project.0, "kind": kind.as_str(), "title": title});
    if let Some(old) = supersedes {
        details["supersedes"] = json!(old.0);
    }
    append_knowledge_event(
        conn,
        project,
        added.id.0,
        user_actor(by),
        "knowledge.added",
        details,
    )
    .await?;
    Ok(added)
}

/// Retires an accepted entry (one a run is given) as the admin `by`, with a reason: kept for
/// history, never given to a run again. Audited as `knowledge.retired`.
pub async fn retire_knowledge(
    pool: &SqlitePool,
    entry: KnowledgeEntryId,
    reason: &str,
    by: UserId,
) -> Result<KnowledgeEntry, KnowledgeError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let retired = retire_in(&mut tx, entry, reason, by, None).await?;
    tx.commit().await?;
    Ok(retired)
}

async fn retire_in(
    conn: &mut sqlx::SqliteConnection,
    entry: KnowledgeEntryId,
    reason: &str,
    by: UserId,
    superseded_by: Option<KnowledgeEntryId>,
) -> Result<KnowledgeEntry, KnowledgeError> {
    if reason.trim().is_empty() {
        return Err(KnowledgeError::Invalid(
            "retiring an entry needs a reason".to_owned(),
        ));
    }
    let current = sqlx::query(concat!(
        "SELECT ",
        knowledge_columns!(),
        " FROM citadel_knowledge_entries WHERE id = ?"
    ))
    .bind(entry.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(knowledge_entry)
    .transpose()?
    .ok_or(KnowledgeError::NotFound)?;
    if current.targets_spec || current.profile_field.is_some() {
        let why = "a spec or profile proposal was applied, not given to runs: nothing to retire";
        return Err(KnowledgeError::Invalid(why.to_owned()));
    }
    if current.status != KnowledgeStatus::Accepted {
        return Err(KnowledgeError::NotPending(current.status));
    }
    let retired = sqlx::query(concat!(
        "UPDATE citadel_knowledge_entries SET status = 'retired', retired_reason = ? \
         WHERE id = ? RETURNING ",
        knowledge_columns!()
    ))
    .bind(reason)
    .bind(entry.0)
    .fetch_one(&mut *conn)
    .await
    .and_then(knowledge_entry)?;
    let mut details = json!({"project": current.project_id.0, "reason": reason});
    if let Some(new) = superseded_by {
        details["superseded_by"] = json!(new.0);
    }
    let project = current.project_id;
    let actor = user_actor(by);
    append_knowledge_event(conn, project, entry.0, actor, "knowledge.retired", details).await?;
    Ok(retired)
}

/// A new version of an accepted entry: `body` (and `title`, `kind` when given, else the old
/// one's) stored accepted with `supersedes` naming the old entry, which is retired with
/// `reason` (default "superseded by #<new>"), in one transaction as the admin `by`. Audited as
/// `knowledge.added` (with `supersedes`) and `knowledge.retired` (with `superseded_by`).
pub async fn supersede_knowledge(
    pool: &SqlitePool,
    old: KnowledgeEntryId,
    kind: Option<KnowledgeKind>,
    title: Option<&str>,
    body: &str,
    reason: Option<&str>,
    by: UserId,
) -> Result<KnowledgeEntry, KnowledgeError> {
    if body.trim().is_empty() || title.is_some_and(|t| t.trim().is_empty()) {
        let why = "a new version needs a body (and a title, when one is given)";
        return Err(KnowledgeError::Invalid(why.to_owned()));
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let prior = sqlx::query(concat!(
        "SELECT ",
        knowledge_columns!(),
        " FROM citadel_knowledge_entries WHERE id = ?"
    ))
    .bind(old.0)
    .fetch_optional(&mut *tx)
    .await?
    .map(knowledge_entry)
    .transpose()?
    .ok_or(KnowledgeError::NotFound)?;
    if prior.status != KnowledgeStatus::Accepted {
        return Err(KnowledgeError::NotPending(prior.status));
    }
    let kind = kind.unwrap_or(prior.kind);
    let title = title.unwrap_or(&prior.title);
    let new = add_in(&mut tx, prior.project_id, kind, title, body, by, Some(old)).await?;
    let why = reason
        .filter(|r| !r.trim().is_empty())
        .map_or_else(|| format!("superseded by #{}", new.id.0), str::to_owned);
    retire_in(&mut tx, old, &why, by, Some(new.id)).await?;
    tx.commit().await?;
    Ok(new)
}

/// The project's accepted entries a run is given, fitted to its `knowledge.budget_bytes`. An
/// accepted spec proposal is not one: it became the spec.
pub async fn project_knowledge(
    pool: &SqlitePool,
    project: ProjectId,
) -> Result<RunKnowledge, Error> {
    let accepted = sqlx::query(concat!(
        "SELECT ",
        knowledge_columns!(),
        " FROM citadel_knowledge_entries WHERE project_id = ? AND status = 'accepted' \
         AND target IS NULL"
    ))
    .bind(project.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(knowledge_entry)
    .collect::<Result<Vec<_>, _>>()?;
    // ponytail: server-wide until the Core settings store has project scopes.
    let budget = crate::settings::value(pool, "knowledge.budget_bytes").await?;
    Ok(fit_knowledge(accepted, budget as usize))
}

/// Appends `action` about entry `id` of `project`'s company, by `actor`.
async fn append_knowledge_event(
    conn: &mut sqlx::SqliteConnection,
    project: ProjectId,
    id: i64,
    actor: AuditActor,
    action: &str,
    details: serde_json::Value,
) -> Result<(), Error> {
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM citadel_projects WHERE id = ?")
        .bind(project.0)
        .fetch_one(&mut *conn)
        .await?;
    let event = Event::new(actor, action)
        .entity("knowledge_entry", id)
        .company(company)
        .details(details);
    append(conn, event).await
}

mod review;
pub use review::*;
