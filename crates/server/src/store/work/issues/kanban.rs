//! Kanban (E5.3): per-project WIP limits per column (an open state). Only top-level issues
//! count and are limited; subtasks go with their parent.
//!
//! The engine refuses an actor's transition into a full column (`transition_issue`,
//! `checkout_issue`). An unblock is exempt: it returns an issue to work when its blockers
//! close, and refusing it would refuse the blocker's close. When a top-level issue leaves a
//! full `in_progress` column (a transition, or its deletion), the agent of the oldest `todo`
//! issue it held back is woken in the same transaction. Limits apply to kanban projects
//! only; sprints apply to scrum projects only.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::exec::{NewWakeRequest, WakeSource};
use ainkrad_core::org::CompanyId;
use ainkrad_core::work::ProjectMode;
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit;
use crate::store::exec::enqueue_in;

/// The project's mode and company; `None` when there is no such project.
pub(super) async fn project_mode(
    conn: &mut SqliteConnection,
    project: ProjectId,
) -> Result<Option<(ProjectMode, CompanyId)>, Error> {
    let Some(row) = sqlx::query("SELECT mode, company_id FROM projects WHERE id = ?")
        .bind(project.0)
        .fetch_optional(&mut *conn)
        .await?
    else {
        return Ok(None);
    };
    Ok(Some((
        text(&row, "mode")?,
        CompanyId(row.try_get("company_id")?),
    )))
}

/// The limit of the project's `state` column when it is a kanban project and the column is
/// full; `None` when there is room or no limit.
pub(super) async fn wip_full(
    conn: &mut SqliteConnection,
    project: ProjectId,
    state: IssueState,
) -> Result<Option<u32>, Error> {
    sqlx::query_scalar(
        "SELECT w.max_issues FROM wip_limits w JOIN projects p ON p.id = w.project_id \
         WHERE w.project_id = ?1 AND w.state = ?2 AND p.mode = 'kanban' \
         AND w.max_issues <= (SELECT count(*) FROM issues WHERE project_id = ?1 \
             AND state = ?2 AND parent_id IS NULL)",
    )
    .bind(project.0)
    .bind(state.as_str())
    .fetch_optional(&mut *conn)
    .await
}

/// Wakes the next-actor agent of the oldest top-level `todo` issue of the kanban project,
/// keyed `key`, when its `in_progress` column has just dropped below its limit: it held its
/// limit of issues until one left, so that `todo` issue could not start. One wake per freed
/// slot; inside the caller's `BEGIN IMMEDIATE` transaction, after the issue left.
pub(super) async fn wake_freed_in(
    conn: &mut SqliteConnection,
    project: ProjectId,
    key: String,
) -> Result<(), Error> {
    let freed: Option<u32> = sqlx::query_scalar(
        "SELECT w.max_issues FROM wip_limits w JOIN projects p ON p.id = w.project_id \
         WHERE w.project_id = ?1 AND w.state = 'in_progress' AND p.mode = 'kanban' \
         AND w.max_issues - 1 = (SELECT count(*) FROM issues WHERE project_id = ?1 \
             AND state = 'in_progress' AND parent_id IS NULL)",
    )
    .bind(project.0)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(limit) = freed else {
        return Ok(());
    };
    let held: Option<(i64, i64)> = sqlx::query_as(
        "SELECT id, next_agent_id FROM issues WHERE project_id = ? AND state = 'todo' \
         AND parent_id IS NULL AND next_agent_id IS NOT NULL ORDER BY id LIMIT 1",
    )
    .bind(project.0)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((issue, agent)) = held else {
        return Ok(());
    };
    let wake = NewWakeRequest {
        agent_id: AgentId(agent),
        issue_id: Some(IssueId(issue)),
        source: WakeSource::Assignment,
        reason: format!("the in_progress column has room again (WIP limit {limit})"),
        idempotency_key: key,
        not_before: None,
    };
    enqueue_in(conn, &wake, 1).await.map(drop)
}

/// Sets (or with `None` removes) the most top-level issues the kanban project's `state`
/// column may hold, and appends `project.wip_limit_set` by `actor`. A missing project is
/// `Error::RowNotFound`; a scrum project, a terminal state or a zero limit is
/// `Error::InvalidArgument`. Issues already over a new limit stay; no more get in.
pub async fn set_wip_limit(
    pool: &SqlitePool,
    project: ProjectId,
    state: IssueState,
    limit: Option<u32>,
    actor: AuditActor,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let (mode, company) = project_mode(&mut tx, project)
        .await?
        .ok_or(Error::RowNotFound)?;
    if mode != ProjectMode::Kanban {
        return Err(Error::InvalidArgument(
            "WIP limits are for kanban projects".into(),
        ));
    }
    if state.is_terminal() || limit == Some(0) {
        let why = format!("no WIP limit of {limit:?} on {}", state.as_str());
        return Err(Error::InvalidArgument(why));
    }
    let query = match limit {
        Some(_) => {
            "INSERT INTO wip_limits (project_id, state, max_issues) VALUES (?1, ?2, ?3) \
             ON CONFLICT (project_id, state) DO UPDATE SET max_issues = excluded.max_issues"
        }
        None => "DELETE FROM wip_limits WHERE project_id = ?1 AND state = ?2",
    };
    sqlx::query(query)
        .bind(project.0)
        .bind(state.as_str())
        .bind(limit)
        .execute(&mut *tx)
        .await?;
    let event = NewAuditEvent {
        actor,
        action: "project.wip_limit_set".to_owned(),
        entity: Some(AuditEntity {
            kind: "project".to_owned(),
            id: project.0,
        }),
        company_id: Some(company),
        run_id: None,
        details: serde_json::json!({"state": state.as_str(), "limit": limit}).to_string(),
    };
    audit::append(&mut *tx, &event).await?;
    tx.commit().await
}

/// The project's WIP limits, by column.
pub async fn wip_limits(
    pool: &SqlitePool,
    project: ProjectId,
) -> Result<Vec<(IssueState, u32)>, Error> {
    sqlx::query("SELECT state, max_issues FROM wip_limits WHERE project_id = ? ORDER BY state")
        .bind(project.0)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| Ok((text(&row, "state")?, row.try_get("max_issues")?)))
        .collect()
}
