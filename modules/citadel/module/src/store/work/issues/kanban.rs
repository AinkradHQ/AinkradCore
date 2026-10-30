//! Kanban (E5.3): per-project WIP limits per column (an open state). Only top-level issues
//! count and are limited; subtasks go with their parent.
//!
//! The engine refuses an actor's transition into a full column (`transition_issue`,
//! `checkout_issue`). An unblock is exempt: it returns an issue to work when its blockers
//! close, and refusing it would refuse the blocker's close. When a top-level issue leaves a
//! full `in_progress` column (a transition, or its deletion), the agent of the oldest `todo`
//! issue it held back is woken in the same transaction. Limits apply to kanban projects
//! only; sprints apply to scrum projects only.

use crate::domain::org::CompanyId;
use crate::domain::work::ProjectMode;
use ainkrad_core::audit::AuditActor;
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit::{self, Event};

/// The project's mode and company; `None` when there is no such project.
pub(super) async fn project_mode(
    conn: &mut SqliteConnection,
    project: ProjectId,
) -> Result<Option<(ProjectMode, CompanyId)>, Error> {
    let Some(row) = sqlx::query("SELECT mode, company_id FROM citadel_projects WHERE id = ?")
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
        "SELECT w.max_issues FROM citadel_wip_limits w JOIN citadel_projects p ON p.id = w.project_id \
         WHERE w.project_id = ?1 AND w.state = ?2 AND p.mode = 'kanban' \
         AND w.max_issues <= (SELECT count(*) FROM citadel_issues WHERE project_id = ?1 \
             AND state = ?2 AND parent_id IS NULL)",
    )
    .bind(project.0)
    .bind(state.as_str())
    .fetch_optional(&mut *conn)
    .await
}

// S7: `wake_freed_in` (wake the next `todo` issue's agent when a full `in_progress` column frees a
// slot) enqueues on the run engine's wake queue; it comes with that slice.

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
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
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
            "INSERT INTO citadel_wip_limits (project_id, state, max_issues) VALUES (?1, ?2, ?3) \
             ON CONFLICT (project_id, state) DO UPDATE SET max_issues = excluded.max_issues"
        }
        None => "DELETE FROM citadel_wip_limits WHERE project_id = ?1 AND state = ?2",
    };
    sqlx::query(query)
        .bind(project.0)
        .bind(state.as_str())
        .bind(limit)
        .execute(&mut *tx)
        .await?;
    let event = Event::new(actor, "project.wip_limit_set")
        .entity("project", project.0)
        .company(company.0)
        .details(serde_json::json!({"state": state.as_str(), "limit": limit}));
    audit::append(&mut tx, event).await?;
    tx.commit().await
}

/// The project's WIP limits, by column.
pub async fn wip_limits(
    pool: &SqlitePool,
    project: ProjectId,
) -> Result<Vec<(IssueState, u32)>, Error> {
    sqlx::query(
        "SELECT state, max_issues FROM citadel_wip_limits WHERE project_id = ? ORDER BY state",
    )
    .bind(project.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| Ok((text(&row, "state")?, row.try_get("max_issues")?)))
    .collect()
}
