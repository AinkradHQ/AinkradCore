//! Scope changes to an active sprint (the admin's only): the issue's points move the sprint's
//! committed points, so the report and burndown stay honest, and the audit log keeps what was
//! committed at start (`sprint.started`) apart from each change after it. Sprint names: no two
//! in a project alike. And deleting an empty planned sprint, again the admin's only.

use crate::domain::work::{Sprint, SprintState};
use ainkrad_core::audit::AuditActor;
use sqlx::SqliteConnection;

use super::sprints::{append_sprint_event, not_awaiting, sprint_in};
use super::*;

/// Only a user (the admin, through the CLI or `/api/v1`) changes an active sprint's scope;
/// agents never do.
pub(super) fn may_change(actor: AuditActor) -> bool {
    matches!(actor, AuditActor::User(_))
}

/// Adds the issue's points to the active sprint's committed points (or takes them off when it
/// leaves) and appends `sprint.scope_added` or `sprint.scope_removed` by `actor` with the
/// issue, its points and the committed points after.
pub(super) async fn changed(
    conn: &mut SqliteConnection,
    s: &Sprint,
    issue: &Issue,
    added: bool,
    actor: AuditActor,
) -> Result<(), Error> {
    let points = i64::from(issue.points.unwrap_or(0));
    let committed: i64 = sqlx::query_scalar(
        "UPDATE citadel_sprints SET committed_points = max(coalesce(committed_points, 0) + ?, 0) \
         WHERE id = ? RETURNING committed_points",
    )
    .bind(if added { points } else { -points })
    .bind(s.id.0)
    .fetch_one(&mut *conn)
    .await?;
    let action = if added {
        "sprint.scope_added"
    } else {
        "sprint.scope_removed"
    };
    let details = serde_json::json!({"issue": issue.id.0, "points": points,
                                     "committed": committed});
    append_sprint_event(conn, s, actor, action, details).await
}

/// `name`, or the next free number when the project already has a sprint called that: a
/// trailing number goes up ("WRK Sprint 1" to "WRK Sprint 2"), else one is added ("Alpha 2").
pub(super) async fn free_name(
    conn: &mut SqliteConnection,
    project: ProjectId,
    name: &str,
) -> Result<String, Error> {
    let taken: Vec<String> =
        sqlx::query_scalar("SELECT name FROM citadel_sprints WHERE project_id = ?")
            .bind(project.0)
            .fetch_all(&mut *conn)
            .await?;
    if !taken.iter().any(|t| t == name) {
        return Ok(name.to_owned());
    }
    let stem = name.trim_end_matches(|c: char| c.is_ascii_digit());
    let (stem, mut n) = match name[stem.len()..].parse::<u64>() {
        Ok(n) => (stem.to_owned(), n),
        Err(_) => (format!("{name} "), 1),
    };
    loop {
        n += 1;
        let next = format!("{stem}{n}");
        if !taken.contains(&next) {
            return Ok(next);
        }
    }
}

/// Deletes a planned sprint that holds no issues and whose commit is not waiting on an approval
/// (the admin's: no agent tool calls this), and appends `sprint.deleted` by `actor` with its
/// name, project, the decided approvals that lose it as their subject (`sprint_id` set to NULL)
/// and the budgets set on it, which go with it.
pub async fn delete_empty_sprint(
    pool: &SqlitePool,
    sprint: SprintId,
    actor: AuditActor,
) -> Result<Sprint, SprintError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let s = sprint_in(&mut tx, sprint).await?;
    if s.state != SprintState::Planned {
        return Err(SprintError::State(s.state));
    }
    not_awaiting(&mut tx, sprint).await?;
    let issues: i64 = sqlx::query_scalar("SELECT count(*) FROM citadel_issues WHERE sprint_id = ?")
        .bind(sprint.0)
        .fetch_one(&mut *tx)
        .await?;
    if issues > 0 {
        return Err(SprintError::NotEmpty(issues));
    }
    let approvals: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM citadel_approvals WHERE sprint_id = ? ORDER BY id")
            .bind(sprint.0)
            .fetch_all(&mut *tx)
            .await?;
    let budgets: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM citadel_budgets WHERE sprint_id = ? ORDER BY id")
            .bind(sprint.0)
            .fetch_all(&mut *tx)
            .await?;
    let details = serde_json::json!({"name": s.name, "project": s.project_id.0,
                                     "approvals": approvals, "budgets": budgets});
    append_sprint_event(&mut tx, &s, actor, "sprint.deleted", details).await?;
    sqlx::query("DELETE FROM citadel_sprints WHERE id = ?")
        .bind(sprint.0)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(s)
}
