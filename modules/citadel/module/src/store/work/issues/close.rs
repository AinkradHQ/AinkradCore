//! Closing a sprint and team member capacity (E5.2), split from `sprints`.

use crate::domain::org::TeamId;
use crate::domain::work::{Sprint, SprintState};
use ainkrad_core::audit::AuditActor;

use super::checkout::issue_in;
use super::sprints::{append_sprint_event, set_sprint_in, sprint_in};
use super::*;

/// Closes the active sprint, freezing its completed points (its done issues') and storing its
/// review (`review::review_in`, E5.5), and appends `sprint.closed` by `actor`. Its open
/// issues move to the planned sprint `carry_to` of the same project, or to the backlog when
/// `None`; done and cancelled ones stay.
pub async fn close_sprint(
    pool: &SqlitePool,
    sprint: SprintId,
    carry_to: Option<SprintId>,
    actor: AuditActor,
) -> Result<Sprint, SprintError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let s = sprint_in(&mut tx, sprint).await?;
    if s.state != SprintState::Active {
        return Err(SprintError::State(s.state));
    }
    if let Some(to) = carry_to {
        let next = sprint_in(&mut tx, to).await?;
        if next.project_id != s.project_id {
            return Err(SprintError::OtherProject);
        }
        if next.state != SprintState::Planned {
            return Err(SprintError::State(next.state));
        }
    }
    let review = super::review::review_in(&mut tx, &s, carry_to).await?;
    let open: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM citadel_issues WHERE sprint_id = ? AND state NOT IN ('done', 'cancelled') \
         ORDER BY id",
    )
    .bind(sprint.0)
    .fetch_all(&mut *tx)
    .await?;
    for &id in &open {
        let i = issue_in(&mut tx, IssueId(id))
            .await?
            .ok_or(SprintError::NotFound)?;
        set_sprint_in(&mut tx, &i, carry_to, actor).await?;
    }
    let completed: i64 = sqlx::query_scalar(
        "UPDATE citadel_sprints SET state = 'closed', review = ?2, completed_points = \
         (SELECT coalesce(sum(points), 0) FROM citadel_issues WHERE sprint_id = ?1 AND state = 'done') \
         WHERE id = ?1 RETURNING completed_points",
    )
    .bind(sprint.0)
    .bind(review.to_string())
    .fetch_one(&mut *tx)
    .await?;
    let closed = Sprint {
        state: SprintState::Closed,
        ..s
    };
    let details = serde_json::json!({"completed": completed, "moved": open,
                                     "to": carry_to.map(|s| s.0)});
    append_sprint_event(&mut tx, &closed, actor, "sprint.closed", details).await?;
    tx.commit().await?;
    Ok(closed)
}

/// Sets how many points the member can take on per sprint (`None` clears it); `false` when
/// the agent is not on the team.
pub async fn set_member_capacity(
    pool: &SqlitePool,
    team: TeamId,
    agent: AgentId,
    capacity: Option<u32>,
) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE citadel_team_memberships SET capacity = ? WHERE team_id = ? AND agent_id = ?",
    )
    .bind(capacity)
    .bind(team.0)
    .bind(agent.0)
    .execute(pool)
    .await
    .map(affected)
}
