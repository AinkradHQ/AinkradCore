//! Quest: a project team's sprint capacity and an issue's flow times (the second half of
//! `quest`).

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::{Error, SqlitePool};

use crate::domain::org::{AgentId, TeamId};
use crate::domain::work::{IssueId, ProjectId};
use crate::store::work::requirements::append_org_event;

use crate::domain::org::TeamRole;

/// A member of a project's owning team and the points it takes on per sprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub agent_id: AgentId,
    pub team_role: TeamRole,
    pub capacity: Option<u32>,
}

/// The project's owning team and its members' capacity; `None` when it has no team.
pub async fn team_capacity(
    pool: &SqlitePool,
    project: ProjectId,
) -> Result<Option<(TeamId, Vec<Member>)>, Error> {
    let team: Option<Option<i64>> =
        sqlx::query_scalar("SELECT team_id FROM citadel_projects WHERE id = ?")
            .bind(project.0)
            .fetch_optional(pool)
            .await?;
    let Some(team) = team.flatten() else {
        return Ok(None);
    };
    let rows: Vec<(i64, String, Option<u32>)> = sqlx::query_as(
        "SELECT agent_id, team_role, capacity FROM citadel_team_memberships WHERE team_id = ? \
         ORDER BY agent_id",
    )
    .bind(team)
    .fetch_all(pool)
    .await?;
    let members = rows
        .into_iter()
        .map(|(agent, role, capacity)| {
            Ok(Member {
                agent_id: AgentId(agent),
                team_role: role.parse().map_err(|e| Error::Decode(Box::new(e)))?,
                capacity,
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok(Some((TeamId(team), members)))
}

/// Sets how many points the member of the project's team takes on per sprint (`None` clears
/// it), `member.capacity_set`; `RowNotFound` when the agent is not on the project's team.
pub async fn set_capacity(
    pool: &SqlitePool,
    project: ProjectId,
    agent: AgentId,
    capacity: Option<u32>,
    actor: AuditActor,
) -> Result<(), Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let company = super::company_of(&mut tx, project).await?;
    let team: Option<i64> = sqlx::query_scalar(
        "UPDATE citadel_team_memberships SET capacity = ?1 WHERE agent_id = ?2 \
         AND team_id = (SELECT team_id FROM citadel_projects WHERE id = ?3) RETURNING team_id",
    )
    .bind(capacity)
    .bind(agent.0)
    .bind(project.0)
    .fetch_optional(&mut *tx)
    .await?;
    let team = team.ok_or(Error::RowNotFound)?;
    let details = json!({"team": team, "project": project.0, "capacity": capacity});
    let entity = ("agent", agent.0);
    append_org_event(
        &mut tx,
        company,
        actor,
        "member.capacity_set",
        entity,
        details,
    )
    .await?;
    tx.commit().await
}

/// An issue's flow, from its state history: created, first in progress, last done; cycle time
/// (in progress → done), lead time (created → done) and age (created → done, or → `now` while
/// open), in seconds. Issues older than the history have no row of their creation: `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueFlow {
    pub created_at: Option<String>,
    pub started_at: Option<String>,
    pub done_at: Option<String>,
    pub cycle_secs: Option<i64>,
    pub lead_secs: Option<i64>,
    pub age_secs: Option<i64>,
}

pub async fn issue_flow(pool: &SqlitePool, issue: IssueId, now: &str) -> Result<IssueFlow, Error> {
    macro_rules! secs {
        ($a:literal, $b:literal) => {
            concat!(
                "CAST(round((julianday(",
                $b,
                ") - julianday(",
                $a,
                ")) * 86400) AS INTEGER)"
            )
        };
    }
    let sql = concat!(
        "WITH h AS (SELECT \
             (SELECT min(at) FROM citadel_issue_state_history WHERE issue_id = ?1 AND from_state IS NULL) \
                 AS created, \
             (SELECT min(at) FROM citadel_issue_state_history WHERE issue_id = ?1 \
                 AND to_state = 'in_progress') AS started, \
             (SELECT max(at) FROM citadel_issue_state_history WHERE issue_id = ?1 AND to_state = 'done' \
                 AND (SELECT state FROM citadel_issues WHERE id = ?1) = 'done') AS done) \
         SELECT created, started, done, ",
        secs!("started", "done"),
        ", ",
        secs!("created", "done"),
        ", ",
        secs!("created", "coalesce(done, ?2)"),
        " FROM h"
    );
    type At = Option<String>;
    type Secs = Option<i64>;
    let row: (At, At, At, Secs, Secs, Secs) = sqlx::query_as(sql)
        .bind(issue.0)
        .bind(now)
        .fetch_one(pool)
        .await?;
    Ok(IssueFlow {
        created_at: row.0,
        started_at: row.1,
        done_at: row.2,
        cycle_secs: row.3,
        lead_secs: row.4,
        age_secs: row.5,
    })
}
