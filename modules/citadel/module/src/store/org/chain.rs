//! The escalation chain (E6.3, brainstorm §4: routers, not relays). Every escalation of an
//! issue (the loop breaker, exhausted retries, a token cap, a lost runner) goes through
//! `escalation_target_in`: up the issue's project team, agent -> team lead -> product owner ->
//! the admin. The CEO (or the CTO when there is no active CEO) comes in after the product
//! owner only when the issue is flagged cross-department; otherwise escalation never climbs
//! back through them.
//!
//! Reporting lines (`reports_to`) are the org chart's only: an issue whose project has no team
//! escalates straight to the admin. Seats held by agents that are not active are skipped, so
//! an escalation never waits on an agent that cannot run.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::begin_write;
use serde_json::json;
use sqlx::{Error, SqliteConnection, SqlitePool};

use super::chart::append_org_event;
use crate::domain::org::{AgentId, CompanyId};
use crate::domain::work::{IssueId, NextActor, UserId};

/// Who an escalation past the ladder's top goes to: the admin.
// ponytail: the monolith keeps this in `exec/lease.rs`; S7 should reuse this one.
pub const ESCALATION_USER: UserId = UserId(1);

/// Who the issue goes to when `from` escalates it: the next active agent after `from` on the
/// ladder (team lead, product owner, then for a cross-department issue the CEO, else the
/// CTO), or the admin past its top. `from` off the ladder starts at its bottom.
pub async fn escalation_target_in(
    conn: &mut SqliteConnection,
    issue: IssueId,
    from: AgentId,
) -> Result<NextActor, Error> {
    let found: Option<(i64, Option<i64>, bool)> = sqlx::query_as(
        "SELECT p.company_id, p.team_id, i.cross_department FROM citadel_issues i \
         JOIN citadel_projects p ON p.id = i.project_id WHERE i.id = ?",
    )
    .bind(issue.0)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((company, team, cross)) = found else {
        return Ok(NextActor::Human(ESCALATION_USER));
    };
    let mut ladder = vec![];
    for role in ["team_lead", "product_owner"] {
        let seat: Option<i64> = sqlx::query_scalar(
            "SELECT m.agent_id FROM citadel_team_memberships m \
             JOIN citadel_agents a ON a.id = m.agent_id \
             WHERE m.team_id = ? AND m.team_role = ? AND a.status = 'active'",
        )
        .bind(team)
        .bind(role)
        .fetch_optional(&mut *conn)
        .await?;
        ladder.push(seat);
    }
    if cross {
        let head: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM citadel_agents WHERE company_id = ? AND org_role IN ('ceo', 'cto') \
             AND status = 'active' ORDER BY org_role = 'ceo' DESC LIMIT 1",
        )
        .bind(company)
        .fetch_optional(&mut *conn)
        .await?;
        ladder.push(head);
    }
    let start = ladder
        .iter()
        .position(|a| *a == Some(from.0))
        .map_or(0, |i| i + 1);
    Ok(ladder[start..]
        .iter()
        .flatten()
        .find(|&&a| a != from.0)
        .map_or(NextActor::Human(ESCALATION_USER), |&a| {
            NextActor::Agent(AgentId(a))
        }))
}

/// The active product owner of the issue's project team, when it has one. Woken on a merge, a
/// sprint start or an issue parked on a person (R7a).
pub async fn product_owner_in(
    conn: &mut SqliteConnection,
    issue: IssueId,
) -> Result<Option<AgentId>, Error> {
    let po: Option<i64> = sqlx::query_scalar(
        "SELECT m.agent_id FROM citadel_issues i JOIN citadel_projects p ON p.id = i.project_id \
         JOIN citadel_team_memberships m ON m.team_id = p.team_id \
             AND m.team_role = 'product_owner' \
         JOIN citadel_agents a ON a.id = m.agent_id AND a.status = 'active' WHERE i.id = ?",
    )
    .bind(issue.0)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(po.map(AgentId))
}

/// Flags the issue cross-department (or not) and appends `issue.cross_department_set` by
/// `actor`; `false` when there is no such issue.
pub async fn set_cross_department(
    pool: &SqlitePool,
    issue: IssueId,
    cross: bool,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = begin_write(pool).await?;
    let company: Option<i64> = sqlx::query_scalar(
        "UPDATE citadel_issues SET cross_department = ? WHERE id = ? \
         RETURNING (SELECT company_id FROM citadel_projects \
                    WHERE id = citadel_issues.project_id)",
    )
    .bind(cross)
    .bind(issue.0)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(company) = company else {
        return Ok(false);
    };
    let details = json!({"cross_department": cross});
    let entity = ("issue", issue.0);
    let action = "issue.cross_department_set";
    append_org_event(&mut tx, CompanyId(company), actor, action, entity, details).await?;
    tx.commit().await?;
    Ok(true)
}

/// Whether the issue is flagged cross-department; `None` when there is no such issue.
pub async fn is_cross_department(pool: &SqlitePool, issue: IssueId) -> Result<Option<bool>, Error> {
    sqlx::query_scalar("SELECT cross_department FROM citadel_issues WHERE id = ?")
        .bind(issue.0)
        .fetch_optional(pool)
        .await
}
