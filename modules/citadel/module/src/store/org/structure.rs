//! Shaping the org from the app (API minor 17): departments (name, about, head), teams (name,
//! department) and seats, each checked and audited in one `BEGIN IMMEDIATE` transaction
//! (`department.updated`, `department.deleted`, `team.updated`, `team.deleted`, and the seat
//! events of `service`). A team has at most one product owner and one lead (`SeatTaken`).

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::begin_write;
use serde_json::json;
use sqlx::{Error, SqliteConnection, SqlitePool};

use super::chart::{OrgError, add_department_in, append_org_event, seat_member_in};
use super::department;
use crate::domain::org::{
    AgentId, CompanyId, Department, DepartmentId, Team, TeamId, TeamMembership, TeamRole,
};

/// A change to a department; `None` leaves a field, `Some(None)` clears the head.
#[derive(Debug, Clone, Default)]
pub struct DepartmentChange {
    pub name: Option<String>,
    pub about: Option<String>,
    pub head: Option<Option<AgentId>>,
}

fn invalid(why: &str) -> OrgError {
    Error::InvalidArgument(why.to_owned()).into()
}

fn checked_name(name: &str) -> Result<&str, OrgError> {
    match name.trim() {
        n if n.is_empty() || n.chars().count() > 100 => Err(invalid("a name is 1-100 characters")),
        n => Ok(n),
    }
}

fn checked_about(about: &str) -> Result<(), OrgError> {
    match about.chars().count() > 2000 {
        true => Err(invalid("about is at most 2000 characters")),
        false => Ok(()),
    }
}

/// Adds department `name` with `about` and `head` (an agent of the company); `head`, `about` and
/// the department are one transaction, audited as `department.added`.
pub async fn create_department_with(
    pool: &SqlitePool,
    company: CompanyId,
    name: &str,
    about: &str,
    head: Option<AgentId>,
    actor: AuditActor,
) -> Result<Department, OrgError> {
    checked_name(name)?;
    checked_about(about)?;
    let mut tx = begin_write(pool).await?;
    let d = add_department_in(&mut tx, company, name, actor).await?;
    let change = DepartmentChange {
        about: Some(about.to_owned()),
        head: head.map(Some),
        ..Default::default()
    };
    let d = apply_in(&mut tx, d, &change).await?;
    tx.commit().await?;
    Ok(d)
}

async fn apply_in(
    tx: &mut SqliteConnection,
    mut d: Department,
    c: &DepartmentChange,
) -> Result<Department, OrgError> {
    if let Some(name) = &c.name {
        d.name = checked_name(name)?.to_owned();
    }
    if let Some(about) = &c.about {
        checked_about(about)?;
        d.about.clone_from(about);
    }
    if let Some(head) = c.head {
        if let Some(h) = head {
            let of: Option<i64> =
                sqlx::query_scalar("SELECT company_id FROM citadel_agents WHERE id = ?")
                    .bind(h.0)
                    .fetch_optional(&mut *tx)
                    .await?;
            match of {
                None => return Err(OrgError::NotFound),
                Some(c) if c != d.company_id.0 => return Err(OrgError::OtherCompany),
                Some(_) => {}
            }
        }
        d.head_agent_id = head;
    }
    sqlx::query(
        "UPDATE citadel_departments SET name = ?, about = ?, head_agent_id = ? WHERE id = ?",
    )
    .bind(&d.name)
    .bind(&d.about)
    .bind(d.head_agent_id.map(|h| h.0))
    .bind(d.id.0)
    .execute(&mut *tx)
    .await?;
    Ok(d)
}

async fn department_in(
    conn: &mut SqliteConnection,
    id: DepartmentId,
) -> Result<Department, OrgError> {
    sqlx::query(
        "SELECT id, company_id, name, about, head_agent_id FROM citadel_departments WHERE id = ?",
    )
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(department)
    .transpose()?
    .ok_or(OrgError::NotFound)
}

/// Applies `c` to the department, audited as `department.updated`. A name its company has is a
/// constraint error; a head of another company `OtherCompany`.
pub async fn edit_department(
    pool: &SqlitePool,
    id: DepartmentId,
    c: &DepartmentChange,
    actor: AuditActor,
) -> Result<Department, OrgError> {
    if c.name.is_none() && c.about.is_none() && c.head.is_none() {
        return Err(invalid("nothing to change"));
    }
    let mut tx = begin_write(pool).await?;
    let before = department_in(&mut tx, id).await?;
    let d = apply_in(&mut tx, before, c).await?;
    let fields: Vec<&str> = [
        c.name.as_ref().map(|_| "name"),
        c.about.as_ref().map(|_| "about"),
        c.head.map(|_| "head_agent_id"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let details = json!({"name": d.name, "head": d.head_agent_id.map(|h| h.0), "fields": fields});
    let entity = ("department", id.0);
    append_org_event(
        &mut tx,
        d.company_id,
        actor,
        "department.updated",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(d)
}

/// Deletes a department with no teams, audited as `department.deleted`; `HasTeams` otherwise.
pub async fn remove_department(
    pool: &SqlitePool,
    id: DepartmentId,
    actor: AuditActor,
) -> Result<(), OrgError> {
    let mut tx = begin_write(pool).await?;
    let d = department_in(&mut tx, id).await?;
    let teams: i64 =
        sqlx::query_scalar("SELECT count(*) FROM citadel_teams WHERE department_id = ?")
            .bind(id.0)
            .fetch_one(&mut *tx)
            .await?;
    if teams > 0 {
        return Err(OrgError::HasTeams);
    }
    sqlx::query("DELETE FROM citadel_departments WHERE id = ?")
        .bind(id.0)
        .execute(&mut *tx)
        .await?;
    let entity = ("department", id.0);
    let details = json!({"name": d.name});
    append_org_event(
        &mut tx,
        d.company_id,
        actor,
        "department.deleted",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn team_company_in(
    conn: &mut SqliteConnection,
    id: TeamId,
) -> Result<(Team, CompanyId), OrgError> {
    let row: Option<(i64, String, i64)> = sqlx::query_as(
        "SELECT t.department_id, t.name, d.company_id FROM citadel_teams t \
         JOIN citadel_departments d ON d.id = t.department_id WHERE t.id = ?",
    )
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?;
    let (department_id, name, company) = row.ok_or(OrgError::NotFound)?;
    let team = Team {
        id,
        department_id: DepartmentId(department_id),
        name,
    };
    Ok((team, CompanyId(company)))
}

/// Renames the team and/or moves it to another department of its company, audited as
/// `team.updated`.
pub async fn edit_team(
    pool: &SqlitePool,
    id: TeamId,
    name: Option<&str>,
    department: Option<DepartmentId>,
    actor: AuditActor,
) -> Result<Team, OrgError> {
    if name.is_none() && department.is_none() {
        return Err(invalid("nothing to change"));
    }
    let mut tx = begin_write(pool).await?;
    let (mut t, company) = team_company_in(&mut tx, id).await?;
    if let Some(n) = name {
        t.name = checked_name(n)?.to_owned();
    }
    if let Some(d) = department {
        if department_in(&mut tx, d).await?.company_id != company {
            return Err(OrgError::OtherCompany);
        }
        t.department_id = d;
    }
    sqlx::query("UPDATE citadel_teams SET name = ?, department_id = ? WHERE id = ?")
        .bind(&t.name)
        .bind(t.department_id.0)
        .bind(id.0)
        .execute(&mut *tx)
        .await?;
    let details = json!({"name": t.name, "department": t.department_id.0});
    append_org_event(
        &mut tx,
        company,
        actor,
        "team.updated",
        ("team", id.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(t)
}

/// Deletes the team and its seats, audited as `team.deleted` (naming the agents unseated).
/// Projects it owned have no team afterwards.
pub async fn remove_team(pool: &SqlitePool, id: TeamId, actor: AuditActor) -> Result<(), OrgError> {
    let mut tx = begin_write(pool).await?;
    let (t, company) = team_company_in(&mut tx, id).await?;
    let seated: Vec<i64> = sqlx::query_scalar(
        "SELECT agent_id FROM citadel_team_memberships WHERE team_id = ? ORDER BY agent_id",
    )
    .bind(id.0)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM citadel_teams WHERE id = ?")
        .bind(id.0)
        .execute(&mut *tx)
        .await?;
    let details = json!({"name": t.name, "unseated": seated});
    append_org_event(
        &mut tx,
        company,
        actor,
        "team.deleted",
        ("team", id.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// `seat_member`, refusing (`SeatTaken`) a product owner or lead seat someone else holds.
pub async fn seat_checked(
    pool: &SqlitePool,
    team: TeamId,
    agent: AgentId,
    role: TeamRole,
    capacity: Option<u32>,
    actor: AuditActor,
) -> Result<TeamMembership, OrgError> {
    let mut tx = begin_write(pool).await?;
    if role != TeamRole::Member {
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM citadel_team_memberships \
             WHERE team_id = ? AND team_role = ? AND agent_id <> ?)",
        )
        .bind(team.0)
        .bind(role.as_str())
        .bind(agent.0)
        .fetch_one(&mut *tx)
        .await?;
        if taken {
            return Err(OrgError::SeatTaken);
        }
    }
    let m = seat_member_in(&mut tx, team, agent, role, capacity, actor).await?;
    tx.commit().await?;
    Ok(m)
}
