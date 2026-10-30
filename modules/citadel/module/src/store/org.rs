//! Org repository: companies, departments, teams, agents and team memberships.
//!
//! `update_*` / `delete_*` return `false` when no row matched the id. The audited service,
//! the escalation chain, the hire gate and the Engineering template are later slices of the
//! port (`Docs/Plans/2026-10-30-citadel-port-slices.md`). `create_agent` and `update_agent`
//! are raw, unaudited writes, test-only (`cfg(test)` or the `test-support` feature): a new
//! agent goes through the hire gate, a reporting line through the audited service.

use std::str::FromStr;

use crate::domain::org::{
    Agent, AgentId, AgentProfile, Company, CompanyId, CompanyProfile, Department, DepartmentId,
    NewAgent, Team, TeamId, TeamMembership, UnknownVariant,
};
use sqlx::sqlite::SqliteRow;
use sqlx::types::Json;
use sqlx::{Error, Row};

pub(crate) fn text<T: FromStr<Err = UnknownVariant>>(
    row: &SqliteRow,
    column: &str,
) -> Result<T, Error> {
    let value: String = row.try_get(column)?;
    value.parse().map_err(|e| Error::ColumnDecode {
        index: column.to_owned(),
        source: Box::new(e),
    })
}

/// An optional enum column: `None` while NULL.
pub(crate) fn opt_text<T: FromStr<Err = UnknownVariant>>(
    row: &SqliteRow,
    column: &str,
) -> Result<Option<T>, Error> {
    let value: Option<String> = row.try_get(column)?;
    value
        .map(|v| {
            v.parse().map_err(|e| Error::ColumnDecode {
                index: column.to_owned(),
                source: Box::new(e),
            })
        })
        .transpose()
}

pub(crate) fn affected(result: sqlx::sqlite::SqliteQueryResult) -> bool {
    result.rows_affected() > 0
}

/// Whether user `id` exists (a human who can review or be handed an issue).
pub async fn user_exists(
    pool: impl sqlx::SqliteExecutor<'_>,
    id: crate::domain::work::UserId,
) -> Result<bool, Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = ?)")
        .bind(id.0)
        .fetch_one(pool)
        .await
}

// --- companies --------------------------------------------------------------

// A macro, not a const, so `concat!` keeps every query a `&'static str`.
macro_rules! company_columns {
    () => {
        "id, name, kind, color, description, industries, website, timezone, work_start, \
         work_end, work_days, logo_sha256"
    };
}

fn company(row: SqliteRow) -> Result<Company, Error> {
    let Json(industries) = row.try_get::<Json<Vec<String>>, _>("industries")?;
    Ok(Company {
        id: CompanyId(row.try_get("id")?),
        name: row.try_get("name")?,
        kind: text(&row, "kind")?,
        profile: CompanyProfile {
            color: row.try_get("color")?,
            description: row.try_get("description")?,
            industries,
            website: row.try_get("website")?,
            timezone: row.try_get("timezone")?,
            work_start: row.try_get("work_start")?,
            work_end: row.try_get("work_end")?,
            work_days: row.try_get("work_days")?,
            logo_sha256: row.try_get("logo_sha256")?,
        },
    })
}

pub async fn create_company(
    pool: impl sqlx::SqliteExecutor<'_>,
    name: &str,
) -> Result<Company, Error> {
    sqlx::query(concat!(
        "INSERT INTO citadel_companies (name) VALUES (?) RETURNING ",
        company_columns!()
    ))
    .bind(name)
    .fetch_one(pool)
    .await
    .and_then(company)
}

pub async fn get_company(
    pool: impl sqlx::SqliteExecutor<'_>,
    id: CompanyId,
) -> Result<Option<Company>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        company_columns!(),
        " FROM citadel_companies WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(company)
    .transpose()
}

pub async fn list_companies(pool: impl sqlx::SqliteExecutor<'_>) -> Result<Vec<Company>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        company_columns!(),
        " FROM citadel_companies ORDER BY id"
    ))
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(company)
    .collect()
}

pub async fn update_company(
    pool: impl sqlx::SqliteExecutor<'_>,
    c: &Company,
) -> Result<bool, Error> {
    sqlx::query("UPDATE citadel_companies SET name = ?, kind = ? WHERE id = ?")
        .bind(&c.name)
        .bind(c.kind.as_str())
        .bind(c.id.0)
        .execute(pool)
        .await
        .map(affected)
}

/// Cascades to the company's departments, teams, agents and memberships.
pub async fn delete_company(
    pool: impl sqlx::SqliteExecutor<'_>,
    id: CompanyId,
) -> Result<bool, Error> {
    sqlx::query("DELETE FROM citadel_companies WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}

// --- departments ------------------------------------------------------------

fn department(row: SqliteRow) -> Result<Department, Error> {
    Ok(Department {
        id: DepartmentId(row.try_get("id")?),
        company_id: CompanyId(row.try_get("company_id")?),
        name: row.try_get("name")?,
        about: row.try_get("about")?,
        head_agent_id: row.try_get::<Option<i64>, _>("head_agent_id")?.map(AgentId),
    })
}

pub async fn create_department(
    pool: impl sqlx::SqliteExecutor<'_>,
    company_id: CompanyId,
    name: &str,
) -> Result<Department, Error> {
    sqlx::query(
        "INSERT INTO citadel_departments (company_id, name) VALUES (?, ?) RETURNING id, company_id, name, about, head_agent_id",
    )
    .bind(company_id.0)
    .bind(name)
    .fetch_one(pool)
    .await
    .and_then(department)
}

pub async fn get_department(
    pool: impl sqlx::SqliteExecutor<'_>,
    id: DepartmentId,
) -> Result<Option<Department>, Error> {
    sqlx::query(
        "SELECT id, company_id, name, about, head_agent_id FROM citadel_departments WHERE id = ?",
    )
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(department)
    .transpose()
}

pub async fn list_departments(
    pool: impl sqlx::SqliteExecutor<'_>,
    company_id: CompanyId,
) -> Result<Vec<Department>, Error> {
    sqlx::query("SELECT id, company_id, name, about, head_agent_id FROM citadel_departments WHERE company_id = ? ORDER BY id")
        .bind(company_id.0)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(department)
        .collect()
}

/// Renames only; a department does not move between companies.
pub async fn update_department(
    pool: impl sqlx::SqliteExecutor<'_>,
    d: &Department,
) -> Result<bool, Error> {
    sqlx::query("UPDATE citadel_departments SET name = ? WHERE id = ?")
        .bind(&d.name)
        .bind(d.id.0)
        .execute(pool)
        .await
        .map(affected)
}

pub async fn delete_department(
    pool: impl sqlx::SqliteExecutor<'_>,
    id: DepartmentId,
) -> Result<bool, Error> {
    sqlx::query("DELETE FROM citadel_departments WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}

// --- teams ------------------------------------------------------------------

fn team(row: SqliteRow) -> Result<Team, Error> {
    Ok(Team {
        id: TeamId(row.try_get("id")?),
        department_id: DepartmentId(row.try_get("department_id")?),
        name: row.try_get("name")?,
    })
}

pub async fn create_team(
    pool: impl sqlx::SqliteExecutor<'_>,
    department_id: DepartmentId,
    name: &str,
) -> Result<Team, Error> {
    sqlx::query(
        "INSERT INTO citadel_teams (department_id, name) VALUES (?, ?) RETURNING id, department_id, name",
    )
    .bind(department_id.0)
    .bind(name)
    .fetch_one(pool)
    .await
    .and_then(team)
}

pub async fn get_team(
    pool: impl sqlx::SqliteExecutor<'_>,
    id: TeamId,
) -> Result<Option<Team>, Error> {
    sqlx::query("SELECT id, department_id, name FROM citadel_teams WHERE id = ?")
        .bind(id.0)
        .fetch_optional(pool)
        .await?
        .map(team)
        .transpose()
}

pub async fn list_teams(
    pool: impl sqlx::SqliteExecutor<'_>,
    department_id: DepartmentId,
) -> Result<Vec<Team>, Error> {
    sqlx::query(
        "SELECT id, department_id, name FROM citadel_teams WHERE department_id = ? ORDER BY id",
    )
    .bind(department_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(team)
    .collect()
}

/// Renames or moves the team to another department.
pub async fn update_team(pool: impl sqlx::SqliteExecutor<'_>, t: &Team) -> Result<bool, Error> {
    sqlx::query("UPDATE citadel_teams SET department_id = ?, name = ? WHERE id = ?")
        .bind(t.department_id.0)
        .bind(&t.name)
        .bind(t.id.0)
        .execute(pool)
        .await
        .map(affected)
}

pub async fn delete_team(pool: impl sqlx::SqliteExecutor<'_>, id: TeamId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM citadel_teams WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}

// --- agents -----------------------------------------------------------------

// A macro, not a const, so `concat!` keeps every query a `&'static str`.
macro_rules! agent_columns {
    () => {
        "id, company_id, name, role, org_role, reports_to, harness, model, runner_tags, status, \
         figure_version, palette_id, avatar_sha256, paused_at, created_at, description, effort, \
         sandbox, instructions, guidelines"
    };
}

/// SQL: the palette a new agent of company `?1` is given (decision #61): the one its company
/// uses least, ties broken by a rotation per company, so it is stable once stored, spread
/// evenly, and unique within the company while palettes last.
macro_rules! palette_pick {
    () => {
        "(SELECT p.id FROM citadel_avatar_palettes p ORDER BY \
         (SELECT count(*) FROM citadel_agents pp WHERE pp.company_id = ?1 AND pp.palette_id = p.id), \
         ((p.position - 1 - ?1 * 7) % (SELECT count(*) FROM citadel_avatar_palettes) \
          + (SELECT count(*) FROM citadel_avatar_palettes)) % (SELECT count(*) FROM citadel_avatar_palettes) \
         LIMIT 1)"
    };
}

fn agent(row: SqliteRow) -> Result<Agent, Error> {
    let Json(runner_tags) = row.try_get::<Json<Vec<String>>, _>("runner_tags")?;
    let Json(guidelines) = row.try_get::<Json<Vec<String>>, _>("guidelines")?;
    Ok(Agent {
        id: AgentId(row.try_get("id")?),
        company_id: CompanyId(row.try_get("company_id")?),
        name: row.try_get("name")?,
        role: row.try_get("role")?,
        org_role: text(&row, "org_role")?,
        reports_to: row.try_get::<Option<i64>, _>("reports_to")?.map(AgentId),
        harness: text(&row, "harness")?,
        model: row.try_get("model")?,
        runner_tags,
        status: text(&row, "status")?,
        profile: AgentProfile {
            description: row.try_get("description")?,
            effort: opt_text(&row, "effort")?,
            sandbox: opt_text(&row, "sandbox")?,
            instructions: row.try_get("instructions")?,
            guidelines,
        },
        figure_version: row.try_get("figure_version")?,
        palette_id: row.try_get("palette_id")?,
        avatar_sha256: row.try_get("avatar_sha256")?,
        paused_at: row.try_get("paused_at")?,
        created_at: row.try_get("created_at")?,
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn create_agent(
    pool: impl sqlx::SqliteExecutor<'_>,
    a: &NewAgent,
) -> Result<Agent, Error> {
    sqlx::query(concat!(
        "INSERT INTO citadel_agents (company_id, name, role, org_role, reports_to, harness, model, \
         runner_tags, status, palette_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ",
        palette_pick!(),
        ") RETURNING ",
        agent_columns!()
    ))
    .bind(a.company_id.0)
    .bind(&a.name)
    .bind(&a.role)
    .bind(a.org_role.as_str())
    .bind(a.reports_to.map(|r| r.0))
    .bind(a.harness.as_str())
    .bind(&a.model)
    .bind(Json(&a.runner_tags))
    .bind(a.status.as_str())
    .fetch_one(pool)
    .await
    .and_then(agent)
}

pub async fn get_agent(
    pool: impl sqlx::SqliteExecutor<'_>,
    id: AgentId,
) -> Result<Option<Agent>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        agent_columns!(),
        " FROM citadel_agents WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(agent)
    .transpose()
}

pub async fn list_agents(
    pool: impl sqlx::SqliteExecutor<'_>,
    company_id: CompanyId,
) -> Result<Vec<Agent>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        agent_columns!(),
        " FROM citadel_agents WHERE company_id = ? ORDER BY id"
    ))
    .bind(company_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(agent)
    .collect()
}

/// Updates every field except `company_id`; an agent does not move between companies.
/// Test-only, like `create_agent`.
#[cfg(any(test, feature = "test-support"))]
pub async fn update_agent(pool: impl sqlx::SqliteExecutor<'_>, a: &Agent) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE citadel_agents SET name = ?, role = ?, org_role = ?, reports_to = ?, harness = ?, \
         model = ?, runner_tags = ?, status = ? WHERE id = ?",
    )
    .bind(&a.name)
    .bind(&a.role)
    .bind(a.org_role.as_str())
    .bind(a.reports_to.map(|r| r.0))
    .bind(a.harness.as_str())
    .bind(&a.model)
    .bind(Json(&a.runner_tags))
    .bind(a.status.as_str())
    .bind(a.id.0)
    .execute(pool)
    .await
    .map(affected)
}

/// Removes the agent's team memberships; its direct reports keep existing with no manager.
pub async fn delete_agent(pool: impl sqlx::SqliteExecutor<'_>, id: AgentId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM citadel_agents WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}

// --- team memberships -------------------------------------------------------

fn membership(row: SqliteRow) -> Result<TeamMembership, Error> {
    Ok(TeamMembership {
        team_id: TeamId(row.try_get("team_id")?),
        agent_id: AgentId(row.try_get("agent_id")?),
        team_role: text(&row, "team_role")?,
    })
}

pub async fn create_membership(
    pool: impl sqlx::SqliteExecutor<'_>,
    m: &TeamMembership,
) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO citadel_team_memberships (team_id, agent_id, team_role) VALUES (?, ?, ?)",
    )
    .bind(m.team_id.0)
    .bind(m.agent_id.0)
    .bind(m.team_role.as_str())
    .execute(pool)
    .await
    .map(drop)
}

pub async fn get_membership(
    pool: impl sqlx::SqliteExecutor<'_>,
    team_id: TeamId,
    agent_id: AgentId,
) -> Result<Option<TeamMembership>, Error> {
    sqlx::query(
        "SELECT team_id, agent_id, team_role FROM citadel_team_memberships \
         WHERE team_id = ? AND agent_id = ?",
    )
    .bind(team_id.0)
    .bind(agent_id.0)
    .fetch_optional(pool)
    .await?
    .map(membership)
    .transpose()
}

pub async fn list_memberships(
    pool: impl sqlx::SqliteExecutor<'_>,
    team_id: TeamId,
) -> Result<Vec<TeamMembership>, Error> {
    sqlx::query(
        "SELECT team_id, agent_id, team_role FROM citadel_team_memberships \
         WHERE team_id = ? ORDER BY agent_id",
    )
    .bind(team_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(membership)
    .collect()
}

/// Changes the agent's role on the team.
pub async fn update_membership(
    pool: impl sqlx::SqliteExecutor<'_>,
    m: &TeamMembership,
) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE citadel_team_memberships SET team_role = ? WHERE team_id = ? AND agent_id = ?",
    )
    .bind(m.team_role.as_str())
    .bind(m.team_id.0)
    .bind(m.agent_id.0)
    .execute(pool)
    .await
    .map(affected)
}

pub async fn delete_membership(
    pool: impl sqlx::SqliteExecutor<'_>,
    team_id: TeamId,
    agent_id: AgentId,
) -> Result<bool, Error> {
    sqlx::query("DELETE FROM citadel_team_memberships WHERE team_id = ? AND agent_id = ?")
        .bind(team_id.0)
        .bind(agent_id.0)
        .execute(pool)
        .await
        .map(affected)
}

pub mod service;

#[cfg(test)]
mod tests;
