//! Org repository: companies, departments, teams, agents and team memberships.
//!
//! `update_*` / `delete_*` return `false` when no row matched the id. The audited service
//! (departments, teams, seats, reporting lines and the org chart, E6.1) is in `service`, the
//! escalation chain (E6.3) in `chain`, the hire gate (E6.4) in `hire`, the Engineering
//! template (E6.5) in `template`. `create_agent` and `update_agent` are raw, unaudited writes,
//! test-only (`cfg(test)` or the `test-support` feature): a new agent goes through `hire_agent`
//! (or `bootstrap_ceo`), a reporting line through `set_manager`.

use std::str::FromStr;

use citadel_core::org::{
    Agent, AgentId, AgentProfile, Company, CompanyId, CompanyProfile, Department, DepartmentId,
    NewAgent, Team, TeamId, TeamMembership, UnknownVariant,
};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::types::Json;
use sqlx::{Error, Row};

pub(super) fn text<T: FromStr<Err = UnknownVariant>>(
    row: &SqliteRow,
    column: &str,
) -> Result<T, Error> {
    let value: String = row.try_get(column)?;
    value.parse().map_err(|e| Error::ColumnDecode {
        index: column.to_owned(),
        source: Box::new(e),
    })
}

pub(super) fn affected(result: sqlx::sqlite::SqliteQueryResult) -> bool {
    result.rows_affected() > 0
}

/// Whether user `id` exists (a human who can review or be handed an issue).
pub async fn user_exists(pool: &SqlitePool, id: citadel_core::work::UserId) -> Result<bool, Error> {
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

pub async fn create_company(pool: &SqlitePool, name: &str) -> Result<Company, Error> {
    sqlx::query(concat!(
        "INSERT INTO companies (name) VALUES (?) RETURNING ",
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
        " FROM companies WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(company)
    .transpose()
}

pub async fn list_companies(pool: &SqlitePool) -> Result<Vec<Company>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        company_columns!(),
        " FROM companies ORDER BY id"
    ))
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(company)
    .collect()
}

pub async fn update_company(pool: &SqlitePool, c: &Company) -> Result<bool, Error> {
    sqlx::query("UPDATE companies SET name = ?, kind = ? WHERE id = ?")
        .bind(&c.name)
        .bind(c.kind.as_str())
        .bind(c.id.0)
        .execute(pool)
        .await
        .map(affected)
}

/// Cascades to the company's departments, teams, agents and memberships.
pub async fn delete_company(pool: &SqlitePool, id: CompanyId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM companies WHERE id = ?")
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
    pool: &SqlitePool,
    company_id: CompanyId,
    name: &str,
) -> Result<Department, Error> {
    sqlx::query(
        "INSERT INTO departments (company_id, name) VALUES (?, ?) RETURNING id, company_id, name, about, head_agent_id",
    )
    .bind(company_id.0)
    .bind(name)
    .fetch_one(pool)
    .await
    .and_then(department)
}

pub async fn get_department(
    pool: &SqlitePool,
    id: DepartmentId,
) -> Result<Option<Department>, Error> {
    sqlx::query("SELECT id, company_id, name, about, head_agent_id FROM departments WHERE id = ?")
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
    sqlx::query("SELECT id, company_id, name, about, head_agent_id FROM departments WHERE company_id = ? ORDER BY id")
        .bind(company_id.0)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(department)
        .collect()
}

/// Renames only; a department does not move between companies.
pub async fn update_department(pool: &SqlitePool, d: &Department) -> Result<bool, Error> {
    sqlx::query("UPDATE departments SET name = ? WHERE id = ?")
        .bind(&d.name)
        .bind(d.id.0)
        .execute(pool)
        .await
        .map(affected)
}

pub async fn delete_department(pool: &SqlitePool, id: DepartmentId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM departments WHERE id = ?")
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
    pool: &SqlitePool,
    department_id: DepartmentId,
    name: &str,
) -> Result<Team, Error> {
    sqlx::query(
        "INSERT INTO teams (department_id, name) VALUES (?, ?) RETURNING id, department_id, name",
    )
    .bind(department_id.0)
    .bind(name)
    .fetch_one(pool)
    .await
    .and_then(team)
}

pub async fn get_team(pool: &SqlitePool, id: TeamId) -> Result<Option<Team>, Error> {
    sqlx::query("SELECT id, department_id, name FROM teams WHERE id = ?")
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
    sqlx::query("SELECT id, department_id, name FROM teams WHERE department_id = ? ORDER BY id")
        .bind(department_id.0)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(team)
        .collect()
}

/// Renames or moves the team to another department.
pub async fn update_team(pool: &SqlitePool, t: &Team) -> Result<bool, Error> {
    sqlx::query("UPDATE teams SET department_id = ?, name = ? WHERE id = ?")
        .bind(t.department_id.0)
        .bind(&t.name)
        .bind(t.id.0)
        .execute(pool)
        .await
        .map(affected)
}

pub async fn delete_team(pool: &SqlitePool, id: TeamId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM teams WHERE id = ?")
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
        "(SELECT p.id FROM avatar_palettes p ORDER BY \
         (SELECT count(*) FROM agents pp WHERE pp.company_id = ?1 AND pp.palette_id = p.id), \
         ((p.position - 1 - ?1 * 7) % (SELECT count(*) FROM avatar_palettes) \
          + (SELECT count(*) FROM avatar_palettes)) % (SELECT count(*) FROM avatar_palettes) \
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
            effort: agent_edit::opt_text(&row, "effort")?,
            sandbox: agent_edit::opt_text(&row, "sandbox")?,
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
pub async fn create_agent(pool: &SqlitePool, a: &NewAgent) -> Result<Agent, Error> {
    sqlx::query(concat!(
        "INSERT INTO agents (company_id, name, role, org_role, reports_to, harness, model, \
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

pub async fn get_agent(pool: &SqlitePool, id: AgentId) -> Result<Option<Agent>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        agent_columns!(),
        " FROM agents WHERE id = ?"
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
        " FROM agents WHERE company_id = ? ORDER BY id"
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
pub async fn update_agent(pool: &SqlitePool, a: &Agent) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE agents SET name = ?, role = ?, org_role = ?, reports_to = ?, harness = ?, \
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
pub async fn delete_agent(pool: &SqlitePool, id: AgentId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM agents WHERE id = ?")
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

pub async fn create_membership(pool: &SqlitePool, m: &TeamMembership) -> Result<(), Error> {
    sqlx::query("INSERT INTO team_memberships (team_id, agent_id, team_role) VALUES (?, ?, ?)")
        .bind(m.team_id.0)
        .bind(m.agent_id.0)
        .bind(m.team_role.as_str())
        .execute(pool)
        .await
        .map(drop)
}

pub async fn get_membership(
    pool: &SqlitePool,
    team_id: TeamId,
    agent_id: AgentId,
) -> Result<Option<TeamMembership>, Error> {
    sqlx::query(
        "SELECT team_id, agent_id, team_role FROM team_memberships \
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
        "SELECT team_id, agent_id, team_role FROM team_memberships \
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
pub async fn update_membership(pool: &SqlitePool, m: &TeamMembership) -> Result<bool, Error> {
    sqlx::query("UPDATE team_memberships SET team_role = ? WHERE team_id = ? AND agent_id = ?")
        .bind(m.team_role.as_str())
        .bind(m.team_id.0)
        .bind(m.agent_id.0)
        .execute(pool)
        .await
        .map(affected)
}

pub async fn delete_membership(
    pool: &SqlitePool,
    team_id: TeamId,
    agent_id: AgentId,
) -> Result<bool, Error> {
    sqlx::query("DELETE FROM team_memberships WHERE team_id = ? AND agent_id = ?")
        .bind(team_id.0)
        .bind(agent_id.0)
        .execute(pool)
        .await
        .map(affected)
}

mod agent_edit;
mod agent_stats;
pub mod avatars;
mod chain;
mod fallbacks;
mod hire;
pub mod logo;
mod notify;
mod presets;
mod roles;
mod service;
mod structure;
mod template;
mod tiers;
pub use agent_edit::edit_agent;
pub use agent_stats::*;
pub(crate) use chain::{escalation_target_in, product_owner_in};
pub use chain::{is_cross_department, set_cross_department};
pub(crate) use fallbacks::fallbacks_in;
pub use fallbacks::{list_fallbacks, set_fallbacks};
pub use hire::{HireExtras, bootstrap_ceo, hire_agent, hire_agent_with};
pub(crate) use hire::{hire_agent_in, hire_decided_in};
pub use notify::*;
pub use presets::*;
pub use roles::*;
pub use service::*;
pub use structure::*;
pub use template::{Applied, ENGINEERING, ENGINEERING_TEAM, apply_engineering};
pub(crate) use tiers::tier_route_in;
pub use tiers::{list_tiers, set_tiers};

#[cfg(test)]
mod tests;
