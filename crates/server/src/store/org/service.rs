//! The org service (E6.1): departments, teams, team seats and reporting lines, each checked and
//! audited in one `BEGIN IMMEDIATE` transaction, and a company's org chart. The same-company
//! and no-cycle rules are also database triggers (migration `org_integrity`), so a raw write
//! cannot break them either; these checks give the typed reason first.

use std::fmt;

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::org::TeamRole;
use serde_json::{Value, json};
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit;

/// Why an org change was refused.
#[derive(Debug)]
pub enum OrgError {
    /// No such company, department, team or agent.
    NotFound,
    /// The agent and the team (or manager) are in different companies.
    OtherCompany,
    /// The manager reports, directly or not, to the agent.
    Cycle,
    /// Only a company's first CEO starts active; every other agent is hired (E6.4).
    NotBootstrap,
    /// The agent is terminated and cannot be changed.
    Terminated,
    /// A department with teams in it is not deleted: move or delete the teams first.
    HasTeams,
    /// The team already has someone in that seat (one product owner, one lead).
    SeatTaken,
    Db(Error),
}

impl From<Error> for OrgError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for OrgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such company, department, team or agent"),
            Self::OtherCompany => f.write_str("they belong to different companies"),
            Self::Cycle => f.write_str("the manager already reports to the agent"),
            Self::NotBootstrap => f.write_str(
                "only a company's first CEO starts active; hire any other agent for approval",
            ),
            Self::Terminated => f.write_str("the agent is terminated"),
            Self::HasTeams => f.write_str("the department still has teams"),
            Self::SeatTaken => f.write_str("the team already has someone in that seat"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for OrgError {}

/// Appends `action` by `actor` about `(kind, id)` of the company.
pub(crate) async fn append_org_event(
    conn: &mut SqliteConnection,
    company: CompanyId,
    actor: AuditActor,
    action: &str,
    (kind, id): (&str, i64),
    details: Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: kind.to_owned(),
            id,
        }),
        company_id: Some(company),
        run_id: None,
        details: details.to_string(),
    };
    audit::append(&mut *conn, &event).await.map(drop)
}

fn named(name: &str) -> Result<&str, OrgError> {
    match name.trim() {
        "" => Err(Error::InvalidArgument("a name is required".to_owned()).into()),
        name => Ok(name),
    }
}

/// Adds the free-form department `name` (#17) to the company and appends
/// `department.added`. A name the company has already is a constraint error.
pub async fn add_department(
    pool: &SqlitePool,
    company: CompanyId,
    name: &str,
    actor: AuditActor,
) -> Result<Department, OrgError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let d = add_department_in(&mut tx, company, name, actor).await?;
    tx.commit().await?;
    Ok(d)
}

/// `add_department` inside the caller's transaction.
pub(crate) async fn add_department_in(
    tx: &mut SqliteConnection,
    company: CompanyId,
    name: &str,
    actor: AuditActor,
) -> Result<Department, OrgError> {
    let name = named(name)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM companies WHERE id = ?)")
        .bind(company.0)
        .fetch_one(&mut *tx)
        .await?;
    if !exists {
        return Err(OrgError::NotFound);
    }
    let d = sqlx::query(
        "INSERT INTO departments (company_id, name) VALUES (?, ?) RETURNING id, company_id, name, about, head_agent_id",
    )
    .bind(company.0)
    .bind(name)
    .fetch_one(&mut *tx)
    .await
    .and_then(department)?;
    let details = json!({"name": name});
    append_org_event(
        tx,
        company,
        actor,
        "department.added",
        ("department", d.id.0),
        details,
    )
    .await?;
    Ok(d)
}

/// Adds team `name` to the department and appends `team.added`.
pub async fn add_team(
    pool: &SqlitePool,
    department: DepartmentId,
    name: &str,
    actor: AuditActor,
) -> Result<Team, OrgError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let t = add_team_in(&mut tx, department, name, actor).await?;
    tx.commit().await?;
    Ok(t)
}

/// `add_team` inside the caller's transaction.
pub(crate) async fn add_team_in(
    tx: &mut SqliteConnection,
    department: DepartmentId,
    name: &str,
    actor: AuditActor,
) -> Result<Team, OrgError> {
    let name = named(name)?;
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM departments WHERE id = ?")
        .bind(department.0)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(OrgError::NotFound)?;
    let t = sqlx::query(
        "INSERT INTO teams (department_id, name) VALUES (?, ?) RETURNING id, department_id, name",
    )
    .bind(department.0)
    .bind(name)
    .fetch_one(&mut *tx)
    .await
    .and_then(team)?;
    let details = json!({"name": name, "department": department.0});
    let company = CompanyId(company);
    append_org_event(tx, company, actor, "team.added", ("team", t.id.0), details).await?;
    Ok(t)
}

/// The company of the team, and of the agent; `NotFound` when either is missing.
async fn companies_of(
    conn: &mut SqliteConnection,
    team: TeamId,
    agent: AgentId,
) -> Result<(CompanyId, CompanyId), OrgError> {
    let row: Option<(Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT (SELECT d.company_id FROM teams t JOIN departments d ON d.id = t.department_id \
             WHERE t.id = ?), (SELECT company_id FROM agents WHERE id = ?)",
    )
    .bind(team.0)
    .bind(agent.0)
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some((Some(t), Some(a))) => Ok((CompanyId(t), CompanyId(a))),
        _ => Err(OrgError::NotFound),
    }
}

/// Seats the agent on the team as `role` with its per-sprint `capacity` (story points, or
/// none), or changes an existing seat to them, and appends `team.member_seated`. The agent must
/// be of the team's company; a second product owner or lead is a constraint error.
pub async fn seat_member(
    pool: &SqlitePool,
    team: TeamId,
    agent: AgentId,
    role: TeamRole,
    capacity: Option<u32>,
    actor: AuditActor,
) -> Result<TeamMembership, OrgError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let m = seat_member_in(&mut tx, team, agent, role, capacity, actor).await?;
    tx.commit().await?;
    Ok(m)
}

/// `seat_member` inside the caller's transaction.
pub(crate) async fn seat_member_in(
    tx: &mut SqliteConnection,
    team: TeamId,
    agent: AgentId,
    role: TeamRole,
    capacity: Option<u32>,
    actor: AuditActor,
) -> Result<TeamMembership, OrgError> {
    let (company, agents) = companies_of(tx, team, agent).await?;
    if company != agents {
        return Err(OrgError::OtherCompany);
    }
    sqlx::query(
        "INSERT INTO team_memberships (team_id, agent_id, team_role, capacity) \
         VALUES (?, ?, ?, ?) ON CONFLICT (team_id, agent_id) DO UPDATE SET \
         team_role = excluded.team_role, capacity = excluded.capacity",
    )
    .bind(team.0)
    .bind(agent.0)
    .bind(role.as_str())
    .bind(capacity)
    .execute(&mut *tx)
    .await?;
    let details = json!({"agent": agent.0, "team_role": role.as_str(), "capacity": capacity});
    append_org_event(
        tx,
        company,
        actor,
        "team.member_seated",
        ("team", team.0),
        details,
    )
    .await?;
    Ok(TeamMembership {
        team_id: team,
        agent_id: agent,
        team_role: role,
    })
}

/// Takes the agent off the team and appends `team.member_unseated`; `false` when it had no
/// seat there.
pub async fn unseat_member(
    pool: &SqlitePool,
    team: TeamId,
    agent: AgentId,
    actor: AuditActor,
) -> Result<bool, OrgError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let (company, _) = companies_of(&mut tx, team, agent).await?;
    let removed = sqlx::query("DELETE FROM team_memberships WHERE team_id = ? AND agent_id = ?")
        .bind(team.0)
        .bind(agent.0)
        .execute(&mut *tx)
        .await
        .map(affected)?;
    if removed {
        let details = json!({"agent": agent.0});
        let entity = ("team", team.0);
        append_org_event(
            &mut tx,
            company,
            actor,
            "team.member_unseated",
            entity,
            details,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(removed)
}

/// Refuses `manager` as `agent`'s (of `company`): another company's, or one that reports to it.
pub(super) async fn check_manager_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    company: i64,
    manager: Option<AgentId>,
) -> Result<(), OrgError> {
    let Some(m) = manager else {
        return Ok(());
    };
    let theirs: i64 = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(m.0)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(OrgError::NotFound)?;
    if theirs != company {
        return Err(OrgError::OtherCompany);
    }
    let cycle: bool = sqlx::query_scalar(
        "WITH RECURSIVE chain(id) AS (SELECT ?1 \
             UNION SELECT a.reports_to FROM agents a JOIN chain c ON a.id = c.id \
             WHERE a.reports_to IS NOT NULL) \
         SELECT EXISTS (SELECT 1 FROM chain WHERE id = ?2)",
    )
    .bind(m.0)
    .bind(agent.0)
    .fetch_one(&mut *conn)
    .await?;
    if cycle {
        return Err(OrgError::Cycle);
    }
    Ok(())
}

/// Sets who the agent reports to (`None`: nobody) and appends `agent.manager_set`. The
/// manager must be of the agent's company and must not report to it, directly or not. The
/// reporting line is the org chart's; escalation follows the issue's team (E6.3).
pub async fn set_manager(
    pool: &SqlitePool,
    agent: AgentId,
    manager: Option<AgentId>,
    actor: AuditActor,
) -> Result<Agent, OrgError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(agent.0)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(OrgError::NotFound)?;
    check_manager_in(&mut tx, agent, company, manager).await?;
    let a = sqlx::query(concat!(
        "UPDATE agents SET reports_to = ? WHERE id = ? RETURNING ",
        agent_columns!()
    ))
    .bind(manager.map(|m| m.0))
    .bind(agent.0)
    .fetch_one(&mut *tx)
    .await
    .and_then(super::agent)?;
    let details = json!({"reports_to": manager.map(|m| m.0)});
    let company = CompanyId(company);
    append_org_event(
        &mut tx,
        company,
        actor,
        "agent.manager_set",
        ("agent", agent.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(a)
}

/// The company's org chart as JSON: its agents (role, org role, manager, status, harness and
/// model) and its departments with their teams and seats (role and capacity); `None` when
/// there is no such company.
pub async fn org_chart(pool: &SqlitePool, company: CompanyId) -> Result<Option<Value>, Error> {
    let Some(c) = get_company(pool, company).await? else {
        return Ok(None);
    };
    let agents: Vec<Value> = list_agents(pool, company)
        .await?
        .iter()
        .map(|a| {
            json!({"id": a.id.0, "name": a.name, "role": a.role, "org_role": a.org_role.as_str(),
                   "reports_to": a.reports_to.map(|r| r.0), "status": a.status.as_str(),
                   "harness": a.harness.as_str(), "model": a.model})
        })
        .collect();
    let seats: Vec<(i64, i64, String, Option<u32>)> = sqlx::query_as(
        "SELECT m.team_id, m.agent_id, m.team_role, m.capacity FROM team_memberships m \
         JOIN teams t ON t.id = m.team_id JOIN departments d ON d.id = t.department_id \
         WHERE d.company_id = ? ORDER BY m.team_id, m.agent_id",
    )
    .bind(company.0)
    .fetch_all(pool)
    .await?;
    let mut departments = vec![];
    for d in list_departments(pool, company).await? {
        let mut teams = vec![];
        for t in list_teams(pool, d.id).await? {
            let members: Vec<Value> = seats
                .iter()
                .filter(|s| s.0 == t.id.0)
                .map(|(_, agent, role, capacity)| {
                    json!({"agent_id": agent, "team_role": role, "capacity": capacity})
                })
                .collect();
            teams.push(json!({"id": t.id.0, "name": t.name, "members": members}));
        }
        departments.push(json!({"id": d.id.0, "name": d.name, "about": d.about,
                                "head_agent_id": d.head_agent_id.map(|h| h.0), "teams": teams}));
    }
    Ok(Some(
        json!({"company": {"id": c.id.0, "name": c.name}, "agents": agents,
                   "departments": departments}),
    ))
}

/// Why a company is refused: no name, or a profile `CompanyProfile::invalid` refuses.
fn refused_company(name: &str, profile: &CompanyProfile) -> Result<(), Error> {
    let why = match name.trim() {
        "" => Some("a company needs a name".to_owned()),
        _ => profile.invalid(),
    };
    why.map_or(Ok(()), |why| Err(Error::InvalidArgument(why)))
}

/// The profile as audit details (the logo is audited by its own actions).
fn profile_details(p: &CompanyProfile) -> Value {
    json!({"color": p.color, "description": p.description, "industries": p.industries,
           "website": p.website, "timezone": p.timezone, "work_start": p.work_start,
           "work_end": p.work_end, "work_days": p.work_days})
}

/// Adds a company named `name` of `kind` (the admin's own or a client's, E15.14) with
/// `profile` (its logo aside) by `actor`, audited as `company.created`. An empty name or an
/// invalid profile is `InvalidArgument`.
pub async fn add_company(
    pool: &SqlitePool,
    name: &str,
    kind: ainkrad_core::org::CompanyKind,
    profile: &CompanyProfile,
    actor: AuditActor,
) -> Result<ainkrad_core::org::Company, Error> {
    refused_company(name, profile)?;
    let name = name.trim();
    let p = profile;
    let mut tx = crate::store::begin_write(pool).await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO companies (name, kind, color, description, industries, website, timezone, \
         work_start, work_end, work_days) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(name)
    .bind(kind.as_str())
    .bind(&p.color)
    .bind(&p.description)
    .bind(Json(&p.industries))
    .bind(&p.website)
    .bind(&p.timezone)
    .bind(p.work_start)
    .bind(p.work_end)
    .bind(p.work_days)
    .fetch_one(&mut *tx)
    .await?;
    let mut details = profile_details(p);
    details["name"] = json!(name);
    details["kind"] = json!(kind.as_str());
    let entity = ("company", id);
    append_org_event(
        &mut tx,
        CompanyId(id),
        actor,
        "company.created",
        entity,
        details,
    )
    .await?;
    let c = super::get_company(&mut *tx, CompanyId(id))
        .await?
        .ok_or(Error::RowNotFound)?;
    tx.commit().await?;
    Ok(c)
}

/// Changes the company's name, kind and profile (its logo aside) to `c`'s, by `actor`, audited
/// as `company.updated`; `false` when it is gone.
pub async fn edit_company(
    pool: &SqlitePool,
    c: &ainkrad_core::org::Company,
    actor: AuditActor,
) -> Result<bool, Error> {
    refused_company(&c.name, &c.profile)?;
    let p = &c.profile;
    let mut tx = crate::store::begin_write(pool).await?;
    let done = sqlx::query(
        "UPDATE companies SET name = ?, kind = ?, color = ?, description = ?, industries = ?, \
         website = ?, timezone = ?, work_start = ?, work_end = ?, work_days = ? WHERE id = ?",
    )
    .bind(c.name.trim())
    .bind(c.kind.as_str())
    .bind(&p.color)
    .bind(&p.description)
    .bind(Json(&p.industries))
    .bind(&p.website)
    .bind(&p.timezone)
    .bind(p.work_start)
    .bind(p.work_end)
    .bind(p.work_days)
    .bind(c.id.0)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    if done {
        let mut details = profile_details(p);
        details["name"] = json!(c.name.trim());
        details["kind"] = json!(c.kind.as_str());
        let entity = ("company", c.id.0);
        append_org_event(&mut tx, c.id, actor, "company.updated", entity, details).await?;
    }
    tx.commit().await?;
    Ok(done)
}
