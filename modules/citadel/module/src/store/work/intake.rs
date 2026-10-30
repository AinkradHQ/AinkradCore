//! CEO intake (E6.2, decision #11): CEO and CTO are routers, not relays.
//!
//! A request for a new goal or project (`submit_intake`) becomes an issue of the company's
//! intake project, waiting on the CEO, or on the admin when the company has no active CEO.
//! Routing it (`route_intake`) sends it to new projects (one per department it names, owned by
//! one of that department's teams) or to existing projects of the company, each with a kickoff
//! issue waiting on (and waking) the owning team's product owner, then closes the intake issue: from there the work flows inside the teams, and the
//! CEO is out of the loop (its escalations never come back to it, E6.3).
//!
//! Each request is also a requirement (E15.10): the projects routing creates carry it, every
//! kickoff issue carries it (an existing project keeps its own spec and requirement: the
//! requirement reaches it through its issues), and its owner moves from the CEO to the first
//! route's product owner.

use std::fmt;

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::{Error, SqliteConnection, SqlitePool};

use super::requirements::append_org_event;
use crate::domain::org::{AgentId, CompanyId, DepartmentId, TeamId};
use crate::domain::work::{
    Issue, IssueKind, IssueState, NewIssue, NewProject, NextActor, Project, ProjectId, ProjectMode,
    UserId,
};
use crate::store::work::{IssueTransitionError, ProjectChange, create_issue_in};

/// The columns of a project row, as `super::project` reads them.
macro_rules! project_cols {
    () => {
        "id, company_id, team_id, name, key, mode, sprint_approval, icon, color, logo_sha256, \
         extra_team_ids, runner_tags, max_parallel_runs, run_timeout_secs, worktree_keep_days"
    };
}

mod route;
pub use route::*;

/// Who handles intake when the company has no active CEO: the admin (#4).
pub const INTAKE_FALLBACK_USER: UserId = UserId(1);
/// The intake project's key, created with the company's first request. A company that already
/// has a project of that key gets the first free of `INTAKE2`, `INTAKE3`, …: the user's key wins,
/// the intake key is only a label.
pub const INTAKE_KEY: &str = "INTAKE";
/// The longest project key a route may ask for.
pub const MAX_KEY: usize = 10;
/// The most departments one request is routed to.
pub const MAX_ROUTES: usize = 10;

/// Where routing sends a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// A new project in `department`, owned by `team` (default: the department's first team).
    New {
        department: DepartmentId,
        team: Option<TeamId>,
        name: String,
        key: String,
        mode: ProjectMode,
    },
    /// An existing project of the company, kicked off by its team's product owner.
    Existing(ProjectId),
}

/// What routing created for one route.
#[derive(Debug, Clone, PartialEq)]
pub struct Routed {
    pub project: Project,
    /// Whether routing created the project (not an existing one).
    pub created: bool,
    /// The kickoff issue, waiting on the product owner.
    pub kickoff: Issue,
    pub product_owner: AgentId,
}

/// Why an intake was not submitted or routed.
#[derive(Debug)]
pub enum IntakeError {
    NotFound,
    /// The issue is not in its company's intake project.
    NotIntake,
    /// Only the intake's next actor routes it.
    NotYours,
    /// It was routed (or closed) already.
    Closed,
    /// A request goes to 1 to `MAX_ROUTES` departments.
    Routes(usize),
    /// The department is not in the request's company, or the team not in the department.
    Elsewhere,
    /// The department has no team to own the project.
    NoTeam(DepartmentId),
    /// The team has no product owner to start the project.
    NoProductOwner(TeamId),
    /// A project key is 1 to `MAX_KEY` capital letters and digits, starting with a letter.
    BadKey(String),
    /// The company has a project with that key already, or two routes ask for it.
    KeyTaken(String),
    /// An existing-project route names no project of the company, the intake project, or one
    /// another route names too.
    NotRoutable(ProjectId),
    /// The existing project has no team, so no product owner to kick it off.
    ProjectNoTeam(ProjectId),
    Transition(IssueTransitionError),
    Db(Error),
}

impl From<Error> for IntakeError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl From<IssueTransitionError> for IntakeError {
    fn from(e: IssueTransitionError) -> Self {
        Self::Transition(e)
    }
}

impl fmt::Display for IntakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such company or issue"),
            Self::NotIntake => f.write_str("the issue is not an intake request"),
            Self::NotYours => f.write_str("only the intake's next actor routes it"),
            Self::Closed => f.write_str("the intake request is closed (routed already)"),
            Self::Routes(n) => write!(f, "{n} routes; a request goes to 1 to {MAX_ROUTES}"),
            Self::Elsewhere => f.write_str(
                "the department is in another company, or the team in another department",
            ),
            Self::NoTeam(d) => write!(f, "department {} has no team to own the project", d.0),
            Self::NoProductOwner(t) => write!(f, "team {} has no product owner", t.0),
            Self::BadKey(k) => write!(
                f,
                "project key `{k}`: 1 to {MAX_KEY} capital letters and digits, starting with a letter"
            ),
            Self::KeyTaken(k) => write!(f, "the company has a project with key `{k}` already"),
            Self::NotRoutable(p) => write!(
                f,
                "project {} is not a project of the company a request can go to (not the \
                 intake project, named once)",
                p.0
            ),
            Self::ProjectNoTeam(p) => write!(f, "project {} has no team to kick it off", p.0),
            Self::Transition(e) => e.fmt(f),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for IntakeError {}

/// The company's intake project, created (kanban, no team) on first use under the first free
/// key of `INTAKE`, `INTAKE2`, … Called inside a `BEGIN IMMEDIATE` transaction, so the key
/// stays free until the insert.
async fn intake_project(conn: &mut SqliteConnection, company: CompanyId) -> Result<i64, Error> {
    let found: Option<i64> =
        sqlx::query_scalar("SELECT id FROM citadel_projects WHERE company_id = ? AND intake = 1")
            .bind(company.0)
            .fetch_optional(&mut *conn)
            .await?;
    if let Some(id) = found {
        return Ok(id);
    }
    let taken: Vec<String> = sqlx::query_scalar(
        "SELECT key FROM citadel_projects WHERE company_id = ? AND key GLOB 'INTAKE*'",
    )
    .bind(company.0)
    .fetch_all(&mut *conn)
    .await?;
    let key = (1..)
        .map(|n| match n {
            1 => INTAKE_KEY.to_owned(),
            n => format!("{INTAKE_KEY}{n}"),
        })
        .find(|k| !taken.contains(k))
        .unwrap_or_default();
    sqlx::query_scalar(
        "INSERT INTO citadel_projects (company_id, name, key, mode, sprint_approval, intake) \
         VALUES (?, 'Intake', ?, 'kanban', 'owner', 1) RETURNING id",
    )
    .bind(company.0)
    .bind(key)
    .fetch_one(&mut *conn)
    .await
}

/// Checks every route's key before anything is written, so routing refuses with a typed reason
/// rather than a database constraint: well-formed, not used by the company, not repeated.
async fn check_keys(
    conn: &mut SqliteConnection,
    company: CompanyId,
    keys: &[&str],
) -> Result<(), IntakeError> {
    for (n, &k) in keys.iter().enumerate() {
        let well_formed = (1..=MAX_KEY).contains(&k.len())
            && k.starts_with(|c: char| c.is_ascii_uppercase())
            && k.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
        if !well_formed {
            return Err(IntakeError::BadKey(k.to_owned()));
        }
        let used: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM citadel_projects WHERE company_id = ? AND key = ?)",
        )
        .bind(company.0)
        .bind(k)
        .fetch_one(&mut *conn)
        .await?;
        if used || keys[..n].contains(&k) {
            return Err(IntakeError::KeyTaken(k.to_owned()));
        }
    }
    Ok(())
}

/// Files a request for a new goal or project as an issue of the company's intake project,
/// waiting on (and waking) its active CEO, or on `INTAKE_FALLBACK_USER` when it has none,
/// and appends `intake.submitted` by `actor`, in one `BEGIN IMMEDIATE` transaction.
pub async fn submit_intake(
    pool: &SqlitePool,
    company: CompanyId,
    title: &str,
    body: &str,
    actor: AuditActor,
) -> Result<Issue, IntakeError> {
    submit_intake_with(pool, company, title, body, &IntakeExtra::default(), actor).await
}

/// What a request may say beyond its title and body (API minor 18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntakeExtra {
    /// The company's project it is for: a hint, named in the CEO's wake.
    pub project_id: Option<ProjectId>,
    pub priority_level: crate::domain::work::PriorityLevel,
    pub criteria: Vec<crate::domain::work::Criterion>,
}

impl Default for IntakeExtra {
    fn default() -> Self {
        Self {
            project_id: None,
            priority_level: crate::domain::work::PriorityLevel::None,
            criteria: vec![],
        }
    }
}

/// `submit_intake` with `extra`, kept on the requirement and its intake issue; a project of
/// another company is `IntakeError::Elsewhere`, a bad criterion `Error::Protocol`.
pub async fn submit_intake_with(
    pool: &SqlitePool,
    company: CompanyId,
    title: &str,
    body: &str,
    extra: &IntakeExtra,
    actor: AuditActor,
) -> Result<Issue, IntakeError> {
    let criteria = super::issues::clean_criteria(&extra.criteria)?;
    if title.trim().is_empty() {
        return Err(Error::Protocol("a request needs a title".to_owned()).into());
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM citadel_companies WHERE id = ?)")
            .bind(company.0)
            .fetch_one(&mut *tx)
            .await?;
    if !exists {
        return Err(IntakeError::NotFound);
    }
    let hint: Option<String> = match extra.project_id {
        Some(p) => {
            let key: Option<(i64, String)> =
                sqlx::query_as("SELECT company_id, key FROM citadel_projects WHERE id = ?")
                    .bind(p.0)
                    .fetch_optional(&mut *tx)
                    .await?;
            match key {
                Some((c, key)) if c == company.0 => Some(key),
                _ => return Err(IntakeError::Elsewhere),
            }
        }
        None => None,
    };
    let project = intake_project(&mut tx, company).await?;
    let ceo: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM citadel_agents WHERE company_id = ? AND org_role = 'ceo' AND status = 'active'",
    )
    .bind(company.0)
    .fetch_optional(&mut *tx)
    .await?;
    let next = match ceo {
        Some(ceo) => NextActor::Agent(AgentId(ceo)),
        None => NextActor::Human(INTAKE_FALLBACK_USER),
    };
    let new = NewIssue {
        project_id: ProjectId(project),
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Story,
        title: title.trim().to_owned(),
        body: body.to_owned(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(next.clone()),
        points: None,
        sprint_id: None,
    };
    let mut i = create_issue_in(&mut tx, &new).await?;
    let owner = match next {
        NextActor::Agent(ceo) => Some(ceo),
        _ => None,
    };
    let r = super::requirements::create_requirement_in(&mut tx, company, &i, owner, actor).await?;
    i.requirement_id = Some(r.id);
    let level = extra.priority_level;
    let json = super::issues::criteria_json(&criteria);
    sqlx::query(
        "UPDATE citadel_requirements SET project_id = ?, priority_level = ?, criteria = ? WHERE id = ?",
    )
    .bind(extra.project_id.map(|p| p.0))
    .bind(level.as_str())
    .bind(&json)
    .bind(r.id.0)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE citadel_issues SET priority_level = ?, priority = ?, criteria = ? WHERE id = ?",
    )
    .bind(level.as_str())
    .bind(level.is_high())
    .bind(&json)
    .bind(i.id.0)
    .execute(&mut *tx)
    .await?;
    i.priority_level = level;
    i.priority = level.is_high();
    i.criteria = criteria;
    // S7: the CEO's `assignment` wake (`intake:<issue>`, reason "intake request: <title>", with
    // " (for project <key>)" when `hint` names one) is enqueued here; the module has no wake
    // queue yet.
    let _ = &hint;
    let details = json!({"title": i.title, "next_actor": format!("{next:?}")});
    let entity = ("issue", i.id.0);
    append_org_event(&mut tx, company, actor, "intake.submitted", entity, details).await?;
    tx.commit().await?;
    Ok(i)
}

/// Adds a project to `p.company_id` outside intake (the app's "New project"), its key checked as
/// a route's, its team (if any) one of the company's; appends `project.created` by `actor`, in one
/// `BEGIN IMMEDIATE` transaction. The project starts with the default permission policy (ask).
pub async fn add_project(
    pool: &SqlitePool,
    p: &NewProject,
    actor: AuditActor,
) -> Result<Project, IntakeError> {
    add_project_with(pool, p, &ProjectChange::default(), actor).await
}

/// `add_project` with `extra` (icon, colour, more teams, runtime limits) applied in the same
/// transaction: a refused value creates nothing.
pub async fn add_project_with(
    pool: &SqlitePool,
    p: &NewProject,
    extra: &ProjectChange,
    actor: AuditActor,
) -> Result<Project, IntakeError> {
    if p.name.trim().is_empty() {
        return Err(Error::Protocol("a project needs a name".to_owned()).into());
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    if let Some(team) = p.team_id {
        let theirs: Option<i64> = sqlx::query_scalar(
            "SELECT d.company_id FROM citadel_teams t JOIN citadel_departments d ON d.id = t.department_id \
             WHERE t.id = ?",
        )
        .bind(team.0)
        .fetch_optional(&mut *tx)
        .await?;
        if theirs != Some(p.company_id.0) {
            return Err(IntakeError::Elsewhere);
        }
    }
    check_keys(&mut tx, p.company_id, &[p.key.as_str()]).await?;
    let project = sqlx::query(concat!(
        "INSERT INTO citadel_projects (company_id, team_id, name, key, mode, sprint_approval) \
         VALUES (?, ?, ?, ?, ?, ?) RETURNING ",
        project_cols!()
    ))
    .bind(p.company_id.0)
    .bind(p.team_id.map(|t| t.0))
    .bind(p.name.trim())
    .bind(&p.key)
    .bind(p.mode.as_str())
    .bind(p.sprint_approval.as_str())
    .fetch_one(&mut *tx)
    .await
    .and_then(super::project)?;
    let project = match extra == &ProjectChange::default() {
        true => project,
        false => match super::quest::change_in(&mut tx, project.id, extra).await {
            Ok((changed, _)) => changed,
            Err(Error::RowNotFound) => return Err(IntakeError::Elsewhere),
            Err(e) => return Err(e.into()),
        },
    };
    let details = json!({"key": project.key, "name": project.name, "mode": project.mode.as_str(),
                         "team": p.team_id.map(|t| t.0)});
    let entity = ("project", project.id.0);
    append_org_event(
        &mut tx,
        p.company_id,
        actor,
        "project.created",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(project)
}
