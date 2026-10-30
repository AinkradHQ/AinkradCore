//! Work repository: projects (and their git repos), epics, sprints and labels here; issues, blocker links and
//! comments in `issues`; CEO intake in `intake`.
//!
//! `update_*` / `delete_*` / `remove_*` return `false` when no row matched. Same-project
//! rules (epic, sprint, parent, label) and same-company rules (owning team) are enforced by
//! database triggers and surface as `Error::Database`.

use crate::domain::org::{CompanyId, TeamId};
use crate::domain::work::{
    Epic, EpicId, IssueId, Label, LabelId, NewProject, NewSprint, Project, ProjectId,
    RequirementId, Sprint, SprintId, SprintState, UserId,
};
use ainkrad_core::audit::AuditActor;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::types::Json;
use sqlx::{Error, Row};

use crate::store::org::{affected, text};

// The slice's own modules (S4a) and the planning slice's (S4b): the store's glob re-exports keep
// the monolith's flat `store::work::<fn>` names.
mod branch;
mod cfd;
pub mod hub;
pub mod intake;
pub mod issues;
pub mod logo;
mod metrics;
mod policy;
pub mod profile;
pub mod quest;
mod repos;
pub mod requirements;
pub use branch::*;
pub use cfd::*;
pub use hub::*;
pub use intake::*;
pub use issues::*;
pub use metrics::*;
pub use policy::*;
pub use profile::*;
pub use quest::*;
pub use repos::*;
pub use requirements::*;

/// The Core's audit actor for the person `u` (its user id is the Core's, not the module's).
pub(crate) const fn core_user(u: UserId) -> AuditActor {
    AuditActor::User(ainkrad_core::ids::UserId(u.0))
}

// --- projects ---------------------------------------------------------------

macro_rules! project_columns {
    () => {
        "id, company_id, team_id, name, key, mode, sprint_approval, icon, color, logo_sha256, \
         extra_team_ids, runner_tags, max_parallel_runs, run_timeout_secs, worktree_keep_days"
    };
}

fn project(row: SqliteRow) -> Result<Project, Error> {
    let team_id = row.try_get::<Option<i64>, _>("team_id")?.map(TeamId);
    let extra: Json<Vec<i64>> = row.try_get("extra_team_ids")?;
    Ok(Project {
        id: ProjectId(row.try_get("id")?),
        company_id: CompanyId(row.try_get("company_id")?),
        team_id,
        team_ids: team_id
            .into_iter()
            .chain(extra.0.into_iter().map(TeamId))
            .collect(),
        icon: row.try_get("icon")?,
        color: row.try_get("color")?,
        logo_sha256: row.try_get("logo_sha256")?,
        runner_tags: row.try_get::<Json<Vec<String>>, _>("runner_tags")?.0,
        max_parallel_runs: row.try_get("max_parallel_runs")?,
        run_timeout_secs: row.try_get("run_timeout_secs")?,
        worktree_keep_days: row.try_get("worktree_keep_days")?,
        name: row.try_get("name")?,
        key: row.try_get("key")?,
        mode: text(&row, "mode")?,
        sprint_approval: text(&row, "sprint_approval")?,
    })
}

pub async fn create_project(pool: &SqlitePool, p: &NewProject) -> Result<Project, Error> {
    sqlx::query(concat!(
        "INSERT INTO citadel_projects (company_id, team_id, name, key, mode, sprint_approval) \
         VALUES (?, ?, ?, ?, ?, ?) RETURNING ",
        project_columns!()
    ))
    .bind(p.company_id.0)
    .bind(p.team_id.map(|t| t.0))
    .bind(&p.name)
    .bind(&p.key)
    .bind(p.mode.as_str())
    .bind(p.sprint_approval.as_str())
    .fetch_one(pool)
    .await
    .and_then(project)
}

pub async fn get_project(pool: &SqlitePool, id: ProjectId) -> Result<Option<Project>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        project_columns!(),
        " FROM citadel_projects WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(project)
    .transpose()
}

pub async fn list_projects(
    pool: &SqlitePool,
    company_id: CompanyId,
) -> Result<Vec<Project>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        project_columns!(),
        " FROM citadel_projects WHERE company_id = ? ORDER BY id"
    ))
    .bind(company_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(project)
    .collect()
}

/// Updates every field except `company_id`; a project does not move between companies.
pub async fn update_project(pool: &SqlitePool, p: &Project) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE citadel_projects SET team_id = ?, name = ?, key = ?, mode = ?, sprint_approval = ? \
         WHERE id = ?",
    )
    .bind(p.team_id.map(|t| t.0))
    .bind(&p.name)
    .bind(&p.key)
    .bind(p.mode.as_str())
    .bind(p.sprint_approval.as_str())
    .bind(p.id.0)
    .execute(pool)
    .await
    .map(affected)
}

/// Cascades to the project's epics, sprints, labels, issues, links and comments.
pub async fn delete_project(pool: &SqlitePool, id: ProjectId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM citadel_projects WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}

/// Of `issues`, those that are done, cancelled or gone: their worktrees can go.
pub async fn closed_issues(pool: &SqlitePool, issues: &[i64]) -> Result<Vec<i64>, Error> {
    sqlx::query_scalar(
        "SELECT value FROM json_each(?) WHERE value NOT IN \
         (SELECT id FROM citadel_issues WHERE state NOT IN ('done', 'cancelled')) ORDER BY value",
    )
    .bind(Json(issues))
    .fetch_all(pool)
    .await
}

// --- epics ------------------------------------------------------------------

macro_rules! epic_columns {
    () => {
        "id, project_id, title, status, number, color, starts_on, ends_on, requirement_id"
    };
}

fn epic(row: SqliteRow) -> Result<Epic, Error> {
    Ok(Epic {
        id: EpicId(row.try_get("id")?),
        project_id: ProjectId(row.try_get("project_id")?),
        title: row.try_get("title")?,
        status: text(&row, "status")?,
        number: row.try_get("number")?,
        color: row.try_get("color")?,
        starts_on: row.try_get("starts_on")?,
        ends_on: row.try_get("ends_on")?,
        requirement_id: row
            .try_get::<Option<i64>, _>("requirement_id")?
            .map(RequirementId),
    })
}

/// Creates an `open` epic.
pub async fn create_epic(
    pool: &SqlitePool,
    project_id: ProjectId,
    title: &str,
) -> Result<Epic, Error> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO citadel_epics (project_id, title, requirement_id) VALUES (?1, ?2, \
         (SELECT requirement_id FROM citadel_projects WHERE id = ?1)) RETURNING id",
    )
    .bind(project_id.0)
    .bind(title)
    .fetch_one(pool)
    .await?;
    // Numbered by the insert's trigger, which RETURNING does not see.
    get_epic(pool, EpicId(id)).await?.ok_or(Error::RowNotFound)
}

pub async fn get_epic(pool: &SqlitePool, id: EpicId) -> Result<Option<Epic>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        epic_columns!(),
        " FROM citadel_epics WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(epic)
    .transpose()
}

/// The epic, read inside the caller's transaction.
pub(crate) async fn get_epic_in(
    conn: &mut sqlx::SqliteConnection,
    id: EpicId,
) -> Result<Option<Epic>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        epic_columns!(),
        " FROM citadel_epics WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(epic)
    .transpose()
}

pub async fn list_epics(pool: &SqlitePool, project_id: ProjectId) -> Result<Vec<Epic>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        epic_columns!(),
        " FROM citadel_epics WHERE project_id = ? ORDER BY id"
    ))
    .bind(project_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(epic)
    .collect()
}

/// Updates title and status; an epic does not move between projects.
pub async fn update_epic(pool: &SqlitePool, e: &Epic) -> Result<bool, Error> {
    sqlx::query("UPDATE citadel_epics SET title = ?, status = ? WHERE id = ?")
        .bind(&e.title)
        .bind(e.status.as_str())
        .bind(e.id.0)
        .execute(pool)
        .await
        .map(affected)
}

/// Its issues stay, with no epic.
pub async fn delete_epic(pool: &SqlitePool, id: EpicId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM citadel_epics WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}

// --- sprints ----------------------------------------------------------------

macro_rules! sprint_columns {
    () => {
        "id, project_id, name, goal, state, starts_on, ends_on"
    };
}

fn sprint(row: SqliteRow) -> Result<Sprint, Error> {
    Ok(Sprint {
        id: SprintId(row.try_get("id")?),
        project_id: ProjectId(row.try_get("project_id")?),
        name: row.try_get("name")?,
        goal: row.try_get("goal")?,
        state: text(&row, "state")?,
        starts_on: row.try_get("starts_on")?,
        ends_on: row.try_get("ends_on")?,
    })
}

/// Creates a `planned` sprint; any other state is `Error::InvalidArgument`: a sprint becomes
/// active or closed only through the commit gate (`commit_sprint`) and `close_sprint`.
pub async fn create_sprint(pool: &SqlitePool, s: &NewSprint) -> Result<Sprint, Error> {
    if s.state != SprintState::Planned {
        let why = format!("a sprint cannot be created {}", s.state.as_str());
        return Err(Error::InvalidArgument(why));
    }
    sqlx::query(concat!(
        "INSERT INTO citadel_sprints (project_id, name, goal, state, starts_on, ends_on) \
         VALUES (?, ?, ?, ?, ?, ?) RETURNING ",
        sprint_columns!()
    ))
    .bind(s.project_id.0)
    .bind(&s.name)
    .bind(&s.goal)
    .bind(s.state.as_str())
    .bind(&s.starts_on)
    .bind(&s.ends_on)
    .fetch_one(pool)
    .await
    .and_then(sprint)
}

pub async fn get_sprint(pool: &SqlitePool, id: SprintId) -> Result<Option<Sprint>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        sprint_columns!(),
        " FROM citadel_sprints WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(sprint)
    .transpose()
}

pub async fn list_sprints(pool: &SqlitePool, project_id: ProjectId) -> Result<Vec<Sprint>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        sprint_columns!(),
        " FROM citadel_sprints WHERE project_id = ? ORDER BY id"
    ))
    .bind(project_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(sprint)
    .collect()
}

/// Updates name, goal and dates. A sprint does not move between projects, and its state
/// changes only through the commit gate (`commit_sprint`) and `close_sprint`.
pub async fn update_sprint(pool: &SqlitePool, s: &Sprint) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE citadel_sprints SET name = ?, goal = ?, starts_on = ?, ends_on = ? WHERE id = ?",
    )
    .bind(&s.name)
    .bind(&s.goal)
    .bind(&s.starts_on)
    .bind(&s.ends_on)
    .bind(s.id.0)
    .execute(pool)
    .await
    .map(affected)
}

/// Its issues return to the backlog.
pub async fn delete_sprint(pool: &SqlitePool, id: SprintId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM citadel_sprints WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}

// --- labels -----------------------------------------------------------------

fn label(row: SqliteRow) -> Result<Label, Error> {
    Ok(Label {
        id: LabelId(row.try_get("id")?),
        project_id: ProjectId(row.try_get("project_id")?),
        name: row.try_get("name")?,
    })
}

pub async fn create_label(
    pool: &SqlitePool,
    project_id: ProjectId,
    name: &str,
) -> Result<Label, Error> {
    sqlx::query(
        "INSERT INTO citadel_labels (project_id, name) VALUES (?, ?) RETURNING id, project_id, name",
    )
    .bind(project_id.0)
    .bind(name)
    .fetch_one(pool)
    .await
    .and_then(label)
}

pub async fn get_label(pool: &SqlitePool, id: LabelId) -> Result<Option<Label>, Error> {
    sqlx::query("SELECT id, project_id, name FROM citadel_labels WHERE id = ?")
        .bind(id.0)
        .fetch_optional(pool)
        .await?
        .map(label)
        .transpose()
}

pub async fn list_labels(pool: &SqlitePool, project_id: ProjectId) -> Result<Vec<Label>, Error> {
    sqlx::query(
        "SELECT id, project_id, name FROM citadel_labels WHERE project_id = ? ORDER BY name",
    )
    .bind(project_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(label)
    .collect()
}

/// Renames only.
pub async fn update_label(pool: &SqlitePool, l: &Label) -> Result<bool, Error> {
    sqlx::query("UPDATE citadel_labels SET name = ? WHERE id = ?")
        .bind(&l.name)
        .bind(l.id.0)
        .execute(pool)
        .await
        .map(affected)
}

/// Removes the label from every issue.
pub async fn delete_label(pool: &SqlitePool, id: LabelId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM citadel_labels WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}

#[cfg(test)]
mod planning_tests;
#[cfg(test)]
mod tests;
