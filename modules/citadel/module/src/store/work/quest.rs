//! Quest in server mode (E12) from the app: a project's settings and labels, its members'
//! sprint capacity, and an issue's flow times. Every write is one `begin_write` transaction,
//! audited by the admin's actor.

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::sqlite::SqliteRow;
use sqlx::{Error, Row, SqliteConnection, SqlitePool};

use super::requirements::append_org_event;
use crate::domain::org::{CompanyId, TeamId};
use crate::domain::work::{
    Label, LabelId, Project, ProjectId, ProjectMode, SprintApproval, is_hex_color,
};

mod flow;
pub use flow::*;

/// The columns of a project row, as `super::project` reads them.
macro_rules! project_cols {
    () => {
        "id, company_id, team_id, name, key, mode, sprint_approval, icon, color, logo_sha256, \
         extra_team_ids, runner_tags, max_parallel_runs, run_timeout_secs, worktree_keep_days"
    };
}

fn label(row: SqliteRow) -> Result<Label, Error> {
    Ok(Label {
        id: LabelId(row.try_get("id")?),
        project_id: ProjectId(row.try_get("project_id")?),
        name: row.try_get("name")?,
    })
}

async fn company_of(conn: &mut SqliteConnection, project: ProjectId) -> Result<CompanyId, Error> {
    sqlx::query_scalar("SELECT company_id FROM citadel_projects WHERE id = ?")
        .bind(project.0)
        .fetch_optional(&mut *conn)
        .await?
        .map(CompanyId)
        .ok_or(Error::RowNotFound)
}

fn invalid(why: &str) -> Error {
    Error::Protocol(why.to_owned())
}

/// A label name: one line, 1–50 characters.
fn label_name(name: &str) -> Result<&str, Error> {
    let name = name.trim();
    match !name.is_empty() && name.chars().count() <= 50 && !name.contains('\n') {
        true => Ok(name),
        false => Err(invalid("a label is one line of 1 to 50 characters")),
    }
}

fn taken(e: Error) -> Error {
    match &e {
        Error::Database(d) if d.message().contains("UNIQUE") => {
            invalid("the project has a label of that name")
        }
        _ => e,
    }
}

/// Adds a label to the project (`label.created`). A missing project is `RowNotFound`.
pub async fn add_label(
    pool: &SqlitePool,
    project: ProjectId,
    name: &str,
    actor: AuditActor,
) -> Result<Label, Error> {
    let name = label_name(name)?;
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let company = company_of(&mut tx, project).await?;
    let l = sqlx::query(
        "INSERT INTO citadel_labels (project_id, name) VALUES (?, ?) RETURNING id, project_id, name",
    )
    .bind(project.0)
    .bind(name)
    .fetch_one(&mut *tx)
    .await
    .map_err(taken)
    .and_then(label)?;
    let details = json!({"project": project.0, "name": l.name});
    append_org_event(
        &mut tx,
        company,
        actor,
        "label.created",
        ("label", l.id.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(l)
}

/// Renames the project's label (`label.renamed`), or deletes it from the project and every
/// issue (`label.deleted`) when `name` is `None`. `RowNotFound` when the project has no such
/// label.
pub async fn change_label(
    pool: &SqlitePool,
    project: ProjectId,
    id: LabelId,
    name: Option<&str>,
    actor: AuditActor,
) -> Result<Option<Label>, Error> {
    let name = name.map(label_name).transpose()?;
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let company = company_of(&mut tx, project).await?;
    let old: String =
        sqlx::query_scalar("SELECT name FROM citadel_labels WHERE id = ? AND project_id = ?")
            .bind(id.0)
            .bind(project.0)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::RowNotFound)?;
    let changed = match name {
        Some(name) => {
            let l = sqlx::query(
                "UPDATE citadel_labels SET name = ? WHERE id = ? RETURNING id, project_id, name",
            )
            .bind(name)
            .bind(id.0)
            .fetch_one(&mut *tx)
            .await
            .map_err(taken)
            .and_then(label)?;
            let details = json!({"project": project.0, "from": old, "to": name});
            append_org_event(
                &mut tx,
                company,
                actor,
                "label.renamed",
                ("label", id.0),
                details,
            )
            .await?;
            Some(l)
        }
        None => {
            let issues: Vec<i64> = sqlx::query_scalar(
                "DELETE FROM citadel_issue_labels WHERE label_id = ? RETURNING issue_id",
            )
            .bind(id.0)
            .fetch_all(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM citadel_labels WHERE id = ?")
                .bind(id.0)
                .execute(&mut *tx)
                .await?;
            let details = json!({"project": project.0, "name": old, "issues": issues});
            append_org_event(
                &mut tx,
                company,
                actor,
                "label.deleted",
                ("label", id.0),
                details,
            )
            .await?;
            None
        }
    };
    tx.commit().await?;
    Ok(changed)
}

/// The labels of each of `issues`, by name: `(issue, label)`.
pub async fn labels_of(pool: &SqlitePool, issues: &[i64]) -> Result<Vec<(i64, Label)>, Error> {
    let rows = sqlx::query(
        "SELECT il.issue_id, l.id, l.project_id, l.name FROM citadel_issue_labels il \
         JOIN citadel_labels l ON l.id = il.label_id \
         WHERE il.issue_id IN (SELECT value FROM json_each(?)) ORDER BY l.name, l.id",
    )
    .bind(json!(issues).to_string())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| Ok((row.try_get("issue_id")?, label(row)?)))
        .collect()
}

/// What may change of a project's settings; absent fields stay. Its key never changes: its
/// issues' keys are built from it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectChange {
    pub name: Option<String>,
    pub mode: Option<ProjectMode>,
    pub sprint_approval: Option<SprintApproval>,
    /// `Some(None)` clears the owning team.
    pub team_id: Option<Option<TeamId>>,
    /// Every team, the owner first: sets `team_id` (the first) and the others; wins over
    /// `team_id` when both are given.
    pub team_ids: Option<Vec<TeamId>>,
    /// `Some(None)` clears a field.
    pub icon: Option<Option<String>>,
    pub color: Option<Option<String>>,
    pub runner_tags: Option<Vec<String>>,
    pub max_parallel_runs: Option<Option<u32>>,
    pub run_timeout_secs: Option<Option<u32>>,
    pub worktree_keep_days: Option<Option<u32>>,
}

/// Whether a team is one of `company`'s.
async fn team_ok(
    conn: &mut SqliteConnection,
    team: TeamId,
    company: CompanyId,
) -> Result<(), Error> {
    let theirs: Option<i64> = sqlx::query_scalar(
        "SELECT d.company_id FROM citadel_teams t JOIN citadel_departments d ON d.id = t.department_id \
         WHERE t.id = ?",
    )
    .bind(team.0)
    .fetch_optional(&mut *conn)
    .await?;
    if theirs == Some(company.0) {
        Ok(())
    } else {
        Err(Error::RowNotFound)
    }
}

/// Applies `c` to the project inside the caller's transaction: the project as changed, and the
/// names of the fields that changed. A scrum project with a planned or active sprint does not
/// become kanban; teams must be the company's (`Error::RowNotFound` otherwise).
pub(crate) async fn change_in(
    conn: &mut SqliteConnection,
    project: ProjectId,
    c: &ProjectChange,
) -> Result<(Project, Vec<&'static str>), Error> {
    let company = company_of(conn, project).await?;
    let mut p = sqlx::query(concat!(
        "SELECT ",
        project_cols!(),
        " FROM citadel_projects WHERE id = ?"
    ))
    .bind(project.0)
    .fetch_one(&mut *conn)
    .await
    .and_then(super::project)?;
    let mut fields = vec![];
    if let Some(name) = c.name.as_deref().map(str::trim) {
        if name.is_empty() {
            return Err(invalid("a project needs a name"));
        }
        if name != p.name {
            p.name = name.to_owned();
            fields.push("name");
        }
    }
    if let Some(mode) = c.mode.filter(|m| *m != p.mode) {
        let sprinting: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM citadel_sprints WHERE project_id = ? \
             AND state IN ('planned', 'active'))",
        )
        .bind(project.0)
        .fetch_one(&mut *conn)
        .await?;
        if mode == ProjectMode::Kanban && sprinting {
            return Err(invalid(
                "close or remove its planned and active sprints first",
            ));
        }
        p.mode = mode;
        fields.push("mode");
    }
    if let Some(a) = c.sprint_approval.filter(|a| *a != p.sprint_approval) {
        p.sprint_approval = a;
        fields.push("sprint_approval");
    }
    let teams = match (&c.team_ids, c.team_id) {
        (Some(all), _) => Some(all.clone()),
        (None, Some(owner)) => {
            let rest = p
                .team_ids
                .iter()
                .skip(1)
                .copied()
                .filter(|t| Some(*t) != owner);
            Some(owner.into_iter().chain(rest).collect())
        }
        (None, None) => None,
    };
    if let Some(teams) = teams.filter(|t| *t != p.team_ids) {
        for (n, t) in teams.iter().enumerate() {
            if teams[..n].contains(t) {
                return Err(invalid("a team is on a project once"));
            }
            team_ok(conn, *t, company).await?;
        }
        if teams.len() > 10 {
            return Err(invalid("at most 10 teams on a project"));
        }
        p.team_id = teams.first().copied();
        p.team_ids = teams;
        fields.push("team_id");
    }
    if let Some(icon) = c.icon.as_ref().filter(|i| **i != p.icon) {
        let bad = |i: &String| i.trim().is_empty() || i.chars().count() > 64;
        if icon.as_ref().is_some_and(bad) {
            return Err(invalid("an icon is 1 to 64 characters"));
        }
        p.icon.clone_from(icon);
        fields.push("icon");
    }
    if let Some(color) = c.color.as_ref().filter(|i| **i != p.color) {
        if color.as_deref().is_some_and(|c| !is_hex_color(c)) {
            return Err(invalid("a colour is #rrggbb"));
        }
        p.color.clone_from(color);
        fields.push("color");
    }
    if let Some(tags) = c.runner_tags.as_ref().filter(|t| **t != p.runner_tags) {
        let bad = |t: &String| t.trim().is_empty() || t.chars().count() > 64;
        if tags.len() > 20 || tags.iter().any(bad) {
            return Err(invalid("at most 20 runner tags of 1 to 64 characters"));
        }
        p.runner_tags.clone_from(tags);
        fields.push("runner_tags");
    }
    for (new, old, name, max) in [
        (
            c.max_parallel_runs,
            &mut p.max_parallel_runs,
            "max_parallel_runs",
            (1, 64),
        ),
        (
            c.run_timeout_secs,
            &mut p.run_timeout_secs,
            "run_timeout_secs",
            (1, 604_800),
        ),
        (
            c.worktree_keep_days,
            &mut p.worktree_keep_days,
            "worktree_keep_days",
            (0, 3650),
        ),
    ] {
        if let Some(v) = new.filter(|v| v != old) {
            if v.is_some_and(|v| v < max.0 || v > max.1) {
                return Err(invalid(&format!("{name} is {} to {}", max.0, max.1)));
            }
            *old = v;
            fields.push(name);
        }
    }
    if !fields.is_empty() {
        let (extra, owner) = (
            p.team_ids.iter().skip(1).map(|t| t.0).collect::<Vec<_>>(),
            p.team_id,
        );
        sqlx::query(
            "UPDATE citadel_projects SET name = ?, mode = ?, sprint_approval = ?, team_id = ?, \
             extra_team_ids = ?, icon = ?, color = ?, runner_tags = ?, max_parallel_runs = ?, \
             run_timeout_secs = ?, worktree_keep_days = ? WHERE id = ?",
        )
        .bind(&p.name)
        .bind(p.mode.as_str())
        .bind(p.sprint_approval.as_str())
        .bind(owner.map(|t| t.0))
        .bind(sqlx::types::Json(extra))
        .bind(&p.icon)
        .bind(&p.color)
        .bind(sqlx::types::Json(&p.runner_tags))
        .bind(p.max_parallel_runs)
        .bind(p.run_timeout_secs)
        .bind(p.worktree_keep_days)
        .bind(project.0)
        .execute(&mut *conn)
        .await?;
    }
    Ok((p, fields))
}

/// Applies `c` to the project (`project.updated`, naming the fields changed).
pub async fn change_project(
    pool: &SqlitePool,
    project: ProjectId,
    c: &ProjectChange,
    actor: AuditActor,
) -> Result<Project, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let company = company_of(&mut tx, project).await?;
    let (p, fields) = change_in(&mut tx, project, c).await?;
    if !fields.is_empty() {
        let details = json!({"fields": fields, "name": p.name, "mode": p.mode.as_str(),
                             "sprint_approval": p.sprint_approval.as_str(),
                             "team": p.team_id.map(|t| t.0),
                             "teams": p.team_ids.iter().map(|t| t.0).collect::<Vec<_>>()});
        let entity = ("project", project.0);
        append_org_event(&mut tx, company, actor, "project.updated", entity, details).await?;
    }
    tx.commit().await?;
    Ok(p)
}
