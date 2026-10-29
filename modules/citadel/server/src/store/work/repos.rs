//! A project's repositories (E3.7, E15.16 multi-repo, decision #51). A project has any number of
//! repos in an order (the order agents see them and PRs merge in, #54), one of them primary.
//! Each has its own forge (E9.1: host, API, repository path, token file) and its own build, test,
//! lint and format commands.
//!
//! An issue touches the repos approved for it (`issue_repos`): set while planning by its
//! project's product owner or team lead (or the admin), or asked for by its agent mid-task
//! (`request_repo`) and decided by the team lead or a human (`decide_repo`, #55). With none
//! approved it touches the primary repo. Its runs get a worktree per repo, all on its one
//! branch name. Every change is audited.

use citadel_core::audit::AuditActor;
use citadel_core::exec::{NewWakeRequest, WakeSource};
use citadel_core::org::AgentId;
use citadel_core::work::{IssueId, ProjectId, ProjectRepo};
use ainkrad_proto::runner::{branch_name_ok, repo_url_problem};
use serde_json::json;
use sqlx::{SqliteConnection, SqliteExecutor};

use super::*;
use crate::store::forge::{ProjectForge, append, forge_problem, note};

/// A repo's commands, each empty when it has none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Commands {
    pub build: String,
    pub test: String,
    pub lint: String,
    pub format: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub id: i64,
    pub project_id: ProjectId,
    /// Its worktree's directory name in a multi-repo workspace: `[A-Za-z0-9._-]`.
    pub name: String,
    /// A URL or path git can clone; never holds credentials.
    pub url: String,
    pub default_branch: String,
    pub position: i64,
    pub primary: bool,
    pub forge: Option<ProjectForge>,
    pub commands: Commands,
}

macro_rules! repo_columns {
    () => {
        "id, project_id, name, url, default_branch, position, is_primary, forge_kind, \
         forge_api_url, forge_repo, forge_token_file, build_cmd, test_cmd, lint_cmd, format_cmd"
    };
}

fn repo(row: SqliteRow) -> Result<Repo, Error> {
    let project_id = ProjectId(row.try_get("project_id")?);
    let forge = match row.try_get::<Option<String>, _>("forge_kind")? {
        Some(kind) => Some(ProjectForge {
            project_id,
            kind: kind.parse().map_err(|e: String| Error::Decode(e.into()))?,
            api_url: row.try_get("forge_api_url")?,
            repo: row.try_get("forge_repo")?,
            token_file: row.try_get::<String, _>("forge_token_file")?.into(),
        }),
        None => None,
    };
    Ok(Repo {
        id: row.try_get("id")?,
        project_id,
        name: row.try_get("name")?,
        url: row.try_get("url")?,
        default_branch: row.try_get("default_branch")?,
        position: row.try_get("position")?,
        primary: row.try_get("is_primary")?,
        forge,
        commands: Commands {
            build: row.try_get("build_cmd")?,
            test: row.try_get("test_cmd")?,
            lint: row.try_get("lint_cmd")?,
            format: row.try_get("format_cmd")?,
        },
    })
}

/// Why `r` cannot be stored.
fn repo_problem(r: &Repo) -> Option<String> {
    let name_ok = !r.name.is_empty()
        && r.name.len() <= 100
        && !r.name.starts_with('.')
        && r.name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if !name_ok {
        return Some(format!(
            "bad repo name {:?}: [A-Za-z0-9._-], not starting with a dot",
            r.name
        ));
    }
    if let Some(why) = repo_url_problem(&r.url) {
        return Some(why);
    }
    if !branch_name_ok(&r.default_branch) {
        return Some(format!("bad branch name {:?}", r.default_branch));
    }
    let c = &r.commands;
    if [&c.build, &c.test, &c.lint, &c.format]
        .iter()
        .any(|c| c.len() > 1000 || c.contains('\0'))
    {
        return Some("a command is longer than 1000 bytes".to_owned());
    }
    r.forge.as_ref().and_then(forge_problem)
}

pub async fn list_repos(
    pool: impl SqliteExecutor<'_>,
    project: ProjectId,
) -> Result<Vec<Repo>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        repo_columns!(),
        " FROM project_repos WHERE project_id = ? \
                         ORDER BY position, id"
    ))
    .bind(project.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(repo)
    .collect()
}

pub async fn get_repo(pool: impl SqliteExecutor<'_>, id: i64) -> Result<Option<Repo>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        repo_columns!(),
        " FROM project_repos WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?
    .map(repo)
    .transpose()
}

/// The project's repo named `name`.
pub(crate) async fn repo_named(
    conn: &mut SqliteConnection,
    project: ProjectId,
    name: &str,
) -> Result<Option<Repo>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        repo_columns!(),
        " FROM project_repos \
                         WHERE project_id = ? AND name = ?"
    ))
    .bind(project.0)
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?
    .map(repo)
    .transpose()
}

async fn company_of(conn: &mut SqliteConnection, project: ProjectId) -> Result<Option<i64>, Error> {
    sqlx::query_scalar("SELECT company_id FROM projects WHERE id = ?")
        .bind(project.0)
        .fetch_optional(&mut *conn)
        .await
}

fn invalid(why: impl Into<String>) -> Error {
    Error::InvalidArgument(why.into())
}

/// Stores `r` as a new repo of its project (its `id`, `position` and `primary` are ignored):
/// last in order, primary when it is the project's first. `None` when there is no such project.
pub async fn add_repo(
    pool: &SqlitePool,
    r: &Repo,
    actor: AuditActor,
) -> Result<Option<Repo>, Error> {
    if let Some(why) = repo_problem(r) {
        return Err(invalid(why));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(company) = company_of(&mut tx, r.project_id).await? else {
        return Ok(None);
    };
    let f = r.forge.as_ref();
    let added = sqlx::query(concat!(
        "INSERT INTO project_repos (project_id, name, url, default_branch, position, is_primary, \
         forge_kind, forge_api_url, forge_repo, forge_token_file, build_cmd, test_cmd, lint_cmd, \
         format_cmd) SELECT ?1, ?2, ?3, ?4, coalesce(max(position) + 1, 0), count(*) = 0, ?5, ?6, \
         ?7, ?8, ?9, ?10, ?11, ?12 FROM project_repos WHERE project_id = ?1 RETURNING ",
        repo_columns!()
    ))
    .bind(r.project_id.0)
    .bind(&r.name)
    .bind(&r.url)
    .bind(&r.default_branch)
    .bind(f.map(|f| f.kind.as_str()))
    .bind(f.map(|f| f.api_url.clone()))
    .bind(f.map(|f| f.repo.clone()))
    .bind(f.map(|f| f.token_file.to_string_lossy().into_owned()))
    .bind(&r.commands.build)
    .bind(&r.commands.test)
    .bind(&r.commands.lint)
    .bind(&r.commands.format)
    .fetch_one(&mut *tx)
    .await
    .map_err(unique("a repo with that name or URL"))
    .and_then(repo)?;
    let details = json!({"repo": added.id, "name": added.name, "url": added.url,
                         "primary": added.primary});
    let entity = ("project", r.project_id.0);
    append(
        &mut tx,
        company,
        actor,
        "project.repo_added",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(Some(added))
}

/// A unique-constraint failure as `InvalidArgument` naming `what` already exists.
fn unique(what: &'static str) -> impl Fn(Error) -> Error {
    move |e| match &e {
        Error::Database(d) if d.message().contains("UNIQUE") => invalid(format!("{what} exists")),
        _ => e,
    }
}

/// Replaces repo `r.id`'s name, URL, default branch, forge and commands; `false` when it is gone.
pub async fn update_repo(pool: &SqlitePool, r: &Repo, actor: AuditActor) -> Result<bool, Error> {
    if let Some(why) = repo_problem(r) {
        return Err(invalid(why));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(current) = get_repo(&mut *tx, r.id).await? else {
        return Ok(false);
    };
    let f = r.forge.as_ref();
    sqlx::query(
        "UPDATE project_repos SET name = ?, url = ?, default_branch = ?, forge_kind = ?, \
         forge_api_url = ?, forge_repo = ?, forge_token_file = ?, build_cmd = ?, test_cmd = ?, \
         lint_cmd = ?, format_cmd = ? WHERE id = ?",
    )
    .bind(&r.name)
    .bind(&r.url)
    .bind(&r.default_branch)
    .bind(f.map(|f| f.kind.as_str()))
    .bind(f.map(|f| f.api_url.clone()))
    .bind(f.map(|f| f.repo.clone()))
    .bind(f.map(|f| f.token_file.to_string_lossy().into_owned()))
    .bind(&r.commands.build)
    .bind(&r.commands.test)
    .bind(&r.commands.lint)
    .bind(&r.commands.format)
    .bind(r.id)
    .execute(&mut *tx)
    .await
    .map_err(unique("a repo with that name or URL"))?;
    let company = company_of(&mut tx, current.project_id)
        .await?
        .unwrap_or_default();
    let details = json!({"repo": r.id, "name": r.name, "url": r.url,
                         "branch": r.default_branch, "forge": f.map(|f| &f.repo)});
    let entity = ("project", current.project_id.0);
    append(&mut tx, company, actor, "project.repo_set", entity, details).await?;
    tx.commit().await?;
    Ok(true)
}

/// Removes repo `id`; `false` when it is gone. Refused while an open issue touches it (approved
/// for it, or a live PR on it), and for the primary repo while the project has others.
pub async fn remove_repo(pool: &SqlitePool, id: i64, actor: AuditActor) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(r) = get_repo(&mut *tx, id).await? else {
        return Ok(false);
    };
    let others = list_repos(&mut *tx, r.project_id).await?.len() > 1;
    if r.primary && others {
        return Err(invalid(
            "make another repo primary before removing this one",
        ));
    }
    let open: Option<String> = sqlx::query_scalar(
        "SELECT p.key || '-' || i.number FROM issues i JOIN projects p ON p.id = i.project_id \
         WHERE i.state NOT IN ('done', 'cancelled') AND (EXISTS (SELECT 1 FROM issue_repos x \
             WHERE x.issue_id = i.id AND x.repo_id = ?1 AND x.state = 'approved') \
         OR EXISTS (SELECT 1 FROM issue_prs pr WHERE pr.issue_id = i.id AND pr.repo_id = ?1 \
             AND pr.state IN ('requested', 'open', 'merging'))) LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(key) = open {
        return Err(invalid(format!(
            "open issue {key} still touches repo {}",
            r.name
        )));
    }
    sqlx::query("DELETE FROM project_repos WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let company = company_of(&mut tx, r.project_id).await?.unwrap_or_default();
    let details = json!({"repo": id, "name": r.name});
    let entity = ("project", r.project_id.0);
    append(
        &mut tx,
        company,
        actor,
        "project.repo_removed",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Makes repo `id` its project's primary; `false` when it is gone.
pub async fn set_primary_repo(
    pool: &SqlitePool,
    id: i64,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(r) = get_repo(&mut *tx, id).await? else {
        return Ok(false);
    };
    sqlx::query("UPDATE project_repos SET is_primary = 0 WHERE project_id = ?")
        .bind(r.project_id.0)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE project_repos SET is_primary = 1 WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let company = company_of(&mut tx, r.project_id).await?.unwrap_or_default();
    let entity = ("project", r.project_id.0);
    let details = json!({"repo": id, "name": r.name});
    append(
        &mut tx,
        company,
        actor,
        "project.repo_primary",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Puts the project's repos in the order of `names` (every one of them, once); `false` when
/// there is no such project.
pub async fn order_repos(
    pool: &SqlitePool,
    project: ProjectId,
    names: &[String],
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(company) = company_of(&mut tx, project).await? else {
        return Ok(false);
    };
    let mut have: Vec<String> = list_repos(&mut *tx, project)
        .await?
        .into_iter()
        .map(|r| r.name)
        .collect();
    let mut given = names.to_vec();
    have.sort();
    given.sort();
    if have != given {
        return Err(invalid(format!(
            "name every repo once: {}",
            have.join(", ")
        )));
    }
    for (i, name) in names.iter().enumerate() {
        sqlx::query("UPDATE project_repos SET position = ? WHERE project_id = ? AND name = ?")
            .bind(i as i64)
            .bind(project.0)
            .bind(name)
            .execute(&mut *tx)
            .await?;
    }
    let entity = ("project", project.0);
    append(
        &mut tx,
        company,
        actor,
        "project.repos_ordered",
        entity,
        json!({"order": names}),
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// The repos `issue` touches, in its project's order: those approved for it, else the primary;
/// empty when its project has none.
pub async fn issue_repos_in(
    conn: &mut SqliteConnection,
    issue: IssueId,
) -> Result<Vec<Repo>, Error> {
    let approved: Vec<Repo> = sqlx::query(concat!(
        "SELECT ",
        repo_columns!(),
        " FROM project_repos WHERE id IN (SELECT repo_id \
         FROM issue_repos WHERE issue_id = ? AND state = 'approved') ORDER BY position, id"
    ))
    .bind(issue.0)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(repo)
    .collect::<Result<_, _>>()?;
    if !approved.is_empty() {
        return Ok(approved);
    }
    sqlx::query(concat!(
        "SELECT ",
        repo_columns!(),
        " FROM project_repos WHERE is_primary = 1 \
         AND project_id = (SELECT project_id FROM issues WHERE id = ?)"
    ))
    .bind(issue.0)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(repo)
    .collect()
}

/// The primary repo's name when `issue` has no approved repo of its own while its project has
/// more than one repo: the case where it silently lands in the primary (R19).
pub async fn implicit_primary_repo(
    pool: &SqlitePool,
    issue: IssueId,
) -> Result<Option<String>, Error> {
    sqlx::query_scalar(
        "SELECT name FROM project_repos WHERE is_primary = 1 \
         AND project_id = (SELECT project_id FROM issues WHERE id = ?1) \
         AND (SELECT COUNT(*) FROM project_repos \
              WHERE project_id = (SELECT project_id FROM issues WHERE id = ?1)) > 1 \
         AND NOT EXISTS (SELECT 1 FROM issue_repos WHERE issue_id = ?1 AND state = 'approved')",
    )
    .bind(issue.0)
    .fetch_optional(pool)
    .await
}

pub async fn issue_repos(pool: &SqlitePool, issue: IssueId) -> Result<Vec<Repo>, Error> {
    issue_repos_in(&mut *pool.acquire().await?, issue).await
}

mod extra;
mod requests;
mod single;
pub use extra::*;
pub use requests::*;
pub use single::*;
