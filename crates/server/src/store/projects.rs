//! Projects (Core 0.9, P1-01): a slug, a name and a set of git repos, one of them primary.
//! A project is archived, never deleted. Every write is audited (`project.*`) and, for the
//! project itself, emitted as an event of the same name in the same transaction. Remotes are
//! checked with `repo_url_problem`; no credential ever lives here. Mirrors are held on the Core
//! machine, so a repo has at most one mirror row.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::{Value, json};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Row, SqliteConnection};

use super::secrets::Error;

/// Slugs that would shadow the Core's own `<name>.ainkrad.io` hosts.
/// Who acts and when: the device named in the audit details, the audit actor, the clock reading.
#[derive(Debug, Clone, Copy)]
pub struct Who<'a> {
    pub by_device: &'a str,
    pub actor: AuditActor,
    pub now: &'a str,
}

/// Also every module name (`modules/*`): a secret named `<module>.…` is that module's to open
/// (`secrets::open_for_module`), so no project may own that prefix. Add a module here when it
/// is added under `modules/`.
pub const RESERVED: &[&str] = &[
    "www", "api", "core", "signin", "admin", "mail", "app", "status", "docs", "brain", "citadel",
    "design", "leyline", "lore", "toy",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Project {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub state: String,
    pub source: String,
    pub secret_group: Option<i64>,
    pub expose: bool,
    pub idle_minutes: i64,
    pub cpu_limit: f64,
    pub mem_limit_mb: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub id: i64,
    pub project_id: i64,
    pub name: String,
    pub remote_url: String,
    pub default_branch: String,
    pub is_primary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirror {
    pub repo_id: i64,
    pub head: Option<String>,
    pub fetched_at: Option<String>,
    pub error: Option<String>,
}

fn refused<T>(code: &'static str, message: &str) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.to_owned(),
    })
}

/// A DNS label, 2-40 characters, not reserved: what the table's CHECK allows, plus the list.
pub fn slug_problem(slug: &str) -> Option<&'static str> {
    let b = slug.as_bytes();
    if !(2..=40).contains(&b.len())
        || !b[0].is_ascii_lowercase()
        || b[b.len() - 1] == b'-'
        || !b
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
    {
        return Some(
            "a slug is 2-40 characters of a-z, 0-9 and -, starting with a letter and not ending in -",
        );
    }
    RESERVED.contains(&slug).then_some("that slug is reserved")
}

const SELECT: &str = "SELECT id, slug, name, description, state, source, secret_group, expose, \
    idle_minutes, cpu_limit, mem_limit_mb, created_at, updated_at FROM core_projects";

fn project(r: SqliteRow) -> Result<Project, sqlx::Error> {
    Ok(Project {
        id: r.try_get("id")?,
        slug: r.try_get("slug")?,
        name: r.try_get("name")?,
        description: r.try_get("description")?,
        state: r.try_get("state")?,
        source: r.try_get("source")?,
        secret_group: r.try_get("secret_group")?,
        expose: r.try_get::<i64, _>("expose")? != 0,
        idle_minutes: r.try_get("idle_minutes")?,
        cpu_limit: r.try_get("cpu_limit")?,
        mem_limit_mb: r.try_get("mem_limit_mb")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

fn repo(r: SqliteRow) -> Result<Repo, sqlx::Error> {
    Ok(Repo {
        id: r.try_get("id")?,
        project_id: r.try_get("project_id")?,
        name: r.try_get("name")?,
        remote_url: r.try_get("remote_url")?,
        default_branch: r.try_get("default_branch")?,
        is_primary: r.try_get::<i64, _>("is_primary")? != 0,
    })
}

pub async fn get(conn: &mut SqliteConnection, id: i64) -> Result<Project, Error> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!("{SELECT} WHERE id = ?")))
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    match row {
        Some(row) => Ok(project(row)?),
        None => refused("not_found", "no such project"),
    }
}

/// The project a public host label names (P6-02): the one whose slug is `label`, else the one
/// with the longest slug that `label` starts with followed by `-` (`<slug>-<service>`). Active,
/// exposed ones only, filtered before the `LIMIT`: an archived or hidden `shop-api` never shadows
/// `shop`'s `api` service. One query, whatever the label.
pub async fn for_host(pool: &SqlitePool, label: &str) -> Result<Option<Project>, sqlx::Error> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE state = 'active' AND expose != 0 \
         AND (slug = ?1 OR substr(?1, 1, length(slug) + 1) = slug || '-') \
         ORDER BY length(slug) DESC LIMIT 1"
    )))
    .bind(label)
    .fetch_optional(pool)
    .await?
    .map(project)
    .transpose()
}

/// Projects by slug; archived ones only when `archived` is set.
pub async fn list(pool: &SqlitePool, archived: bool) -> Result<Vec<Project>, sqlx::Error> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE (? OR state = 'active') ORDER BY slug"
    )))
    .bind(archived)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(project)
    .collect()
}

/// A project's repos, primary first, then by name.
pub async fn repos(conn: &mut SqliteConnection, project_id: i64) -> Result<Vec<Repo>, sqlx::Error> {
    sqlx::query(
        "SELECT id, project_id, name, remote_url, default_branch, is_primary \
         FROM core_project_repos WHERE project_id = ? ORDER BY is_primary DESC, name",
    )
    .bind(project_id)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(repo)
    .collect()
}

/// Audit row plus, for `project.created/updated/archived`, the event, in the caller's transaction.
pub(super) async fn record(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    id: i64,
    details: Value,
    event: bool,
) -> Result<(), Error> {
    let entry = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "project".to_owned(),
            id,
        }),
        details: details.to_string(),
    };
    super::audit::append(conn, &entry).await?;
    if event {
        let mut payload = details;
        payload["id"] = json!(id);
        super::events::append(conn, action, &payload).await?;
    }
    Ok(())
}

fn line(text: &str, max: usize, what: &str) -> Result<(), Error> {
    match (1..=max).contains(&text.chars().count()) && !text.contains(['\n', '\r']) {
        true => Ok(()),
        false => refused(
            "bad_request",
            &format!("{what} is one line of 1-{max} characters"),
        ),
    }
}

/// A project name: one line of 1-100 characters.
pub fn name_ok(name: &str) -> Result<(), Error> {
    line(name, 100, "a name")
}

pub async fn create(
    pool: &SqlitePool,
    slug: &str,
    name: &str,
    description: &str,
    source: &str,
    who: Who<'_>,
) -> Result<Project, Error> {
    if let Some(why) = slug_problem(slug) {
        return refused("bad_request", why);
    }
    line(name, 100, "a name")?;
    if !["manual", "github"].contains(&source) {
        return refused("bad_request", "a source is manual or github");
    }
    let mut tx = super::begin_write(pool).await?;
    let p = create_in(&mut tx, slug, name, description, source, who).await?;
    tx.commit().await?;
    Ok(p)
}

/// [`create`] inside the caller's write transaction.
async fn create_in(
    tx: &mut SqliteConnection,
    slug: &str,
    name: &str,
    description: &str,
    source: &str,
    who: Who<'_>,
) -> Result<Project, Error> {
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM core_projects WHERE slug = ?")
        .bind(slug)
        .fetch_one(&mut *tx)
        .await?;
    if taken > 0 {
        return refused("conflict", "a project of that slug exists");
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO core_projects (slug, name, description, source, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(slug)
    .bind(name)
    .bind(description)
    .bind(source)
    .bind(who.now)
    .bind(who.now)
    .fetch_one(&mut *tx)
    .await?;
    let details = json!({"slug": slug, "name": name, "source": source, "by_device": who.by_device});
    record(tx, who.actor, "project.created", id, details, true).await?;
    let p = get(tx, id).await?;
    super::project_secrets::ensure_group(tx, &p, who).await?;
    get(tx, id).await
}

/// Changes name, description and/or public exposure (`None` keeps it). An archived project is
/// read-only.
pub async fn update(
    pool: &SqlitePool,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
    expose: Option<bool>,
    who: Who<'_>,
) -> Result<Project, Error> {
    let mut tx = super::begin_write(pool).await?;
    let old = get(&mut tx, id).await?;
    if old.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let name = name.unwrap_or(&old.name);
    line(name, 100, "a name")?;
    let description = description.unwrap_or(&old.description);
    let expose = expose.unwrap_or(old.expose);
    sqlx::query(
        "UPDATE core_projects SET name = ?, description = ?, expose = ?, updated_at = ? WHERE id = ?",
    )
    .bind(name)
    .bind(description)
    .bind(expose)
    .bind(who.now)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let details = json!({"name": name, "expose": expose, "by_device": who.by_device});
    record(&mut tx, who.actor, "project.updated", id, details, true).await?;
    let p = get(&mut tx, id).await?;
    tx.commit().await?;
    Ok(p)
}

/// Archives a project (idempotent refusal: archiving twice is a conflict). Repos, mirrors and
/// sessions stay.
pub async fn archive(pool: &SqlitePool, id: i64, who: Who<'_>) -> Result<Project, Error> {
    let mut tx = super::begin_write(pool).await?;
    let old = get(&mut tx, id).await?;
    if old.state == "archived" {
        return refused("conflict", "the project is already archived");
    }
    sqlx::query("UPDATE core_projects SET state = 'archived', updated_at = ? WHERE id = ?")
        .bind(who.now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"slug": old.slug, "by_device": who.by_device});
    record(&mut tx, who.actor, "project.archived", id, details, true).await?;
    let p = get(&mut tx, id).await?;
    tx.commit().await?;
    Ok(p)
}

mod github;
mod repos;
pub use github::{NewGithubRepo, create_from_github};
use repos::add_repo_in;
pub use repos::{add_repo, mirror, remove_repo, set_mirror, set_primary};

#[cfg(test)]
mod tests;
