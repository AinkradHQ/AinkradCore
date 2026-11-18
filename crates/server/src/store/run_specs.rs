//! Project run specs (Core 0.9, P4-01): the versioned store behind `core_project_run_specs`.
//! A save is a new version (never an update), refused for an archived project, audited and
//! emitted as `project.spec_saved` in the same transaction. The spec is validated by `spec::parse`
//! (shape, limits, image refs, `${secret:NAME}` syntax, and that each NAME is a project secret) and against the project's own repos; the
//! stored JSON is the normalised re-serialisation, so key order is stable.

use std::collections::BTreeSet;

use serde_json::{Value, json};
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqliteRow};

use super::projects::{self, Who};
use super::secrets::Error;

pub mod spec;

pub use spec::RunSpec;

/// Where a spec came from; the converters (P4-02/03) save as their own origin.
pub const ORIGINS: [&str; 5] = ["manual", "compose", "package_json", "makefile", "run_sh"];

#[derive(Debug, Clone, PartialEq)]
pub struct SpecVersion {
    pub version: i64,
    pub spec: RunSpec,
    pub origin: String,
    pub created_by: String,
    pub created_at: String,
}

/// A version without its body, for the history list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecSummary {
    pub version: i64,
    pub origin: String,
    pub created_by: String,
    pub created_at: String,
}

fn refused<T>(code: &'static str, message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.into(),
    })
}

fn full(r: SqliteRow) -> Result<SpecVersion, sqlx::Error> {
    let text: String = r.try_get("spec")?;
    Ok(SpecVersion {
        version: r.try_get("version")?,
        spec: serde_json::from_str(&text).map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
        origin: r.try_get("origin")?,
        created_by: r.try_get("created_by")?,
        created_at: r.try_get("created_at")?,
    })
}

const COLS: &str = "version, spec, origin, created_by, created_at";

async fn project_exists(pool: &SqlitePool, id: i64) -> Result<(), Error> {
    projects::get(&mut *pool.acquire().await?, id)
        .await
        .map(drop)
}

/// The newest version; `not_found` when the project has none yet.
pub async fn latest(pool: &SqlitePool, project_id: i64) -> Result<SpecVersion, Error> {
    project_exists(pool, project_id).await?;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS} FROM core_project_run_specs WHERE project_id = ? \
         ORDER BY version DESC LIMIT 1"
    )))
    .bind(project_id)
    .fetch_optional(pool)
    .await?;
    match row {
        Some(r) => Ok(full(r)?),
        None => refused("not_found", "the project has no run spec yet"),
    }
}

pub async fn version(
    pool: &SqlitePool,
    project_id: i64,
    version: i64,
) -> Result<SpecVersion, Error> {
    project_exists(pool, project_id).await?;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS} FROM core_project_run_specs WHERE project_id = ? AND version = ?"
    )))
    .bind(project_id)
    .bind(version)
    .fetch_optional(pool)
    .await?;
    match row {
        Some(r) => Ok(full(r)?),
        None => refused("not_found", "no such spec version"),
    }
}

/// Every version, newest first.
pub async fn versions(pool: &SqlitePool, project_id: i64) -> Result<Vec<SpecSummary>, Error> {
    project_exists(pool, project_id).await?;
    let rows = sqlx::query(
        "SELECT version, origin, created_by, created_at FROM core_project_run_specs \
         WHERE project_id = ? ORDER BY version DESC",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(SpecSummary {
                version: r.try_get("version")?,
                origin: r.try_get("origin")?,
                created_by: r.try_get("created_by")?,
                created_at: r.try_get("created_at")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()
        .map_err(Into::into)
}

/// Validates `body` and stores it as the project's next version. 400 `invalid_spec` names the bad
/// field; 409 `conflict` for an archived project; 404 for no such project.
pub async fn save(
    pool: &SqlitePool,
    project_id: i64,
    body: &Value,
    origin: &str,
    who: Who<'_>,
) -> Result<SpecVersion, Error> {
    if !ORIGINS.contains(&origin) {
        return refused(
            "bad_request",
            format!("an origin is one of {}", ORIGINS.join(", ")),
        );
    }
    let spec = match spec::parse(body) {
        Ok(s) => s,
        Err(why) => return refused("invalid_spec", why),
    };
    let mut tx = super::begin_write(pool).await?;
    let project = projects::get(&mut tx, project_id).await?;
    if project.state == "archived" {
        return refused("conflict", "the project is archived");
    }
    let have: BTreeSet<String> = projects::repos(&mut tx, project_id)
        .await?
        .into_iter()
        .map(|r| r.name)
        .collect();
    for (path, repo) in spec::repo_refs(&spec) {
        if !have.contains(repo) {
            return refused(
                "invalid_spec",
                format!("{path}: the project has no repo named {repo}"),
            );
        }
    }
    super::project_secrets::check_refs(&mut tx, &project, &spec::secret_refs(&spec)).await?;
    let version: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(version), 0) + 1 FROM core_project_run_specs WHERE project_id = ?",
    )
    .bind(project_id)
    .fetch_one(&mut *tx)
    .await?;
    let text = serde_json::to_string(&spec).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
    sqlx::query(
        "INSERT INTO core_project_run_specs (project_id, version, spec, origin, created_by, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(project_id)
    .bind(version)
    .bind(&text)
    .bind(origin)
    .bind(who.by_device)
    .bind(who.now)
    .execute(&mut *tx)
    .await?;
    let details = json!({"version": version, "origin": origin, "services": spec.services.len(),
                         "by_device": who.by_device});
    projects::record(
        &mut tx,
        who.actor,
        "project.spec_saved",
        project_id,
        details,
        true,
    )
    .await?;
    tx.commit().await?;
    Ok(SpecVersion {
        version,
        spec,
        origin: origin.to_owned(),
        created_by: who.by_device.to_owned(),
        created_at: who.now.to_owned(),
    })
}

#[cfg(test)]
mod tests;
