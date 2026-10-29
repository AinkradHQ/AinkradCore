//! Settings (E15.17, decision #52): the stored values of the tunables in
//! `citadel_core::settings::REGISTRY`, per scope, and the resolver every read site goes
//! through (`value_in`): the most specific allowed scope with a value wins, else the default.
//!
//! `set` and `reset` validate against the registry (bounds, allowed scopes, the scope's row
//! exists) and refuse with the reason, never clamping; each appends `setting.set` /
//! `setting.reset` with the old and new value, which `history` reads back.

use citadel_core::audit::{AuditActor, AuditEntity, AuditSeq, NewAuditEvent};
use citadel_core::exec::RunId;
use citadel_core::org::{AgentId, CompanyId};
use citadel_core::settings::{Key, REGISTRY, Scope, ScopeKind, SettingError, Spec, chain, resolve};
use citadel_core::work::{IssueId, ProjectId};
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, Row, SqliteConnection};

use super::audit;

/// A setting's effective value at a scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    pub spec: &'static Spec,
    pub value: i64,
    /// Where the value was set; `None` is the default.
    pub source: Option<Scope>,
}

/// One set or reset, from the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub seq: AuditSeq,
    pub at: String,
    pub actor: AuditActor,
    pub key: String,
    pub scope: Scope,
    /// The value set there before; `None` when it inherited.
    pub old: Option<i64>,
    /// The value set; `None` for a reset.
    pub new: Option<i64>,
}

/// Why a set or reset was refused.
#[derive(Debug)]
pub enum SetError {
    Refused(SettingError),
    /// The company, project, runner or account does not exist.
    NoScope(Scope),
    Db(Error),
}

impl From<Error> for SetError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl std::fmt::Display for SetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(e) => e.fmt(f),
            Self::NoScope(s) => write!(f, "no {s}"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SetError {}

/// The company a project belongs to, for the project → company → server chain.
async fn chain_in(conn: &mut SqliteConnection, at: Scope) -> Result<Vec<Scope>, Error> {
    let company = match at {
        Scope::Project(p) => sqlx::query_scalar("SELECT company_id FROM projects WHERE id = ?")
            .bind(p.0)
            .fetch_optional(&mut *conn)
            .await?
            .map(CompanyId),
        _ => None,
    };
    Ok(chain(at, company))
}

async fn rows_in(conn: &mut SqliteConnection, key: Key) -> Result<Vec<(Scope, i64)>, Error> {
    let rows = sqlx::query("SELECT scope_kind, scope_id, value FROM settings WHERE key = ?")
        .bind(key.name())
        .fetch_all(&mut *conn)
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let kind: String = row.try_get("scope_kind")?;
        let value: String = row.try_get("value")?;
        // A value the registry no longer accepts is skipped: the next scope (or default) holds.
        if let (Ok(kind), Ok(value)) = (kind.parse::<ScopeKind>(), value.parse::<i64>()) {
            out.push((Scope::of(kind, row.try_get("scope_id")?), value));
        }
    }
    Ok(out)
}

/// `key`'s effective value for a read at `at`, inside the caller's transaction.
pub(crate) async fn effective_in(
    conn: &mut SqliteConnection,
    key: Key,
    at: Scope,
) -> Result<Effective, Error> {
    let chain = chain_in(conn, at).await?;
    let (value, source) = resolve(key, &chain, &rows_in(conn, key).await?);
    Ok(Effective {
        spec: key.spec(),
        value,
        source,
    })
}

/// `key`'s effective value at `at`, inside the caller's transaction.
pub(crate) async fn value_in(
    conn: &mut SqliteConnection,
    key: Key,
    at: Scope,
) -> Result<i64, Error> {
    Ok(effective_in(conn, key, at).await?.value)
}

/// `key`'s effective value at `at`.
pub async fn value(pool: &SqlitePool, key: Key, at: Scope) -> Result<i64, Error> {
    value_in(&mut *pool.acquire().await?, key, at).await
}

pub async fn effective(pool: &SqlitePool, key: Key, at: Scope) -> Result<Effective, Error> {
    effective_in(&mut *pool.acquire().await?, key, at).await
}

/// Where a run's settings are read: its issue's project, else its agent's company.
pub(crate) async fn run_scope_in(
    conn: &mut SqliteConnection,
    issue: Option<IssueId>,
    agent: AgentId,
) -> Result<Scope, Error> {
    let project: Option<i64> = match issue {
        Some(i) => {
            sqlx::query_scalar("SELECT project_id FROM issues WHERE id = ?")
                .bind(i.0)
                .fetch_optional(&mut *conn)
                .await?
        }
        None => None,
    };
    if let Some(p) = project {
        return Ok(Scope::Project(ProjectId(p)));
    }
    let company: Option<i64> = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(agent.0)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(company.map_or(Scope::Server, |c| Scope::Company(CompanyId(c))))
}

/// `run_scope_in` for a run by id; the server for a missing run.
pub(crate) async fn scope_of_run_in(
    conn: &mut SqliteConnection,
    run: RunId,
) -> Result<Scope, Error> {
    let found: Option<(Option<i64>, i64)> =
        sqlx::query_as("SELECT issue_id, agent_id FROM runs WHERE id = ?")
            .bind(run.0)
            .fetch_optional(&mut *conn)
            .await?;
    match found {
        Some((issue, agent)) => run_scope_in(conn, issue.map(IssueId), AgentId(agent)).await,
        None => Ok(Scope::Server),
    }
}

/// `scope_of_run_in` on its own connection.
pub async fn scope_of_run(pool: &SqlitePool, run: RunId) -> Result<Scope, Error> {
    scope_of_run_in(&mut *pool.acquire().await?, run).await
}

/// Every setting that may be set at `at`'s kind of scope, with its effective value there.
pub async fn list(pool: &SqlitePool, at: Scope) -> Result<Vec<Effective>, Error> {
    let mut conn = pool.acquire().await?;
    let mut out = vec![];
    for spec in REGISTRY.iter().filter(|s| s.scopes.contains(&at.kind())) {
        out.push(effective_in(&mut conn, spec.key, at).await?);
    }
    Ok(out)
}

/// Whether the scope's row exists.
async fn scope_exists(conn: &mut SqliteConnection, at: Scope) -> Result<bool, Error> {
    let sql = match at {
        Scope::Server => return Ok(true),
        Scope::Company(_) => "SELECT EXISTS (SELECT 1 FROM companies WHERE id = ?)",
        Scope::Project(_) => "SELECT EXISTS (SELECT 1 FROM projects WHERE id = ?)",
        Scope::Runner(_) => "SELECT EXISTS (SELECT 1 FROM runners WHERE id = ?)",
        Scope::Account(_) => "SELECT EXISTS (SELECT 1 FROM accounts WHERE id = ?)",
    };
    sqlx::query_scalar(sql)
        .bind(at.id())
        .fetch_one(&mut *conn)
        .await
}

/// The company an audit event about `at` belongs to.
async fn company_of(conn: &mut SqliteConnection, at: Scope) -> Result<Option<CompanyId>, Error> {
    Ok(match at {
        Scope::Company(c) => Some(c),
        Scope::Project(p) => sqlx::query_scalar("SELECT company_id FROM projects WHERE id = ?")
            .bind(p.0)
            .fetch_optional(&mut *conn)
            .await?
            .map(CompanyId),
        _ => None,
    })
}

async fn stored_in(conn: &mut SqliteConnection, key: Key, at: Scope) -> Result<Option<i64>, Error> {
    let value: Option<String> = sqlx::query_scalar(
        "SELECT value FROM settings WHERE key = ? AND scope_kind = ? AND scope_id = ?",
    )
    .bind(key.name())
    .bind(at.kind().as_str())
    .bind(at.id())
    .fetch_optional(&mut *conn)
    .await?;
    Ok(value.and_then(|v| v.parse().ok()))
}

/// Writes (`Some`) or removes (`None`) `key`'s value at `at` and audits it, in `conn`'s
/// transaction; a reset of a value never set changes and audits nothing.
async fn write_in(
    conn: &mut SqliteConnection,
    key: Key,
    at: Scope,
    new: Option<i64>,
    actor: AuditActor,
    now: &str,
) -> Result<(), SetError> {
    let spec = key.spec();
    if !spec.scopes.contains(&at.kind()) {
        let refused = SettingError::WrongScope {
            key: spec.name,
            scope: at.kind(),
            allowed: spec.scopes,
        };
        return Err(SetError::Refused(refused));
    }
    if !scope_exists(conn, at).await? {
        return Err(SetError::NoScope(at));
    }
    let old = stored_in(conn, key, at).await?;
    if new.is_none() && old.is_none() {
        return Ok(());
    }
    let (by_kind, by_id) = actor.parts();
    match new {
        Some(v) => sqlx::query(
            "INSERT INTO settings (key, scope_kind, scope_id, value, updated_by_kind, \
             updated_by_id, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (key, scope_kind, scope_id) DO UPDATE SET value = excluded.value, \
             updated_by_kind = excluded.updated_by_kind, updated_by_id = excluded.updated_by_id, \
             updated_at = excluded.updated_at",
        )
        .bind(key.name())
        .bind(at.kind().as_str())
        .bind(at.id())
        .bind(v.to_string())
        .bind(by_kind)
        .bind(by_id)
        .bind(now),
        None => {
            sqlx::query("DELETE FROM settings WHERE key = ? AND scope_kind = ? AND scope_id = ?")
                .bind(key.name())
                .bind(at.kind().as_str())
                .bind(at.id())
        }
    }
    .execute(&mut *conn)
    .await?;
    let event = NewAuditEvent {
        actor,
        action: if new.is_some() {
            "setting.set"
        } else {
            "setting.reset"
        }
        .to_owned(),
        entity: (at != Scope::Server).then(|| AuditEntity {
            kind: at.kind().as_str().to_owned(),
            id: at.id(),
        }),
        company_id: company_of(conn, at).await?,
        run_id: None,
        details: json!({"key": key.name(), "scope": at.to_string(), "old": old, "new": new,
                        "at": now})
        .to_string(),
    };
    audit::append(&mut *conn, &event).await?;
    Ok(())
}

/// Sets `key` to `value` (JSON text) at `at` by `actor`, after checking it against the
/// registry; returns the effective value there.
pub async fn set(
    pool: &SqlitePool,
    key: Key,
    at: Scope,
    value: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Effective, SetError> {
    let v = key
        .spec()
        .check(at.kind(), value)
        .map_err(SetError::Refused)?;
    let mut tx = crate::store::begin_write(pool).await?;
    write_in(&mut tx, key, at, Some(v), actor, now).await?;
    let e = effective_in(&mut tx, key, at).await?;
    tx.commit().await?;
    Ok(e)
}

/// Removes `key`'s value at `at`, so it inherits again; returns the effective value there.
pub async fn reset(
    pool: &SqlitePool,
    key: Key,
    at: Scope,
    actor: AuditActor,
    now: &str,
) -> Result<Effective, SetError> {
    let mut tx = crate::store::begin_write(pool).await?;
    write_in(&mut tx, key, at, None, actor, now).await?;
    let e = effective_in(&mut tx, key, at).await?;
    tx.commit().await?;
    Ok(e)
}

/// A value set at a scope: the setting, where, the value, who set it last and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    pub spec: &'static Spec,
    pub scope: Scope,
    pub value: i64,
    pub by: AuditActor,
    pub at: String,
}

/// Every value set at `company` or at one of its projects, by key, then scope. A row the
/// registry no longer knows, or not an integer, is passed over.
pub async fn company_overrides(
    pool: &SqlitePool,
    company: CompanyId,
) -> Result<Vec<Override>, Error> {
    let rows = sqlx::query(
        "SELECT key, scope_kind, scope_id, value, updated_by_kind, updated_by_id, updated_at \
         FROM settings WHERE (scope_kind = 'company' AND scope_id = ?1) \
         OR (scope_kind = 'project' AND scope_id IN (SELECT id FROM projects WHERE company_id = ?1)) \
         ORDER BY key, scope_kind, scope_id",
    )
    .bind(company.0)
    .fetch_all(pool)
    .await?;
    let mut out = vec![];
    for row in rows {
        let (key, kind, value, by): (String, String, String, String) = (
            row.try_get("key")?,
            row.try_get("scope_kind")?,
            row.try_get("value")?,
            row.try_get("updated_by_kind")?,
        );
        let (Ok(key), Ok(kind), Ok(value), Some(by)) = (
            key.parse::<Key>(),
            kind.parse::<ScopeKind>(),
            value.parse::<i64>(),
            AuditActor::from_parts(&by, row.try_get("updated_by_id")?),
        ) else {
            continue;
        };
        out.push(Override {
            spec: key.spec(),
            scope: Scope::of(kind, row.try_get("scope_id")?),
            value,
            by,
            at: row.try_get("updated_at")?,
        });
    }
    Ok(out)
}

/// Every set and reset of `key` (at `at` only, when given), newest first.
pub async fn history(pool: &SqlitePool, key: Key, at: Option<Scope>) -> Result<Vec<Change>, Error> {
    let rows = sqlx::query(
        "SELECT seq, at, actor_kind, actor_id, action, details FROM audit_events \
         WHERE action IN ('setting.set', 'setting.reset') \
         AND json_extract(details, '$.key') = ?1 \
         AND (?2 IS NULL OR json_extract(details, '$.scope') = ?2) ORDER BY seq DESC",
    )
    .bind(key.name())
    .bind(at.map(|s| s.to_string()))
    .fetch_all(pool)
    .await?;
    let mut out = vec![];
    for row in rows {
        let kind: String = row.try_get("actor_kind")?;
        let details: String = row.try_get("details")?;
        let details: Value = serde_json::from_str(&details).unwrap_or_default();
        let (Some(actor), Some(scope)) = (
            AuditActor::from_parts(&kind, row.try_get("actor_id")?),
            details["scope"].as_str().and_then(|s| s.parse().ok()),
        ) else {
            continue;
        };
        out.push(Change {
            seq: AuditSeq(row.try_get("seq")?),
            // When it was made, as the caller's clock said; the log's own stamp otherwise.
            at: match details["at"].as_str() {
                Some(at) => at.to_owned(),
                None => row.try_get("at")?,
            },
            actor,
            key: key.name().to_owned(),
            scope,
            old: details["old"].as_i64(),
            new: details["new"].as_i64(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
