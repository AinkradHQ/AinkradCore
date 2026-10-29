//! Settings (E15.17, decision #52): the stored values of the tunables in
//! `ainkrad_core::settings::REGISTRY`, per scope, and the resolver every read site goes
//! through (`value_in`): the most specific allowed scope with a value wins, else the default.
//!
//! `set` and `reset` validate against the registry (bounds, allowed scopes) and refuse with the reason, never clamping; each appends `setting.set` /
//! `setting.reset` with the old and new value, which `history` reads back.

use ainkrad_core::audit::{AuditActor, AuditEntity, AuditSeq, NewAuditEvent};
use ainkrad_core::settings::{Key, REGISTRY, Scope, ScopeKind, SettingError, Spec, resolve};
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
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SetError {}

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
        let scope = kind
            .parse::<ScopeKind>()
            .ok()
            .and_then(|k| Scope::of(k, row.try_get("scope_id").ok()?));
        if let (Some(scope), Ok(value)) = (scope, value.parse::<i64>()) {
            out.push((scope, value));
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
    // The platform's one scope; modules' scopes extend the chain (E1-09.1).
    let (value, source) = resolve(key, &[at], &rows_in(conn, key).await?);
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

/// Every setting that may be set at `at`'s kind of scope, with its effective value there.
pub async fn list(pool: &SqlitePool, at: Scope) -> Result<Vec<Effective>, Error> {
    let mut conn = pool.acquire().await?;
    let mut out = vec![];
    for spec in REGISTRY.iter().filter(|s| s.scopes.contains(&at.kind())) {
        out.push(effective_in(&mut conn, spec.key, at).await?);
    }
    Ok(out)
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
