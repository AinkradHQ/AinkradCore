//! Where a connection applies, per kind (design §2, decision 7): the **workspace default** is the
//! kind's default connection, which `resolve` prefers when several connections cover a use. The
//! project, agent and session scopes are accepted and stored but unused: a session never names a
//! connection. One binding per (user, kind, scope); setting it again replaces it, so two writers
//! of one default end with exactly one row (writes queue on `begin_write`, and the table's unique
//! key backs it).

use serde_json::json;
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqliteRow};

use super::{MAX_BINDINGS, Who, audit, find, refused, valid_ref};
use crate::store::secrets::Error;

/// Only `workspace` is read by `resolve`; the rest are unused capacity.
pub const SCOPES: [&str; 4] = ["workspace", "project", "agent", "session"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub user_id: i64,
    pub kind: String,
    pub scope_kind: String,
    /// `''` for the workspace default.
    pub scope_ref: String,
    pub connection_id: i64,
    pub created_by: String,
    pub created_at: String,
}

fn binding(r: &SqliteRow) -> Result<Binding, sqlx::Error> {
    Ok(Binding {
        user_id: r.try_get("user_id")?,
        kind: r.try_get("kind")?,
        scope_kind: r.try_get("scope_kind")?,
        scope_ref: r.try_get("scope_ref")?,
        connection_id: r.try_get("connection_id")?,
        created_by: r.try_get("created_by")?,
        created_at: r.try_get("created_at")?,
    })
}

fn check_scope(scope_kind: &str, scope_ref: &str) -> Result<(), Error> {
    match (scope_kind, scope_ref) {
        ("workspace", "") => Ok(()),
        ("workspace", _) => refused("bad_request", "the workspace default has no reference"),
        ("project" | "agent" | "session", r) if valid_ref(r) => Ok(()),
        ("project" | "agent" | "session", _) => {
            refused("bad_request", "a reference is 1 to 128 of [A-Za-z0-9._:/-]")
        }
        _ => refused(
            "bad_request",
            "a scope is workspace, project, agent or session",
        ),
    }
}

/// Binds `connection_id` as the workspace's connection of its kind at the scope, replacing the one
/// there. Audited `connection.bound`.
pub async fn set(
    pool: &SqlitePool,
    connection_id: i64,
    (scope_kind, scope_ref): (&str, &str),
    who: Who<'_>,
) -> Result<Binding, Error> {
    check_scope(scope_kind, scope_ref)?;
    let user_id = who.workspace;
    let mut tx = crate::store::begin_write(pool).await?;
    let c = find(&mut tx, user_id, connection_id).await?;
    let previous: Option<i64> = sqlx::query_scalar(
        "SELECT connection_id FROM core_connection_bindings WHERE user_id = ? AND kind = ? \
         AND scope_kind = ? AND scope_ref = ?",
    )
    .bind(user_id)
    .bind(&c.kind)
    .bind(scope_kind)
    .bind(scope_ref)
    .fetch_optional(&mut *tx)
    .await?;
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM core_connection_bindings WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    if previous.is_none() && n >= MAX_BINDINGS {
        return refused("limit_reached", "too many bindings");
    }
    let r = sqlx::query(
        "INSERT INTO core_connection_bindings (user_id, kind, scope_kind, scope_ref, \
         connection_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (user_id, kind, scope_kind, scope_ref) DO UPDATE SET \
         connection_id = excluded.connection_id, created_by = excluded.created_by, \
         created_at = excluded.created_at \
         RETURNING user_id, kind, scope_kind, scope_ref, connection_id, created_by, created_at",
    )
    .bind(user_id)
    .bind(&c.kind)
    .bind(scope_kind)
    .bind(scope_ref)
    .bind(connection_id)
    .bind(who.by_device)
    .bind(who.now)
    .fetch_one(&mut *tx)
    .await?;
    let b = binding(&r)?;
    audit(
        &mut tx,
        who.actor,
        "connection.bound",
        connection_id,
        json!({"kind": c.kind, "scope": scope_kind, "ref": scope_ref, "previous": previous,
               "by_device": who.by_device}),
    )
    .await?;
    tx.commit().await?;
    Ok(b)
}

/// Drops the binding of `kind` at the scope; whether there was one. Audited `connection.unbound`.
pub async fn clear(
    pool: &SqlitePool,
    kind: &str,
    (scope_kind, scope_ref): (&str, &str),
    who: Who<'_>,
) -> Result<bool, Error> {
    check_scope(scope_kind, scope_ref)?;
    let user_id = who.workspace;
    let mut tx = crate::store::begin_write(pool).await?;
    let gone: Option<i64> = sqlx::query_scalar(
        "DELETE FROM core_connection_bindings WHERE user_id = ? AND kind = ? AND scope_kind = ? \
         AND scope_ref = ? RETURNING connection_id",
    )
    .bind(user_id)
    .bind(kind)
    .bind(scope_kind)
    .bind(scope_ref)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(id) = gone {
        audit(
            &mut tx,
            who.actor,
            "connection.unbound",
            id,
            json!({"kind": kind, "scope": scope_kind, "ref": scope_ref, "by_device": who.by_device}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(gone.is_some())
}

/// `user_id`'s bindings (of `kind` when given), by kind and scope.
pub async fn list(
    pool: &SqlitePool,
    user_id: i64,
    kind: Option<&str>,
) -> Result<Vec<Binding>, sqlx::Error> {
    sqlx::query(
        "SELECT user_id, kind, scope_kind, scope_ref, connection_id, created_by, created_at \
         FROM core_connection_bindings WHERE user_id = ?1 AND (?2 IS NULL OR kind = ?2) \
         ORDER BY kind, scope_kind, scope_ref",
    )
    .bind(user_id)
    .bind(kind)
    .fetch_all(pool)
    .await?
    .iter()
    .map(binding)
    .collect()
}
