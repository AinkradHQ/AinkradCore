//! The sealed config of Ainkrad's OAuth apps (C5; design `2026-11-06-core-connections-design`
//! §6, decision 1) and the GitHub App installation of a connection.
//!
//! Settings are integers only, so the apps' strings live here: one sealed row per (workspace, kind,
//! field) in `core_connection_apps`, under the master key, label
//! `core.connection_app:<user>:<kind>:<field>:v<version>`, rotated with the other sealed tables
//! ([`reseal_in`]) and wiped from an export. [`present`] says which fields are set; the only reader
//! of a value is [`open_all`], for the process that builds the adapters' apps. No route, event,
//! audit row or error names a value: the audit row lists field NAMES.
//!
//! Gate: `secrets.mode` 0 refuses a write and a read, like every sealed table. The real-credential
//! shape check of a connection's own credential is NOT applied: these are the registrations of
//! Ainkrad's own apps (a PEM private key is a recognised shape), not a person's credential.

use std::collections::BTreeMap;

use ainkrad_core::audit::NewAuditEvent;
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};
use zeroize::Zeroizing;

use super::secret::enabled;
use super::{Who, find, refused};
use crate::ops::secretbox::SecretBox;
use crate::store::secrets::Error;

/// Longest value of one field: a PEM private key is the biggest.
pub const MAX_FIELD_BYTES: usize = 8192;

fn label(user: i64, kind: &str, field: &str, version: i64) -> String {
    format!("core.connection_app:{user}:{kind}:{field}:v{version}")
}

/// The fields of `kind` that are set in workspace `ws` (names only).
pub async fn present(pool: &SqlitePool, ws: i64, kind: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT field FROM core_connection_apps WHERE user_id = ? AND kind = ? ORDER BY field",
    )
    .bind(ws)
    .bind(kind)
    .fetch_all(pool)
    .await
}

/// Every set field of `kind` with its value, for the process that builds the adapters' apps. A
/// field that does not open is left out (the app then reads as not configured).
pub(crate) async fn open_all(
    pool: &SqlitePool,
    sealer: &SecretBox,
    ws: i64,
    kind: &str,
) -> Result<BTreeMap<String, Zeroizing<String>>, Error> {
    let mut conn = pool.acquire().await?;
    enabled(&mut conn).await?;
    let rows = sqlx::query(
        "SELECT field, version, key_id, sealed FROM core_connection_apps \
         WHERE user_id = ? AND kind = ?",
    )
    .bind(ws)
    .bind(kind)
    .fetch_all(&mut *conn)
    .await?;
    let mut out = BTreeMap::new();
    for r in &rows {
        let field: String = r.try_get("field")?;
        let (version, key_id): (i64, String) = (r.try_get("version")?, r.try_get("key_id")?);
        let sealed: Vec<u8> = r.try_get("sealed")?;
        let Ok(plain) = sealer.open_as(&key_id, &label(ws, kind, &field, version), &sealed) else {
            continue;
        };
        if let Ok(text) = String::from_utf8(plain.to_vec()) {
            out.insert(field, Zeroizing::new(text));
        }
    }
    Ok(out)
}

/// What to do to one field: store `Some(value)`, or remove it with `None`.
pub type Change<'a> = (&'a str, Option<&'a str>);

/// Applies `changes` to `kind`'s fields in one transaction (the caller validated names and
/// values). Audited `connection.app_set` with the field names and whether each was stored or
/// cleared, never a value. Returns the fields now set.
pub async fn set(
    pool: &SqlitePool,
    sealer: &SecretBox,
    kind: &str,
    changes: &[Change<'_>],
    who: Who<'_>,
) -> Result<Vec<String>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    enabled(&mut tx).await?;
    let ws = who.workspace;
    let owner: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE id = ?")
        .bind(ws)
        .fetch_one(&mut *tx)
        .await?;
    if owner == 0 {
        return refused("bad_request", "no such user");
    }
    let (mut stored, mut cleared) = (Vec::new(), Vec::new());
    for (field, value) in changes {
        match value {
            Some(v) => {
                let old: i64 = sqlx::query_scalar(
                    "SELECT version FROM core_connection_apps WHERE user_id = ? AND kind = ? \
                     AND field = ?",
                )
                .bind(ws)
                .bind(kind)
                .bind(field)
                .fetch_optional(&mut *tx)
                .await?
                .unwrap_or(0);
                let version = old + 1;
                let sealed = sealer
                    .seal(&label(ws, kind, field, version), v.as_bytes())
                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
                sqlx::query(
                    "INSERT INTO core_connection_apps (user_id, kind, field, version, key_id, \
                     sealed, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
                     ON CONFLICT (user_id, kind, field) DO UPDATE SET version = excluded.version, \
                     key_id = excluded.key_id, sealed = excluded.sealed, \
                     updated_at = excluded.updated_at",
                )
                .bind(ws)
                .bind(kind)
                .bind(field)
                .bind(version)
                .bind(sealer.key_id())
                .bind(&sealed)
                .bind(who.now)
                .execute(&mut *tx)
                .await?;
                stored.push(*field);
            }
            None => {
                super::secret::secure(&mut tx).await?;
                let n = sqlx::query(
                    "DELETE FROM core_connection_apps WHERE user_id = ? AND kind = ? AND field = ?",
                )
                .bind(ws)
                .bind(kind)
                .bind(field)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                super::secret::secure_off(&mut tx).await?;
                if n > 0 {
                    cleared.push(*field);
                }
            }
        }
    }
    let event = NewAuditEvent {
        actor: who.actor,
        action: "connection.app_set".to_owned(),
        entity: None,
        details: json!({"kind": kind, "stored": stored, "cleared": cleared,
                        "by_device": who.by_device})
        .to_string(),
    };
    crate::store::audit::append(&mut tx, &event).await?;
    let fields = sqlx::query_scalar(
        "SELECT field FROM core_connection_apps WHERE user_id = ? AND kind = ? ORDER BY field",
    )
    .bind(ws)
    .bind(kind)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(fields)
}

/// The master-key rotation's half for this table (`secrets::reseal_all`, in its transaction), the
/// same as [`super::secret::reseal_in`]: returns how many rows there are, how many moved and the
/// key ids they left.
pub(crate) async fn reseal_in(
    conn: &mut SqliteConnection,
    keys: &SecretBox,
    target: &SecretBox,
) -> Result<(usize, usize, Vec<String>), Error> {
    const ROWS: &str = "SELECT user_id, kind, field, version, key_id, sealed FROM \
                        core_connection_apps";
    let rows = sqlx::query(ROWS).fetch_all(&mut *conn).await?;
    let (mut moved, mut from) = (0, Vec::<String>::new());
    for r in &rows {
        let (user, kind): (i64, String) = (r.try_get("user_id")?, r.try_get("kind")?);
        let (field, version): (String, i64) = (r.try_get("field")?, r.try_get("version")?);
        let key_id: String = r.try_get("key_id")?;
        if key_id == target.key_id() {
            continue;
        }
        let aad = label(user, &kind, &field, version);
        let Ok(plain) = keys.open_as(&key_id, &aad, &r.try_get::<Vec<u8>, _>("sealed")?) else {
            return refused(
                "secrets_unavailable",
                format!("a connection app field did not open under its key {key_id}"),
            );
        };
        let sealed = target
            .seal(&aad, &plain)
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        sqlx::query(
            "UPDATE core_connection_apps SET key_id = ?, sealed = ? \
             WHERE user_id = ? AND kind = ? AND field = ?",
        )
        .bind(target.key_id())
        .bind(&sealed)
        .bind(user)
        .bind(&kind)
        .bind(&field)
        .execute(&mut *conn)
        .await?;
        moved += 1;
        if !from.contains(&key_id) {
            from.push(key_id);
        }
    }
    let rows = sqlx::query(ROWS).fetch_all(&mut *conn).await?;
    for r in &rows {
        let (user, kind): (i64, String) = (r.try_get("user_id")?, r.try_get("kind")?);
        let (field, version): (String, i64) = (r.try_get("field")?, r.try_get("version")?);
        let ok = r.try_get::<String, _>("key_id")? == target.key_id()
            && target
                .open(
                    &label(user, &kind, &field, version),
                    &r.try_get::<Vec<u8>, _>("sealed")?,
                )
                .is_ok();
        if !ok {
            return refused(
                "secrets_unavailable",
                "a connection app field did not verify under the new key; nothing was changed",
            );
        }
    }
    Ok((rows.len(), moved, from))
}

/// The GitHub App installation connection `id` of workspace `ws` is minted for, when it has one.
pub async fn installation_of(
    pool: &SqlitePool,
    ws: i64,
    id: i64,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar("SELECT installation_id FROM core_connections WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(ws)
        .fetch_optional(pool)
        .await
        .map(Option::flatten)
}

/// Sets the installation of connection `id` (a reconnect through a new installation).
pub async fn set_installation(
    pool: &SqlitePool,
    id: i64,
    installation: i64,
    who: Who<'_>,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    find(&mut tx, who.workspace, id).await?;
    sqlx::query("UPDATE core_connections SET installation_id = ?, updated_at = ? WHERE id = ?")
        .bind(installation)
        .bind(who.now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
