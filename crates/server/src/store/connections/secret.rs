//! The sealed credential of a connection: store, replace, open, and the master-key rotation hook.

use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::redact::Redactor;
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};

use super::{Connection, Who, audit, find, refused};
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::store::secrets::Error;
use crate::store::settings::value_in;

/// The associated data of a sealed credential: its connection and version, so it opens only there.
fn label(id: i64, version: i64) -> String {
    format!("core.connection:{id}:v{version}")
}

fn unavailable<T>() -> Result<T, Error> {
    refused(
        "secrets_unavailable",
        "the connection's credential did not open",
    )
}

/// The broker's gates for a credential about to be sealed: off at `secrets.mode` 0, and below
/// mode 2 a token with a recognised real-credential shape is refused.
pub(super) async fn gate(conn: &mut SqliteConnection, m: &Material) -> Result<(), Error> {
    let mode = value_in(conn, Key::SecretsMode, Scope::Server).await?;
    if mode == 0 {
        return refused(
            "secrets_disabled",
            "the secrets broker is off (secrets.mode 0, gate G-SEC)",
        );
    }
    if mode < 2 {
        let redactor = Redactor::new();
        let real = [Some(m.access()), m.refresh()]
            .into_iter()
            .flatten()
            .any(|t| redactor.text(t) != t);
        if real {
            return refused(
                "real_secret_refused",
                "the credential has a recognised real-credential shape; real secrets wait for \
                 gate G-SEC (secrets.mode 2)",
            );
        }
    }
    Ok(())
}

pub(super) async fn store_in(
    conn: &mut SqliteConnection,
    sealer: &SecretBox,
    id: i64,
    user_id: i64,
    version: i64,
    m: &Material,
    now: &str,
) -> Result<(), Error> {
    let sealed = sealer
        .seal(&label(id, version), &m.to_sealed())
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    sqlx::query(
        "INSERT INTO core_connection_secrets (connection_id, user_id, version, key_id, sealed, \
         expires_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (connection_id) DO UPDATE \
         SET version = excluded.version, key_id = excluded.key_id, sealed = excluded.sealed, \
         expires_at = excluded.expires_at, updated_at = excluded.updated_at",
    )
    .bind(id)
    .bind(user_id)
    .bind(version)
    .bind(sealer.key_id())
    .bind(&sealed)
    .bind(&m.expires_at)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

/// Replaces the credential (a rotation, or an OAuth refresh): a new version, audited
/// `connection.secret_replaced` with the version and key id, never the value. A pending or
/// confirmed auth failure is cleared: the credential it judged is gone.
pub async fn replace(
    pool: &SqlitePool,
    sealer: &SecretBox,
    id: i64,
    m: &Material,
    who: Who<'_>,
) -> Result<Connection, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    gate(&mut tx, m).await?;
    let c = find(&mut tx, id).await?;
    let old: i64 =
        sqlx::query_scalar("SELECT version FROM core_connection_secrets WHERE connection_id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or(0);
    store_in(&mut tx, sealer, id, c.user_id, old + 1, m, who.now).await?;
    super::verdict::clear_auth_in(&mut tx, id, who.now, "replaced").await?;
    audit(
        &mut tx,
        who.actor,
        "connection.secret_replaced",
        id,
        json!({"version": old + 1, "key_id": sealer.key_id(), "by_device": who.by_device}),
    )
    .await?;
    let c = find(&mut tx, id).await?;
    tx.commit().await?;
    Ok(c)
}

/// The credential, for the broker's upstream call and an adapter's test, in this process only.
/// Nothing exposes it: no route, event or audit row. Uses are audited by `resolve::record_use`.
pub(crate) async fn open(
    pool: &SqlitePool,
    sealer: &SecretBox,
    id: i64,
) -> Result<Material, Error> {
    let row = sqlx::query(
        "SELECT version, key_id, sealed, expires_at FROM core_connection_secrets \
         WHERE connection_id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return refused("not_found", "no such connection");
    };
    let (version, key_id): (i64, String) = (row.try_get("version")?, row.try_get("key_id")?);
    let sealed: Vec<u8> = row.try_get("sealed")?;
    let Ok(plain) = sealer.open_as(&key_id, &label(id, version), &sealed) else {
        return unavailable();
    };
    match Material::from_sealed(&plain, row.try_get("expires_at")?) {
        Some(m) => Ok(m),
        None => unavailable(),
    }
}

/// The master-key rotation's half (`secrets::reseal_all`, in its transaction): every credential
/// not yet under `target` is opened with its own key and sealed again, then all are opened with
/// `target` alone. Returns how many there are, how many moved and the key ids they left.
pub(crate) async fn reseal_in(
    conn: &mut SqliteConnection,
    keys: &SecretBox,
    target: &SecretBox,
) -> Result<(usize, usize, Vec<String>), Error> {
    let rows =
        sqlx::query("SELECT connection_id, version, key_id, sealed FROM core_connection_secrets")
            .fetch_all(&mut *conn)
            .await?;
    let (mut moved, mut from) = (0, Vec::<String>::new());
    for r in &rows {
        let (id, version): (i64, i64) = (r.try_get("connection_id")?, r.try_get("version")?);
        let key_id: String = r.try_get("key_id")?;
        if key_id == target.key_id() {
            continue;
        }
        let aad = label(id, version);
        let Ok(plain) = keys.open_as(&key_id, &aad, &r.try_get::<Vec<u8>, _>("sealed")?) else {
            return refused(
                "secrets_unavailable",
                format!("connection {id} did not open under its key {key_id}"),
            );
        };
        let sealed = target
            .seal(&aad, &plain)
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        sqlx::query(
            "UPDATE core_connection_secrets SET key_id = ?, sealed = ? WHERE connection_id = ?",
        )
        .bind(target.key_id())
        .bind(&sealed)
        .bind(id)
        .execute(&mut *conn)
        .await?;
        moved += 1;
        if !from.contains(&key_id) {
            from.push(key_id);
        }
    }
    let rows =
        sqlx::query("SELECT connection_id, version, key_id, sealed FROM core_connection_secrets")
            .fetch_all(&mut *conn)
            .await?;
    for r in &rows {
        let (id, version): (i64, i64) = (r.try_get("connection_id")?, r.try_get("version")?);
        let ok = r.try_get::<String, _>("key_id")? == target.key_id()
            && target
                .open(&label(id, version), &r.try_get::<Vec<u8>, _>("sealed")?)
                .is_ok();
        if !ok {
            return refused(
                "secrets_unavailable",
                format!("connection {id} did not verify under the new key; nothing was changed"),
            );
        }
    }
    Ok((rows.len(), moved, from))
}
