//! The sealed credential of a connection: store, replace, open, and the master-key rotation hook.

use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::redact::Redactor;
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};
use zeroize::Zeroizing;

use super::{Connection, Who, audit, find, refused};
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::store::secrets::Error;
use crate::store::settings::value_in;

/// The associated data of a sealed credential: its connection, the row's random nonce and the
/// version, so it opens only there (not under another row, even one that reuses the id).
fn label(id: i64, nonce: &str, version: i64) -> String {
    format!("core.connection:{id}:{nonce}:v{version}")
}

/// 128 random bits, hex: the row's part of the sealing label.
pub(super) fn new_nonce() -> Result<String, sqlx::Error> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Where a credential is sealed.
pub(super) struct Seal<'a> {
    pub id: i64,
    pub user_id: i64,
    pub nonce: &'a str,
    pub version: i64,
}

/// Wipes freed pages for the writes that drop a credential (`secure_delete` stays on for this
/// pooled connection; harmless elsewhere).
pub(super) async fn secure(conn: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    sqlx::query("PRAGMA secure_delete = ON")
        .execute(conn)
        .await
        .map(drop)
}

/// Overwrites a credential's sealed bytes, then removes its row.
pub(super) async fn wipe_in(conn: &mut SqliteConnection, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE core_connection_secrets SET sealed = zeroblob(length(sealed)) WHERE connection_id = ?",
    )
    .bind(id)
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM core_connection_secrets WHERE connection_id = ?")
        .bind(id)
        .execute(conn)
        .await
        .map(drop)
}

/// Refuses while the broker is off (`secrets.mode` 0): connection credentials are secrets too.
pub(super) async fn enabled(conn: &mut SqliteConnection) -> Result<i64, Error> {
    let mode = value_in(conn, Key::SecretsMode, Scope::Server).await?;
    match mode {
        0 => refused(
            "secrets_disabled",
            "the secrets broker is off (secrets.mode 0, gate G-SEC)",
        ),
        m => Ok(m),
    }
}

fn unavailable<T>() -> Result<T, Error> {
    refused(
        "secrets_unavailable",
        "the connection's credential did not open",
    )
}

/// The broker's gates for a credential about to be sealed: off at `secrets.mode` 0, and below
/// mode 2 a token with a recognised real-credential shape is refused. (`secrets.connections` and
/// per-kind token shapes, which will admit a kind's own token, are read by C2, not here.)
pub(super) async fn gate(conn: &mut SqliteConnection, m: &Material) -> Result<(), Error> {
    let mode = enabled(conn).await?;
    if mode < 2 {
        let redactor = Redactor::new();
        let real = [Some(m.access()), m.refresh()]
            .into_iter()
            .flatten()
            .any(|t| Zeroizing::new(redactor.text(t)).as_str() != t);
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
    at: &Seal<'_>,
    m: &Material,
    now: &str,
) -> Result<(), Error> {
    let sealed = sealer
        .seal(&label(at.id, at.nonce, at.version), &m.to_sealed())
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    sqlx::query(
        "INSERT INTO core_connection_secrets (connection_id, user_id, version, key_id, sealed, \
         expires_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (connection_id) DO UPDATE \
         SET version = excluded.version, key_id = excluded.key_id, sealed = excluded.sealed, \
         expires_at = excluded.expires_at, updated_at = excluded.updated_at",
    )
    .bind(at.id)
    .bind(at.user_id)
    .bind(at.version)
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
/// confirmed auth failure is cleared: the credential it judged is gone. The old bytes are
/// overwritten first.
pub async fn replace(
    pool: &SqlitePool,
    sealer: &SecretBox,
    id: i64,
    m: &Material,
    who: Who<'_>,
) -> Result<Connection, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    gate(&mut tx, m).await?;
    secure(&mut tx).await?;
    let c = find(&mut tx, who.workspace, id).await?;
    let nonce: String = sqlx::query_scalar("SELECT nonce FROM core_connections WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let old: i64 =
        sqlx::query_scalar("SELECT version FROM core_connection_secrets WHERE connection_id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or(0);
    sqlx::query(
        "UPDATE core_connection_secrets SET sealed = zeroblob(length(sealed)) WHERE connection_id = ?",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let at = Seal {
        id,
        user_id: c.user_id,
        nonce: &nonce,
        version: old + 1,
    };
    store_in(&mut tx, sealer, &at, m, who.now).await?;
    super::verdict::clear_auth_in(&mut tx, id, who.now, "replaced").await?;
    // An export left it without a credential; this one is the new one.
    sqlx::query(
        "UPDATE core_connections SET status = 'active', state_reason = NULL, state_until = NULL \
         WHERE id = ? AND state_reason = 'exported'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    audit(
        &mut tx,
        who.actor,
        "connection.secret_replaced",
        id,
        json!({"version": old + 1, "key_id": sealer.key_id(), "by_device": who.by_device}),
    )
    .await?;
    let c = find(&mut tx, who.workspace, id).await?;
    tx.commit().await?;
    Ok(c)
}

/// The credential of workspace `ws`'s connection `id` and its version, for the broker's upstream
/// call and an adapter's test, in this process only. Refused while the broker is off
/// (`secrets.mode` 0): nothing is decrypted then. Nothing exposes it: no route, event or audit
/// row. Uses are audited by `resolve::record_use`.
pub(crate) async fn open(
    pool: &SqlitePool,
    sealer: &SecretBox,
    ws: i64,
    id: i64,
) -> Result<(Material, i64), Error> {
    let mut conn = pool.acquire().await?;
    enabled(&mut conn).await?;
    let row = sqlx::query(
        "SELECT s.version, s.key_id, s.sealed, s.expires_at, c.nonce FROM core_connection_secrets s \
         JOIN core_connections c ON c.id = s.connection_id WHERE s.connection_id = ? AND c.user_id = ?",
    )
    .bind(id)
    .bind(ws)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return refused("not_found", "no such connection credential");
    };
    let (version, key_id): (i64, String) = (row.try_get("version")?, row.try_get("key_id")?);
    let nonce: String = row.try_get("nonce")?;
    let sealed: Vec<u8> = row.try_get("sealed")?;
    let Ok(plain) = sealer.open_as(&key_id, &label(id, &nonce, version), &sealed) else {
        return unavailable();
    };
    match Material::from_sealed(&plain, row.try_get("expires_at")?) {
        Some(m) => Ok((m, version)),
        None => unavailable(),
    }
}

/// The version of the credential now stored (0: none, as after an export).
pub(super) async fn version_in(conn: &mut SqliteConnection, id: i64) -> Result<i64, sqlx::Error> {
    let v: Option<i64> =
        sqlx::query_scalar("SELECT version FROM core_connection_secrets WHERE connection_id = ?")
            .bind(id)
            .fetch_optional(conn)
            .await?;
    Ok(v.unwrap_or(0))
}

const RESEAL_ROWS: &str = "SELECT s.connection_id, s.version, s.key_id, s.sealed, c.nonce \
     FROM core_connection_secrets s JOIN core_connections c ON c.id = s.connection_id";

/// The master-key rotation's half (`secrets::reseal_all`, in its transaction): every credential
/// not yet under `target` is opened with its own key and sealed again, then all are opened with
/// `target` alone. Returns how many there are, how many moved and the key ids they left.
pub(crate) async fn reseal_in(
    conn: &mut SqliteConnection,
    keys: &SecretBox,
    target: &SecretBox,
) -> Result<(usize, usize, Vec<String>), Error> {
    let rows = sqlx::query(RESEAL_ROWS).fetch_all(&mut *conn).await?;
    let (mut moved, mut from) = (0, Vec::<String>::new());
    for r in &rows {
        let (id, version): (i64, i64) = (r.try_get("connection_id")?, r.try_get("version")?);
        let (key_id, nonce): (String, String) = (r.try_get("key_id")?, r.try_get("nonce")?);
        if key_id == target.key_id() {
            continue;
        }
        let aad = label(id, &nonce, version);
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
    let rows = sqlx::query(RESEAL_ROWS).fetch_all(&mut *conn).await?;
    for r in &rows {
        let (id, version): (i64, i64) = (r.try_get("connection_id")?, r.try_get("version")?);
        let nonce: String = r.try_get("nonce")?;
        let ok = r.try_get::<String, _>("key_id")? == target.key_id()
            && target
                .open(
                    &label(id, &nonce, version),
                    &r.try_get::<Vec<u8>, _>("sealed")?,
                )
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
