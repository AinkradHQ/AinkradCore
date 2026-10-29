//! Passkey credentials (E1-08, handshake spec §9; migration `0005_passkeys`): one per device of
//! kind `passkey`, inserted with the device by its pairing claim (`claim_pairing`), read at
//! sign-in and step-up, its sign count moved on after each, and locked (with its device) when
//! the count shows a clone. The verifier's record (`passkey`) is opaque JSON here.

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, SqliteConnection};

use super::devices::audit_device;
use crate::store::begin_write;

/// A credential to store with its new device.
#[derive(Debug, Clone)]
pub struct NewCredential<'a> {
    pub credential_id: &'a [u8],
    /// The verifier's record, JSON.
    pub passkey: &'a str,
    pub sign_count: u32,
    /// The transports the browser reported, JSON.
    pub transports: Option<&'a str>,
}

/// A stored credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub credential_id: Vec<u8>,
    pub device_id: String,
    pub passkey: String,
    pub sign_count: i64,
    pub revoked: bool,
}

pub(crate) async fn insert_credential(
    conn: &mut SqliteConnection,
    device: &str,
    c: &NewCredential<'_>,
) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO core_passkeys (credential_id, device_id, passkey, sign_count, transports) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(c.credential_id)
    .bind(device)
    .bind(c.passkey)
    .bind(i64::from(c.sign_count))
    .bind(c.transports)
    .execute(conn)
    .await
    .map(drop)
}

type Row = (Vec<u8>, String, String, i64, Option<String>);

fn credential((credential_id, device_id, passkey, sign_count, revoked): Row) -> Credential {
    Credential {
        credential_id,
        device_id,
        passkey,
        sign_count,
        revoked: revoked.is_some(),
    }
}

const COLUMNS: &str = "credential_id, device_id, passkey, sign_count, revoked_at";

/// The credential with id `id`, revoked or not.
pub async fn get_credential(pool: &SqlitePool, id: &[u8]) -> Result<Option<Credential>, Error> {
    let q = format!("SELECT {COLUMNS} FROM core_passkeys WHERE credential_id = ?");
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(q))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(credential))
}

/// The credential of passkey device `device`.
pub async fn device_credential(
    pool: &SqlitePool,
    device: &str,
) -> Result<Option<Credential>, Error> {
    let q = format!("SELECT {COLUMNS} FROM core_passkeys WHERE device_id = ?");
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(q))
        .bind(device)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(credential))
}

/// Records a verified use: the verifier's updated record and the count it reported. Never
/// moves the count back: of two uses verified at once, the one with the lower count does not
/// overwrite the other's record (the clone check compares against it).
pub async fn credential_used(
    pool: &SqlitePool,
    id: &[u8],
    passkey: &str,
    sign_count: u32,
    now: &str,
) -> Result<(), Error> {
    sqlx::query(
        "UPDATE core_passkeys SET passkey = ?, sign_count = ?, last_used_at = ? \
         WHERE credential_id = ? AND revoked_at IS NULL AND sign_count <= ?",
    )
    .bind(passkey)
    .bind(i64::from(sign_count))
    .bind(now)
    .bind(id)
    .bind(i64::from(sign_count))
    .execute(pool)
    .await
    .map(drop)
}

/// What `lock_credential` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lock {
    /// Revoked and its device locked, now.
    Locked,
    /// Revoked before: nothing written, so a clone cannot grow the audit log.
    Already,
    /// Not a clone: a lower count than one stored by a use in the last `recent_secs`, which is
    /// two ceremonies of the same authenticator finishing out of order (two tabs). Nothing written.
    Raced,
}

/// A verified assertion whose sign count did not grow (a cloned authenticator): revokes the
/// credential and locks its device, audited once as `passkey.locked`, in one transaction.
/// A count *below* the stored one, stored by a use within `recent_secs` (the ceremony
/// lifetime), is `Raced` instead: a concurrent sign-in moved the count on after this
/// ceremony's options were issued. An equal count is always a clone.
pub async fn lock_credential(
    pool: &SqlitePool,
    id: &[u8],
    reported: u32,
    now: &str,
    recent_secs: i64,
) -> Result<Lock, Error> {
    let mut tx = begin_write(pool).await?;
    let row: Option<(i64, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT sign_count, last_used_at, revoked_at FROM core_passkeys WHERE credential_id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((stored, used, None)) = row else {
        return Ok(Lock::Already);
    };
    let unix = crate::scheduler::unix_secs;
    let recent = match (used.as_deref().and_then(unix), unix(now)) {
        (Some(used), Some(now)) => now - used < recent_secs,
        _ => false,
    };
    // ponytail: a clone answering within `recent_secs` of a real use only fails, unlocked; its
    // next try outside that window locks it. Exact ordering needs per-ceremony sequence numbers.
    if i64::from(reported) < stored && recent {
        return Ok(Lock::Raced);
    }
    let device: String = sqlx::query_scalar(
        "UPDATE core_passkeys SET revoked_at = ? WHERE credential_id = ? RETURNING device_id",
    )
    .bind(now)
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let seq: Option<i64> = sqlx::query_scalar(
        "UPDATE core_devices SET status = 'locked' WHERE id = ? AND status = 'active' RETURNING seq",
    )
    .bind(&device)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(seq) = seq {
        let details = json!({"device": device, "reason": "sign count did not grow",
            "stored": stored, "reported": reported});
        audit_device(&mut tx, seq, "passkey.locked", AuditActor::System, details).await?;
    }
    tx.commit().await?;
    Ok(Lock::Locked)
}
