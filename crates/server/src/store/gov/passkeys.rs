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

/// Records a verified use: the verifier's updated record and the count it reported.
pub async fn credential_used(
    pool: &SqlitePool,
    id: &[u8],
    passkey: &str,
    sign_count: u32,
    now: &str,
) -> Result<(), Error> {
    sqlx::query(
        "UPDATE core_passkeys SET passkey = ?, sign_count = max(sign_count, ?), last_used_at = ? \
         WHERE credential_id = ? AND revoked_at IS NULL",
    )
    .bind(passkey)
    .bind(i64::from(sign_count))
    .bind(now)
    .bind(id)
    .execute(pool)
    .await
    .map(drop)
}

/// A verified assertion whose sign count did not grow (a cloned authenticator): revokes the
/// credential and locks its device, audited once as `passkey.locked`, in one transaction.
/// `false` when it was locked already (nothing written, so a clone cannot grow the audit log).
pub async fn lock_credential(
    pool: &SqlitePool,
    id: &[u8],
    reported: u32,
    now: &str,
) -> Result<bool, Error> {
    let mut tx = begin_write(pool).await?;
    let hit: Option<(String, i64)> = sqlx::query_as(
        "UPDATE core_passkeys SET revoked_at = ? WHERE credential_id = ? AND revoked_at IS NULL \
         RETURNING device_id, sign_count",
    )
    .bind(now)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((device, stored)) = hit else {
        return Ok(false);
    };
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
    Ok(true)
}
