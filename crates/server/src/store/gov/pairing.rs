//! Device pairing (parity API B2): the admin asks for a 6-character code; a new device trades it,
//! once and before it expires, for its own device key. Only the code's hash is stored.
//! Audited: `device.pairing_started` and `device.paired` (the new key's own `device_key.created`
//! too), each an event on the stream.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::device::DeviceKey;
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, SqliteConnection};

use super::issue_device_key;
use crate::store::{audit, key_hash};

/// How long a code lives.
pub const PAIRING_SECS: i64 = 300;

/// Letters and digits that cannot be mistaken for each other (no 0 O 1 I L).
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

fn code() -> Result<String, Error> {
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    // ponytail: 256 % 31 skews each character by under 1%; fine for a 5-minute code behind a
    // rate limit.
    Ok(bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect())
}

/// The code as typed: trimmed and upper-cased.
fn normal(code: &str) -> String {
    code.trim().to_ascii_uppercase()
}

async fn append(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    entity: Option<i64>,
    details: serde_json::Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: entity.map(|id| AuditEntity {
            kind: "device_key".to_owned(),
            id,
        }),
        details: details.to_string(),
    };
    audit::append(conn, &event).await.map(drop)
}

async fn prune_in(conn: &mut SqliteConnection, now: &str) -> Result<u64, Error> {
    sqlx::query("DELETE FROM device_pairings WHERE expires_at <= ?")
        .bind(now)
        .execute(conn)
        .await
        .map(|r| r.rows_affected())
}

/// Drops the codes expired at `now` (the scheduler's tick); returns how many.
pub async fn prune_pairings(pool: &SqlitePool, now: &str) -> Result<u64, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let n = prune_in(&mut tx, now).await?;
    tx.commit().await?;
    Ok(n)
}

/// A new code, live for `PAIRING_SECS` from `now`: `(code, expires_at)`. Expired codes are
/// dropped. Appends `device.pairing_started`.
pub async fn start_pairing(
    pool: &SqlitePool,
    actor: AuditActor,
    now: &str,
) -> Result<(String, String), Error> {
    let code = code()?;
    let mut tx = crate::store::begin_write(pool).await?;
    prune_in(&mut tx, now).await?;
    let expires: String = sqlx::query_scalar(
        "INSERT INTO device_pairings (code_hash, created_at, expires_at) \
         VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', ?2, '+' || ?3 || ' seconds')) \
         RETURNING expires_at",
    )
    .bind(key_hash(&code))
    .bind(now)
    .bind(PAIRING_SECS)
    .fetch_one(&mut *tx)
    .await?;
    append(
        &mut tx,
        actor,
        "device.pairing_started",
        None,
        json!({"expires_at": expires}),
    )
    .await?;
    tx.commit().await?;
    Ok((code, expires))
}

/// Trades `code` for a new device key named `name`: `None` when the code is unknown, used or
/// expired (it is spent by this call whatever follows); else the device and its key, shown once.
/// Appends `device.paired`.
pub async fn pair_device(
    pool: &SqlitePool,
    code: &str,
    name: &str,
    now: &str,
) -> Result<Option<(DeviceKey, String)>, Error> {
    if name.trim().is_empty() {
        return Err(Error::InvalidArgument("a device needs a name".to_owned()));
    }
    let hash = key_hash(&normal(code));
    let spent = sqlx::query(
        "UPDATE device_pairings SET used_at = ? WHERE code_hash = ? AND used_at IS NULL \
         AND expires_at > ?",
    )
    .bind(now)
    .bind(&hash)
    .bind(now)
    .execute(pool)
    .await?
    .rows_affected();
    if spent == 0 {
        return Ok(None);
    }
    let by = AuditActor::User(ainkrad_core::ids::UserId(1));
    let (device, key) = issue_device_key(pool, name, by).await?;
    sqlx::query("UPDATE device_pairings SET device_key_id = ? WHERE code_hash = ?")
        .bind(device.id.0)
        .bind(&hash)
        .execute(pool)
        .await?;
    let mut conn = pool.acquire().await?;
    let d = json!({"name": device.name});
    append(
        &mut conn,
        AuditActor::System,
        "device.paired",
        Some(device.id.0),
        d,
    )
    .await?;
    Ok(Some((device, key)))
}
