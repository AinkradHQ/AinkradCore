//! Pairings (handshake spec §7). A pairing lives 5 minutes from creation, covering the claim
//! and the approval; past that it is `expired`, and a device that claimed it but was not
//! approved becomes `expired` too and is never usable.

use sqlx::Error;
use sqlx::sqlite::SqlitePool;

/// How long a pairing lives.
pub const PAIRING_SECS: i64 = 300;

/// Expires the pairings past `now` that are still live or claimed, and their pending devices
/// (the scheduler's tick); returns how many pairings.
pub async fn expire_pairings(pool: &SqlitePool, now: &str) -> Result<u64, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    sqlx::query(
        "UPDATE core_devices SET status = 'expired' WHERE status = 'pending' AND id IN \
         (SELECT device_id FROM core_pairings WHERE status = 'claimed' AND expires_at <= ?)",
    )
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let n = sqlx::query(
        "UPDATE core_pairings SET status = 'expired' \
         WHERE status IN ('live', 'claimed') AND expires_at <= ?",
    )
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(n)
}
