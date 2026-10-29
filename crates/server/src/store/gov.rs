//! Devices: reading device keys here; issuing, authorizing and revoking them, and where their
//! pushes go (E10.3, E10.4), in `devices`; pairing a new device with a one-time code in
//! `pairing`.

use ainkrad_core::device::DeviceKey;
use ainkrad_core::ids::DeviceKeyId;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row};

use crate::store::key_hash;

mod devices;
mod pairing;
pub use devices::*;
pub use pairing::*;

macro_rules! device_key_columns {
    () => {
        "id, name, created_at, last_used_at, revoked_at"
    };
}

fn device_key(row: SqliteRow) -> Result<DeviceKey, Error> {
    Ok(DeviceKey {
        id: DeviceKeyId(row.try_get("id")?),
        name: row.try_get("name")?,
        created_at: row.try_get("created_at")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

pub async fn get_device_key(
    pool: &SqlitePool,
    id: DeviceKeyId,
) -> Result<Option<DeviceKey>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        device_key_columns!(),
        " FROM device_keys WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(device_key)
    .transpose()
}

/// The device key matching `key`, revoked or not; the caller checks `revoked_at`.
pub async fn get_device_key_by_key(
    pool: &SqlitePool,
    key: &str,
) -> Result<Option<DeviceKey>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        device_key_columns!(),
        " FROM device_keys WHERE key_hash = ?"
    ))
    .bind(key_hash(key))
    .fetch_optional(pool)
    .await?
    .map(device_key)
    .transpose()
}

pub async fn list_device_keys(pool: &SqlitePool) -> Result<Vec<DeviceKey>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        device_key_columns!(),
        " FROM device_keys ORDER BY id"
    ))
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(device_key)
    .collect()
}
