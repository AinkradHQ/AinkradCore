//! Devices (handshake spec §3): each one a P-256 public key it generated itself, a random
//! `d_…` id, a kind, scopes and a status; read here. Enrolling, revoking and push targets are
//! in `devices`, persisted lockouts in `limits`, pairings in `pairing`.

use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row};

mod devices;
mod limits;
mod manage;
mod pairing;
mod passkeys;
mod pushtokens;
pub use devices::*;
pub use limits::*;
pub use manage::*;
pub use pairing::*;
pub use passkeys::*;
pub use pushtokens::*;

/// The scope catalogue (spec §8, E1-09 enforces it).
pub const SCOPES: [&str; 6] = ["read", "approve", "terminal", "agent", "admin", "runner"];

/// What a device is: a native client or CLI, a runner, or a browser passkey (E1-08).
pub const KINDS: [&str; 3] = ["device", "runner", "passkey"];

/// A device row. Never a private key: the Core has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The local row number: what audit rows name.
    pub seq: i64,
    /// `d_` + 26 characters.
    pub id: String,
    pub kind: String,
    pub name: String,
    /// The routine key, a 91-byte SPKI.
    pub routine_spki: Vec<u8>,
    pub fingerprint: String,
    pub stepup_spki: Option<Vec<u8>>,
    pub platform: Option<String>,
    pub key_storage: Option<String>,
    pub scopes: Vec<String>,
    /// `pending`, `active`, `rejected`, `expired` or `locked`.
    pub status: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl Device {
    /// Whether it may authenticate at all: active and not revoked.
    pub fn usable(&self) -> bool {
        self.status == "active" && self.revoked_at.is_none()
    }
}

macro_rules! device_columns {
    () => {
        "seq, id, kind, name, routine_spki, fingerprint, stepup_spki, platform, key_storage, \
         scopes, status, created_at, last_used_at, revoked_at"
    };
}

fn device(row: SqliteRow) -> Result<Device, Error> {
    let scopes: String = row.try_get("scopes")?;
    Ok(Device {
        seq: row.try_get("seq")?,
        id: row.try_get("id")?,
        kind: row.try_get("kind")?,
        name: row.try_get("name")?,
        routine_spki: row.try_get("routine_spki")?,
        fingerprint: row.try_get("fingerprint")?,
        stepup_spki: row.try_get("stepup_spki")?,
        platform: row.try_get("platform")?,
        key_storage: row.try_get("key_storage")?,
        scopes: serde_json::from_str(&scopes).map_err(|e| Error::Decode(Box::new(e)))?,
        status: row.try_get("status")?,
        created_at: row.try_get("created_at")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

/// The device `id`, in any state.
pub async fn get_device(pool: &SqlitePool, id: &str) -> Result<Option<Device>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        device_columns!(),
        " FROM core_devices WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?
    .map(device)
    .transpose()
}

/// Every device, revoked ones too, oldest first.
pub async fn list_devices(pool: &SqlitePool) -> Result<Vec<Device>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        device_columns!(),
        " FROM core_devices ORDER BY seq"
    ))
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(device)
    .collect()
}

/// Whether `id` is a device that may still authenticate (the WebSocket backstop, §10).
pub async fn device_usable(pool: &SqlitePool, id: &str) -> Result<bool, Error> {
    sqlx::query_scalar(
        "SELECT count(*) > 0 FROM core_devices \
         WHERE id = ? AND status = 'active' AND revoked_at IS NULL",
    )
    .bind(id)
    .fetch_one(pool)
    .await
}
