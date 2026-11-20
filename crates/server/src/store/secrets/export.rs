//! Exporting every value to its owner (E2-6, D-4): a danger route (a fresh step-up) that
//! is rate limited. The broker must be on, each value is opened inside the write transaction that
//! audits the export (`secret.exported`: the count, never a value), and every plaintext lives in a
//! `Zeroizing` buffer. Never exported: provider-account keys (the secrets `core_accounts` names, and any `acct.*`),
//! a module's own secrets (`brain.*`, `leyline.*`) and file secrets.

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use serde_json::json;
use sqlx::Row;
use sqlx::sqlite::SqlitePool;
use zeroize::Zeroizing;

use super::{Error, enabled, label, refused};
use crate::ops::secretbox::SecretBox;

/// One secret of an export. No `Debug`.
pub struct Exported {
    pub name: String,
    pub kind: String,
    pub group: Option<String>,
    pub file_name: Option<String>,
    pub value: Zeroizing<String>,
}

fn open(
    sealer: &SecretBox,
    name: &str,
    version: i64,
    key_id: &str,
    sealed: &[u8],
) -> Result<Zeroizing<String>, Error> {
    if !sealer.holds(key_id) {
        return refused(
            "secrets_unavailable",
            "the secret is sealed under a master key this Core does not hold",
        );
    }
    let value = sealer
        .open_as(key_id, &label(name, version), sealed)
        .ok()
        .and_then(|p| {
            std::str::from_utf8(&p)
                .ok()
                .map(|v| Zeroizing::new(v.to_owned()))
        });
    match value {
        Some(v) => Ok(v),
        None => {
            tracing::error!(name, "a sealed secret did not open");
            refused("secrets_unavailable", "the secret did not open")
        }
    }
}

/// Opens every secret the export may hold (see the module doc), by name, and
/// audits the export once as `secret.exported` with the count.
pub async fn export_all(
    pool: &SqlitePool,
    sealer: &SecretBox,
    by_device: &str,
    actor: AuditActor,
) -> Result<Vec<Exported>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    enabled(&mut tx).await?;
    let rows = sqlx::query(
        "SELECT s.name, s.version, s.key_id, s.sealed, s.kind, s.file_name, g.name AS group_name \
         FROM core_secrets s LEFT JOIN core_secret_groups g ON g.id = s.group_id \
         WHERE s.name NOT LIKE 'acct.%' \
         AND NOT EXISTS (SELECT 1 FROM core_accounts a WHERE a.secret_name = s.name) AND s.name NOT LIKE 'brain.%' \
         AND s.name NOT LIKE 'leyline.%' AND s.kind <> 'file' ORDER BY s.name",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let name: String = row.try_get("name")?;
        let version: i64 = row.try_get("version")?;
        let key_id: String = row.try_get("key_id")?;
        let sealed: Vec<u8> = row.try_get("sealed")?;
        out.push(Exported {
            value: open(sealer, &name, version, &key_id, &sealed)?,
            kind: row.try_get("kind")?,
            group: row.try_get("group_name")?,
            file_name: row.try_get("file_name")?,
            name,
        });
    }
    let event = NewAuditEvent {
        actor,
        action: "secret.exported".to_owned(),
        entity: None,
        details: json!({"count": out.len(), "by_device": by_device}).to_string(),
    };
    crate::store::audit::append(&mut tx, &event).await?;
    tx.commit().await?;
    Ok(out)
}
