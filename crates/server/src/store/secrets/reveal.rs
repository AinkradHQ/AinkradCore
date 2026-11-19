//! Showing and exporting a value to its owner (E2-6, D-4): the only way a value leaves the Core
//! other than a lease to a runner. The routes need an admin device with a live step-up and are
//! rate limited; here the broker must be on, the value is opened inside the write transaction
//! that audits it (`secret.revealed`, `secret.exported`: the name or the count, never a value),
//! and every plaintext lives in a `Zeroizing` buffer. Provider-account keys (`acct.*`) are the
//! Accounts screen's and are never shown or exported.

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use serde_json::json;
use sqlx::Row;
use sqlx::sqlite::SqlitePool;
use zeroize::Zeroizing;

use super::{ACCOUNT_PREFIX, Error, audit, enabled, label, refused};
use crate::ops::secretbox::SecretBox;

/// One secret's value, for its owner. No `Debug`.
pub struct Revealed {
    pub name: String,
    pub version: i64,
    pub kind: String,
    pub file_name: Option<String>,
    pub value: Zeroizing<String>,
}

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

/// Opens secret `name` for the device `by_device` and audits it as `secret.revealed`.
pub async fn reveal(
    pool: &SqlitePool,
    sealer: &SecretBox,
    name: &str,
    by_device: &str,
    actor: AuditActor,
) -> Result<Revealed, Error> {
    if name.starts_with(ACCOUNT_PREFIX) {
        return refused(
            "bad_request",
            "provider-account keys are managed through the accounts API",
        );
    }
    let mut tx = crate::store::begin_write(pool).await?;
    enabled(&mut tx).await?;
    let row = sqlx::query(
        "SELECT id, version, key_id, sealed, kind, file_name FROM core_secrets WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        return refused("not_found", "no such secret");
    };
    let (id, version): (i64, i64) = (row.try_get("id")?, row.try_get("version")?);
    let key_id: String = row.try_get("key_id")?;
    let sealed: Vec<u8> = row.try_get("sealed")?;
    let value = open(sealer, name, version, &key_id, &sealed)?;
    let details = json!({"name": name, "version": version, "by_device": by_device});
    audit(&mut tx, actor, "secret.revealed", id, details).await?;
    tx.commit().await?;
    Ok(Revealed {
        name: name.to_owned(),
        version,
        kind: row.try_get("kind")?,
        file_name: row.try_get("file_name")?,
        value,
    })
}

/// Opens every secret the Secrets screen lists (all but provider-account keys), by name, and
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
         WHERE s.name NOT LIKE 'acct.%' ORDER BY s.name",
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
