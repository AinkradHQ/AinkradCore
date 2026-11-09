//! Device management from another device (E1-09.5, handshake spec §8, §12): rename, change
//! scopes, revoke. Each is one write transaction that reads, checks and changes the row and
//! audits it, so two concurrent changes cannot both pass a check the other breaks (the last
//! admin above all).
//!
//! - **Subset rule:** a device grants only scopes it holds itself, so nobody widens anyone,
//!   itself included, past its own scopes.
//! - **Kinds:** a runner holds exactly `[runner]`; no other kind ever holds `runner`.
//! - **The last admin:** no change through the API may leave the Core without an active admin
//!   device (removing `admin` from it, or revoking it). The host's `device revoke` and
//!   `recover` are not held to this: the host is the root of trust (§12).

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, SqliteConnection};

use super::SCOPES;
use super::devices::audit_device;

/// Why a change was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// No such device, or it is revoked.
    NotFound,
    /// The request itself is wrong (400).
    Bad(&'static str),
    /// It would leave no active admin device (409).
    LastAdmin,
}

/// Longest device name, in characters.
pub const NAME_MAX: usize = 64;

/// A valid device name: trimmed, 1 to [`NAME_MAX`] characters, no control characters.
pub fn valid_name(name: &str) -> Option<&str> {
    let n = name.trim();
    (!n.is_empty() && n.chars().count() <= NAME_MAX && !n.chars().any(char::is_control))
        .then_some(n)
}

/// A live (not revoked) row, read inside the transaction.
struct Live {
    seq: i64,
    kind: String,
    status: String,
    scopes: Vec<String>,
}

async fn live(conn: &mut SqliteConnection, id: &str) -> Result<Option<Live>, Error> {
    let row: Option<(i64, String, String, String)> = sqlx::query_as(
        "SELECT seq, kind, status, scopes FROM core_devices WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|(seq, kind, status, scopes)| {
        serde_json::from_str(&scopes)
            .map(|scopes| Live {
                seq,
                kind,
                status,
                scopes,
            })
            .map_err(|e| Error::Decode(Box::new(e)))
    })
    .transpose()
}

/// Active, unrevoked admin devices other than `id` that can elevate (a step-up key, or an
/// unrevoked passkey). One that never can does not stand in for the admin removed (review S2).
async fn other_admins(conn: &mut SqliteConnection, id: &str) -> Result<i64, Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM core_devices WHERE id <> ? AND status = 'active' \
         AND revoked_at IS NULL AND (stepup_spki IS NOT NULL OR (kind = 'passkey' AND EXISTS \
         (SELECT 1 FROM core_passkeys p WHERE p.device_id = core_devices.id AND p.revoked_at IS NULL))) \
         AND EXISTS (SELECT 1 FROM json_each(scopes) WHERE value = 'admin')",
    )
    .bind(id)
    .fetch_one(conn)
    .await
}

/// Renames `id`, audited as `device.renamed`.
pub async fn rename_device(
    pool: &SqlitePool,
    id: &str,
    name: &str,
    by: AuditActor,
    by_device: &str,
) -> Result<Result<(), Refused>, Error> {
    let Some(name) = valid_name(name) else {
        return Ok(Err(Refused::Bad(
            "a name is 1 to 64 characters, no control characters",
        )));
    };
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(Live { seq, .. }) = live(&mut tx, id).await? else {
        return Ok(Err(Refused::NotFound));
    };
    sqlx::query("UPDATE core_devices SET name = ? WHERE id = ?")
        .bind(name)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"device": id, "name": name, "by_device": by_device});
    audit_device(&mut tx, seq, "device.renamed", by, details).await?;
    tx.commit().await?;
    Ok(Ok(()))
}

/// Sets `id`'s scopes to `scopes` on behalf of a device holding `mine`, audited as
/// `device.scopes_changed`. Returns the scopes as stored (deduplicated, catalogue order). The
/// caller fans the change out after this commits (`auth::Auth::rescoped`).
pub async fn set_device_scopes(
    pool: &SqlitePool,
    id: &str,
    scopes: &[String],
    mine: &[String],
    by: AuditActor,
    by_device: &str,
) -> Result<Result<Vec<String>, Refused>, Error> {
    if scopes.iter().any(|s| !SCOPES.contains(&s.as_str())) {
        return Ok(Err(Refused::Bad("unknown scope")));
    }
    if scopes.iter().any(|s| !mine.contains(s)) {
        return Ok(Err(Refused::Bad("a device grants only scopes it holds")));
    }
    let new: Vec<String> = SCOPES
        .iter()
        .filter(|s| scopes.iter().any(|x| x == *s))
        .map(|s| (*s).to_owned())
        .collect();
    if new.is_empty() {
        return Ok(Err(Refused::Bad("at least one scope")));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(Live {
        seq,
        kind,
        scopes: old,
        ..
    }) = live(&mut tx, id).await?
    else {
        return Ok(Err(Refused::NotFound));
    };
    let runner = new.iter().any(|s| s == "runner");
    if (kind == "runner") != runner || (runner && new.len() != 1) {
        return Ok(Err(Refused::Bad(
            "a runner holds exactly the runner scope; nothing else does",
        )));
    }
    let admin = |s: &[String]| s.iter().any(|x| x == "admin");
    if admin(&old) && !admin(&new) && other_admins(&mut tx, id).await? == 0 {
        return Ok(Err(Refused::LastAdmin));
    }
    sqlx::query("UPDATE core_devices SET scopes = ? WHERE id = ?")
        .bind(serde_json::to_string(&new).expect("strings serialise"))
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"device": id, "from": old, "to": new, "by_device": by_device});
    audit_device(&mut tx, seq, "device.scopes_changed", by, details).await?;
    tx.commit().await?;
    Ok(Ok(new))
}

/// Revokes `id` on behalf of another device: as `revoke_device`, but never the last active
/// admin device (checked in the same transaction).
pub async fn revoke_from_device(
    pool: &SqlitePool,
    id: &str,
    by: AuditActor,
    by_device: &str,
    now: &str,
) -> Result<Result<(), Refused>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(d) = live(&mut tx, id).await? else {
        return Ok(Err(Refused::NotFound));
    };
    let admin = d.status == "active" && d.scopes.iter().any(|s| s == "admin");
    if admin && other_admins(&mut tx, id).await? == 0 {
        return Ok(Err(Refused::LastAdmin));
    }
    match super::devices::revoke_in(&mut tx, id, by, Some(by_device), now).await? {
        true => {
            tx.commit().await?;
            Ok(Ok(()))
        }
        false => Ok(Err(Refused::NotFound)),
    }
}
