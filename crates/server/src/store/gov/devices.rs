//! Devices as a service: enrolment (through pairing, and a test-only shortcut for fixtures),
//! use marking, revocation and where pushes go (E10.4). A revoked device keeps its row.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, SqliteConnection};

use super::{KINDS, SCOPES};
use crate::auth::crypto::{fingerprint, spki_point};
use crate::store::audit;

/// Appends `action` about the device at row `seq`, with `details` (its `d_…` id among them).
pub(crate) async fn audit_device(
    conn: &mut SqliteConnection,
    seq: i64,
    action: &str,
    by: AuditActor,
    details: Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor: by,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "device".to_owned(),
            id: seq,
        }),
        details: details.to_string(),
    };
    audit::append(conn, &event).await.map(drop)
}

/// A device to insert: its keys and what it was bound to.
#[derive(Debug, Clone)]
pub struct NewDevice<'a> {
    pub id: &'a str,
    pub kind: &'a str,
    pub name: &'a str,
    pub routine_spki: &'a [u8],
    pub stepup_spki: Option<&'a [u8]>,
    pub platform: Option<&'a str>,
    pub key_storage: Option<&'a str>,
    pub scopes: &'a [String],
}

/// Inserts `d` with `status` inside the caller's transaction; returns its row number. Refuses
/// (`InvalidArgument`) a key that is not a P-256 SPKI on the curve, an unknown kind or scope,
/// a runner with any scope but `runner`, and a step-up key equal to the routine key.
pub(crate) async fn insert_device(
    conn: &mut SqliteConnection,
    d: &NewDevice<'_>,
    status: &str,
) -> Result<i64, Error> {
    let bad = |why: &str| Err(Error::InvalidArgument(why.to_owned()));
    if spki_point(d.routine_spki).is_none()
        || d.stepup_spki.is_some_and(|k| spki_point(k).is_none())
    {
        return bad("a device key is a P-256 SubjectPublicKeyInfo");
    }
    // The step-up key must be a second key: the routine key enrolled twice would make a plain
    // signature count as user verification (§8).
    if d.stepup_spki == Some(d.routine_spki) {
        return bad("the step-up key is not the routine key");
    }
    if !KINDS.contains(&d.kind) || d.name.trim().is_empty() {
        return bad("a device has a known kind and a name");
    }
    if d.scopes.iter().any(|s| !SCOPES.contains(&s.as_str())) {
        return bad("unknown scope");
    }
    if d.kind == "runner" && d.scopes.iter().any(|s| s != "runner") {
        return bad("a runner may only have the runner scope");
    }
    sqlx::query_scalar(
        "INSERT INTO core_devices (id, kind, name, routine_spki, fingerprint, stepup_spki, \
         platform, key_storage, scopes, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING seq",
    )
    .bind(d.id)
    .bind(d.kind)
    .bind(d.name.trim())
    .bind(d.routine_spki)
    .bind(fingerprint(d.routine_spki))
    .bind(d.stepup_spki)
    .bind(d.platform)
    .bind(d.key_storage)
    .bind(serde_json::to_string(d.scopes).expect("strings serialise"))
    .bind(status)
    .fetch_one(conn)
    .await
}

/// Test fixtures only: an active device straight into the store, skipping pairing. Audited
/// as `device.enrolled`. Not compiled into a release build.
#[cfg(any(test, feature = "test-support"))]
pub async fn enroll_for_tests(
    pool: &SqlitePool,
    d: &NewDevice<'_>,
) -> Result<super::Device, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let seq = insert_device(&mut tx, d, "active").await?;
    let details = json!({"device": d.id, "via": "test fixture"});
    audit_device(&mut tx, seq, "device.enrolled", AuditActor::System, details).await?;
    tx.commit().await?;
    super::get_device(pool, d.id)
        .await?
        .ok_or(Error::RowNotFound)
}

/// Marks `id` used at `now`, at most once a minute, so a busy client does not turn every read
/// into a write.
pub async fn mark_used(
    pool: &SqlitePool,
    id: &str,
    last: Option<&str>,
    now: &str,
) -> Result<(), Error> {
    let minute = |t: &str| t.get(..16).map(str::to_owned);
    if last.and_then(minute) == minute(now) {
        return Ok(());
    }
    sqlx::query("UPDATE core_devices SET last_used_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(pool)
        .await
        .map(drop)
}

/// Revokes `id` at `now` and audits `device.revoked` (naming the acting device, if any) in one
/// transaction. `false` when there is no such device or it was already revoked. The caller fans
/// the revocation out after this commits (`auth::Auth::revoked`).
pub async fn revoke_device(
    pool: &SqlitePool,
    id: &str,
    by: AuditActor,
    by_device: Option<&str>,
    now: &str,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let done = revoke_in(&mut tx, id, by, by_device, now).await?;
    if done {
        tx.commit().await?;
    }
    Ok(done)
}

/// `revoke_device` inside the caller's transaction.
pub(crate) async fn revoke_in(
    conn: &mut SqliteConnection,
    id: &str,
    by: AuditActor,
    by_device: Option<&str>,
    now: &str,
) -> Result<bool, Error> {
    let seq: Option<i64> = sqlx::query_scalar(
        "UPDATE core_devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL RETURNING seq",
    )
    .bind(now)
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(seq) = seq else {
        return Ok(false);
    };
    // Its push tokens go with it (E2-12.1): a revoked device is pushed nothing.
    sqlx::query("DELETE FROM core_push_tokens WHERE device_seq = ?")
        .bind(seq)
        .execute(&mut *conn)
        .await?;
    let details = json!({"device": id, "by_device": by_device});
    audit_device(conn, seq, "device.revoked", by, details).await?;
    Ok(true)
}

/// The last event seq the pusher has handled; `None` before its first run.
pub async fn push_cursor(pool: &SqlitePool) -> Result<Option<i64>, Error> {
    sqlx::query_scalar("SELECT after FROM push_cursor WHERE id = 1")
        .fetch_optional(pool)
        .await
}

pub async fn set_push_cursor(pool: &SqlitePool, after: i64) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO push_cursor (id, after) VALUES (1, ?) \
         ON CONFLICT (id) DO UPDATE SET after = excluded.after",
    )
    .bind(after)
    .execute(pool)
    .await
    .map(drop)
}

#[cfg(test)]
mod tests;
