//! Pairings (handshake spec §7). A pairing is created by an approver device (or by `bootstrap`
//! on the host), claimed once by a new device, which becomes `pending`, then approved (the
//! device becomes `active`) or rejected. It lives 5 minutes from creation, claim and approval
//! included; past that it is `expired`, and so is a device that claimed it unapproved. Each
//! state change writes exactly one audit row in the same transaction as the change.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::{Value, json};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row, SqliteConnection};

use super::devices::{NewDevice, insert_device};
use crate::auth::crypto::random_id;
use crate::auth::pairing::{code_hash, ct_eq, new_code, new_secret, secret_hash};
use crate::scheduler::iso_of_unix;
use crate::store::{audit, begin_write};

/// How long a pairing lives.
pub const PAIRING_SECS: i64 = 300;
/// Live pairings at once.
pub const MAX_LIVE: i64 = 3;

/// A pairing row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub scopes: Vec<String>,
    /// The approver device that created it; `None` for the host's bootstrap.
    pub created_by: Option<String>,
    pub bootstrap: bool,
    pub created_at: String,
    pub expires_at: String,
    /// `live`, `claimed`, `approved`, `rejected`, `expired` or `burned`.
    pub status: String,
    pub device_id: Option<String>,
    pub sas: Option<String>,
}

fn pairing(row: SqliteRow) -> Result<Pairing, Error> {
    let scopes: String = row.try_get("scopes")?;
    Ok(Pairing {
        id: row.try_get("id")?,
        kind: row.try_get("kind")?,
        name: row.try_get("name")?,
        scopes: serde_json::from_str(&scopes).map_err(|e| Error::Decode(Box::new(e)))?,
        created_by: row.try_get("created_by")?,
        bootstrap: row.try_get("bootstrap")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        status: row.try_get("status")?,
        device_id: row.try_get("device_id")?,
        sas: row.try_get("sas")?,
    })
}

const COLUMNS: &str = "id, kind, name, scopes, created_by, bootstrap, created_at, expires_at, \
                       status, device_id, sas";

/// Appends `action` about a pairing; the entity is its device's row when it has one.
async fn append(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    device: Option<&str>,
    details: Value,
) -> Result<(), Error> {
    let seq: Option<i64> = match device {
        Some(d) => {
            sqlx::query_scalar("SELECT seq FROM core_devices WHERE id = ?")
                .bind(d)
                .fetch_optional(&mut *conn)
                .await?
        }
        None => None,
    };
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: seq.map(|id| AuditEntity {
            kind: "device".to_owned(),
            id,
        }),
        details: details.to_string(),
    };
    audit::append(conn, &event).await.map(drop)
}

/// Whether any device row exists, revoked ones included (bootstrap's guard, §7.3).
pub async fn any_device(conn: &mut SqliteConnection) -> Result<bool, Error> {
    sqlx::query_scalar("SELECT count(*) > 0 FROM core_devices")
        .fetch_one(conn)
        .await
}

pub async fn get_pairing(pool: &SqlitePool, id: &str) -> Result<Option<Pairing>, Error> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM core_pairings WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await?
    .map(pairing)
    .transpose()
}

/// What a new pairing binds.
#[derive(Debug, Clone)]
pub struct NewPairing<'a> {
    pub kind: &'a str,
    pub name: &'a str,
    pub scopes: &'a [String],
    pub created_by: Option<&'a str>,
    pub bootstrap: bool,
}

/// A created pairing: its credentials, shown once and kept only as hashes.
#[derive(Debug, Clone)]
pub struct Created {
    pub id: String,
    /// The typed code, canonical (10 characters).
    pub code: String,
    /// The QR secret, base64url.
    pub secret: String,
    pub expires: i64,
}

/// Creates a pairing at `now` (unix seconds), audited as `pairing.created`. Refused
/// (`InvalidArgument`) with three live already, or for a bootstrap once any device exists.
pub async fn create_pairing(
    pool: &SqlitePool,
    p: &NewPairing<'_>,
    actor: AuditActor,
    now: i64,
) -> Result<Created, Error> {
    let refuse = |why: &str| Err(Error::InvalidArgument(why.to_owned()));
    let mut tx = begin_write(pool).await?;
    let (now_at, expires) = (iso_of_unix(now), now + PAIRING_SECS);
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_pairings WHERE status = 'live' AND expires_at > ?",
    )
    .bind(&now_at)
    .fetch_one(&mut *tx)
    .await?;
    if live >= MAX_LIVE {
        return refuse("three pairings are live already");
    }
    if p.bootstrap && any_device(&mut tx).await? {
        return refuse("a device exists: bootstrap is for the first one only");
    }
    let (id, code, (secret_bytes, secret)) = (random_id("p_"), new_code(), new_secret());
    sqlx::query(
        "INSERT INTO core_pairings (id, code_hash, secret_hash, kind, name, scopes, created_by, \
         bootstrap, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(code_hash(&code).to_vec())
    .bind(secret_hash(&secret_bytes).to_vec())
    .bind(p.kind)
    .bind(p.name.trim())
    .bind(serde_json::to_string(p.scopes).expect("strings serialise"))
    .bind(p.created_by)
    .bind(p.bootstrap)
    .bind(&now_at)
    .bind(iso_of_unix(expires))
    .execute(&mut *tx)
    .await?;
    let details = json!({"pairing": id, "kind": p.kind, "name": p.name.trim(),
        "scopes": p.scopes, "by_device": p.created_by, "bootstrap": p.bootstrap});
    append(&mut tx, actor, "pairing.created", None, details).await?;
    tx.commit().await?;
    Ok(Created {
        id,
        code,
        secret,
        expires,
    })
}

/// The pairing a credential names, by the hash of the code (`by_code`) or of the secret, in any
/// state; the caller checks it is live.
pub async fn find_pairing(
    pool: &SqlitePool,
    hash: &[u8; 32],
    by_code: bool,
) -> Result<Option<Pairing>, Error> {
    let column = if by_code { "code_hash" } else { "secret_hash" };
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM core_pairings WHERE {column} = ?"
    )))
    .bind(hash.to_vec())
    .fetch_optional(pool)
    .await?
    .map(pairing)
    .transpose()
}

/// A claim whose credential and proofs were checked.
#[derive(Debug, Clone)]
pub struct Claim<'a> {
    pub pairing: &'a Pairing,
    pub device_id: &'a str,
    pub routine_spki: &'a [u8],
    pub stepup_spki: Option<&'a [u8]>,
    pub platform: Option<&'a str>,
    pub key_storage: Option<&'a str>,
    pub sas: &'a str,
}

/// Spends the pairing, inserts the device as `pending` with what the pairing bound, and audits
/// `pairing.claimed`, in one transaction: all of it or none. `false` when the pairing is no
/// longer live at `now` (or, for a bootstrap, a device appeared meanwhile).
pub async fn claim_pairing(pool: &SqlitePool, c: &Claim<'_>, now: i64) -> Result<bool, Error> {
    let mut tx = begin_write(pool).await?;
    let spent = sqlx::query(
        "UPDATE core_pairings SET status = 'claimed' \
         WHERE id = ? AND status = 'live' AND expires_at > ?",
    )
    .bind(&c.pairing.id)
    .bind(iso_of_unix(now))
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if spent != 1 || (c.pairing.bootstrap && any_device(&mut tx).await?) {
        return Ok(false);
    }
    let new = NewDevice {
        id: c.device_id,
        kind: &c.pairing.kind,
        name: &c.pairing.name,
        routine_spki: c.routine_spki,
        stepup_spki: c.stepup_spki,
        platform: c.platform,
        key_storage: c.key_storage,
        scopes: &c.pairing.scopes,
    };
    insert_device(&mut tx, &new, "pending").await?;
    sqlx::query("UPDATE core_pairings SET device_id = ?, sas = ? WHERE id = ?")
        .bind(c.device_id)
        .bind(c.sas)
        .bind(&c.pairing.id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"pairing": c.pairing.id, "device": c.device_id,
        "platform": c.platform, "key_storage": c.key_storage});
    let d = Some(c.device_id);
    append(&mut tx, AuditActor::System, "pairing.claimed", d, details).await?;
    tx.commit().await?;
    Ok(true)
}

/// How a decision on a pairing went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Done,
    NotFound,
    /// Not claimed (approve) or already decided.
    NotPending,
    Expired,
    SasMismatch,
    /// The scopes asked for are not within the pairing's (or the approver's).
    Wider,
}

/// Who decides: an approver device, or the host's bootstrap.
#[derive(Debug, Clone, Copy)]
pub struct Decider<'a> {
    pub actor: AuditActor,
    pub device: Option<&'a str>,
    /// The approver's own scopes; `None` for the host.
    pub scopes: Option<&'a [String]>,
}

/// Approves the claimed pairing `id` when `sas` is the one stored (compared in constant time):
/// the device becomes `active` with the bound scopes, or `narrow` (a subset of them and of the
/// approver's). Audited as `pairing.approved`, or `pairing.refused` on a SAS mismatch (the
/// device stays pending), or `pairing.expired` past the pairing's life.
pub async fn approve_pairing(
    pool: &SqlitePool,
    id: &str,
    sas: &str,
    narrow: Option<&[String]>,
    by: Decider<'_>,
    now: i64,
) -> Result<Decision, Error> {
    // Read and decided in one write transaction: a claim racing this call is either wholly
    // before it or wholly after.
    let mut tx = begin_write(pool).await?;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM core_pairings WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(p) = row.map(pairing).transpose()? else {
        return Ok(Decision::NotFound);
    };
    let scopes = narrow.unwrap_or(&p.scopes);
    let within = |outer: &[String]| scopes.iter().all(|s| outer.contains(s));
    if !within(&p.scopes) || by.scopes.is_some_and(|mine| !within(mine)) {
        return Ok(Decision::Wider);
    }
    if p.status != "claimed" || p.device_id.is_none() || p.sas.is_none() {
        return Ok(Decision::NotPending);
    }
    let expires_at = p.expires_at.clone();
    let device = p.device_id.as_deref();
    if expires_at <= iso_of_unix(now) {
        expire_one(&mut tx, &p.id, device).await?;
        tx.commit().await?;
        return Ok(Decision::Expired);
    }
    let typed = sas.replace('-', "").to_uppercase();
    let stored = p.sas.clone().unwrap_or_default().replace('-', "");
    if !ct_eq(&typed, &stored) {
        let details = json!({"pairing": p.id, "reason": "sas_mismatch", "by_device": by.device});
        append(&mut tx, by.actor, "pairing.refused", device, details).await?;
        tx.commit().await?;
        return Ok(Decision::SasMismatch);
    }
    sqlx::query(
        "UPDATE core_devices SET status = 'active', scopes = ? WHERE id = ? AND status = 'pending'",
    )
    .bind(serde_json::to_string(scopes).expect("strings serialise"))
    .bind(device)
    .execute(&mut *tx)
    .await?;
    decide(&mut tx, &p.id, "approved", by.device, now).await?;
    let details = json!({"pairing": p.id, "device": device, "scopes": scopes,
        "by_device": by.device, "bootstrap": p.bootstrap});
    append(&mut tx, by.actor, "pairing.approved", device, details).await?;
    tx.commit().await?;
    Ok(Decision::Done)
}

/// Rejects the pairing `id`, live or claimed; a claimant becomes `rejected`. Audited as
/// `pairing.rejected`.
pub async fn reject_pairing(
    pool: &SqlitePool,
    id: &str,
    by: Decider<'_>,
    now: i64,
) -> Result<Decision, Error> {
    let mut tx = begin_write(pool).await?;
    let row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT status, device_id FROM core_pairings WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((status, device)) = row else {
        return Ok(Decision::NotFound);
    };
    if !matches!(status.as_str(), "live" | "claimed") {
        return Ok(Decision::NotPending);
    }
    sqlx::query("UPDATE core_devices SET status = 'rejected' WHERE id = ? AND status = 'pending'")
        .bind(&device)
        .execute(&mut *tx)
        .await?;
    decide(&mut tx, id, "rejected", by.device, now).await?;
    let details = json!({"pairing": id, "device": device, "by_device": by.device});
    append(
        &mut tx,
        by.actor,
        "pairing.rejected",
        device.as_deref(),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(Decision::Done)
}

async fn decide(
    conn: &mut SqliteConnection,
    id: &str,
    status: &str,
    by: Option<&str>,
    now: i64,
) -> Result<(), Error> {
    sqlx::query("UPDATE core_pairings SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?")
        .bind(status)
        .bind(by.unwrap_or("local-admin"))
        .bind(iso_of_unix(now))
        .bind(id)
        .execute(conn)
        .await
        .map(drop)
}

async fn expire_one(
    conn: &mut SqliteConnection,
    id: &str,
    device: Option<&str>,
) -> Result<(), Error> {
    sqlx::query("UPDATE core_devices SET status = 'expired' WHERE id = ? AND status = 'pending'")
        .bind(device)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE core_pairings SET status = 'expired' WHERE id = ?")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    let details = json!({"pairing": id, "device": device});
    append(conn, AuditActor::System, "pairing.expired", device, details).await
}

/// Expires the pairings past `now` that are still live or claimed, and their pending devices
/// (the scheduler's tick), one `pairing.expired` row each; returns how many.
pub async fn expire_pairings(pool: &SqlitePool, now: &str) -> Result<u64, Error> {
    let mut tx = begin_write(pool).await?;
    let due: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT id, device_id FROM core_pairings \
         WHERE status IN ('live', 'claimed') AND expires_at <= ?",
    )
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    for (id, device) in &due {
        expire_one(&mut tx, id, device.as_deref()).await?;
    }
    tx.commit().await?;
    Ok(due.len() as u64)
}

/// Burns every live pairing (the global wrong-claim budget ran out, §7.4), audited as one
/// `pairing.burned` row naming them all; returns their ids.
pub async fn burn_pairings(pool: &SqlitePool) -> Result<Vec<String>, Error> {
    let mut tx = begin_write(pool).await?;
    let burned: Vec<String> = sqlx::query_scalar(
        "UPDATE core_pairings SET status = 'burned' WHERE status = 'live' RETURNING id",
    )
    .fetch_all(&mut *tx)
    .await?;
    // Nothing live, nothing burned, nothing to record (review M4).
    if !burned.is_empty() {
        let details = json!({"pairings": burned, "reason": "wrong-claim budget spent"});
        append(&mut tx, AuditActor::System, "pairing.burned", None, details).await?;
    }
    tx.commit().await?;
    Ok(burned)
}
