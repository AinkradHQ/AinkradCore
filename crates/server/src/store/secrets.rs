//! The secrets broker v0 (E2-07, P2.9; ADR §Security 4; threat model T-SEC-1..4): agent API
//! tokens, git credentials and SSH material, held by the Core and handed to a runner only for
//! what it runs.
//!
//! - **At rest** a value is sealed with the master key (`ops::secretbox`: AES-256-GCM, a fresh
//!   nonce per seal, the key's `key_id` stored beside it). The associated data names the secret
//!   and its version, so a sealed value cannot be moved to another secret or rolled back to an
//!   older one.
//! - **Out** only through a lease: granted (by an elevated `admin` device, or the Core itself)
//!   for one runner in the secret's scope (`runners`), redeemed once, by that runner, before it
//!   expires. Nothing lists, returns or logs a value; the plaintext lives in `Zeroizing` buffers.
//! - **Audited**: every store, rotation, deletion, grant and redemption appends a `secret.*`
//!   row in the same transaction, naming the secret, never its value.
//! - **Gate G-SEC** (`secrets.mode`): 0 (the default) refuses every store, rotation, grant and
//!   redemption; 1 takes throwaway values only (one shaped like a real key is refused); 2 takes
//!   real ones, once the external review has closed. Listing and deleting always work.
//! - **Bounded**: the value's size, the number of secrets and of live leases, and a lease's
//!   lifetime are settings (`secrets.*`).

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::redact::Redactor;
use ring::digest::{SHA256, digest};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};
use zeroize::Zeroizing;

use super::settings::value_in;
use crate::ops::secretbox::SecretBox;

/// How a runner hands a secret to a session (E2-07.2).
pub const DELIVERY: [&str; 3] = ["env", "file", "askpass"];

/// A secret as it is listed: everything but its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub id: i64,
    pub name: String,
    /// The device that stored it, `d_…`.
    pub owner: String,
    /// The runner devices it may be leased to.
    pub runners: Vec<String>,
    pub delivery: String,
    /// 1 when stored, one more per rotation.
    pub version: i64,
    /// The value's length in bytes.
    pub size: i64,
    /// The master key it is sealed under.
    pub key_id: String,
    pub created_at: String,
    pub updated_at: String,
}

/// A value to store, with its scope. No `Debug`: nothing may print it.
pub struct NewValue<'a> {
    pub value: &'a str,
    /// `None` keeps what it was (an empty scope for a new secret).
    pub runners: Option<&'a [String]>,
    /// `None` keeps what it was (`env` for a new secret).
    pub delivery: Option<&'a str>,
}

/// A redeemed lease: the value and how to deliver it. No `Debug`.
pub struct Redeemed {
    pub name: String,
    pub version: i64,
    pub delivery: String,
    pub value: Zeroizing<String>,
    /// The lease's end, unix seconds: the runner drops the value by then or at session end.
    pub expires_at: i64,
}

/// Why the broker refused, with a stable code. The message never holds a value.
#[derive(Debug)]
pub enum Error {
    Refused { code: &'static str, message: String },
    Db(sqlx::Error),
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused { code, message } => write!(f, "{code}: {message}"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

fn refused<T>(code: &'static str, message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.into(),
    })
}

/// `[a-z][a-z0-9_.-]{0,63}`, the table's own check: a name can carry nothing else into a path,
/// a log line or an audit row.
pub fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
}

/// The associated data of a sealed value: its secret and version.
fn label(name: &str, version: i64) -> String {
    format!("core.secret:{name}:v{version}")
}

fn hex8(bytes: &[u8]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}

async fn setting(conn: &mut SqliteConnection, key: Key) -> Result<i64, Error> {
    Ok(value_in(conn, key, Scope::Server).await?)
}

/// Refuses while the broker is off (G-SEC, `secrets.mode` 0); the mode otherwise.
async fn enabled(conn: &mut SqliteConnection) -> Result<i64, Error> {
    match setting(conn, Key::SecretsMode).await? {
        0 => refused(
            "secrets_disabled",
            "the secrets broker is off (secrets.mode 0, gate G-SEC)",
        ),
        mode => Ok(mode),
    }
}

/// The checks every value passes before it is sealed.
async fn check_value(conn: &mut SqliteConnection, value: &str) -> Result<(), Error> {
    let mode = enabled(conn).await?;
    let max = setting(conn, Key::SecretsMaxBytes).await?;
    if value.is_empty() {
        return refused("bad_request", "the value is empty");
    }
    if value.len() as i64 > max {
        return refused(
            "too_large",
            format!("the value is over secrets.max_bytes ({max} bytes)"),
        );
    }
    // Before G-SEC only throwaway values: one the redactor recognises as a real key shape is
    // refused. ponytail: shapes only, as the redactor; a real value with no known prefix gets
    // through, which is why mode 1 is a guard rail and the gate itself is mode 2.
    if mode < 2 && Redactor::new().text(value) != value {
        return refused(
            "real_secret_refused",
            "the value looks like a real credential; real secrets wait for gate G-SEC \
             (secrets.mode 2)",
        );
    }
    Ok(())
}

/// The scope, checked: each an active runner device, no repeats.
async fn check_runners(conn: &mut SqliteConnection, runners: &[String]) -> Result<(), Error> {
    for (i, id) in runners.iter().enumerate() {
        if runners[..i].contains(id) || !active_runner(conn, id).await? {
            return refused(
                "bad_request",
                format!("{id:?} is not an active runner, or is listed twice"),
            );
        }
    }
    Ok(())
}

async fn active_runner(conn: &mut SqliteConnection, id: &str) -> Result<bool, Error> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_devices WHERE id = ? AND kind = 'runner' \
         AND status = 'active' AND revoked_at IS NULL",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(n == 1)
}

fn check_delivery(delivery: &str) -> Result<(), Error> {
    match DELIVERY.contains(&delivery) {
        true => Ok(()),
        false => refused("bad_request", "delivery is env, file or askpass"),
    }
}

fn meta(row: sqlx::sqlite::SqliteRow) -> Result<Meta, sqlx::Error> {
    let runners: String = row.try_get("runners")?;
    Ok(Meta {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        owner: row.try_get("owner")?,
        runners: serde_json::from_str(&runners).unwrap_or_default(),
        delivery: row.try_get("delivery")?,
        version: row.try_get("version")?,
        size: row.try_get("size")?,
        key_id: row.try_get("key_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

const META: &str = "SELECT id, name, owner, runners, delivery, version, size, key_id, \
                    created_at, updated_at FROM core_secrets";

async fn find(conn: &mut SqliteConnection, name: &str) -> Result<Meta, Error> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!("{META} WHERE name = ?")))
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;
    match row {
        Some(row) => Ok(meta(row)?),
        None => refused("not_found", "no such secret"),
    }
}

async fn audit(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    id: i64,
    details: serde_json::Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "secret".to_owned(),
            id,
        }),
        details: details.to_string(),
    };
    super::audit::append(conn, &event).await?;
    Ok(())
}

/// Every secret, by name; never a value.
pub async fn list(pool: &SqlitePool) -> Result<Vec<Meta>, sqlx::Error> {
    sqlx::query(sqlx::AssertSqlSafe(format!("{META} ORDER BY name")))
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(meta)
        .collect()
}

/// Stores a new secret `name` for `owner` (a device id), audited as `secret.created`.
pub async fn create(
    pool: &SqlitePool,
    sealer: &SecretBox,
    name: &str,
    new: &NewValue<'_>,
    owner: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Meta, Error> {
    if !valid_name(name) {
        return refused("bad_request", "a name is [a-z][a-z0-9_.-]{0,63}");
    }
    let delivery = new.delivery.unwrap_or("env");
    check_delivery(delivery)?;
    let runners = new.runners.unwrap_or_default();
    let mut tx = super::begin_write(pool).await?;
    check_value(&mut tx, new.value).await?;
    check_runners(&mut tx, runners).await?;
    let max = setting(&mut tx, Key::SecretsMaxCount).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secrets")
        .fetch_one(&mut *tx)
        .await?;
    if count >= max {
        return refused(
            "limit_reached",
            format!("the broker holds secrets.max_count ({max}) secrets"),
        );
    }
    let exists: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secrets WHERE name = ?")
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;
    if exists > 0 {
        return refused("conflict", "a secret of that name exists; rotate it");
    }
    let sealed = sealer
        .seal(&label(name, 1), new.value.as_bytes())
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let runners_json = json!(runners).to_string();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO core_secrets (name, owner, runners, delivery, version, key_id, sealed, \
         size, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(name)
    .bind(owner)
    .bind(&runners_json)
    .bind(delivery)
    .bind(sealer.key_id())
    .bind(&sealed)
    .bind(new.value.len() as i64)
    .bind(now)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    let details = json!({"name": name, "version": 1, "runners": runners, "delivery": delivery,
                         "size": new.value.len(), "key_id": sealer.key_id(), "by_device": owner});
    audit(&mut tx, actor, "secret.created", id, details).await?;
    let m = find(&mut tx, name).await?;
    tx.commit().await?;
    Ok(m)
}

/// Replaces `name`'s value (and its scope or delivery, when given): a new version, audited as
/// `secret.rotated`. Every outstanding lease on it is dropped in the same transaction (review
/// M2): a grant made for one version never delivers the next; a new value needs a new grant.
pub async fn rotate(
    pool: &SqlitePool,
    sealer: &SecretBox,
    name: &str,
    new: &NewValue<'_>,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Meta, Error> {
    let mut tx = super::begin_write(pool).await?;
    let old = find(&mut tx, name).await?;
    check_value(&mut tx, new.value).await?;
    let delivery = new.delivery.unwrap_or(&old.delivery);
    check_delivery(delivery)?;
    let runners = new.runners.unwrap_or(&old.runners);
    check_runners(&mut tx, runners).await?;
    let version = old.version + 1;
    let sealed = sealer
        .seal(&label(name, version), new.value.as_bytes())
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    sqlx::query(
        "UPDATE core_secrets SET runners = ?, delivery = ?, version = ?, key_id = ?, sealed = ?, \
         size = ?, updated_at = ? WHERE id = ?",
    )
    .bind(json!(runners).to_string())
    .bind(delivery)
    .bind(version)
    .bind(sealer.key_id())
    .bind(&sealed)
    .bind(new.value.len() as i64)
    .bind(now)
    .bind(old.id)
    .execute(&mut *tx)
    .await?;
    let dropped = sqlx::query("DELETE FROM core_secret_leases WHERE secret_id = ?")
        .bind(old.id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let details = json!({"name": name, "version": version, "runners": runners,
                         "delivery": delivery, "size": new.value.len(),
                         "key_id": sealer.key_id(), "leases_revoked": dropped,
                         "by_device": by_device});
    audit(&mut tx, actor, "secret.rotated", old.id, details).await?;
    let m = find(&mut tx, name).await?;
    tx.commit().await?;
    Ok(m)
}

/// Deletes `name` and its leases, audited as `secret.deleted`. Works whatever the mode.
pub async fn delete(
    pool: &SqlitePool,
    name: &str,
    by_device: &str,
    actor: AuditActor,
) -> Result<(), Error> {
    let mut tx = super::begin_write(pool).await?;
    let old = find(&mut tx, name).await?;
    sqlx::query("DELETE FROM core_secrets WHERE id = ?")
        .bind(old.id)
        .execute(&mut *tx)
        .await?;
    let details = json!({"name": name, "version": old.version, "by_device": by_device});
    audit(&mut tx, actor, "secret.deleted", old.id, details).await?;
    tx.commit().await?;
    Ok(())
}

/// Grants `runner` a lease on `name` for `ttl` seconds (default and most: `secrets.lease_secs`),
/// audited as `secret.leased`. The runner must be in the secret's scope. Returns the lease's
/// `l_…` id, which only that runner can redeem, and its end (unix seconds).
#[allow(clippy::too_many_arguments)]
pub async fn lease(
    pool: &SqlitePool,
    name: &str,
    runner: &str,
    ttl: Option<i64>,
    by_device: &str,
    actor: AuditActor,
    now: &str,
    now_unix: i64,
) -> Result<(String, i64), Error> {
    let mut tx = super::begin_write(pool).await?;
    enabled(&mut tx).await?;
    let s = find(&mut tx, name).await?;
    if !s.runners.iter().any(|r| r == runner) || !active_runner(&mut tx, runner).await? {
        return refused(
            "bad_request",
            "the runner is not an active runner in this secret's scope",
        );
    }
    let most = setting(&mut tx, Key::SecretsLeaseSecs).await?;
    let ttl = ttl.unwrap_or(most);
    if !(1..=most).contains(&ttl) {
        return refused(
            "bad_request",
            format!("ttl_secs is 1..={most} (secrets.lease_secs)"),
        );
    }
    // Spent and expired leases go first: they only count against the bound.
    sqlx::query("DELETE FROM core_secret_leases WHERE used_at IS NOT NULL OR expires_at <= ?")
        .bind(now_unix)
        .execute(&mut *tx)
        .await?;
    let max = setting(&mut tx, Key::SecretsMaxLeases).await?;
    let live: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secret_leases")
        .fetch_one(&mut *tx)
        .await?;
    if live >= max {
        return refused(
            "limit_reached",
            format!("secrets.max_leases ({max}) leases are live"),
        );
    }
    // One runner may hold a quarter of them (review L5): a runaway agent session, now that the
    // Core grants leases itself (E2-08), cannot starve every other runner.
    let per_runner = (max / 4).max(2).min(max);
    let mine: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secret_leases WHERE runner = ?")
        .bind(runner)
        .fetch_one(&mut *tx)
        .await?;
    if mine >= per_runner {
        return refused(
            "limit_reached",
            format!("this runner holds {per_runner} live leases (a quarter of secrets.max_leases)"),
        );
    }
    let id = crate::auth::crypto::random_id("l_");
    let hash = digest(&SHA256, id.as_bytes());
    let expires_at = now_unix + ttl;
    sqlx::query(
        "INSERT INTO core_secret_leases (hash, secret_id, runner, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(hash.as_ref())
    .bind(s.id)
    .bind(runner)
    .bind(expires_at)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let details = json!({"name": name, "version": s.version, "runner": runner,
                         "lease": hex8(hash.as_ref()), "expires_at": expires_at,
                         "by_device": by_device});
    audit(&mut tx, actor, "secret.leased", s.id, details).await?;
    tx.commit().await?;
    Ok((id, expires_at))
}

/// Redeems lease `id` for `runner` (the calling device): once, before it expires, while the
/// runner is still in the secret's scope. Audited as `secret.redeemed`. A lease that is not
/// this runner's is `not_found`, as one that never existed; a spent or expired one is
/// `lease_expired`. A refusal leaves the lease as it was.
pub async fn redeem(
    pool: &SqlitePool,
    sealer: &SecretBox,
    id: &str,
    runner: &str,
    actor: AuditActor,
    now: &str,
    now_unix: i64,
) -> Result<Redeemed, Error> {
    let hash = digest(&SHA256, id.as_bytes());
    let mut tx = super::begin_write(pool).await?;
    enabled(&mut tx).await?;
    let row = sqlx::query(
        "SELECT l.runner, l.expires_at, l.used_at, s.id, s.name, s.runners, s.delivery, \
         s.version, s.key_id, s.sealed FROM core_secret_leases l \
         JOIN core_secrets s ON s.id = l.secret_id WHERE l.hash = ?",
    )
    .bind(hash.as_ref())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) =
        row.filter(|r| r.try_get::<String, _>("runner").ok().as_deref() == Some(runner))
    else {
        return refused("not_found", "no such lease");
    };
    let used: Option<String> = row.try_get("used_at")?;
    let expires_at: i64 = row.try_get("expires_at")?;
    if used.is_some() || expires_at <= now_unix {
        return refused("lease_expired", "the lease is spent or expired");
    }
    let scope: Vec<String> =
        serde_json::from_str(&row.try_get::<String, _>("runners")?).unwrap_or_default();
    if !scope.iter().any(|r| r == runner) || !active_runner(&mut tx, runner).await? {
        return refused("not_found", "no such lease");
    }
    let (secret, name): (i64, String) = (row.try_get("id")?, row.try_get("name")?);
    let version: i64 = row.try_get("version")?;
    let key_id: String = row.try_get("key_id")?;
    if key_id != sealer.key_id() {
        tracing::error!(
            name,
            key_id,
            loaded = sealer.key_id(),
            "secret sealed under another master key"
        );
        return refused(
            "secrets_unavailable",
            "the secret is sealed under a master key this Core does not hold",
        );
    }
    let sealed: Vec<u8> = row.try_get("sealed")?;
    let plain = match sealer.open(&label(&name, version), &sealed) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(name, error = %e, "a sealed secret did not open");
            return refused("secrets_unavailable", "the secret did not open");
        }
    };
    let value = match std::str::from_utf8(&plain) {
        Ok(v) => Zeroizing::new(v.to_owned()),
        Err(_) => return refused("secrets_unavailable", "the secret did not open"),
    };
    sqlx::query("UPDATE core_secret_leases SET used_at = ? WHERE hash = ?")
        .bind(now)
        .bind(hash.as_ref())
        .execute(&mut *tx)
        .await?;
    let delivery: String = row.try_get("delivery")?;
    let details = json!({"name": name, "version": version, "runner": runner,
                         "lease": hex8(hash.as_ref()), "delivery": delivery,
                         "by_device": runner});
    audit(&mut tx, actor, "secret.redeemed", secret, details).await?;
    tx.commit().await?;
    Ok(Redeemed {
        name,
        version,
        delivery,
        value,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_narrow() {
        for ok in ["a", "github.token", "ssh-deploy_key.2", &"a".repeat(64)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            "A",
            "1a",
            ".a",
            "a b",
            "a/b",
            "a{b}",
            "é",
            &"a".repeat(65),
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
    }
}
