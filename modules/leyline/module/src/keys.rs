//! Keys (Y1-02): generate an ed25519 key in the Core, or import an OpenSSH private key (ed25519,
//! ECDSA P-256/P-384). RSA and DSA are refused (no `rsa` crate in the tree: RUSTSEC-2023-0071).
//!
//! Where the private bytes are, and for how long:
//! - The request body holds them (and a passphrase) in `Zeroizing` strings; the passphrase is used
//!   once, to decrypt, and is dropped. The key is re-written unencrypted and without a comment.
//! - They are sealed at once as a `core_secrets` entry (kind `file`, group `leyline-keys`) in the
//!   same transaction as the `leyline_keys` row; from then on they leave only through the secret
//!   lease path (`leaseSecret` -> `redeemSecretLease`), which this module never calls.
//! - Nothing below logs, audits, publishes or returns them: the view, the audit row and the event
//!   carry the id, the public key and the fingerprint. Every refusal is a fixed sentence.
//!
//! Who may be leased a key: each key's secret carries its own runner list (`sync_runners`): the
//! active `via_runner` of every host that uses the key directly, and of every host that has a host
//! using it as a jump hop (the built-in runner stands for an unset `via_runner`), and the runner of
//! every open Mac-direct lease for such a host (`leyline_direct`, Y6-01). A key no host
//! uses has no runner. The group's own list stays empty.
//!
//! ECDSA keys are parsed, not validated: the `ssh-key` curve features (`p256`, `p384`) pull
//! `crypto-bigint` 0.5 (RUSTSEC-2026-0387), so a private scalar that does not match its public point
//! is not caught here. It fails safe at use: the runner's `ring` backend refuses a mismatched pair.
//!
//! The private key is stored with delivery `file`; the lease path (Y2) must hand it to `ssh` over an
//! inherited fd, never write it to disk.

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use ainkrad_core_server::store::gov::LOCAL_ENROL_SAS;
use ainkrad_core_server::store::secrets::{self, Error, NewValue};
use ainkrad_core_server::store::{audit, begin_write, events, secret_groups};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqliteConnection};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, Kdf, LineEnding, PrivateKey};
use std::collections::{BTreeSet, HashMap, HashSet};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::hosts::In;
use crate::valid;

/// The secret group every Leyline private key lives in.
pub const GROUP: &str = "leyline-keys";
const INVALID: &str = "the key is not valid";
const UNSUPPORTED: &str = "RSA keys are not supported; generate an ed25519 key (Generate Key). \
                           Only OpenSSH private keys of type ed25519 or ECDSA (P-256, P-384) are \
                           accepted; DSA is refused too";
const PEM_MAX: usize = 16 * 1024;
const PASS_MAX: usize = 1024;
/// `ssh-keygen` writes 16; each round is milliseconds of CPU, so a hostile count is a DoS.
const BCRYPT_ROUNDS_MAX: u32 = 1024;

#[derive(Serialize, ToSchema)]
pub struct KeyView {
    /// `k_` and 16 hex characters.
    pub id: String,
    pub name: String,
    /// `ed25519`, `ecdsa-p256` or `ecdsa-p384`.
    pub algo: String,
    /// The OpenSSH one-line public key.
    pub public_key: String,
    /// `SHA256:...`, as `ssh-keygen -l` prints it.
    pub fingerprint: String,
    /// `generated` or `imported`.
    pub origin: String,
    pub created_at: String,
}

fn view(r: &sqlx::sqlite::SqliteRow) -> Result<KeyView, sqlx::Error> {
    let text = |c: &str| r.try_get::<String, _>(c);
    Ok(KeyView {
        id: text("id")?,
        name: text("name")?,
        algo: text("algo")?,
        public_key: text("public_key")?,
        fingerprint: text("fingerprint")?,
        origin: text("origin")?,
        created_at: text("created_at")?,
    })
}

#[derive(Deserialize, ToSchema)]
pub struct NewKey {
    pub name: String,
}

/// No `Debug`: nothing may print it.
#[derive(Deserialize, ToSchema)]
pub struct ImportKey {
    pub name: String,
    /// An OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`), at most 16 KiB.
    #[schema(value_type = String)]
    pub private_key: Zeroizing<String>,
    /// Only for an encrypted key. Used once to decrypt, then dropped; never stored.
    #[schema(value_type = Option<String>)]
    pub passphrase: Option<Zeroizing<String>>,
}

fn refuse(why: &'static str) -> ApiError {
    ApiError::bad_request(why)
}

fn algo_of(a: &Algorithm) -> Option<&'static str> {
    match a {
        Algorithm::Ed25519 => Some("ed25519"),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        } => Some("ecdsa-p256"),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        } => Some("ecdsa-p384"),
        _ => None,
    }
}

/// An importable key, decrypted. The algorithm and the hashing cost are public even on an
/// encrypted key, so an RSA or DSA key and a hostile cost are refused before the passphrase is
/// used. CPU-bound: call it from `spawn_blocking`.
fn parse(pem: &str, pass: Option<&str>) -> Result<PrivateKey, ApiError> {
    if pem.len() > PEM_MAX || pass.is_some_and(|p| p.len() > PASS_MAX) {
        return Err(refuse(INVALID));
    }
    let key = PrivateKey::from_openssh(pem).map_err(|_| refuse(INVALID))?;
    if algo_of(&key.algorithm()).is_none() {
        return Err(refuse(UNSUPPORTED));
    }
    if !key.is_encrypted() {
        return Ok(key);
    }
    if matches!(key.kdf(), Kdf::Bcrypt { rounds, .. } if *rounds > BCRYPT_ROUNDS_MAX) {
        return Err(refuse("the key's password hashing cost is too high"));
    }
    let pass = pass
        .filter(|p| !p.is_empty())
        .ok_or_else(|| refuse("the key is encrypted; send its passphrase"))?;
    key.decrypt(pass)
        .map_err(|_| refuse("the passphrase does not match the key"))
}

fn sealer(app: &App) -> Result<&ainkrad_core_server::ops::secretbox::SecretBox, ApiError> {
    app.secrets.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "secrets_unavailable",
            "this Core has no master key loaded",
        )
    })
}

/// Maps a table refusal to a fixed sentence (never the database's text).
fn store_err(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            ApiError::conflict("a key with that name or fingerprint exists")
        }
        sqlx::Error::Database(d) if d.is_check_violation() => refuse(INVALID),
        _ => e.into(),
    }
}

async fn record(conn: &mut SqliteConnection, op: &str, id: &str) -> Result<(), sqlx::Error> {
    let row = NewAuditEvent {
        actor: BY,
        action: format!("leyline.key.{op}"),
        entity: None,
        details: json!({"key": id}).to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(conn, "leyline.key", &json!({"op": op, "id": id})).await?;
    Ok(())
}

/// Seals `key` and records it, in one transaction: either both the secret and the row exist or
/// neither does.
async fn store(
    app: &App,
    me: &Caller,
    name: &str,
    mut key: PrivateKey,
    origin: &str,
) -> ApiResult<KeyView> {
    let algo = algo_of(&key.algorithm()).ok_or_else(|| refuse(UNSUPPORTED))?;
    if !valid::label(name) {
        return Err(refuse(INVALID));
    }
    let sealer = sealer(app)?;
    // The mode gate first, so a refused store leaves nothing; then the (empty) group exists.
    secrets::require_enabled(&app.pool).await?;
    ensure_group(app).await?;
    key.set_comment("");
    let pem = Zeroizing::new(
        key.to_openssh(LineEnding::LF)
            .map_err(|_| refuse(INVALID))?
            .to_string(),
    );
    let b64 = Zeroizing::new(STANDARD.encode(pem.as_bytes()));
    let public = key.public_key().to_openssh().map_err(|_| refuse(INVALID))?;
    let fp = key.fingerprint(HashAlg::Sha256).to_string();
    let id = valid::new_id("k_");
    let secret = format!("leyline.{id}");
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "INSERT INTO leyline_keys (id, name, algo, public_key, fingerprint, secret, origin) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(algo)
    .bind(&public)
    .bind(&fp)
    .bind(&secret)
    .bind(origin)
    .execute(&mut *tx)
    .await
    .map_err(store_err)?;
    let new = NewValue {
        value: &b64,
        kind: Some("file"),
        delivery: Some("file"),
        file_name: Some("id_leyline"),
        file_mode: Some(0o600),
        group: Some(GROUP),
        description: Some("Leyline key"),
        ..NewValue::default()
    };
    let now = app.clock.now();
    secrets::create_in(&mut tx, sealer, &secret, &new, &me.device.id, BY, &now).await?;
    record(&mut tx, "created", &id).await?;
    let row = sqlx::query("SELECT * FROM leyline_keys WHERE id = ?")
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
    let out = view(&row)?;
    tx.commit().await?;
    // A new key has no host yet, so its (empty) runner list needs no sync.
    Ok(Json(out))
}

#[utoipa::path(post, path = "/keys", operation_id = "leylineGenerateKey", tag = "leyline", request_body = NewKey,
    responses((status = 200, description = "A new ed25519 key, generated in the Core and sealed (audited as `leyline.key.created`). The private half is never returned. 409 `secrets_disabled` (`secrets.mode` 0), `real_secret_refused` (mode 1: a real key waits for mode 2), `conflict`", body = KeyView)))]
pub(crate) async fn generate(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    In(req): In<NewKey>,
) -> ApiResult<KeyView> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed).map_err(|_| refuse(INVALID))?;
    let key = PrivateKey::new(KeypairData::from(Ed25519Keypair::from_seed(&seed)), "")
        .map_err(|_| refuse(INVALID))?;
    store(&app, &me, &req.name, key, "generated").await
}

#[utoipa::path(post, path = "/keys/import", operation_id = "leylineImportKey", tag = "leyline", request_body = ImportKey,
    responses((status = 200, description = "The imported key, sealed (step-up; audited as `leyline.key.created`). ed25519 and ECDSA P-256/P-384 only; RSA and DSA are refused (400). The passphrase is used once and discarded; the private half is never returned", body = KeyView)))]
pub(crate) async fn import(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    In(req): In<ImportKey>,
) -> ApiResult<KeyView> {
    let ImportKey {
        name,
        private_key,
        passphrase,
    } = req;
    // Both secrets move into the closure and are dropped (zeroized) when it ends.
    let key = tokio::task::spawn_blocking(move || {
        parse(&private_key, passphrase.as_deref().map(String::as_str))
    })
    .await
    .map_err(|_| refuse(INVALID))??;
    store(&app, &me, &name, key, "imported").await
}

#[utoipa::path(get, path = "/keys", operation_id = "leylineListKeys", tag = "leyline",
    responses((status = 200, description = "Every key by name: public data only", body = Vec<KeyView>)))]
pub(crate) async fn list(State(app): State<App>) -> ApiResult<Vec<KeyView>> {
    let rows = sqlx::query("SELECT * FROM leyline_keys ORDER BY name COLLATE NOCASE")
        .fetch_all(&app.pool)
        .await?;
    Ok(Json(rows.iter().map(view).collect::<Result<_, _>>()?))
}

#[utoipa::path(get, path = "/keys/{key}", operation_id = "leylineGetKey", tag = "leyline",
    params(("key" = String, Path, description = "Key id")),
    responses((status = 200, description = "The key: public data only", body = KeyView)))]
pub(crate) async fn get(State(app): State<App>, Path(key): Path<String>) -> ApiResult<KeyView> {
    let none = || ApiError::not_found("no such key");
    if !valid::key_id(&key) {
        return Err(none());
    }
    let row = sqlx::query("SELECT * FROM leyline_keys WHERE id = ?")
        .bind(&key)
        .fetch_optional(&app.pool)
        .await?
        .ok_or_else(none)?;
    Ok(Json(view(&row)?))
}

#[derive(Serialize, ToSchema)]
pub struct KeyDeleted {
    pub deleted: String,
}

#[utoipa::path(delete, path = "/keys/{key}", operation_id = "leylineDeleteKey", tag = "leyline",
    params(("key" = String, Path, description = "Key id")),
    responses((status = 200, description = "Deleted with its sealed private half (step-up; audited as `leyline.key.deleted`); 409 while a host uses it", body = KeyDeleted)))]
pub(crate) async fn remove(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(key): Path<String>,
) -> ApiResult<KeyDeleted> {
    let none = || ApiError::not_found("no such key");
    if !valid::key_id(&key) {
        return Err(none());
    }
    let mut tx = begin_write(&app.pool).await?;
    let secret: String = sqlx::query_scalar("SELECT secret FROM leyline_keys WHERE id = ?")
        .bind(&key)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(none)?;
    let used: i64 = sqlx::query_scalar("SELECT count(*) FROM leyline_hosts WHERE key_id = ?")
        .bind(&key)
        .fetch_one(&mut *tx)
        .await?;
    if used > 0 {
        return Err(ApiError::conflict("a host uses this key"));
    }
    match secrets::delete_in(&mut tx, &secret, &me.device.id, BY).await {
        Ok(()) => {}
        // Already gone (a person removed the secret by hand): the row still goes.
        Err(Error::Refused {
            code: "not_found", ..
        }) => {}
        Err(e) => return Err(e.into()),
    }
    sqlx::query("DELETE FROM leyline_keys WHERE id = ?")
        .bind(&key)
        .execute(&mut *tx)
        .await
        .map_err(store_err)?;
    record(&mut tx, "deleted", &key).await?;
    tx.commit().await?;
    Ok(Json(KeyDeleted { deleted: key }))
}

/// One sync at a time: each reads the hosts afresh after taking the lock, so the last to run
/// leaves the lists that match the latest hosts.
static SYNC: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The `leyline-keys` group exists and has no runner of its own: a key's own list decides, so a
/// group list would only widen it. Called with `SYNC` held, outside any transaction (the group
/// store opens its own).
async fn assert_group(app: &App) -> Result<(), ApiError> {
    let current = {
        let mut conn = app.pool.acquire().await?;
        secret_groups::find(&mut conn, GROUP).await
    };
    let now = app.clock.now();
    match current {
        Ok(g) if g.runners.is_empty() => Ok(()),
        Ok(_) => secret_groups::update(&app.pool, GROUP, None, Some(&[]), "leyline", BY, &now)
            .await
            .map(drop),
        Err(Error::Refused {
            code: "not_found", ..
        }) => secret_groups::create(
            &app.pool,
            GROUP,
            "Leyline SSH keys",
            &[],
            "leyline",
            BY,
            &now,
        )
        .await
        .map(drop),
        Err(e) => Err(e),
    }
    .map_err(ApiError::from)
}

async fn ensure_group(app: &App) -> Result<(), ApiError> {
    let _one = SYNC.lock().await;
    assert_group(app).await
}

/// Sets each key's secret to the runners that may be leased it (see the module doc). Idempotent;
/// hosts call it after every change, in one transaction, and it re-asserts the group's empty
/// list each time. The broker does the write (`secrets::set_runners_in`: it drops the key's
/// outstanding leases and audits `secret.runners_changed`); a change also publishes a
/// `leyline.key` event.
pub(crate) async fn sync_runners(app: &App) -> Result<(), ApiError> {
    let _one = SYNC.lock().await;
    assert_group(app).await?;
    let now = app.clock.now();
    let mut tx = begin_write(&app.pool).await?;
    let active: HashSet<String> = sqlx::query_scalar(
        "SELECT id FROM core_devices WHERE kind = 'runner' AND status = 'active' AND revoked_at IS NULL",
    )
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .collect();
    let built_in: Vec<String> = sqlx::query_scalar(
        "SELECT device_id FROM core_pairings WHERE kind = 'runner' AND sas = ? AND device_id IS NOT NULL",
    )
    .bind(LOCAL_ENROL_SAS)
    .fetch_all(&mut *tx)
    .await?;
    // (key secret, runner of a host that uses the key, or has it as a jump hop's key).
    let uses: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT k.secret, h.via_runner FROM leyline_keys k, leyline_hosts h WHERE h.key_id = k.id \
         UNION \
         SELECT k.secret, h.via_runner FROM leyline_keys k, leyline_hosts hop, leyline_hosts h, \
                json_each(h.jump_chain) j WHERE hop.key_id = k.id AND j.value = hop.id \
         UNION \
         SELECT k.secret, d.runner FROM leyline_direct d, leyline_hosts h, leyline_keys k \
                WHERE d.ended_at IS NULL AND h.id = d.host_id AND k.id = h.key_id \
         UNION \
         SELECT k.secret, d.runner FROM leyline_direct d, leyline_hosts h, \
                json_each(h.jump_chain) j, leyline_hosts hop, leyline_keys k \
                WHERE d.ended_at IS NULL AND h.id = d.host_id AND hop.id = j.value AND k.id = hop.key_id",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut want: HashMap<&str, BTreeSet<&String>> = HashMap::new();
    for (secret, via) in &uses {
        let set = want.entry(secret).or_default();
        match via {
            Some(r) => set.extend(active.get(r)),
            None => set.extend(built_in.iter().filter(|b| active.contains(*b))),
        }
    }
    let keys: Vec<(String, String)> = sqlx::query_as(
        "SELECT k.secret, s.runners FROM leyline_keys k JOIN core_secrets s ON s.name = k.secret",
    )
    .fetch_all(&mut *tx)
    .await?;
    for (secret, have) in keys {
        let wanted: Vec<String> = want
            .get(secret.as_str())
            .map(|s| s.iter().map(|r| (*r).clone()).collect())
            .unwrap_or_default();
        let have: Vec<String> = serde_json::from_str(&have).unwrap_or_default();
        if have.iter().eq(wanted.iter()) {
            continue;
        }
        if secrets::set_runners_in(&mut tx, &secret, &wanted, "leyline", BY, &now).await? {
            let id = secret.strip_prefix("leyline.").unwrap_or(&secret);
            events::append(&mut tx, "leyline.key", &json!({"op": "runners", "id": id})).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_ed25519_and_nist_p256_p384_are_accepted() {
        assert_eq!(algo_of(&Algorithm::Ed25519), Some("ed25519"));
        let ecdsa = |curve| Algorithm::Ecdsa { curve };
        assert_eq!(algo_of(&ecdsa(EcdsaCurve::NistP256)), Some("ecdsa-p256"));
        assert_eq!(algo_of(&ecdsa(EcdsaCurve::NistP384)), Some("ecdsa-p384"));
        assert_eq!(algo_of(&ecdsa(EcdsaCurve::NistP521)), None);
        assert_eq!(algo_of(&Algorithm::Dsa), None);
        assert_eq!(algo_of(&Algorithm::Rsa { hash: None }), None);
    }
}
