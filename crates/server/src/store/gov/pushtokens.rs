//! Push tokens (E2-12.1): where a device gets pushes. One token per provider per device, bound
//! to the device that registered it; another device cannot register a token that is held. The row
//! goes when the device is revoked (`revoke_in`) and when the provider says the token is dead or
//! it fails too often (`note_result`).

use ainkrad_core::ids::DeviceKeyId;
use sqlx::sqlite::{SqliteConnection, SqlitePool};
use sqlx::{Error, Row};

use crate::store::begin_write;

/// The push providers a token can be for.
pub const PROVIDERS: [&str; 3] = ["apns", "fcm", "webpush"];

/// Where one push goes: a usable device's token at one provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushTarget {
    /// The device's row number.
    pub device: DeviceKeyId,
    /// The device's `d_…` id (what a delivery event names).
    pub device_id: String,
    /// The device's scopes: which notifications it may get.
    pub scopes: Vec<String>,
    /// One of [`PROVIDERS`].
    pub provider: String,
    /// The provider's token: APNs lowercase hex; FCM and web-push text.
    pub token: String,
    /// APNs only: a development build's token, for the sandbox gateway.
    pub sandbox: bool,
    /// The kinds the device opted into; `None` is every kind its scopes allow.
    pub kinds: Option<Vec<String>>,
}

/// The most kinds a device can list, and the longest one.
const MAX_KINDS: usize = 32;
const MAX_KIND: usize = 64;

/// `kinds` as stored: sorted, once each, each a short id-like name (`approval_needed`,
/// `citadel.issue_blocked`). A name no code raises is harmless; it just never matches.
pub fn clean_kinds(kinds: &[String]) -> Result<Vec<String>, Error> {
    let ok = |k: &String| {
        !k.is_empty()
            && k.len() <= MAX_KIND
            && k.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    };
    if kinds.len() > MAX_KINDS || !kinds.iter().all(ok) {
        return Err(Error::InvalidArgument(format!(
            "at most {MAX_KINDS} kinds, each 1 to {MAX_KIND} letters, digits, '_', '.' or '-'"
        )));
    }
    let mut out = kinds.to_vec();
    out.sort();
    out.dedup();
    Ok(out)
}

/// The kinds the device opted into (`None`: every kind its scopes allow).
pub async fn get_kinds(pool: &SqlitePool, device: &str) -> Result<Option<Vec<String>>, Error> {
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT k.kinds FROM core_push_kinds k JOIN core_devices d ON d.seq = k.device_seq \
         WHERE d.id = ?",
    )
    .bind(device)
    .fetch_optional(pool)
    .await?;
    raw.map(|r| serde_json::from_str(&r).map_err(|e| Error::Decode(Box::new(e))))
        .transpose()
}

/// Sets (`None` resets to every kind) what the device is pushed; `false` when the device is
/// gone or not usable. The choice outlives any one token: a pruned token that is registered
/// again keeps it.
pub async fn set_kinds(
    pool: &SqlitePool,
    device: &str,
    kinds: Option<&[String]>,
) -> Result<bool, Error> {
    let kinds = kinds.map(clean_kinds).transpose()?;
    let mut tx = begin_write(pool).await?;
    let seq: Option<i64> = sqlx::query_scalar(
        "SELECT seq FROM core_devices WHERE id = ? AND status = 'active' AND revoked_at IS NULL",
    )
    .bind(device)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(seq) = seq else {
        return Ok(false);
    };
    match kinds {
        Some(k) => {
            sqlx::query(
                "INSERT INTO core_push_kinds (device_seq, kinds) VALUES (?, ?) \
                 ON CONFLICT (device_seq) DO UPDATE SET kinds = excluded.kinds",
            )
            .bind(seq)
            .bind(serde_json::to_string(&k).map_err(|e| Error::Encode(Box::new(e)))?)
            .execute(&mut *tx)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM core_push_kinds WHERE device_seq = ?")
                .bind(seq)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(true)
}

/// The token as stored, or why it is refused.
fn clean(provider: &str, token: &str) -> Result<String, Error> {
    let bad = |why: &str| Err(Error::InvalidArgument(why.to_owned()));
    let t = token.trim();
    match provider {
        "apns" => {
            let t = t.to_ascii_lowercase();
            if (32..=200).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_hexdigit()) {
                Ok(t)
            } else {
                bad("a push token is 32 to 200 hex digits")
            }
        }
        "fcm" | "webpush" => {
            if (8..=4096).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_graphic()) {
                Ok(t.to_owned())
            } else {
                bad("a push token is 8 to 4096 printable characters")
            }
        }
        _ => bad("unknown push provider"),
    }
}

/// Sets (or with `None` clears) the device's `provider` token; `false` when the device is gone
/// or not usable. An invalid token is `Error::InvalidArgument`.
pub async fn set_token(
    pool: &SqlitePool,
    device: &str,
    provider: &str,
    token: Option<(&str, bool)>,
) -> Result<bool, Error> {
    let token = match token {
        Some((t, sandbox)) => Some((clean(provider, t)?, sandbox && provider == "apns")),
        None if PROVIDERS.contains(&provider) => None,
        None => return Err(Error::InvalidArgument("unknown push provider".to_owned())),
    };
    let mut tx = begin_write(pool).await?;
    let seq: Option<i64> = sqlx::query_scalar(
        "SELECT seq FROM core_devices WHERE id = ? AND status = 'active' AND revoked_at IS NULL",
    )
    .bind(device)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(seq) = seq else {
        return Ok(false);
    };
    match token {
        Some((token, sandbox)) => {
            // A token is one device's: another device cannot take it over (it would then
            // receive pushes under its own scopes, and the first would silently get none). A
            // reinstall on the same device re-registers its own; a revoked device's rows are
            // already gone.
            let held: Option<i64> = sqlx::query_scalar(
                "SELECT device_seq FROM core_push_tokens WHERE provider = ? AND token = ?",
            )
            .bind(provider)
            .bind(&token)
            .fetch_optional(&mut *tx)
            .await?;
            if held.is_some_and(|h| h != seq) {
                return Err(Error::InvalidArgument(
                    "that push token cannot be registered".to_owned(),
                ));
            }
            sqlx::query(
                "INSERT INTO core_push_tokens (device_seq, provider, token, sandbox) \
                 VALUES (?, ?, ?, ?) ON CONFLICT (device_seq, provider) DO UPDATE SET \
                 token = excluded.token, sandbox = excluded.sandbox, failures = 0",
            )
            .bind(seq)
            .bind(provider)
            .bind(token)
            .bind(sandbox)
            .execute(&mut *tx)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM core_push_tokens WHERE device_seq = ? AND provider = ?")
                .bind(seq)
                .bind(provider)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(true)
}

/// [`set_token`] for APNs, the one provider the client API registers today.
pub async fn set_push_token(
    pool: &SqlitePool,
    device: &str,
    token: Option<(&str, bool)>,
) -> Result<bool, Error> {
    set_token(pool, device, "apns", token).await
}

/// Every token of a usable device, oldest device first.
pub async fn push_targets(pool: &SqlitePool) -> Result<Vec<PushTarget>, Error> {
    let rows = sqlx::query(
        "SELECT d.seq, d.id, d.scopes, t.provider, t.token, t.sandbox, k.kinds \
         FROM core_push_tokens t JOIN core_devices d ON d.seq = t.device_seq \
         LEFT JOIN core_push_kinds k ON k.device_seq = d.seq \
         WHERE d.status = 'active' AND d.revoked_at IS NULL ORDER BY d.seq, t.id",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            let scopes: String = r.try_get("scopes")?;
            let kinds: Option<String> = r.try_get("kinds")?;
            Ok(PushTarget {
                device: DeviceKeyId(r.try_get("seq")?),
                device_id: r.try_get("id")?,
                scopes: serde_json::from_str(&scopes).map_err(|e| Error::Decode(Box::new(e)))?,
                provider: r.try_get("provider")?,
                token: r.try_get("token")?,
                sandbox: r.try_get("sandbox")?,
                kinds: kinds
                    .map(|k| serde_json::from_str(&k).map_err(|e| Error::Decode(Box::new(e))))
                    .transpose()?,
            })
        })
        .collect()
}

/// What a delivery did to a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenResult {
    Delivered,
    /// The provider says the token is dead.
    Invalid,
    /// A failure that may pass; the token goes after `max_failures` in a row.
    Failed,
}

/// Records a delivery's `result` on the token inside the caller's transaction; `true` when the
/// token was removed (dead, or `max_failures` failures in a row).
pub async fn note_result(
    conn: &mut SqliteConnection,
    to: &PushTarget,
    result: TokenResult,
    max_failures: i64,
) -> Result<bool, Error> {
    let key = (to.device.0, &to.provider, &to.token);
    let failures: Option<i64> = match result {
        TokenResult::Delivered => {
            sqlx::query(
                "UPDATE core_push_tokens SET failures = 0 \
                 WHERE device_seq = ? AND provider = ? AND token = ?",
            )
            .bind(key.0)
            .bind(key.1)
            .bind(key.2)
            .execute(&mut *conn)
            .await?;
            return Ok(false);
        }
        TokenResult::Invalid => None,
        TokenResult::Failed => {
            sqlx::query_scalar(
                "UPDATE core_push_tokens SET failures = failures + 1 \
                 WHERE device_seq = ? AND provider = ? AND token = ? RETURNING failures",
            )
            .bind(key.0)
            .bind(key.1)
            .bind(key.2)
            .fetch_optional(&mut *conn)
            .await?
        }
    };
    if result == TokenResult::Failed && failures.is_none_or(|f| f < max_failures) {
        return Ok(false);
    }
    let gone = sqlx::query(
        "DELETE FROM core_push_tokens WHERE device_seq = ? AND provider = ? AND token = ?",
    )
    .bind(key.0)
    .bind(key.1)
    .bind(key.2)
    .execute(&mut *conn)
    .await?;
    Ok(gone.rows_affected() == 1)
}
