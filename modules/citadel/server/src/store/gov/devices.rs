//! Device keys as a service (E10.3): issue, authorize, revoke. Each device the admin uses
//! (#18: one admin, a key per device) gets its own random key, shown once; only its hash is
//! stored (`library`). A revoked key keeps its row, so its last use stays visible.

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::gov::{DeviceKey, DeviceKeyId};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, SqliteConnection};

use super::{get_device_key, get_device_key_by_key};
use crate::store::{audit, key_hash, random_key};

async fn append(
    conn: &mut SqliteConnection,
    id: DeviceKeyId,
    action: &str,
    by: AuditActor,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor: by,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "device_key".to_owned(),
            id: id.0,
        }),
        company_id: None,
        run_id: None,
        details: json!({}).to_string(),
    };
    audit::append(conn, &event).await.map(drop)
}

/// A new device key named `name` (`cit_device_` + 256 bits): the row, and the key, which is
/// returned here once and never stored. Appends `device_key.created`.
pub async fn issue_device_key(
    pool: &SqlitePool,
    name: &str,
    by: AuditActor,
) -> Result<(DeviceKey, String), Error> {
    if name.trim().is_empty() {
        return Err(Error::InvalidArgument("a device needs a name".to_owned()));
    }
    let key = random_key("cit_device_")?;
    let mut tx = crate::store::begin_write(pool).await?;
    let id: i64 =
        sqlx::query_scalar("INSERT INTO device_keys (name, key_hash) VALUES (?, ?) RETURNING id")
            .bind(name.trim())
            .bind(key_hash(&key))
            .fetch_one(&mut *tx)
            .await?;
    append(&mut tx, DeviceKeyId(id), "device_key.created", by).await?;
    tx.commit().await?;
    let device = get_device_key(pool, DeviceKeyId(id))
        .await?
        .ok_or(Error::RowNotFound)?;
    Ok((device, key))
}

/// The live (not revoked) device holding `key`, if any. Marks it used at `now`, at most once
/// a minute, so a busy client does not turn every read into a write.
pub async fn authorize_device_key(
    pool: &SqlitePool,
    key: &str,
    now: &str,
) -> Result<Option<DeviceKey>, Error> {
    let Some(mut d) = get_device_key_by_key(pool, key).await? else {
        return Ok(None);
    };
    if d.revoked_at.is_some() {
        return Ok(None);
    }
    // Same minute: the stored `YYYY-MM-DDTHH:MM` prefix already says it.
    let minute = |t: &str| t.get(..16).map(str::to_owned);
    if d.last_used_at.as_deref().and_then(minute) != minute(now) {
        sqlx::query("UPDATE device_keys SET last_used_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(now)
            .bind(d.id.0)
            .execute(pool)
            .await?;
        d.last_used_at = Some(now.to_owned());
    }
    Ok(Some(d))
}

/// Revokes the key at `now`, so it stops authorizing at once; appends `device_key.revoked`.
/// `false` when there is no such device or it was already revoked.
pub async fn revoke_device_key(
    pool: &SqlitePool,
    id: DeviceKeyId,
    by: AuditActor,
    now: &str,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let revoked =
        sqlx::query("UPDATE device_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(now)
            .bind(id.0)
            .execute(&mut *tx)
            .await?
            .rows_affected()
            == 1;
    if revoked {
        append(&mut tx, id, "device_key.revoked", by).await?;
    }
    tx.commit().await?;
    Ok(revoked)
}

/// Where a device gets pushes (E10.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushTarget {
    pub device: DeviceKeyId,
    /// The APNs device token, lowercase hex.
    pub token: String,
    /// A development build's token: the sandbox gateway.
    pub sandbox: bool,
}

/// Sets (or with `None` clears) the device's push token; `false` when it is gone or
/// revoked. A token is lowercase hex; anything else is `Error::InvalidArgument`.
pub async fn set_push_token(
    pool: &SqlitePool,
    device: DeviceKeyId,
    token: Option<(&str, bool)>,
) -> Result<bool, Error> {
    let token = token.map(|(t, sandbox)| (t.trim().to_ascii_lowercase(), sandbox));
    if let Some((t, _)) = &token
        && (!(32..=200).contains(&t.len()) || !t.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(Error::InvalidArgument(
            "a push token is 32 to 200 hex digits".to_owned(),
        ));
    }
    sqlx::query(
        "UPDATE device_keys SET push_token = ?, push_sandbox = ? \
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(token.as_ref().map(|(t, _)| t))
    .bind(token.as_ref().is_some_and(|(_, s)| *s))
    .bind(device.0)
    .execute(pool)
    .await
    .map(|r| r.rows_affected() == 1)
}

/// Every live device with a push token.
pub async fn push_targets(pool: &SqlitePool) -> Result<Vec<PushTarget>, Error> {
    let rows: Vec<(i64, String, bool)> = sqlx::query_as(
        "SELECT id, push_token, push_sandbox FROM device_keys \
         WHERE revoked_at IS NULL AND push_token IS NOT NULL ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, token, sandbox)| PushTarget {
            device: DeviceKeyId(id),
            token,
            sandbox,
        })
        .collect())
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
mod tests {
    use citadel_core::audit::AuditFilter;
    use citadel_core::work::UserId;

    use super::*;
    use crate::store::gov::list_device_keys;

    const BY: AuditActor = AuditActor::User(UserId(1));

    #[tokio::test]
    async fn issue_authorize_and_revoke() {
        let dir = std::env::temp_dir().join(format!("citadel-devices-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::store::connect(&dir.join("citadel.db"))
            .await
            .unwrap();

        let (d, key) = issue_device_key(&pool, " MacBook ", BY).await.unwrap();
        assert!(
            key.starts_with("cit_device_") && key.len() == 11 + 64,
            "{key}"
        );
        assert_eq!(d.name, "MacBook");
        assert!(issue_device_key(&pool, " ", BY).await.is_err());

        let t1 = "2026-10-22T10:00:01.000Z";
        let got = authorize_device_key(&pool, &key, t1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.last_used_at.as_deref(), Some(t1));
        // Same minute: not written again.
        let t2 = "2026-10-22T10:00:59.000Z";
        authorize_device_key(&pool, &key, t2)
            .await
            .unwrap()
            .unwrap();
        let stored = &list_device_keys(&pool).await.unwrap()[0];
        assert_eq!(stored.last_used_at.as_deref(), Some(t1));
        assert!(
            authorize_device_key(&pool, "cit_device_nope", t1)
                .await
                .unwrap()
                .is_none()
        );

        assert!(revoke_device_key(&pool, d.id, BY, t2).await.unwrap());
        assert!(!revoke_device_key(&pool, d.id, BY, t2).await.unwrap());
        assert!(
            authorize_device_key(&pool, &key, t2)
                .await
                .unwrap()
                .is_none()
        );
        let actions: Vec<String> = audit::list(&pool, &AuditFilter::default(), None, 10)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(actions, ["device_key.created", "device_key.revoked"]);

        // Push tokens: live devices only, hex only.
        let (live, _) = issue_device_key(&pool, "iPhone", BY).await.unwrap();
        let hex = "ab".repeat(32);
        assert!(
            set_push_token(&pool, live.id, Some((&hex.to_uppercase(), true)))
                .await
                .unwrap()
        );
        assert!(
            !set_push_token(&pool, d.id, Some((&hex, false)))
                .await
                .unwrap(),
            "revoked"
        );
        assert!(
            set_push_token(&pool, live.id, Some(("not hex", false)))
                .await
                .is_err()
        );
        let want = PushTarget {
            device: live.id,
            token: hex,
            sandbox: true,
        };
        assert_eq!(push_targets(&pool).await.unwrap(), [want]);
        assert!(set_push_token(&pool, live.id, None).await.unwrap());
        assert_eq!(push_targets(&pool).await.unwrap(), []);
        assert_eq!(push_cursor(&pool).await.unwrap(), None);
        set_push_cursor(&pool, 7).await.unwrap();
        set_push_cursor(&pool, 9).await.unwrap();
        assert_eq!(push_cursor(&pool).await.unwrap(), Some(9));

        pool.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
