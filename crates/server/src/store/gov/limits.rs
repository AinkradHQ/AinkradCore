//! Persisted failure counters and lockouts (handshake spec §11), in `core_auth_limits`, so a
//! restart does not reset an attacker's budget. Keys are by address (`ip:…`) and by address
//! and claimed device (`ipdev:…`), never by device alone: device ids are claimed by whoever
//! sends them, so a lock on a device id would let anyone lock its owner out. Only failures
//! write. Times are unix seconds.

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use serde_json::json;
use sqlx::Error;
use sqlx::sqlite::SqlitePool;

use crate::store::audit;

/// How a key locks: `threshold` failures within `window` lock it for `lock`, doubling per
/// strike up to `max_lock`. Strikes are forgotten after a day without one.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub threshold: i64,
    pub window: i64,
    pub lock: i64,
    pub max_lock: i64,
}

/// Every auth failure from one address: 20 per 10 minutes, then 1 minute doubling to 1 hour.
pub const ADDRESS: Rule = Rule {
    threshold: 20,
    window: 600,
    lock: 60,
    max_lock: 3600,
};

/// Auth failures from one address naming one device: 5 per 10 minutes, then 5 minutes doubling
/// to 1 hour.
pub const ADDRESS_DEVICE: Rule = Rule {
    threshold: 5,
    window: 600,
    lock: 300,
    max_lock: 3600,
};

const STRIKE_DECAY: i64 = 86_400;

/// The latest `locked_until` after `now` among `keys`, if any is locked.
pub async fn locked_until(
    pool: &SqlitePool,
    keys: &[&str],
    now: i64,
) -> Result<Option<i64>, Error> {
    let mut until = None;
    for key in keys {
        let got: Option<i64> = sqlx::query_scalar(
            "SELECT locked_until FROM core_auth_limits WHERE key = ? AND locked_until > ?",
        )
        .bind(key)
        .bind(now)
        .fetch_optional(pool)
        .await?;
        until = until.max(got);
    }
    Ok(until)
}

/// Counts one failure against `key`; when it reaches the rule's threshold the key is locked,
/// and the lock is audited (`auth.lockout`) in the same transaction. Returns the lock's end
/// when this failure set one.
pub async fn record_failure(
    pool: &SqlitePool,
    key: &str,
    rule: Rule,
    now: i64,
) -> Result<Option<i64>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let row: Option<(i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT fails, window_start, strikes, strikes_at FROM core_auth_limits WHERE key = ?",
    )
    .bind(key)
    .fetch_optional(&mut *tx)
    .await?;
    let (mut fails, mut window_start, mut strikes, mut strikes_at) = row.unwrap_or((0, now, 0, 0));
    if now - window_start >= rule.window {
        (fails, window_start) = (0, now);
    }
    if strikes > 0 && now - strikes_at >= STRIKE_DECAY {
        strikes = 0;
    }
    fails += 1;
    let mut locked = None;
    if fails >= rule.threshold {
        strikes += 1;
        strikes_at = now;
        let secs = rule
            .lock
            .saturating_mul(1 << (strikes - 1).clamp(0, 20))
            .min(rule.max_lock);
        locked = Some(now + secs);
        (fails, window_start) = (0, now);
    }
    sqlx::query(
        "INSERT INTO core_auth_limits (key, fails, window_start, locked_until, strikes, strikes_at) \
         VALUES (?1, ?2, ?3, coalesce(?4, 0), ?5, ?6) ON CONFLICT (key) DO UPDATE SET \
         fails = ?2, window_start = ?3, locked_until = coalesce(?4, locked_until), \
         strikes = ?5, strikes_at = ?6",
    )
    .bind(key)
    .bind(fails)
    .bind(window_start)
    .bind(locked)
    .bind(strikes)
    .bind(strikes_at)
    .execute(&mut *tx)
    .await?;
    if let Some(until) = locked {
        let event = NewAuditEvent {
            actor: AuditActor::System,
            action: "auth.lockout".to_owned(),
            entity: None,
            details: json!({"key": key, "until": until, "strikes": strikes}).to_string(),
        };
        audit::append(&mut tx, &event).await?;
    }
    tx.commit().await?;
    Ok(locked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn locks_at_the_threshold_doubles_per_strike_and_persists() {
        let dir = std::env::temp_dir().join(format!("core-limits-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("core.db");
        let pool = crate::store::connect(&path).await.unwrap();
        let rule = ADDRESS_DEVICE;
        let t = 1_000_000;
        for i in 0..4 {
            assert_eq!(record_failure(&pool, "k", rule, t + i).await.unwrap(), None);
        }
        assert_eq!(locked_until(&pool, &["k"], t).await.unwrap(), None);
        let until = record_failure(&pool, "k", rule, t + 4).await.unwrap();
        assert_eq!(until, Some(t + 4 + 300));
        assert_eq!(
            locked_until(&pool, &["other", "k"], t + 5).await.unwrap(),
            until
        );
        // A restart keeps it.
        pool.close().await;
        let pool = crate::store::connect(&path).await.unwrap();
        assert_eq!(locked_until(&pool, &["k"], t + 5).await.unwrap(), until);
        assert_eq!(locked_until(&pool, &["k"], t + 304).await.unwrap(), None);
        // The second strike doubles.
        let t2 = t + 400;
        for i in 0..4 {
            record_failure(&pool, "k", rule, t2 + i).await.unwrap();
        }
        assert_eq!(
            record_failure(&pool, "k", rule, t2 + 4).await.unwrap(),
            Some(t2 + 4 + 600)
        );
        // Failures spread beyond the window never add up.
        for i in 0..10 {
            let at = t + 10_000 + i * rule.window;
            assert_eq!(record_failure(&pool, "slow", rule, at).await.unwrap(), None);
        }
        let audited: i64 =
            sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'auth.lockout'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(audited, 2, "one audit row per lock");
        pool.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
