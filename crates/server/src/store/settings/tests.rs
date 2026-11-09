//! The settings store (E15.17): a stored value beats the default, bounds are refused with the
//! reason, every change is audited and read back as history, and a reset inherits again.

use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::ids::UserId;

use super::*;
use crate::store::connect;

const NOW: &str = "2026-10-22T10:00:00.000Z";
const BY: AuditActor = AuditActor::User(UserId(1));

struct Db(SqlitePool, std::path::PathBuf);

impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

async fn db() -> Db {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-settings-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Db(connect(&dir.join("core.db")).await.unwrap(), dir)
}

async fn set(pool: &SqlitePool, key: Key, value: &str) -> Result<Effective, SetError> {
    super::set(pool, key, Scope::Server, value, BY, NOW).await
}

#[tokio::test]
async fn a_set_value_beats_the_default_and_reset_inherits() {
    let db = db().await;
    let pool = &db.0;
    let key = Key::PushIntervalSecs;
    let e = effective(pool, key, Scope::Server).await.unwrap();
    assert_eq!((e.value, e.source), (5, None));
    let e = set(pool, key, "30").await.unwrap();
    assert_eq!((e.value, e.source), (30, Some(Scope::Server)));
    assert_eq!(value(pool, key, Scope::Server).await.unwrap(), 30);
    let e = reset(pool, key, Scope::Server, BY, NOW).await.unwrap();
    assert_eq!((e.value, e.source), (5, None));
    // Resetting what is not set changes and audits nothing.
    reset(pool, key, Scope::Server, BY, NOW).await.unwrap();
    assert_eq!(history(pool, key, None).await.unwrap().len(), 2);
    // Every platform setting is listed at the server.
    assert_eq!(
        list(pool, Scope::Server).await.unwrap().len(),
        REGISTRY.len()
    );
}

#[tokio::test]
async fn bad_values_are_refused_and_change_nothing() {
    let db = db().await;
    let pool = &db.0;
    let code = |e: SetError| match e {
        SetError::Refused(e) => e.code().to_owned(),
        SetError::Db(e) => panic!("{e}"),
    };
    let burst = Key::ApiRequestBurst;
    for (value, why) in [
        ("9", "out_of_bounds"),
        ("10001", "out_of_bounds"),
        ("1.5", "not_integer"),
        ("\"500\"", "not_integer"),
    ] {
        let e = set(pool, burst, value).await.unwrap_err();
        assert_eq!(code(e), why, "{value}");
    }
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM settings")
        .fetch_one(pool)
        .await
        .unwrap();
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action LIKE 'setting.%'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!((rows, audits), (0, 0));
    // The bounds themselves are accepted.
    set(pool, burst, "10").await.unwrap();
    set(pool, burst, "10000").await.unwrap();
}

#[tokio::test]
async fn every_change_is_audited_and_read_back_as_history() {
    let db = db().await;
    let pool = &db.0;
    let key = Key::SchedulerTickSecs;
    set(pool, key, "20").await.unwrap();
    super::set(
        pool,
        key,
        Scope::Server,
        "30",
        AuditActor::System,
        "2026-10-22T11:00:00.000Z",
    )
    .await
    .unwrap();
    reset(pool, key, Scope::Server, BY, "2026-10-22T12:00:00.000Z")
        .await
        .unwrap();
    let all = history(pool, key, None).await.unwrap();
    let seen: Vec<_> = all
        .iter()
        .map(|c| (c.scope.to_string(), c.old, c.new, c.actor))
        .collect();
    let server = "server".to_owned();
    assert_eq!(
        seen,
        [
            (server.clone(), Some(30), None, BY),
            (server.clone(), Some(20), Some(30), AuditActor::System),
            (server, None, Some(20), BY),
        ]
    );
    assert_eq!(all[0].at, "2026-10-22T12:00:00.000Z");
    assert_eq!(all[1].at, "2026-10-22T11:00:00.000Z");
    assert_eq!(
        history(pool, key, Some(Scope::Server)).await.unwrap().len(),
        3
    );
    assert!(
        history(pool, Key::PushIntervalSecs, None)
            .await
            .unwrap()
            .is_empty()
    );
    set(pool, key, "40").await.unwrap();
    let (by_kind, at): (String, String) =
        sqlx::query_as("SELECT updated_by_kind, updated_at FROM settings WHERE key = ?")
            .bind(key.name())
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!((by_kind.as_str(), at.as_str()), ("user", NOW));
}

#[tokio::test]
async fn a_stored_row_the_registry_no_longer_accepts_is_passed_over() {
    let db = db().await;
    let pool = &db.0;
    let key = Key::PushIntervalSecs;
    sqlx::query(
        "INSERT INTO settings (key, scope_kind, scope_id, value, updated_by_kind, updated_at) \
         VALUES (?, 'server', 0, '100000', 'system', ?)",
    )
    .bind(key.name())
    .bind(NOW)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(value(pool, key, Scope::Server).await.unwrap(), 5);
}
