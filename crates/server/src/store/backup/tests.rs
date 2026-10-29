use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ainkrad_core::audit::{AuditActor, AuditEntity, AuditFilter, NewAuditEvent};

use super::*;
use crate::store::{audit, connect};

/// A temp dir, removed on drop.
struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn dir() -> Dir {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-backup-{}-{n}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    Dir(dir)
}

/// One user plus its audit event, in one transaction.
async fn write(pool: &SqlitePool, i: usize) {
    crate::store::kinds::allow(pool, &[], &["user.created"]).await;
    let mut tx = crate::store::begin_write(pool).await.unwrap();
    let id: i64 = sqlx::query_scalar("INSERT INTO users (name) VALUES (?) RETURNING id")
        .bind(format!("c{i}"))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let e = NewAuditEvent {
        actor: AuditActor::System,
        action: "user.created".to_owned(),
        entity: Some(AuditEntity {
            kind: "user".to_owned(),
            id,
        }),
        details: "{}".to_owned(),
    };
    audit::append(&mut tx, &e).await.unwrap();
    tx.commit().await.unwrap();
}

/// The written users' names (not the seeded admin), oldest first.
async fn names(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar("SELECT name FROM users WHERE id <> 1 ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn integrity(pool: &SqlitePool) -> String {
    sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn backup_during_writes_restores_a_consistent_prefix() {
    let d = dir();
    let live = connect(&d.0.join("live.db")).await.unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let written = Arc::new(AtomicUsize::new(0));
    let writer = tokio::spawn({
        let (pool, stop, written) = (live.clone(), stop.clone(), written.clone());
        async move {
            while !stop.load(Ordering::Relaxed) {
                write(&pool, written.load(Ordering::Relaxed)).await;
                written.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    while written.load(Ordering::Relaxed) < 50 {
        tokio::task::yield_now().await;
    }
    let snapshot = d.0.join("snapshot.db");
    backup(&live, &snapshot).await.unwrap();
    let at_backup = written.load(Ordering::Relaxed);
    while written.load(Ordering::Relaxed) < at_backup + 50 {
        tokio::task::yield_now().await;
    }
    stop.store(true, Ordering::Relaxed);
    writer.await.unwrap();
    let total = written.load(Ordering::Relaxed);

    let restored = d.0.join("restored.db");
    restore(&snapshot, &restored, false).await.unwrap();
    let pool = connect(&restored).await.unwrap();
    assert_eq!(integrity(&pool).await, "ok");

    // A prefix c0..c{k-1} of the writes, taken mid-stream...
    let got = names(&pool).await;
    let k = got.len();
    assert!(k >= 50 && k < total, "k = {k}, total = {total}");
    assert_eq!(got, (0..k).map(|i| format!("c{i}")).collect::<Vec<_>>());
    // ...with every user's audit event and no other: no torn transaction.
    let events = audit::list(&pool, &AuditFilter::default(), None, u32::MAX)
        .await
        .unwrap();
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM users WHERE id <> 1 ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    let entities: Vec<i64> = events
        .iter()
        .map(|e| e.entity.as_ref().unwrap().id)
        .collect();
    assert_eq!(entities, ids);
}

#[tokio::test]
async fn restore_replaces_an_idle_database_and_drops_its_wal() {
    let d = dir();
    let (src, dest) = (d.0.join("src.db"), d.0.join("dest.db"));
    let pool = connect(&src).await.unwrap();
    write(&pool, 0).await;
    let snapshot = d.0.join("snapshot.db");
    backup(&pool, &snapshot).await.unwrap();

    let old = connect(&dest).await.unwrap();
    write(&old, 0).await;
    write(&old, 1).await;
    old.close().await;

    restore(&snapshot, &dest, false).await.unwrap();
    assert!(!sibling(&dest, "-wal").exists());
    assert!(!sibling(&dest, "-shm").exists());
    assert!(!sibling(&dest, ".restore-tmp").exists());
    let pool = connect(&dest).await.unwrap();
    assert_eq!(names(&pool).await, ["c0"]);
}

#[tokio::test]
async fn restore_refuses_an_open_database_unless_forced() {
    let d = dir();
    let (src, dest) = (d.0.join("src.db"), d.0.join("dest.db"));
    let pool = connect(&src).await.unwrap();
    let snapshot = d.0.join("snapshot.db");
    backup(&pool, &snapshot).await.unwrap();

    let open = connect(&dest).await.unwrap();
    write(&open, 0).await;
    let err = restore(&snapshot, &dest, false).await.unwrap_err();
    assert!(matches!(err, BackupError::InUse), "{err}");
    assert_eq!(names(&open).await, ["c0"]);
    assert!(!sibling(&dest, ".restore-tmp").exists());

    restore(&snapshot, &dest, true).await.unwrap();
    open.close().await;
    let pool = connect(&dest).await.unwrap();
    assert!(names(&pool).await.is_empty());
}

#[tokio::test]
async fn restore_rejects_a_newer_schema() {
    let d = dir();
    let pool = connect(&d.0.join("src.db")).await.unwrap();
    let snapshot = d.0.join("snapshot.db");
    backup(&pool, &snapshot).await.unwrap();
    let newer = connect(&snapshot).await.unwrap();
    sqlx::query(
        "INSERT INTO _migrations_core (version, name, checksum) \
         VALUES (99991231000000, 'from the future', x'00')",
    )
    .execute(&newer)
    .await
    .unwrap();
    newer.close().await;

    let dest = d.0.join("dest.db");
    let err = restore(&snapshot, &dest, false).await.unwrap_err();
    assert!(
        matches!(
            err,
            BackupError::NewerSchema {
                found: 99991231000000,
                ..
            }
        ),
        "{err}"
    );
    assert!(!dest.exists());
}

#[tokio::test]
async fn restore_rejects_a_corrupt_file_and_keeps_the_target() {
    let d = dir();
    let pool = connect(&d.0.join("src.db")).await.unwrap();
    for i in 0..200 {
        write(&pool, i).await;
    }
    let snapshot = d.0.join("snapshot.db");
    backup(&pool, &snapshot).await.unwrap();
    let dest = d.0.join("dest.db");
    restore(&snapshot, &dest, false).await.unwrap();

    // Garble every page after the header page.
    let mut bytes = fs::read(&snapshot).unwrap();
    let page = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
    for b in &mut bytes[page..] {
        *b ^= 0x5a;
    }
    fs::write(&snapshot, &bytes).unwrap();
    let err = restore(&snapshot, &dest, false).await.unwrap_err();
    assert!(matches!(err, BackupError::Invalid(_)), "{err}");

    let garbage = d.0.join("garbage.db");
    fs::write(&garbage, b"not a database at all, just text").unwrap();
    let err = restore(&garbage, &dest, false).await.unwrap_err();
    assert!(matches!(err, BackupError::Invalid(_)), "{err}");

    assert!(!sibling(&dest, ".restore-tmp").exists());
    let pool = connect(&dest).await.unwrap();
    assert_eq!(names(&pool).await.len(), 200);
}
