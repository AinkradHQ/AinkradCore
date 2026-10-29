//! SQLite storage: one pool, WAL journal, namespaced reversible migrations (`migrate`).

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use sqlx::Transaction;
use sqlx::sqlite::{
    Sqlite, SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool,
    SqlitePoolOptions,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub mod audit;
mod backup;
pub mod events;
pub mod gov;
pub mod migrate;
pub mod settings;

pub use backup::{BackupError, backup, restore};
pub use migrate::{MigrateError, Migration};

/// What the store keeps of a device key or pairing code: its SHA-256, never the key. Keys are
/// random, so an unsalted digest is enough.
fn key_hash(key: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(key.as_bytes()).to_vec()
}

/// A new secret: `prefix` and 32 bytes (256 bits) from the OS RNG, hex-encoded. The prefix
/// lets secret scanners spot it.
fn random_key(prefix: &str) -> Result<String, sqlx::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| sqlx::Error::Io(std::io::Error::other(e.to_string())))?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{prefix}{hex}"))
}

/// A write transaction from `begin_write`; derefs to its connection. Dropped without
/// `commit`, it rolls back.
pub struct WriteTx {
    // Declared first so it drops (queueing its rollback) before the gate opens.
    tx: Transaction<'static, Sqlite>,
    _turn: OwnedSemaphorePermit,
}

impl WriteTx {
    pub async fn commit(self) -> Result<(), sqlx::Error> {
        self.tx.commit().await
    }

    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        self.tx.rollback().await
    }
}

impl Deref for WriteTx {
    type Target = SqliteConnection;
    fn deref(&self) -> &SqliteConnection {
        &self.tx
    }
}

impl DerefMut for WriteTx {
    fn deref_mut(&mut self) -> &mut SqliteConnection {
        &mut self.tx
    }
}

/// Begins a transaction that writes: `BEGIN IMMEDIATE`, taken in arrival order among this
/// process's writers to the same database file.
///
/// SQLite's own wait for the write lock (`busy_timeout`) is sleep-and-poll, not a queue: a
/// writer that has slept is overtaken by every writer that arrives while the lock is free,
/// so under steady contention it can wait out the whole timeout and fail with
/// `database is locked` — a lost enqueue, dispatch or transition. Queueing here first means
/// SQLite's wait only ever covers another process's writer (the CLI, a backup).
pub async fn begin_write(pool: &SqlitePool) -> Result<WriteTx, sqlx::Error> {
    static GATES: LazyLock<Mutex<HashMap<PathBuf, Arc<Semaphore>>>> = LazyLock::new(Mutex::default);
    // ponytail: one entry per database file, never removed; fine for one server database
    // (and a test binary's few hundred).
    let gate = GATES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(pool.connect_options().get_filename().to_owned())
        .or_insert_with(|| Arc::new(Semaphore::new(1)))
        .clone();
    let turn = gate
        .acquire_owned()
        .await
        .expect("the gate is never closed");
    let tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    Ok(WriteTx { tx, _turn: turn })
}

/// Opens (creating if missing) the database at `path` and applies the platform's pending
/// migrations. Modules' migrations come after, with `migrate::migrate_modules`. A migration refusal is a `sqlx::Error::Configuration` holding
/// the `MigrateError`.
pub async fn connect(path: &Path) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new().connect_with(options).await?;
    migrate::migrate_core(&pool).await.map_err(|e| match e {
        MigrateError::Database(e) => e,
        e => sqlx::Error::Configuration(Box::new(e)),
    })?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLES: [&str; 7] = [
        "users",
        "device_keys",
        "device_pairings",
        "audit_events",
        "events",
        "push_cursor",
        "settings",
    ];

    async fn tables_present(pool: &SqlitePool) -> usize {
        let mut n = 0;
        for table in TABLES {
            n += sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            )
            .bind(table)
            .fetch_one(pool)
            .await
            .unwrap() as usize;
        }
        n
    }

    #[tokio::test]
    async fn migrates_up_down_up_with_pragmas() {
        let dir = std::env::temp_dir().join(format!("core-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = connect(&dir.join("core.db")).await.unwrap();

        let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(journal, "wal");
        let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(fk, 1);
        let busy: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(busy, 5000);

        assert_eq!(tables_present(&pool).await, TABLES.len());
        migrate::undo(&pool, migrate::CORE, migrate::CORE_MIGRATIONS, 0)
            .await
            .unwrap();
        assert_eq!(tables_present(&pool).await, 0);
        migrate::migrate_core(&pool).await.unwrap();
        assert_eq!(tables_present(&pool).await, TABLES.len());

        pool.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A writer that is already waiting is not overtaken by one that arrives later. Raw
    /// `BEGIN IMMEDIATE` fails this: the waiter sleeps inside SQLite's busy handler, the
    /// latecomer takes the lock the moment it is free, holds it past the waiter's
    /// `busy_timeout`, and the waiter gets `database is locked`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_waiting_writer_is_not_overtaken_and_never_times_out() {
        let dir = std::env::temp_dir().join(format!("core-store-gate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let options = SqliteConnectOptions::new()
            .filename(dir.join("core.db"))
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_millis(500));
        let pool = SqlitePoolOptions::new()
            .connect_with(options)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE t (who TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        let write = |who: &'static str| sqlx::query("INSERT INTO t VALUES (?)").bind(who);

        let mut first = begin_write(&pool).await.unwrap();
        write("first").execute(&mut *first).await.unwrap();
        let waiter = tokio::spawn({
            let pool = pool.clone();
            async move {
                let mut tx = begin_write(&pool).await?;
                write("waiter").execute(&mut *tx).await?;
                tx.commit().await
            }
        });
        // Long enough for the waiter to be waiting, and inside SQLite to be sleeping
        // between polls.
        tokio::time::sleep(Duration::from_millis(300)).await;
        first.commit().await.unwrap();
        let mut late = begin_write(&pool).await.unwrap();
        write("late").execute(&mut *late).await.unwrap();
        // Past the waiter's busy_timeout, had it still been waiting.
        tokio::time::sleep(Duration::from_millis(700)).await;
        late.commit().await.unwrap();

        waiter.await.unwrap().expect("the waiter got the lock");
        let order: Vec<String> = sqlx::query_scalar("SELECT who FROM t ORDER BY rowid")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(order, ["first", "waiter", "late"]);
        pool.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
