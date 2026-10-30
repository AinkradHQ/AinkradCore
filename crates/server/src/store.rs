//! SQLite storage: one pool, WAL journal, namespaced reversible migrations (`migrate`).

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use sqlx::sqlite::{
    Sqlite, SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool,
    SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::{AssertSqlSafe, Transaction};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub mod agents;
pub mod audit;
mod backup;
pub mod events;
pub mod gov;
pub mod kinds;
pub mod migrate;
pub mod redact;
pub mod secrets;
pub mod settings;

pub use backup::{BackupError, backup, restore};
pub use migrate::{MigrateError, Migration};

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

/// How long a connection waits for another process's write lock (the CLI, a backup) before
/// `database is locked`. This process's own writers queue on `begin_write` instead.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The pool's size, for a 2 vCPU host. Writes are one at a time anyway (`begin_write`), and a
/// writer takes its connection only after its turn, so this is one writer plus a few
/// concurrent readers; more would only add contention for two cores.
const MAX_CONNECTIONS: u32 = 4;

/// The connection settings every Core database runs with; `connect` asserts them.
///
/// `synchronous = FULL`, not the WAL-usual NORMAL: under NORMAL a commit is durable against a
/// crash of the process but not of the OS or the power, which can lose the last commits. This
/// database holds auth state (a revoked device key, a spent pairing code), and forgetting one
/// of those after a reboot reopens access. FULL costs one fsync of the WAL per commit, which
/// the Core's write rate affords.
fn options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .foreign_keys(true)
        .busy_timeout(BUSY_TIMEOUT)
}

/// Fails unless the pool's connections run with `options`' settings: SQLite ignores some
/// pragmas silently (WAL on a filesystem without shared memory, for one).
async fn check_pragmas(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&mut *conn)
        .await?;
    let ints = [
        ("synchronous", 2),
        ("foreign_keys", 1),
        ("busy_timeout", BUSY_TIMEOUT.as_millis() as i64),
    ];
    let mut wrong = Vec::new();
    if journal != "wal" {
        wrong.push(format!("journal_mode = {journal}, want wal"));
    }
    for (pragma, want) in ints {
        let got: i64 = sqlx::query_scalar(AssertSqlSafe(format!("PRAGMA {pragma}")))
            .fetch_one(&mut *conn)
            .await?;
        if got != want {
            wrong.push(format!("{pragma} = {got}, want {want}"));
        }
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(sqlx::Error::Configuration(wrong.join("; ").into()))
    }
}

/// Opens (creating if missing) the database at `path`, asserts its connection settings and
/// applies the platform's pending migrations and registers its event kinds and audit actions
/// (`kinds`). Modules' migrations come after, with
/// `migrate::migrate_modules`. A migration refusal is a `sqlx::Error::Configuration` holding
/// the `MigrateError`.
pub async fn connect(path: &Path) -> Result<SqlitePool, sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .connect_with(options(path))
        .await?;
    check_pragmas(&pool).await?;
    migrate::migrate_core(&pool).await.map_err(|e| match e {
        MigrateError::Database(e) => e,
        e => sqlx::Error::Configuration(Box::new(e)),
    })?;
    kinds::register_platform(&pool).await?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLES: [&str; 8] = [
        "users",
        "core_devices",
        "core_pairings",
        "core_auth_limits",
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
        let sync: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(sync, 2, "FULL");

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

    /// The startup check catches a connection that is not configured as `options` says.
    #[tokio::test]
    async fn a_wrongly_configured_pool_fails_the_startup_check() {
        let dir = std::env::temp_dir().join(format!("core-store-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("core.db");
        let good = SqlitePool::connect_with(options(&path)).await.unwrap();
        check_pragmas(&good).await.unwrap();
        good.close().await;
        let normal = options(&path)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(false);
        let bad = SqlitePool::connect_with(normal).await.unwrap();
        let err = check_pragmas(&bad).await.unwrap_err().to_string();
        assert!(err.contains("synchronous = 1, want 2"), "{err}");
        assert!(err.contains("foreign_keys = 0, want 1"), "{err}");
        bad.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Fifty writers at once, each a read-modify-write of one counter plus an insert, through
    /// `connect`'s pool and `begin_write`: none sees `database is locked`, and none loses an
    /// update.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fifty_concurrent_writers_never_lock_or_lose_an_update() {
        const WRITERS: i64 = 50;
        const EACH: i64 = 20;
        let dir = std::env::temp_dir().join(format!("core-store-50-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = connect(&dir.join("core.db")).await.unwrap();
        sqlx::raw_sql(
            "CREATE TABLE counter (n INTEGER NOT NULL); INSERT INTO counter VALUES (0);
             CREATE TABLE log (writer INTEGER NOT NULL, value INTEGER NOT NULL);",
        )
        .execute(&pool)
        .await
        .unwrap();

        let writers: Vec<_> = (0..WRITERS)
            .map(|w| {
                let pool = pool.clone();
                tokio::spawn(async move {
                    for _ in 0..EACH {
                        let mut tx = begin_write(&pool).await?;
                        let n: i64 = sqlx::query_scalar("SELECT n FROM counter")
                            .fetch_one(&mut *tx)
                            .await?;
                        tokio::task::yield_now().await;
                        sqlx::query("UPDATE counter SET n = ?")
                            .bind(n + 1)
                            .execute(&mut *tx)
                            .await?;
                        sqlx::query("INSERT INTO log VALUES (?, ?)")
                            .bind(w)
                            .bind(n + 1)
                            .execute(&mut *tx)
                            .await?;
                        tx.commit().await?;
                    }
                    Ok::<_, sqlx::Error>(())
                })
            })
            .collect();
        // Readers alongside, on the same pool.
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move {
                    for _ in 0..50 {
                        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM log")
                            .fetch_one(&pool)
                            .await?;
                    }
                    Ok::<_, sqlx::Error>(())
                })
            })
            .collect();
        for task in writers.into_iter().chain(readers) {
            task.await.unwrap().expect("no writer or reader failed");
        }

        let total = WRITERS * EACH;
        let n: i64 = sqlx::query_scalar("SELECT n FROM counter")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, total);
        let (rows, sum, distinct): (i64, i64, i64) =
            sqlx::query_as("SELECT count(*), sum(value), count(DISTINCT value) FROM log")
                .fetch_one(&pool)
                .await
                .unwrap();
        // Every value 1..=total exactly once: no two writers read the same counter.
        assert_eq!(
            (rows, sum, distinct),
            (total, total * (total + 1) / 2, total)
        );
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
