//! SQLite storage: one pool, WAL journal, reversible migrations from `migrations/`.

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use sqlx::Transaction;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{
    Sqlite, SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool,
    SqlitePoolOptions,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// SQL: whether agent `$agent`'s work on issue `$issue` waits on the plan of the issue's
/// requirement (plan-first, E15.10): the requirement is `planning`, `plan_review` or `cancelled`,
/// and the agent does not plan the issue's project (its product owner or team lead, the CEO or
/// the CTO), or the requirement is paused (`paused_at`, for everyone). Dispatch skips such a wake, the stuck detector leaves such an issue alone, and
/// `start` is refused.
macro_rules! plan_held {
    ($agent:literal, $issue:literal) => {
        concat!(
            "EXISTS (SELECT 1 FROM issues ph_i \
             JOIN requirements ph_q ON ph_q.id = ph_i.requirement_id \
             JOIN projects ph_p ON ph_p.id = ph_i.project_id \
             JOIN agents ph_a ON ph_a.id = ",
            $agent,
            " WHERE ph_i.id = ",
            $issue,
            " AND (ph_q.paused_at IS NOT NULL \
             OR (ph_q.state IN ('planning', 'plan_review', 'cancelled') \
             AND ph_a.org_role NOT IN ('ceo', 'cto') \
             AND NOT EXISTS (SELECT 1 FROM team_memberships ph_m \
                 WHERE ph_m.team_id = ph_p.team_id AND ph_m.agent_id = ph_a.id \
                 AND ph_m.team_role IN ('product_owner', 'team_lead')))))"
        )
    };
}

pub mod artifacts;
pub mod audit;
mod backup;
pub mod events;
pub mod exec;
pub mod forge;
pub mod gov;
pub mod linear;
pub mod org;
pub mod settings;
pub mod work;

pub use backup::{BackupError, backup, restore};

pub static MIGRATOR: Migrator = sqlx::migrate!();

/// What the store keeps of a runner or device key: its SHA-256, never the key. Keys are
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

/// Opens (creating if missing) the database at `path` and applies pending migrations.
pub async fn connect(path: &Path) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new().connect_with(options).await?;
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLES: [&str; 53] = [
        "users",
        "companies",
        "departments",
        "teams",
        "agents",
        "team_memberships",
        "projects",
        "epics",
        "sprints",
        "issues",
        "labels",
        "issue_labels",
        "blocker_links",
        "comments",
        "runners",
        "wake_requests",
        "runs",
        "leases",
        "cost_events",
        "approvals",
        "budgets",
        "skills",
        "knowledge_entries",
        "device_keys",
        "audit_events",
        "run_tokens",
        "project_repos",
        "run_events",
        "issue_state_history",
        "wip_limits",
        "sprint_retro_items",
        "budget_spend",
        "prices",
        "harness_billing",
        "issue_repos",
        "issue_prs",
        "project_linear",
        "linear_issues",
        "events",
        "push_cursor",
        "accounts",
        "account_companies",
        "account_limits",
        "account_events",
        "agent_fallbacks",
        "settings",
        "requirements",
        "requirement_plans",
        "questions",
        "artifacts",
        "artifact_reads",
        "run_controls",
        "issue_allow_rules",
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
        let dir = std::env::temp_dir().join(format!("citadel-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = connect(&dir.join("citadel.db")).await.unwrap();

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
        MIGRATOR.undo(&pool, 0).await.unwrap();
        assert_eq!(tables_present(&pool).await, 0);
        MIGRATOR.run(&pool).await.unwrap();
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
        let dir = std::env::temp_dir().join(format!("citadel-store-gate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let options = SqliteConnectOptions::new()
            .filename(dir.join("citadel.db"))
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
