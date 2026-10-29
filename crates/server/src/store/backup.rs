//! Backup and restore of the whole database file.
//!
//! Backup is `VACUUM INTO`: it reads inside one transaction, so it is a consistent snapshot
//! even while other connections keep writing through the WAL, and it writes a compact,
//! rollback-journal file with no `-wal` to carry along. SQLite's online backup API would do
//! the same, but sqlx does not expose it and calling it directly needs `unsafe`, which the
//! workspace forbids.
//!
//! Restore validates the source, then swaps it in by rename so the target is either the old
//! database or the new one, never half of each.

use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection, SqlitePool};
use sqlx::{Connection, Executor};

use super::migrate::CORE_MIGRATIONS;

#[derive(Debug)]
pub enum BackupError {
    /// Another connection has the target database open.
    InUse,
    /// The source failed validation; the text says why.
    Invalid(String),
    /// The source was migrated by a newer Core than this one.
    NewerSchema {
        found: i64,
        supported: i64,
    },
    Io(io::Error),
    Database(sqlx::Error),
}

impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InUse => write!(f, "the target database is in use; stop the server or force"),
            Self::Invalid(why) => write!(f, "invalid backup: {why}"),
            Self::NewerSchema { found, supported } => write!(
                f,
                "backup schema {found} is newer than this binary supports ({supported})"
            ),
            Self::Io(e) => write!(f, "{e}"),
            Self::Database(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<io::Error> for BackupError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<sqlx::Error> for BackupError {
    fn from(e: sqlx::Error) -> Self {
        Self::Database(e)
    }
}

fn utf8(path: &Path) -> Result<&str, BackupError> {
    path.to_str()
        .ok_or_else(|| BackupError::Invalid(format!("path is not UTF-8: {}", path.display())))
}

/// `path` with `suffix` appended to its file name, e.g. `core.db-wal`.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Writes a consistent snapshot of the database to `dest`, which must not exist yet.
pub async fn backup(pool: &SqlitePool, dest: &Path) -> Result<(), BackupError> {
    sqlx::query("VACUUM INTO ?")
        .bind(utf8(dest)?)
        .execute(pool)
        .await?;
    Ok(())
}

/// Opens an existing file with no busy wait: any lock held elsewhere fails at once.
async fn open(path: &Path) -> Result<SqliteConnection, sqlx::Error> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .busy_timeout(Duration::ZERO);
    SqliteConnection::connect_with(&options).await
}

/// Checks `copy` is a whole Core database this binary can migrate, and leaves it in
/// rollback-journal mode so it is a single self-contained file.
async fn validate(copy: &Path) -> Result<(), BackupError> {
    let mut conn = open(copy)
        .await
        .map_err(|e| BackupError::Invalid(e.to_string()))?;
    let checked: Result<Vec<String>, _> = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_all(&mut conn)
        .await;
    match checked {
        Ok(rows) if rows == ["ok"] => {}
        Ok(rows) => return Err(BackupError::Invalid(rows.join("; "))),
        Err(e) => return Err(BackupError::Invalid(e.to_string())),
    }
    let found: Option<i64> = sqlx::query_scalar("SELECT max(version) FROM _migrations_core")
        .fetch_one(&mut conn)
        .await
        .map_err(|_| BackupError::Invalid("not a Core database".to_owned()))?;
    let found = found.ok_or_else(|| BackupError::Invalid("no migrations applied".to_owned()))?;
    let supported = CORE_MIGRATIONS.last().map_or(0, |m| m.version);
    if found > supported {
        return Err(BackupError::NewerSchema { found, supported });
    }
    conn.execute("PRAGMA journal_mode = DELETE").await?;
    conn.close().await?;
    Ok(())
}

/// Replaces the database at `dest` with the backup at `src`.
///
/// Refuses while any other connection has `dest` open, unless `force`. The source must pass
/// `integrity_check` and carry no migration newer than this binary. The copy is written
/// next to `dest` and renamed over it; the old `-wal` / `-shm` are removed first so they
/// can never be replayed onto the new file.
pub async fn restore(src: &Path, dest: &Path, force: bool) -> Result<(), BackupError> {
    if fs::metadata(sibling(src, "-wal")).is_ok_and(|m| m.len() > 0) {
        return Err(BackupError::Invalid(
            "source has an unmerged -wal; take it with `backup` instead".to_owned(),
        ));
    }
    let tmp = sibling(dest, ".restore-tmp");
    fs::copy(src, &tmp)?;
    let result = swap_in(&tmp, dest, force).await;
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_file(sibling(&tmp, "-journal"));
    }
    result
}

async fn swap_in(tmp: &Path, dest: &Path, force: bool) -> Result<(), BackupError> {
    validate(tmp).await?;
    File::open(tmp)?.sync_all()?;

    // Leaving WAL needs every other connection closed, so success proves dest is unused;
    // it also folds dest's -wal into the file and deletes -wal / -shm. The exclusive
    // transaction then keeps new openers out until the rename is done.
    let mut guard = None;
    if !force && dest.exists() {
        let mut conn = open(dest).await.map_err(|_| BackupError::InUse)?;
        let held = async {
            conn.execute("PRAGMA journal_mode = DELETE").await?;
            conn.execute("BEGIN EXCLUSIVE").await
        };
        if held.await.is_err() {
            return Err(BackupError::InUse);
        }
        guard = Some(conn);
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        match fs::remove_file(sibling(dest, suffix)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    fs::rename(tmp, dest)?;
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        File::open(parent)?.sync_all()?;
    }
    // The guard's connection still points at the replaced file; closing it touches only that.
    if let Some(conn) = guard {
        let _ = conn.close().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
