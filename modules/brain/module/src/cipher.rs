//! Open a whole-file encrypted SQLite file (SQLCipher) with the one brain key (Q-6, Q-7).
//! The key is passed as a raw 32-byte key (`x'..'`), so SQLCipher skips its password KDF.

use std::path::Path;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

/// Open or create `path` under `key`. Opening an existing file with a wrong key fails on the first
/// read (SQLCipher reports "file is not a database"), which `open` forces so callers see it at once.
pub async fn open(path: &Path, key: &[u8; 32], create: bool) -> Result<SqlitePool, sqlx::Error> {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(create)
        .busy_timeout(std::time::Duration::from_secs(5))
        // `key` must be the first pragma the connection runs; sqlx orders `key` first.
        .pragma("key", format!("\"x'{hex}'\""));
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await?;
    sqlx::query("SELECT count(*) FROM sqlite_master")
        .execute(&pool)
        .await?;
    Ok(pool)
}
