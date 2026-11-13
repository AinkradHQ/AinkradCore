//! The Brain's encrypted files (Q-6): one staging file per import run and one `canon.db` per room,
//! all under `<core db dir>/brain/`, all opened with the one brain key. Each file keeps its own
//! migrations (E0-4); a file written by a newer binary is refused, never opened.

use std::path::{Path, PathBuf};

use ainkrad_core_server::api::App;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::cipher;

pub struct FileMigration {
    pub version: i64,
    pub name: &'static str,
    pub up: &'static str,
}

#[derive(Debug)]
pub enum FileError {
    /// The file has migration `found`, this binary knows up to `known`.
    Newer {
        found: i64,
        known: i64,
    },
    /// An applied migration's text changed.
    Tampered(i64),
    Db(sqlx::Error),
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Newer { found, known } => {
                write!(
                    f,
                    "the file has migration {found}, newer than this binary knows ({known})"
                )
            }
            Self::Tampered(v) => write!(f, "migration {v} changed since it was applied"),
            Self::Db(e) => write!(f, "{e}"),
        }
    }
}

impl From<sqlx::Error> for FileError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

fn sum(m: &FileMigration) -> Vec<u8> {
    Sha256::digest(m.up.as_bytes()).to_vec()
}

/// Opens `path` under `key`, creating it when `create`, and brings it to the newest migration in
/// one transaction. A newer file is `FileError::Newer`.
pub async fn open_migrated(
    path: &Path,
    key: &[u8; 32],
    create: bool,
    migrations: &[FileMigration],
) -> Result<SqlitePool, FileError> {
    if create && let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(sqlx::Error::Io)?;
    }
    let pool = cipher::open(path, key, create).await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS _file_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum BLOB NOT NULL)",
    )
    .execute(&pool)
    .await?;
    let rows: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version, checksum FROM _file_migrations ORDER BY version")
            .fetch_all(&pool)
            .await?;
    let known = migrations.last().map_or(0, |m| m.version);
    for (v, s) in &rows {
        match migrations.iter().find(|m| m.version == *v) {
            Some(m) if sum(m) == *s => {}
            Some(_) => return Err(FileError::Tampered(*v)),
            None => return Err(FileError::Newer { found: *v, known }),
        }
    }
    let mut tx = pool.begin().await?;
    for m in migrations
        .iter()
        .filter(|m| !rows.iter().any(|(v, _)| *v == m.version))
    {
        sqlx::raw_sql(m.up).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO _file_migrations (version, name, checksum) VALUES (?, ?, ?)")
            .bind(m.version)
            .bind(m.name)
            .bind(sum(m))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(pool)
}

/// `<core db dir>/brain`.
pub fn root(app: &App) -> PathBuf {
    app.pool
        .connect_options()
        .get_filename()
        .parent()
        .map_or_else(|| PathBuf::from("brain"), |p| p.join("brain"))
}

/// A run or room id is made by this module (`[a-z0-9-]`), so it can name a path; anything else is
/// refused before it reaches the file system.
pub fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn staging_path(root: &Path, run: &str) -> PathBuf {
    root.join("staging").join(format!("{run}.db"))
}

pub fn room_path(root: &Path, room: &str) -> PathBuf {
    root.join("rooms").join(room).join("canon.db")
}

pub fn index_path(root: &Path, room: &str) -> PathBuf {
    root.join("rooms").join(room).join("index.db")
}

pub fn vectors_path(root: &Path) -> PathBuf {
    root.join("vectors.db")
}

pub static VECTORS: &[FileMigration] = &[
    FileMigration {
        version: 1,
        name: "vectors_0001",
        up: include_str!("../migrations/vectors_0001.sql"),
    },
    FileMigration {
        version: 2,
        name: "vectors_0002",
        up: include_str!("../migrations/vectors_0002.sql"),
    },
];

pub static INDEX: &[FileMigration] = &[FileMigration {
    version: 1,
    name: "index_0001",
    up: include_str!("../migrations/index_0001.sql"),
}];

pub static STAGING: &[FileMigration] = &[
    FileMigration {
        version: 1,
        name: "staging_0001",
        up: include_str!("../migrations/staging_0001.sql"),
    },
    FileMigration {
        version: 2,
        name: "staging_0002",
        up: include_str!("../migrations/staging_0002.sql"),
    },
];

pub static CANON: &[FileMigration] = &[
    FileMigration {
        version: 1,
        name: "canon_0001",
        up: include_str!("../migrations/canon_0001.sql"),
    },
    FileMigration {
        version: 2,
        name: "canon_0002",
        up: include_str!("../migrations/canon_0002.sql"),
    },
    FileMigration {
        version: 3,
        name: "canon_0003",
        up: include_str!("../migrations/canon_0003.sql"),
    },
];
