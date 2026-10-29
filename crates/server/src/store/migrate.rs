//! Namespaced, checksummed migrations (E1-03.2). The platform's run first, in namespace `core`;
//! then each module's, in its own namespace, its id. A namespace keeps what it has applied in
//! its own table `_migrations_<namespace>`: version, name, and the SHA-256 of the migration's
//! up and down text.
//!
//! The runner refuses to go on, and the server to start, when:
//! - an applied migration's text has changed since it was applied (`Tampered`);
//! - the database has a migration newer than this binary knows (`Newer`, a downgrade);
//! - the database has a migration this binary never had (`Unknown`);
//! - a module's migration names anything outside its prefix `<id>_` (`Refused`, see `guard`).
//!
//! A namespace's pending migrations apply in one write transaction with their version rows, so
//! a crash leaves all of them or none.

use std::sync::Arc;

use sqlx::sqlite::{SqliteConnection, SqlitePool};
use sqlx::{AssertSqlSafe, Connection};

use super::begin_write;
use crate::module::{Module, valid_id};

mod guard;

/// One reversible migration. `version`s are positive and strictly increasing in a list.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub up: &'static str,
    pub down: &'static str,
}

/// The platform's namespace.
pub const CORE: &str = "core";

/// The platform's migrations, in order. A file, once in a release, never changes: its
/// checksum is recorded, and a changed text refuses to start.
pub static CORE_MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "core_0001",
        up: include_str!("../../migrations/0001_core_0001.up.sql"),
        down: include_str!("../../migrations/0001_core_0001.down.sql"),
    },
    Migration {
        version: 2,
        name: "events_audit",
        up: include_str!("../../migrations/0002_events_audit.up.sql"),
        down: include_str!("../../migrations/0002_events_audit.down.sql"),
    },
    Migration {
        version: 3,
        name: "device_identity",
        up: include_str!("../../migrations/0003_device_identity.up.sql"),
        down: include_str!("../../migrations/0003_device_identity.down.sql"),
    },
    Migration {
        version: 4,
        name: "event_visibility",
        up: include_str!("../../migrations/0004_event_visibility.up.sql"),
        down: include_str!("../../migrations/0004_event_visibility.down.sql"),
    },
];

#[derive(Debug)]
pub enum MigrateError {
    /// The database was migrated by sqlx's runner, before namespaces; recreate it.
    Legacy,
    Tampered {
        namespace: String,
        version: i64,
    },
    Newer {
        namespace: String,
        found: i64,
        known: i64,
    },
    Unknown {
        namespace: String,
        version: i64,
    },
    /// A module or its migrations broke a rule; the text says which.
    Refused {
        namespace: String,
        why: String,
    },
    Database(sqlx::Error),
}

impl std::fmt::Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Legacy => write!(
                f,
                "the database was created before namespaced migrations (it has \
                 _sqlx_migrations); recreate it"
            ),
            Self::Tampered { namespace, version } => write!(
                f,
                "migration {namespace} {version} changed since it was applied"
            ),
            Self::Newer {
                namespace,
                found,
                known,
            } => write!(
                f,
                "the database has migration {namespace} {found}, newer than this binary \
                 knows ({known}); refusing to downgrade"
            ),
            Self::Unknown { namespace, version } => write!(
                f,
                "the database has migration {namespace} {version}, which this binary never had"
            ),
            Self::Refused { namespace, why } => write!(f, "module {namespace}: {why}"),
            Self::Database(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MigrateError {}

impl From<sqlx::Error> for MigrateError {
    fn from(e: sqlx::Error) -> Self {
        Self::Database(e)
    }
}

fn checksum(m: &Migration) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(m.up.as_bytes());
    h.update([0]);
    h.update(m.down.as_bytes());
    h.finalize().to_vec()
}

fn refused(namespace: &str, why: impl Into<String>) -> MigrateError {
    MigrateError::Refused {
        namespace: namespace.to_owned(),
        why: why.into(),
    }
}

/// The applied `(version, checksum)`s of `namespace`, after checking each against
/// `migrations`. Creates the version table on first use.
async fn applied(
    conn: &mut SqliteConnection,
    namespace: &str,
    migrations: &[Migration],
) -> Result<Vec<i64>, MigrateError> {
    sqlx::raw_sql(AssertSqlSafe(format!(
        "CREATE TABLE IF NOT EXISTS _migrations_{namespace} (
            version    INTEGER PRIMARY KEY,
            name       TEXT    NOT NULL,
            checksum   BLOB    NOT NULL,
            applied_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )"
    )))
    .execute(&mut *conn)
    .await?;
    let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT version, checksum FROM _migrations_{namespace} ORDER BY version"
    )))
    .fetch_all(&mut *conn)
    .await?;
    let known = migrations.last().map_or(0, |m| m.version);
    let namespace = namespace.to_owned();
    for (version, sum) in &rows {
        match migrations.iter().find(|m| m.version == *version) {
            Some(m) if checksum(m) == *sum => {}
            Some(_) => {
                return Err(MigrateError::Tampered {
                    namespace,
                    version: *version,
                });
            }
            None if *version > known => {
                let found = rows.last().map_or(*version, |r| r.0);
                return Err(MigrateError::Newer {
                    namespace,
                    found,
                    known,
                });
            }
            None => {
                return Err(MigrateError::Unknown {
                    namespace,
                    version: *version,
                });
            }
        }
    }
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// `(type, name, tbl_name, sql)` of a schema object.
type SchemaObject = (String, String, String, Option<String>);

async fn schema(conn: &mut SqliteConnection) -> Result<Vec<SchemaObject>, sqlx::Error> {
    sqlx::query_as("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
        .fetch_all(conn)
        .await
}

/// The objects created, dropped or changed between `before` and `after` that are not
/// `prefix`'s own.
fn foreign_changes(prefix: &str, before: &[SchemaObject], after: &[SchemaObject]) -> Vec<String> {
    let autoindex = format!("sqlite_autoindex_{prefix}");
    let own = |o: &SchemaObject| {
        (o.1.starts_with(prefix) || o.1.starts_with(&autoindex)) && o.2.starts_with(prefix)
    };
    before
        .iter()
        .filter(|o| !after.contains(o))
        .chain(after.iter().filter(|o| !before.contains(o)))
        .filter(|o| !own(o))
        .map(|o| format!("{} {}", o.0, o.1))
        .collect()
}

/// Applies `namespace`'s pending `migrations`. With `guard` (a module's prefix and the
/// platform's object names), each migration's text is checked by `guard` first and its schema
/// changes after.
async fn apply(
    pool: &SqlitePool,
    namespace: &str,
    migrations: &[Migration],
    guard: Option<(&str, &[String])>,
) -> Result<(), MigrateError> {
    let prefix = guard.map(|g| g.0);
    if migrations.first().is_some_and(|m| m.version < 1)
        || migrations.windows(2).any(|w| w[0].version >= w[1].version)
    {
        return Err(refused(
            namespace,
            "migration versions must be positive and increasing",
        ));
    }
    if let Some((prefix, platform)) = guard {
        for m in migrations {
            for sql in [m.up, m.down] {
                guard::check(prefix, platform, sql)
                    .map_err(|why| refused(namespace, format!("migration {}: {why}", m.version)))?;
            }
        }
    }
    let mut tx = begin_write(pool).await?;
    let done = applied(&mut tx, namespace, migrations).await?;
    for m in migrations.iter().filter(|m| !done.contains(&m.version)) {
        let before = match prefix {
            Some(_) => schema(&mut tx).await?,
            None => Vec::new(),
        };
        sqlx::raw_sql(m.up).execute(&mut *tx).await?;
        if let Some(prefix) = prefix {
            let foreign = foreign_changes(prefix, &before, &schema(&mut tx).await?);
            if !foreign.is_empty() {
                let why = format!("migration {} changed {}", m.version, foreign.join(", "));
                return Err(refused(namespace, why));
            }
        }
        sqlx::query(AssertSqlSafe(format!(
            "INSERT INTO _migrations_{namespace} (version, name, checksum) VALUES (?, ?, ?)"
        )))
        .bind(m.version)
        .bind(m.name)
        .bind(checksum(m))
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Applies the platform's pending migrations.
pub async fn migrate_core(pool: &SqlitePool) -> Result<(), MigrateError> {
    let legacy: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
    )
    .fetch_one(pool)
    .await?;
    if legacy > 0 {
        return Err(MigrateError::Legacy);
    }
    apply(pool, CORE, CORE_MIGRATIONS, None).await
}

/// The names of the platform's schema objects, from its migrations run on a scratch
/// in-memory database (the live one also holds the modules' objects).
async fn platform_objects() -> Result<Vec<String>, sqlx::Error> {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await?;
    for m in CORE_MIGRATIONS {
        sqlx::raw_sql(m.up).execute(&mut conn).await?;
    }
    let names = sqlx::query_scalar("SELECT name FROM sqlite_master")
        .fetch_all(&mut conn)
        .await?;
    conn.close().await?;
    Ok(names)
}

/// Applies each module's pending migrations, in the order given, after the platform's
/// (`migrate_core`, which `connect` runs), then registers each module's event kinds and audit
/// actions (`Module::event_kinds`, `Module::audit_actions`).
///
/// Refuses a module whose id is illegal, reserved (`core`, `sqlite`), a duplicate, or whose
/// prefix `<id>_` would also cover a platform object (`audit_` covers `audit_events`) or
/// another module's prefix (`toy_` covers `toy_x_`).
pub async fn migrate_modules(
    pool: &SqlitePool,
    modules: &[Arc<dyn Module>],
) -> Result<(), MigrateError> {
    let platform = platform_objects().await?;
    let ids: Vec<&str> = modules.iter().map(|m| m.id()).collect();
    for (n, id) in ids.iter().enumerate() {
        let prefix = format!("{id}_");
        if !valid_id(id) || ["core", "sqlite"].contains(id) {
            return Err(refused(id, "illegal or reserved module id"));
        }
        if let Some(other) = ids
            .iter()
            .enumerate()
            .find(|(m, other)| *m != n && (other == &id || other.starts_with(&prefix)))
        {
            return Err(refused(
                id,
                format!("its prefix overlaps module {}", other.1),
            ));
        }
        if let Some(name) = platform.iter().find(|name| name.starts_with(&prefix)) {
            return Err(refused(
                id,
                format!("its prefix covers the platform's {name}"),
            ));
        }
    }
    for module in modules {
        let id = module.id();
        let prefix = format!("{id}_");
        apply(pool, id, module.migrations(), Some((&prefix, &platform))).await?;
    }
    // Then their event kinds and audit actions (E1-04.2), so a refused name stops the start too.
    let mut tx = begin_write(pool).await?;
    for module in modules {
        let kinds: Vec<(&str, &str)> = module
            .event_kinds()
            .iter()
            .map(|k| (*k, module.event_scope(k)))
            .collect();
        crate::store::kinds::register(&mut tx, module.id(), &kinds, module.audit_actions())
            .await
            .map_err(|e| match e {
                sqlx::Error::InvalidArgument(why) => refused(module.id(), why),
                e => e.into(),
            })?;
    }
    tx.commit().await?;
    Ok(())
}

/// Reverts `namespace`'s applied migrations above version `to`, newest first, in one write
/// transaction. Checks the applied ones as `apply` does before reverting anything.
pub async fn undo(
    pool: &SqlitePool,
    namespace: &str,
    migrations: &[Migration],
    to: i64,
) -> Result<(), MigrateError> {
    if namespace != CORE {
        if !valid_id(namespace) {
            return Err(refused(namespace, "illegal module id"));
        }
        let prefix = format!("{namespace}_");
        let platform = platform_objects().await?;
        for m in migrations {
            guard::check(&prefix, &platform, m.down)
                .map_err(|why| refused(namespace, format!("migration {}: {why}", m.version)))?;
        }
    }
    let mut tx = begin_write(pool).await?;
    let done = applied(&mut tx, namespace, migrations).await?;
    for m in migrations
        .iter()
        .rev()
        .filter(|m| m.version > to && done.contains(&m.version))
    {
        sqlx::raw_sql(m.down).execute(&mut *tx).await?;
        sqlx::query(AssertSqlSafe(format!(
            "DELETE FROM _migrations_{namespace} WHERE version = ?"
        )))
        .bind(m.version)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
