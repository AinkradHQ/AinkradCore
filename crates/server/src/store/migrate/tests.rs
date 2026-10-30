use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;

use super::*;
use crate::api::App;
use crate::store::connect;

/// A platform-migrated database in its own temp dir, removed on drop.
struct Db {
    pool: SqlitePool,
    dir: PathBuf,
}

impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn db() -> Db {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-migrate-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    Db { pool, dir }
}

struct Toy(&'static str, &'static [Migration]);

impl Module for Toy {
    fn id(&self) -> &'static str {
        self.0
    }

    fn routes(&self) -> Router<App> {
        Router::new()
    }

    fn migrations(&self) -> &'static [Migration] {
        self.1
    }
}

fn toy(id: &'static str, migrations: &'static [Migration]) -> Vec<Arc<dyn Module>> {
    vec![Arc::new(Toy(id, migrations))]
}

const TOY_1: Migration = Migration {
    version: 1,
    name: "toy_0001",
    up: "CREATE TABLE toy_items (
             id      INTEGER PRIMARY KEY,
             user_id INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
             name    TEXT NOT NULL
         );
         CREATE INDEX toy_items_name ON toy_items (name);",
    down: "DROP INDEX toy_items_name; DROP TABLE toy_items;",
};
const TOY_2: Migration = Migration {
    version: 2,
    name: "toy_0002",
    up: "ALTER TABLE toy_items ADD COLUMN note TEXT;",
    down: "ALTER TABLE toy_items DROP COLUMN note;",
};
const TOY_3: Migration = Migration {
    version: 3,
    name: "toy_0003",
    up: "CREATE TABLE toy_more (id INTEGER PRIMARY KEY);",
    down: "DROP TABLE toy_more;",
};

async fn versions(pool: &SqlitePool, namespace: &str) -> Vec<(i64, String, String)> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT version, name, applied_at FROM _migrations_{namespace} ORDER BY version"
    )))
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn has_table(pool: &SqlitePool, name: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sqlite_master WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
        == 1
}

#[tokio::test]
async fn a_fresh_database_records_the_baseline_and_a_second_run_is_a_no_op() {
    let db = db().await;
    let first = versions(&db.pool, CORE).await;
    let names: Vec<(i64, &str)> = first.iter().map(|v| (v.0, v.1.as_str())).collect();
    assert_eq!(
        names,
        [
            (1, "core_0001"),
            (2, "events_audit"),
            (3, "device_identity"),
            (4, "event_visibility"),
            (5, "passkeys"),
            (6, "audit_device_ref"),
            (7, "secrets")
        ]
    );
    let sum: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _migrations_core WHERE version = 1")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(sum, checksum(&CORE_MIGRATIONS[0]));
    assert!(!has_table(&db.pool, "_sqlx_migrations").await);

    migrate_core(&db.pool).await.unwrap();
    assert_eq!(versions(&db.pool, CORE).await, first, "nothing re-applied");
}

#[tokio::test]
async fn a_tampered_migration_is_refused() {
    let db = db().await;
    sqlx::query("UPDATE _migrations_core SET checksum = zeroblob(32) WHERE version = 1")
        .execute(&db.pool)
        .await
        .unwrap();
    let err = migrate_core(&db.pool).await.unwrap_err();
    assert!(
        matches!(err, MigrateError::Tampered { version: 1, .. }),
        "{err}"
    );

    // `connect`, which `serve` and the CLI use, refuses too.
    db.pool.close().await;
    let err = connect(&db.dir.join("core.db")).await.unwrap_err();
    let sqlx::Error::Configuration(inner) = &err else {
        panic!("{err}")
    };
    assert!(inner.downcast_ref::<MigrateError>().is_some(), "{err}");
}

#[tokio::test]
async fn a_newer_database_is_refused() {
    let db = db().await;
    sqlx::query(
        "INSERT INTO _migrations_core (version, name, checksum) VALUES (99, 'core_0099', x'00')",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let err = migrate_core(&db.pool).await.unwrap_err();
    assert!(
        matches!(
            err,
            MigrateError::Newer {
                found: 99,
                known,
                ..
            } if known == CORE_MIGRATIONS.last().unwrap().version
        ),
        "{err}"
    );
}

#[tokio::test]
async fn a_database_from_the_sqlx_runner_is_refused() {
    let db = db().await;
    sqlx::query("CREATE TABLE _sqlx_migrations (version INTEGER)")
        .execute(&db.pool)
        .await
        .unwrap();
    let err = migrate_core(&db.pool).await.unwrap_err();
    assert!(matches!(err, MigrateError::Legacy), "{err}");
}

#[tokio::test]
async fn a_module_migrates_its_own_tables_in_its_own_namespace() {
    static V1: &[Migration] = &[TOY_1];
    static V2: &[Migration] = &[TOY_1, TOY_2];
    let db = db().await;
    migrate_modules(&db.pool, &toy("toy", V1)).await.unwrap();
    assert!(has_table(&db.pool, "toy_items").await);
    assert_eq!(versions(&db.pool, "toy").await.len(), 1);
    assert_eq!(
        versions(&db.pool, CORE).await.len(),
        CORE_MIGRATIONS.len(),
        "the platform's is untouched"
    );

    // The next release adds a migration; the one after re-runs as a no-op.
    migrate_modules(&db.pool, &toy("toy", V2)).await.unwrap();
    let applied = versions(&db.pool, "toy").await;
    migrate_modules(&db.pool, &toy("toy", V2)).await.unwrap();
    assert_eq!(versions(&db.pool, "toy").await, applied);
    sqlx::query("INSERT INTO toy_items (name, note) VALUES ('a', 'b')")
        .execute(&db.pool)
        .await
        .unwrap();

    undo(&db.pool, "toy", V2, 0).await.unwrap();
    assert!(!has_table(&db.pool, "toy_items").await);
    assert!(versions(&db.pool, "toy").await.is_empty());
    assert!(has_table(&db.pool, "users").await);
}

#[tokio::test]
async fn a_module_is_held_to_its_checksums_and_versions() {
    static V2: &[Migration] = &[TOY_1, TOY_2];
    static V1: &[Migration] = &[TOY_1];
    static TAMPERED: &[Migration] = &[
        TOY_1,
        Migration {
            up: "ALTER TABLE toy_items ADD COLUMN other TEXT;",
            ..TOY_2
        },
    ];
    static SKIPS_2: &[Migration] = &[TOY_1, TOY_3];
    let db = db().await;
    migrate_modules(&db.pool, &toy("toy", V2)).await.unwrap();

    let err = migrate_modules(&db.pool, &toy("toy", TAMPERED))
        .await
        .unwrap_err();
    assert!(
        matches!(err, MigrateError::Tampered { version: 2, .. }),
        "{err}"
    );
    let err = migrate_modules(&db.pool, &toy("toy", V1))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            MigrateError::Newer {
                found: 2,
                known: 1,
                ..
            }
        ),
        "{err}"
    );
    let err = migrate_modules(&db.pool, &toy("toy", SKIPS_2))
        .await
        .unwrap_err();
    assert!(
        matches!(err, MigrateError::Unknown { version: 2, .. }),
        "{err}"
    );
    assert!(
        !has_table(&db.pool, "toy_more").await,
        "nothing applied after a refusal"
    );
}

#[tokio::test]
async fn a_module_cannot_touch_a_platform_table() {
    static ALTER: &[Migration] = &[Migration {
        version: 1,
        name: "evil_0001",
        up: "CREATE TABLE evil_x (id INTEGER); ALTER TABLE users ADD COLUMN evil TEXT;",
        down: "DROP TABLE evil_x;",
    }];
    static DROP_TRIGGER: &[Migration] = &[Migration {
        version: 1,
        name: "evil_0001",
        up: "DROP TRIGGER audit_events_no_delete;",
        down: "",
    }];
    let db = db().await;
    for migrations in [ALTER, DROP_TRIGGER] {
        let err = migrate_modules(&db.pool, &toy("evil", migrations))
            .await
            .unwrap_err();
        assert!(matches!(err, MigrateError::Refused { .. }), "{err}");
    }
    assert!(!has_table(&db.pool, "evil_x").await);
    assert!(!has_table(&db.pool, "_migrations_evil").await);
    let columns: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pragma_table_info('users') WHERE name = 'evil'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(columns, 0);
    assert!(has_table(&db.pool, "audit_events_no_delete").await);
}

#[tokio::test]
async fn ids_whose_prefix_reaches_the_platform_or_another_module_are_refused() {
    static NONE: &[Migration] = &[];
    let db = db().await;
    // `audit_` covers `audit_events`, `events_` the `events_*` triggers, `push_` the push
    // cursor; `core` (which also covers the device tables) and `sqlite` are reserved.
    for id in ["audit", "events", "push", "core", "sqlite", "Toy"] {
        let err = migrate_modules(&db.pool, &toy(id, NONE)).await.unwrap_err();
        assert!(matches!(err, MigrateError::Refused { .. }), "{id}: {err}");
    }
    for pair in [["toy", "toy_x"], ["toy", "toy"]] {
        let modules: Vec<Arc<dyn Module>> =
            pair.iter().map(|id| Arc::new(Toy(id, NONE)) as _).collect();
        let err = migrate_modules(&db.pool, &modules).await.unwrap_err();
        assert!(
            matches!(err, MigrateError::Refused { .. }),
            "{pair:?}: {err}"
        );
    }
    migrate_modules(&db.pool, &toy("ops", NONE)).await.unwrap();
}

#[test]
fn the_schema_diff_flags_objects_outside_the_prefix() {
    let obj = |kind: &str, name: &str, table: &str| {
        (kind.to_owned(), name.to_owned(), table.to_owned(), None)
    };
    let before = vec![obj("table", "users", "users")];
    let after = vec![
        obj("table", "users", "users"),
        obj("table", "toy_x", "toy_x"),
        obj("index", "sqlite_autoindex_toy_x_1", "toy_x"),
        obj("trigger", "toy_t", "users"),
    ];
    assert_eq!(foreign_changes("toy_", &before, &after), ["trigger toy_t"]);
    assert_eq!(
        foreign_changes("toy_", &before, &[]),
        ["table users"],
        "a dropped platform table"
    );
}

/// E1-03.5: every table carries `user_id` unless it is allow-listed here with the reason its
/// rows belong to no user (the rule is in the header of the baseline migration). Checked over
/// the platform's schema and a module's, so a module table is held to it too.
#[tokio::test]
async fn user_owned_tables_carry_user_id() {
    const NOT_USER_OWNED: [&str; 10] = [
        // A registered name belongs to the platform or a module, not to a user.
        "event_kinds",
        "audit_actions",
        // One row: the event log's retention floor.
        "events_floor",
        // One row: the event log's running totals per visibility scope.
        "event_counts",
        // Each describes an event, which describes a row that carries its own user.
        "event_views",
        // The owners themselves.
        "users",
        // Failure counters by address: they belong to whoever is failing, not to a user.
        "core_auth_limits",
        // Each describes a row that carries its own user.
        "events",
        // One row: the pusher's position, the process's.
        "push_cursor",
        // Owned by their scope; a user scope is a scope kind, not a column.
        "settings",
    ];
    static V1: &[Migration] = &[TOY_1];
    let db = db().await;
    migrate_modules(&db.pool, &toy("toy", V1)).await.unwrap();
    // GLOB, not LIKE: `_` is a LIKE wildcard.
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' \
         AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_migrations_*' ORDER BY name",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert!(tables.contains(&"toy_items".to_owned()), "{tables:?}");
    let mut missing = Vec::new();
    for table in &tables {
        let has: i64 =
            sqlx::query_scalar("SELECT count(*) FROM pragma_table_info(?) WHERE name = 'user_id'")
                .bind(table)
                .fetch_one(&db.pool)
                .await
                .unwrap();
        if has == 0 && !NOT_USER_OWNED.contains(&table.as_str()) {
            missing.push(table.clone());
        }
    }
    assert!(missing.is_empty(), "tables without user_id: {missing:?}");
    for table in NOT_USER_OWNED {
        assert!(
            tables.iter().any(|t| t == table),
            "stale allow-list entry {table}"
        );
    }
}

/// `CORE_MIGRATIONS` is written by hand, so a file added to `migrations/` and not to the list
/// would never run: every `NNNN_<name>.{up,down}.sql` there must be listed, with its text.
#[test]
fn every_migration_file_is_listed() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");
    let mut files: Vec<(i64, String, String, String)> = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let file = entry.unwrap().file_name().into_string().unwrap();
        if file.ends_with(".down.sql") {
            continue;
        }
        let stem = file
            .strip_suffix(".up.sql")
            .unwrap_or_else(|| panic!("{file}: only NNNN_name.{{up,down}}.sql belongs here"));
        let (version, name) = stem.split_once('_').unwrap();
        let read =
            |kind: &str| std::fs::read_to_string(format!("{dir}/{stem}.{kind}.sql")).unwrap();
        files.push((
            version.parse().unwrap(),
            name.to_owned(),
            read("up"),
            read("down"),
        ));
    }
    files.sort();
    let listed: Vec<_> = CORE_MIGRATIONS
        .iter()
        .map(|m| {
            (
                m.version,
                m.name.to_owned(),
                m.up.to_owned(),
                m.down.to_owned(),
            )
        })
        .collect();
    assert_eq!(files, listed);
}

/// A module declaring kinds (E1-04.2): `migrate_modules` registers them, so its events append;
/// a name outside its prefix stops the start.
#[tokio::test]
async fn a_module_registers_its_event_kinds_and_audit_actions() {
    struct Kinds(&'static str, &'static [&'static str]);
    impl Module for Kinds {
        fn id(&self) -> &'static str {
            self.0
        }
        fn routes(&self) -> Router<App> {
            Router::new()
        }
        fn event_kinds(&self) -> &'static [&'static str] {
            self.1
        }
        fn audit_actions(&self) -> &'static [&'static str] {
            &["toy.made"]
        }
    }
    let db = db().await;
    let good: Vec<Arc<dyn Module>> = vec![Arc::new(Kinds("toy", &["toy.line", "toy.run.done"]))];
    migrate_modules(&db.pool, &good).await.unwrap();
    let mut tx = begin_write(&db.pool).await.unwrap();
    crate::store::events::append(&mut tx, "toy.run.done", &serde_json::json!({}))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    for bad in [&["other.line"][..], &["toy"], &["toy.Line"]] {
        let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Kinds("toy", bad))];
        let err = migrate_modules(&db.pool, &modules).await.unwrap_err();
        assert!(
            matches!(err, MigrateError::Refused { .. }),
            "{bad:?}: {err}"
        );
    }
}
