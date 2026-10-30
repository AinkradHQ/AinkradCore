//! The baseline migration against the platform's: only `citadel_` objects, FKs on, the module's
//! own namespace and its down migration clean.

use std::sync::Arc;

use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::migrate;
use citadel_module::Citadel;
use citadel_module::testing::db;

const TABLES: usize = 56;

#[tokio::test]
async fn the_baseline_creates_only_citadel_objects_and_seeds_the_palettes() {
    let db = db().await;
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE name LIKE 'citadel\\_%' ESCAPE '\\' AND type = 'table'",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(names.len(), TABLES, "{names:?}");
    // Every table of the baseline is in the module's namespace: nothing else was added.
    let stray: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE tbl_name IN (SELECT name FROM sqlite_master \
         WHERE name IN ('companies', 'agents', 'issues', 'runs', 'projects', 'approvals'))",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert!(stray.is_empty(), "{stray:?}");
    let palettes: i64 = sqlx::query_scalar("SELECT count(*) FROM citadel_avatar_palettes")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(palettes, 17);
    let foreign_keys: Vec<(String, String)> = sqlx::query_as(
        "SELECT m.name, f.\"table\" FROM sqlite_master m, pragma_foreign_key_list(m.name) f \
         WHERE m.type = 'table' AND m.name LIKE 'citadel\\_%' ESCAPE '\\' \
         AND f.\"table\" NOT LIKE 'citadel\\_%' ESCAPE '\\'",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert!(
        foreign_keys.iter().all(|(_, to)| to == "users"),
        "only users is referenced outside the module: {foreign_keys:?}"
    );
}

#[tokio::test]
async fn migrating_twice_changes_nothing_and_down_removes_every_citadel_object() {
    let db = db().await;
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Citadel::default())];
    migrate::migrate_modules(&db.pool, &modules).await.unwrap();
    migrate::undo(
        &db.pool,
        "citadel",
        citadel_module::migrations::MIGRATIONS,
        0,
    )
    .await
    .unwrap();
    let left: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE name LIKE 'citadel\\_%' ESCAPE '\\'",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert!(left.is_empty(), "{left:?}");
}

#[tokio::test]
async fn the_module_declares_its_names_and_they_are_registered() {
    let db = db().await;
    let kinds: i64 = sqlx::query_scalar("SELECT count(*) FROM event_kinds WHERE owner = 'citadel'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let actions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_actions WHERE owner = 'citadel'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(kinds as usize, citadel_module::kinds::EVENT_KINDS.len());
    assert_eq!(actions as usize, citadel_module::kinds::AUDIT_ACTIONS.len());
}
