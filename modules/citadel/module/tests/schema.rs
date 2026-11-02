//! The baseline migration against the platform's: only `citadel_` objects, FKs on, the module's
//! own namespace and its down migration clean.

use std::sync::Arc;

use ainkrad_core_server::module::Module;
use ainkrad_core_server::store::migrate;
use citadel_module::Citadel;
use citadel_module::testing::db;

const TABLES: usize = 58;

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

/// KAN-178 (E2-13.5): no credential is stored outside the secrets broker. Every column of the
/// migrated schema (Core and Citadel) whose name looks like credential material is listed here and
/// reviewed: it is a broker secret *name*, a hash, a public identifier or a delivery address, never
/// a value. A new column that matches must be added with that review, or the test fails.
#[tokio::test]
async fn no_column_outside_the_broker_can_hold_a_credential() {
    const REVIEWED: &[(&str, &str, &str)] = &[
        // (table, column, why it is not a credential)
        ("citadel_accounts", "secret_name", "name of a broker secret"),
        (
            "citadel_forge_secret_hosts",
            "secret",
            "name of a broker secret",
        ),
        (
            "citadel_project_linear",
            "secret",
            "name of a broker secret",
        ),
        (
            "citadel_project_repos",
            "forge_secret",
            "name of a broker secret",
        ),
        ("citadel_run_tokens", "token_hash", "SHA-256 of a run token"),
        ("core_pairings", "secret_hash", "hash of a pairing secret"),
        (
            "core_passkeys",
            "credential_id",
            "public WebAuthn credential id",
        ),
        (
            "core_push_tokens",
            "token",
            "device push address, not an account credential",
        ),
        (
            "core_devices",
            "push_token",
            "device push address, not an account credential",
        ),
        ("core_agent_sessions", "secrets", "names of broker secrets"),
    ];
    let db = db().await;
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
         AND name NOT LIKE 'core\\_secret%' ESCAPE '\\'",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    let mut found = vec![];
    for t in tables {
        let cols: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT name FROM pragma_table_info('{t}')"
        )))
        .fetch_all(&db.pool)
        .await
        .unwrap();
        for c in cols {
            let l = c.to_lowercase();
            // Counts of model tokens (`input_tokens`, `token_cap`) are numbers, not credentials.
            if l.contains("tokens") || l == "token_cap" {
                continue;
            }
            if [
                "secret",
                "token",
                "password",
                "passwd",
                "credential",
                "api_key",
                "apikey",
                "private",
                "bearer",
                "cert",
            ]
            .iter()
            .any(|w| l.contains(w))
            {
                found.push(format!("{t}.{c}"));
            }
        }
    }
    found.sort();
    let mut want: Vec<String> = REVIEWED
        .iter()
        .map(|(t, c, _)| format!("{t}.{c}"))
        .collect();
    want.sort();
    assert_eq!(found, want, "review the column, then list it in REVIEWED");
}
