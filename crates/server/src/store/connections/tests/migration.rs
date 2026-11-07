use super::*;
use crate::store::migrate::{CORE, CORE_MIGRATIONS, migrate_core, undo};

async fn tables(fx: &Fx) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name GLOB 'core_connection*' ORDER BY name",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn migrates_up_down_up_over_a_database_with_data() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    grant_role(&fx, c.id, "member", None).await;
    bind(&fx, c.id, ("workspace", "")).await;
    let before = tables(&fx).await;
    assert_eq!(
        before,
        [
            "core_connection_bindings",
            "core_connection_grants",
            "core_connection_secrets",
            "core_connections"
        ]
    );
    let old: Vec<u8> =
        sqlx::query_scalar("SELECT sealed FROM core_connection_secrets WHERE connection_id = ?")
            .bind(c.id)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    undo(&fx.pool, CORE, CORE_MIGRATIONS, 26).await.unwrap();
    assert!(tables(&fx).await.is_empty(), "down drops all four");
    let (core, audit): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM core_pools) + (SELECT count(*) FROM core_accounts), \
         (SELECT count(*) FROM audit_events WHERE action = 'connection.created')",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(
        (core, audit),
        (0, 1),
        "earlier tables and the append-only audit log are untouched"
    );
    migrate_core(&fx.pool).await.unwrap();
    assert_eq!(tables(&fx).await, before);
    let again = make(&fx, "fake", "a").await;
    assert_eq!(
        again.id, 1,
        "a down migration drops the table, so ids restart (dev only)"
    );
    // A sealed blob of the old row never opens under the new row that reuses its id: the seal
    // label carries the row's own random nonce.
    sqlx::query("UPDATE core_connection_secrets SET sealed = ? WHERE connection_id = ?")
        .bind(&old)
        .bind(again.id)
        .execute(&fx.pool)
        .await
        .unwrap();
    assert_eq!(
        code(secret::open(&fx.pool, &fx.sealer, 1, again.id).await),
        "secrets_unavailable"
    );
    assert_eq!(list(&fx.pool, 1, None).await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_actions_are_registered_and_in_the_contract_list() {
    let fx = fx().await;
    let registered: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_actions WHERE action LIKE 'connection.%' ORDER BY action",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap();
    assert_eq!(registered, AUDIT_ACTIONS);
    assert!(
        AUDIT_ACTIONS.windows(2).all(|p| p[0] < p[1]),
        "sorted, as the contract list is"
    );
    for a in AUDIT_ACTIONS {
        assert!(
            crate::store::kinds::PLATFORM_AUDIT_ACTIONS.contains(a),
            "{a}: written in production since C4, so part of the contract list"
        );
    }
    let in_contract = crate::store::kinds::PLATFORM_AUDIT_ACTIONS
        .iter()
        .filter(|a| a.starts_with("connection."))
        .count();
    assert_eq!(
        in_contract,
        AUDIT_ACTIONS.len(),
        "no connection action only on one list"
    );
    assert!(
        crate::store::kinds::refusal("connection", "connection.x", true).is_some(),
        "a module may not take the connection namespace"
    );
    // Registering twice (a restart) is harmless.
    crate::store::kinds::register_platform(&fx.pool)
        .await
        .unwrap();
}
