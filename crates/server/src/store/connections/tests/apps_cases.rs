//! The sealed config of the OAuth apps (C5): sealed at rest, write-only, rotated with the master
//! key, refused while the broker is off, and the audit row names fields, never values.

use super::*;
use crate::store::connections::apps;
use crate::store::secrets::Error;

const VALUE: &str = "c5app-secret-9d2f7a41c8e0";

async fn put(fx: &Fx, kind: &str, changes: &[apps::Change<'_>]) -> Result<Vec<String>, Error> {
    apps::set(&fx.pool, &fx.sealer, kind, changes, w(NOW)).await
}

#[tokio::test]
async fn fields_are_sealed_listed_by_name_and_audited_without_values() {
    let fx = fx().await;
    let set = put(
        &fx,
        "jira",
        &[
            ("client_id", Some("client-1")),
            ("client_secret", Some(VALUE)),
        ],
    )
    .await
    .unwrap();
    assert_eq!(set, ["client_id", "client_secret"]);
    assert_eq!(apps::present(&fx.pool, 1, "jira").await.unwrap(), set);
    assert!(
        apps::present(&fx.pool, 1, "github")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        apps::present(&fx.pool, 2, "jira").await.unwrap().is_empty(),
        "another workspace"
    );
    let all = apps::open_all(&fx.pool, &fx.sealer, 1, "jira")
        .await
        .unwrap();
    assert_eq!(all.get("client_secret").map(|v| v.as_str()), Some(VALUE));
    // At rest the value is not in the row, and the audit row has the names only.
    let blobs: Vec<Vec<u8>> = sqlx::query_scalar("SELECT sealed FROM core_connection_apps")
        .fetch_all(&fx.pool)
        .await
        .unwrap();
    assert!(
        blobs
            .iter()
            .all(|b| !b.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()))
    );
    let audit: String =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'connection.app_set'")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert!(
        audit.contains("client_secret") && !audit.contains(VALUE),
        "{audit}"
    );
    // Replaced: a new version; cleared: gone.
    put(
        &fx,
        "jira",
        &[("client_secret", Some("c5app-second-1a2b3c4d5e"))],
    )
    .await
    .unwrap();
    let v: i64 = sqlx::query_scalar(
        "SELECT version FROM core_connection_apps WHERE field = 'client_secret'",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(v, 2);
    let left = put(&fx, "jira", &[("client_secret", None)]).await.unwrap();
    assert_eq!(left, ["client_id"]);
}

#[tokio::test]
async fn the_broker_off_refuses_a_write_and_a_read() {
    let fx = fx().await;
    crate::store::settings::set(
        &fx.pool,
        Key::SecretsMode,
        Scope::Server,
        "0",
        AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    let r = put(&fx, "jira", &[("client_id", Some("x"))]).await;
    assert_eq!(code(r), "secrets_disabled");
    let r = apps::open_all(&fx.pool, &fx.sealer, 1, "jira").await;
    assert_eq!(code(r), "secrets_disabled");
}

#[tokio::test]
async fn master_rotation_moves_the_apps_config_too() {
    let fx = fx().await;
    put(
        &fx,
        "jira",
        &[
            ("client_id", Some("client-1")),
            ("client_secret", Some(VALUE)),
        ],
    )
    .await
    .unwrap();
    let target = SecretBox::new(&[8; 32]);
    let keys = SecretBox::new(&[7; 32]).with_extra(vec![SecretBox::new(&[8; 32])]);
    let r = crate::store::secrets::reseal_all(&fx.pool, &keys, &target, false)
        .await
        .unwrap();
    assert_eq!((r.secrets, r.moved), (2, 2));
    let key: Vec<String> = sqlx::query_scalar("SELECT DISTINCT key_id FROM core_connection_apps")
        .fetch_all(&fx.pool)
        .await
        .unwrap();
    assert_eq!(key, [target.key_id()]);
    let all = apps::open_all(&fx.pool, &target, 1, "jira").await.unwrap();
    assert_eq!(
        all.get("client_secret").map(|v| v.as_str()),
        Some(VALUE),
        "opens under the new key alone"
    );
    let again = crate::store::secrets::reseal_all(&fx.pool, &keys, &target, false)
        .await
        .unwrap();
    assert_eq!(again.moved, 0);
    // A field moved to another row's label does not open there.
    sqlx::query("UPDATE core_connection_apps SET sealed = (SELECT sealed FROM core_connection_apps WHERE field = 'client_secret') WHERE field = 'client_id'")
        .execute(&fx.pool)
        .await
        .unwrap();
    let all = apps::open_all(&fx.pool, &target, 1, "jira").await.unwrap();
    assert!(!all.contains_key("client_id") && all.contains_key("client_secret"));
}

#[tokio::test]
async fn an_installation_is_stored_with_the_connection_and_goes_with_it() {
    let fx = fx().await;
    let new = NewConnection {
        kind: "fake",
        name: "app",
        label: "An app connection",
        auth_method: "token",
    };
    let c = create_with(
        &fx.pool,
        &fx.sealer,
        &fx.reg,
        &new,
        &material(SECRET),
        Some(77),
        w(NOW),
    )
    .await
    .unwrap();
    assert_eq!(
        apps::installation_of(&fx.pool, 1, c.id).await.unwrap(),
        Some(77)
    );
    assert_eq!(
        apps::installation_of(&fx.pool, 2, c.id).await.unwrap(),
        None,
        "another workspace"
    );
    let plain = make(&fx, "fake", "plain").await;
    assert_eq!(
        apps::installation_of(&fx.pool, 1, plain.id).await.unwrap(),
        None
    );
    apps::set_installation(&fx.pool, plain.id, 78, w(NOW))
        .await
        .unwrap();
    assert_eq!(
        apps::installation_of(&fx.pool, 1, plain.id).await.unwrap(),
        Some(78)
    );
    delete(&fx.pool, c.id, w(NOW)).await.unwrap();
    assert_eq!(
        apps::installation_of(&fx.pool, 1, c.id).await.unwrap(),
        None
    );
}
