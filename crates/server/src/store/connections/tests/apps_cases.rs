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
        Some((77, "octo-org")),
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
    apps::set_installation(&fx.pool, plain.id, (78, "octo-org"), w(NOW))
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

#[tokio::test]
async fn an_installation_belongs_to_the_first_workspace_that_uses_it() {
    let fx = fx().await;
    second_user(&fx).await;
    let new = |name| NewConnection {
        kind: "fake",
        name,
        label: "An app connection",
        auth_method: "token",
    };
    let first = create_with(
        &fx.pool,
        &fx.sealer,
        &fx.reg,
        &new("a"),
        &material(SECRET),
        Some((77, "octo-org")),
        w(NOW),
    )
    .await
    .unwrap();
    assert_eq!(apps::claimed_by(&fx.pool, 77).await.unwrap(), Some(1));
    // Another workspace is refused, and nothing is created for it.
    let r = create_with(
        &fx.pool,
        &fx.sealer,
        &fx.reg,
        &new("b"),
        &material(SECRET),
        Some((77, "octo-org")),
        ww(2, NOW),
    )
    .await;
    assert_eq!(code(r), "conflict");
    assert!(list(&fx.pool, 2, None).await.unwrap().is_empty());
    let other = create_with(
        &fx.pool,
        &fx.sealer,
        &fx.reg,
        &new("b"),
        &material(SECRET),
        None,
        ww(2, NOW),
    )
    .await
    .unwrap();
    assert_eq!(
        code(apps::set_installation(&fx.pool, other.id, (77, "octo-org"), ww(2, NOW)).await),
        "conflict"
    );
    // The claim outlives the connection: a deleted one does not free the installation.
    delete(&fx.pool, first.id, w(NOW)).await.unwrap();
    assert_eq!(apps::claimed_by(&fx.pool, 77).await.unwrap(), Some(1));
    // The same workspace may use it again.
    create_with(
        &fx.pool,
        &fx.sealer,
        &fx.reg,
        &new("c"),
        &material(SECRET),
        Some((77, "octo-org")),
        w(NOW),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn a_credential_and_its_installation_change_together_or_not_at_all() {
    let fx = fx().await;
    second_user(&fx).await;
    let new = |name| NewConnection {
        kind: "fake",
        name,
        label: "An app connection",
        auth_method: "token",
    };
    let mine = create_with(
        &fx.pool,
        &fx.sealer,
        &fx.reg,
        &new("a"),
        &material(SECRET),
        Some((77, "octo-org")),
        w(NOW),
    )
    .await
    .unwrap();
    create_with(
        &fx.pool,
        &fx.sealer,
        &fx.reg,
        &new("b"),
        &material(SECRET),
        Some((78, "other-org")),
        ww(2, NOW),
    )
    .await
    .unwrap();
    // 78 is another workspace's: nothing changes, neither the token nor the installation.
    let r = secret::replace_installed(
        &fx.pool,
        &fx.sealer,
        mine.id,
        &material("c5new-token-1a2b3c4d5e"),
        (78, "other-org"),
        w(NOW),
    )
    .await;
    assert_eq!(code(r), "conflict");
    assert_eq!(version(&fx, mine.id).await, 1);
    assert_eq!(
        apps::installation_of(&fx.pool, 1, mine.id).await.unwrap(),
        Some(77)
    );
    let (m, _) = secret::open(&fx.pool, &fx.sealer, 1, mine.id)
        .await
        .unwrap();
    assert_eq!(m.access(), SECRET);
    // A free installation moves with the new token, in one write.
    secret::replace_installed(
        &fx.pool,
        &fx.sealer,
        mine.id,
        &material("c5new-token-1a2b3c4d5e"),
        (79, "octo-org"),
        w(NOW),
    )
    .await
    .unwrap();
    assert_eq!(version(&fx, mine.id).await, 2);
    assert_eq!(
        apps::installation_of(&fx.pool, 1, mine.id).await.unwrap(),
        Some(79)
    );
}

#[tokio::test]
async fn an_edit_is_one_transaction_a_refused_name_leaves_the_label_and_switch() {
    let fx = fx().await;
    let a = make(&fx, "fake", "a").await;
    make(&fx, "fake", "b").await;
    let change = Edit {
        name: Some("b"),
        label: Some("A new label"),
        disabled: Some(true),
    };
    assert_eq!(
        code(edit(&fx.pool, a.id, &change, w(NOW)).await),
        "conflict"
    );
    let now = get(&fx.pool, 1, a.id).await.unwrap();
    assert_eq!(
        (now.label.as_str(), now.disabled, now.name.as_str()),
        (a.label.as_str(), false, "a")
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action IN ('connection.updated', 'connection.disabled')",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(audited, 0, "a rolled back edit leaves no audit row");
    let done = Edit {
        name: Some("c"),
        ..change
    };
    let c = edit(&fx.pool, a.id, &done, w(NOW)).await.unwrap();
    assert_eq!(
        (c.name.as_str(), c.label.as_str(), c.disabled),
        ("c", "A new label", true)
    );
}
