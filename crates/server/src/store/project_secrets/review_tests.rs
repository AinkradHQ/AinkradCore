//! Review fixes of P4-04: an archived project's secrets can be deleted, and `list` filters by
//! group id like `names`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::fixtures::{VALUE, seed, who};
use super::*;
use crate::store::connect;

async fn pool() -> (SqlitePool, PathBuf, i64) {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-psec-rev-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let p = projects::create(&pool, "shop", "Shop", "", "manual", who())
        .await
        .unwrap();
    (pool, dir, p.id)
}

#[tokio::test]
async fn an_archived_project_can_still_delete_and_force_delete_secrets() {
    let (pool, dir, id) = pool().await;
    seed(&pool, id, &["leaked", "other"]).await;
    projects::archive(&pool, id, who()).await.unwrap();
    delete(&pool, id, "leaked", false, who()).await.unwrap();
    delete(&pool, id, "other", true, who()).await.unwrap();
    assert!(list(&pool, id).await.unwrap().is_empty());
    // Writing stays refused.
    let sealer = super::fixtures::broker(&pool).await;
    let input = Input {
        value: VALUE,
        kind: None,
        description: None,
        file_name: None,
        file_mode: None,
    };
    let r = set(&pool, &sealer, id, "again", &input, who()).await;
    assert!(matches!(
        r,
        Err(Error::Refused {
            code: "conflict",
            ..
        })
    ));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn list_is_by_group_id_not_by_name_alone() {
    let (pool, dir, id) = pool().await;
    seed(&pool, id, &["mine"]).await;
    // A look-alike `shop.*` secret outside the project's group must not be listed.
    let sealer = super::fixtures::broker(&pool).await;
    let new = NewValue {
        value: VALUE,
        ..NewValue::default()
    };
    secrets::create(
        &pool,
        &sealer,
        "shop.planted",
        &new,
        super::fixtures::DEVICE,
        ainkrad_core::audit::AuditActor::System,
        super::fixtures::NOW,
    )
    .await
    .unwrap();
    let got: Vec<_> = list(&pool, id)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(got, ["mine"]);
    let _ = std::fs::remove_dir_all(dir);
}
