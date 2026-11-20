//! E15 security review regressions that need the database.

use super::*;
use crate::store::gov;

/// A runner device paired with `sas` (`bundled`: the attested This Mac), or with no pairing row.
async fn runner(fx: &Fx, name: &str, pairing: Option<(&str, bool)>) -> String {
    let r = TestDevice::enroll(
        &fx.app.pool,
        name,
        "runner",
        &["runner"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    if let Some((sas, bundled)) = pairing {
        let id = format!("p_{:0>26}", name);
        sqlx::query(
            "INSERT INTO core_pairings (id, code_hash, secret_hash, kind, name, scopes, bootstrap, \
             invite, created_at, expires_at, status, device_id, sas, bundled) \
             VALUES (?, randomblob(32), randomblob(32), 'runner', ?, '[\"runner\"]', 0, 0, \
             '2026-01-01T00:00:00Z', '2026-01-01T00:05:00Z', 'approved', ?, ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(&r.id)
        .bind(sas)
        .bind(bundled)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    }
    r.id
}

/// M6: the Core itself refuses a terminal on a plain paired runner; the Core's own runner and
/// the attested This Mac keep theirs.
#[tokio::test]
async fn only_the_core_and_this_mac_host_terminals() {
    let fx = fx().await;
    let core = runner(&fx, "core", Some((gov::LOCAL_ENROL_SAS, false))).await;
    let mac = runner(&fx, "mac", Some(("123456", true))).await;
    let remote = runner(&fx, "remote", Some(("654321", false))).await;
    let ok = |d: String| {
        let pool = fx.app.pool.clone();
        async move {
            crate::hardware::view::hosts_terminals(&pool, &d)
                .await
                .unwrap()
        }
    };
    assert!(ok(core).await);
    assert!(ok(mac).await);
    assert!(!ok(remote).await);
}
