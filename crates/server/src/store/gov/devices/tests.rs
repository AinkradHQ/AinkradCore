use std::sync::Arc;

use ainkrad_core::audit::AuditFilter;
use ainkrad_core::ids::{DeviceKeyId, UserId};

use super::*;
use crate::auth::testing::TestDevice;
use crate::scheduler::SystemClock;
use crate::store::gov::{
    PushTarget, device_usable, get_device, list_devices, push_targets, set_push_token,
};

const BY: AuditActor = AuditActor::User(UserId(1));

fn key() -> TestDevice {
    TestDevice::new("fp", Arc::new(SystemClock))
}

#[tokio::test]
async fn enroll_validate_mark_and_revoke() {
    let dir = std::env::temp_dir().join(format!("core-devices-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = crate::store::connect(&dir.join("core.db")).await.unwrap();

    let k = key();
    let scopes = ["read".to_owned(), "admin".to_owned()];
    fn new(k: &TestDevice) -> NewDevice<'_> {
        NewDevice {
            id: &k.id,
            kind: "device",
            name: " MacBook ",
            routine_spki: &k.spki,
            stepup_spki: None,
            platform: Some("macos"),
            key_storage: Some("secure_enclave"),
            scopes: &[],
        }
    }
    let d = enroll_for_tests(
        &pool,
        &NewDevice {
            scopes: &scopes,
            ..new(&k)
        },
    )
    .await
    .unwrap();
    assert_eq!((d.name.as_str(), d.status.as_str()), ("MacBook", "active"));
    assert_eq!(d.scopes, scopes);
    assert_eq!(d.fingerprint, crate::auth::crypto::fingerprint(&k.spki));
    assert!(d.usable() && device_usable(&pool, &d.id).await.unwrap());

    // Refused: a key that is not a P-256 SPKI, the same key twice, unknown kinds and scopes,
    // and a runner with more than the runner scope.
    let other = key();
    let mut bad_key = other.spki.clone();
    bad_key[90] ^= 1;
    let wide = ["read".to_owned()];
    let runner_ok = ["runner".to_owned()];
    for (case, why) in [
        (
            NewDevice {
                routine_spki: &bad_key,
                ..new(&other)
            },
            "off the curve",
        ),
        (
            NewDevice {
                routine_spki: &other.spki[..90],
                ..new(&other)
            },
            "short",
        ),
        (
            NewDevice {
                kind: "toaster",
                ..new(&other)
            },
            "kind",
        ),
        (
            NewDevice {
                scopes: &["root".to_owned()],
                ..new(&other)
            },
            "scope",
        ),
        (
            NewDevice {
                kind: "runner",
                scopes: &wide,
                ..new(&other)
            },
            "runner scope",
        ),
    ] {
        assert!(enroll_for_tests(&pool, &case).await.is_err(), "{why}");
    }
    assert!(
        enroll_for_tests(
            &pool,
            &NewDevice {
                id: &other.id,
                ..new(&k)
            }
        )
        .await
        .is_err(),
        "the same key twice"
    );
    let runner = enroll_for_tests(
        &pool,
        &NewDevice {
            kind: "runner",
            scopes: &runner_ok,
            ..new(&other)
        },
    )
    .await
    .unwrap();
    assert_eq!(runner.kind, "runner");

    // Use is marked at most once a minute.
    let t1 = "2026-10-22T10:00:01.000Z";
    mark_used(&pool, &d.id, None, t1).await.unwrap();
    mark_used(&pool, &d.id, Some(t1), "2026-10-22T10:00:59.000Z")
        .await
        .unwrap();
    let got = get_device(&pool, &d.id).await.unwrap().unwrap();
    assert_eq!(got.last_used_at.as_deref(), Some(t1));

    // Revocation: once, audited, and the device is no longer usable.
    let t2 = "2026-10-22T10:01:00.000Z";
    assert!(
        revoke_device(&pool, &d.id, BY, Some(&runner.id), t2)
            .await
            .unwrap()
    );
    assert!(!revoke_device(&pool, &d.id, BY, None, t2).await.unwrap());
    assert!(!revoke_device(&pool, "d_nope", BY, None, t2).await.unwrap());
    let gone = get_device(&pool, &d.id).await.unwrap().unwrap();
    assert!(!gone.usable() && !device_usable(&pool, &d.id).await.unwrap());
    assert_eq!(list_devices(&pool).await.unwrap().len(), 2, "the row stays");
    let audit = crate::store::audit::list(&pool, &AuditFilter::default(), None, 10)
        .await
        .unwrap();
    let actions: Vec<&str> = audit.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions,
        ["device.enrolled", "device.enrolled", "device.revoked"]
    );
    let revoked = audit.last().unwrap();
    assert_eq!(revoked.entity.as_ref().unwrap().id, d.seq);
    let details: serde_json::Value = serde_json::from_str(&revoked.details).unwrap();
    assert_eq!(details["device"], d.id.as_str());
    assert_eq!(details["by_device"], runner.id.as_str());

    // Push tokens: usable devices only, hex only.
    let hex = "ab".repeat(32);
    assert!(
        set_push_token(&pool, &runner.id, Some((&hex.to_uppercase(), true)))
            .await
            .unwrap()
    );
    assert!(
        !set_push_token(&pool, &d.id, Some((&hex, false)))
            .await
            .unwrap(),
        "revoked"
    );
    assert!(
        set_push_token(&pool, &runner.id, Some(("not hex", false)))
            .await
            .is_err()
    );
    let want = PushTarget {
        device: DeviceKeyId(runner.seq),
        device_id: runner.id.clone(),
        scopes: runner.scopes.clone(),
        provider: "apns".to_owned(),
        token: hex,
        sandbox: true,
    };
    assert_eq!(push_targets(&pool).await.unwrap(), [want]);
    assert!(set_push_token(&pool, &runner.id, None).await.unwrap());
    assert_eq!(push_targets(&pool).await.unwrap(), []);
    assert_eq!(push_cursor(&pool).await.unwrap(), None);
    set_push_cursor(&pool, 7).await.unwrap();
    set_push_cursor(&pool, 9).await.unwrap();
    assert_eq!(push_cursor(&pool).await.unwrap(), Some(9));

    pool.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
