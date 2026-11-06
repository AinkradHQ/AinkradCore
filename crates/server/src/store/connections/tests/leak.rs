//! No path shows a credential: every printable form, error, audit row, event and the database
//! file itself are scanned for the secret text.

use super::*;
use health::Signal;

#[tokio::test]
async fn the_secret_appears_nowhere_it_could_be_read() {
    let fx = fx().await;
    let c = make_with(&fx, "fake", "a", SECRET).await;
    let m = material(SECRET);
    let mut seen: Vec<String> = vec![format!("{m:?}{m}{m:#?}"), format!("{c:?}{c:#?}")];
    // Every write, with the secret in play.
    grant_role(&fx, c.id, "member", None).await;
    bind(&fx, c.id, ("workspace", "")).await;
    health::signal(
        &fx.pool,
        1,
        c.id,
        Signal::Agent {
            class: "rate_limited",
        },
        NOW,
    )
    .await
    .unwrap();
    verdict::run_test(&fx.pool, &fx.sealer, &fx.reg, c.id, w(NOW))
        .await
        .unwrap();
    let new = Material::new(REFRESH, Some(SECRET), None).unwrap();
    secret::replace(&fx.pool, &fx.sealer, c.id, &new, w(NOW))
        .await
        .unwrap();
    resolve::record_use(
        &fx.pool,
        &fx.reg,
        Some(c.id),
        "fake",
        ("fake.get_item", "ok", None),
        &cx("read_items"),
    )
    .await
    .unwrap();
    seen.push(format!(
        "{:?}{:?}",
        get(&fx.pool, 1, c.id).await.unwrap(),
        list(&fx.pool, 1, None).await.unwrap()
    ));
    seen.push(format!(
        "{:?}",
        grants::list(&fx.pool, 1, c.id).await.unwrap()
    ));
    seen.push(format!(
        "{:?}",
        bindings::list(&fx.pool, 1, None).await.unwrap()
    ));
    // Every refusal, as an error string and as Debug.
    let clash = NewConnection {
        kind: "fake",
        name: "a",
        label: "x",
        auth_method: "token",
    };
    let errs = [
        create(
            &fx.pool,
            &fx.sealer,
            &fx.reg,
            &clash,
            &material(SECRET),
            w(NOW),
        )
        .await
        .map(drop),
        rename(&fx.pool, c.id, "Bad", w(NOW)).await.map(drop),
        delete(&fx.pool, c.id, w(NOW)).await,
        resolve::resolve(&fx.pool, &fx.reg, "fake", &cx("write_items"), NOW)
            .await
            .map(drop),
        secret::open(&fx.pool, &SecretBox::new(&[9; 32]), 1, c.id)
            .await
            .map(drop),
    ];
    for e in errs {
        let e = e.unwrap_err();
        seen.push(format!("{e} {e:?}"));
    }
    // A panic message carrying the printable credential.
    let caught = std::panic::catch_unwind(|| panic!("failed with {m:?} and {m}")).unwrap_err();
    seen.push(caught.downcast_ref::<String>().cloned().unwrap_or_default());
    // The audit log and the event log.
    for q in [
        "SELECT details FROM audit_events",
        "SELECT payload FROM events",
    ] {
        let rows: Vec<String> = sqlx::query_scalar(q).fetch_all(&fx.pool).await.unwrap();
        assert!(!rows.is_empty(), "{q}");
        seen.extend(rows);
    }
    for text in &seen {
        for s in [SECRET, REFRESH, "7f3a9d41e0b2c8a6", "91c4d2b7a6e1f035"] {
            assert!(!text.contains(s), "leaked {s:?} in {text:.200}");
        }
    }
    // At rest: neither the database nor its write-ahead log holds the text.
    for file in ["core.db", "core.db-wal"] {
        let bytes = std::fs::read(fx.dir.join(file)).unwrap_or_default();
        for s in [SECRET, REFRESH] {
            assert!(
                !bytes.windows(s.len()).any(|w| w == s.as_bytes()),
                "{s} in {file}"
            );
        }
    }
    // The one reader still has it.
    let open = secret::open(&fx.pool, &fx.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(open.access(), REFRESH);
    assert_eq!(open.refresh(), Some(SECRET));
}

#[tokio::test]
async fn a_credential_under_another_label_or_key_does_not_open() {
    let fx = fx().await;
    let (a, b) = (
        make(&fx, "fake", "a").await,
        make_with(&fx, "fake", "b", "c1probe-other-bbbb").await,
    );
    // Moving a's sealed bytes to b's row must not open as b's.
    sqlx::query("UPDATE core_connection_secrets SET sealed = (SELECT sealed FROM core_connection_secrets WHERE connection_id = ?) WHERE connection_id = ?")
        .bind(a.id).bind(b.id).execute(&fx.pool).await.unwrap();
    assert_eq!(
        code(secret::open(&fx.pool, &fx.sealer, 1, b.id).await),
        "secrets_unavailable"
    );
    assert_eq!(
        code(secret::open(&fx.pool, &SecretBox::new(&[1; 32]), 1, a.id).await),
        "secrets_unavailable"
    );
    assert!(secret::open(&fx.pool, &fx.sealer, 1, a.id).await.is_ok());
}

#[tokio::test]
async fn master_rotation_moves_connection_credentials_too() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let target = SecretBox::new(&[8; 32]);
    let keys = SecretBox::new(&[7; 32]).with_extra(vec![SecretBox::new(&[8; 32])]);
    let r = crate::store::secrets::reseal_all(&fx.pool, &keys, &target, false)
        .await
        .unwrap();
    assert_eq!((r.secrets, r.moved), (1, 1));
    let key: String = sqlx::query_scalar("SELECT key_id FROM core_connection_secrets")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(key, target.key_id());
    let m = secret::open(&fx.pool, &target, 1, c.id).await.unwrap().0;
    assert_eq!(m.access(), SECRET, "opens under the new key alone");
    let again = crate::store::secrets::reseal_all(&fx.pool, &keys, &target, false)
        .await
        .unwrap();
    assert_eq!(again.moved, 0, "idempotent");
    // A rotation that has to roll back leaves the credential under its old key.
    let fx2 = super::fx().await;
    make(&fx2, "fake", "a").await;
    let keys2 = SecretBox::new(&[7; 32]).with_extra(vec![SecretBox::new(&[8; 32])]);
    assert!(
        crate::store::secrets::reseal_all(&fx2.pool, &keys2, &target, true)
            .await
            .is_err()
    );
    let key: String = sqlx::query_scalar("SELECT key_id FROM core_connection_secrets")
        .fetch_one(&fx2.pool)
        .await
        .unwrap();
    assert_eq!(key, SecretBox::new(&[7; 32]).key_id());
}
