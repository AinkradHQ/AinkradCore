use super::*;

#[tokio::test]
async fn create_stores_a_sealed_credential_and_audits_without_it() {
    let fx = fx().await;
    let c = make(&fx, "fake", "main").await;
    assert_eq!(
        (c.kind.as_str(), c.name.as_str(), c.status.as_str()),
        ("fake", "main", "active")
    );
    assert_eq!(c.identity, None, "an identity comes from a test");
    assert_eq!(c.expires_at.as_deref(), Some("2026-11-06T11:00:00Z"));
    let m = secret::open(&fx.pool, &fx.sealer, c.id).await.unwrap();
    assert_eq!((m.access(), m.refresh()), (SECRET, Some(REFRESH)));
    assert_eq!(actions(&fx).await, ["connection.created"]);
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT sealed FROM core_connection_secrets WHERE connection_id = ?")
            .bind(c.id)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert!(
        !String::from_utf8_lossy(&stored).contains(SECRET),
        "sealed at rest"
    );
    assert_eq!(
        list(&fx.pool, 1, Some("fake")).await.unwrap(),
        std::slice::from_ref(&c)
    );
    assert!(list(&fx.pool, 1, Some("other")).await.unwrap().is_empty());
}

#[tokio::test]
async fn many_connections_per_kind_with_a_unique_name() {
    let fx = fx().await;
    let a = make(&fx, "fake", "work").await;
    let b = make(&fx, "fake", "personal").await;
    let o = make(&fx, "other", "work").await;
    assert_eq!(list(&fx.pool, 1, Some("fake")).await.unwrap().len(), 2);
    assert!(a.id != b.id && a.id != o.id);
    let new = NewConnection {
        user_id: 1,
        kind: "fake",
        name: "work",
        label: "x",
        auth_method: "token",
    };
    let dup = create(
        &fx.pool,
        &fx.sealer,
        &fx.reg,
        &new,
        &material(SECRET),
        w(NOW),
    )
    .await;
    assert_eq!(code(dup), "conflict");
    assert_eq!(
        code(rename(&fx.pool, b.id, "work", w(NOW)).await),
        "conflict"
    );
    let renamed = rename(&fx.pool, b.id, "home", w(NOW)).await.unwrap();
    assert_eq!(renamed.name, "home");
    assert_eq!(
        rename(&fx.pool, 999, "x", w(NOW))
            .await
            .map(drop)
            .unwrap_err()
            .to_string(),
        "not_found: no such connection"
    );
    let l = update_label(&fx.pool, a.id, "Work account", w(NOW))
        .await
        .unwrap();
    assert_eq!(l.label, "Work account");
    assert_eq!(
        code(update_label(&fx.pool, a.id, "bad\nlabel", w(NOW)).await),
        "bad_request"
    );
}

#[tokio::test]
async fn create_refuses_what_is_not_valid() {
    let fx = fx().await;
    let ok = |kind, name, label, auth| NewConnection {
        user_id: 1,
        kind,
        name,
        label,
        auth_method: auth,
    };
    let m = material(SECRET);
    for (new, want) in [
        (ok("nope", "a", "A", "token"), "bad_request"),
        (ok("other", "a", "A", "oauth"), "bad_request"),
        (ok("fake", "Bad Name", "A", "token"), "bad_request"),
        (ok("fake", "a", "", "token"), "bad_request"),
        (ok("fake", "a", "tab\there", "token"), "bad_request"),
        (
            NewConnection {
                user_id: 99,
                ..ok("fake", "a", "A", "token")
            },
            "bad_request",
        ),
    ] {
        let r = create(&fx.pool, &fx.sealer, &fx.reg, &new, &m, w(NOW)).await;
        assert_eq!(code(r), want, "{}", new.name);
    }
    assert!(
        list(&fx.pool, 1, None).await.unwrap().is_empty(),
        "nothing half-made"
    );
    // The broker's gates: a real shape below mode 2, and the broker off.
    let real = Material::new(&format!("ghp_{}", "A1b2C3d4E5".repeat(4)), None, None).unwrap();
    let new = ok("fake", "a", "A", "token");
    let r = create(&fx.pool, &fx.sealer, &fx.reg, &new, &real, w(NOW)).await;
    assert_eq!(code(r), "real_secret_refused");
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
    let r = create(&fx.pool, &fx.sealer, &fx.reg, &new, &m, w(NOW)).await;
    assert_eq!(code(r), "secrets_disabled");
    assert_eq!(
        code(secret::replace(&fx.pool, &fx.sealer, 1, &m, w(NOW)).await),
        "secrets_disabled"
    );
}

#[tokio::test]
async fn disable_and_enable_are_idempotent_and_audited_once() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    for _ in 0..2 {
        assert!(
            set_disabled(&fx.pool, c.id, true, w(NOW))
                .await
                .unwrap()
                .disabled
        );
    }
    for _ in 0..2 {
        assert!(
            !set_disabled(&fx.pool, c.id, false, w(NOW))
                .await
                .unwrap()
                .disabled
        );
    }
    assert_eq!(
        actions(&fx).await,
        [
            "connection.created",
            "connection.disabled",
            "connection.enabled"
        ]
    );
}

#[tokio::test]
async fn delete_refuses_while_bound_and_takes_its_dependents_with_it() {
    let fx = fx().await;
    let (a, b) = (make(&fx, "fake", "a").await, make(&fx, "fake", "b").await);
    grant_role(&fx, a.id, "member", None).await;
    bind(&fx, a.id, ("workspace", "")).await;
    bind(&fx, a.id, ("session", "s1")).await;
    assert_eq!(code(delete(&fx.pool, a.id, w(NOW)).await), "conflict");
    assert!(get(&fx.pool, a.id).await.is_ok(), "refused, so untouched");
    assert!(
        bindings::clear(&fx.pool, 1, "fake", ("workspace", ""), w(NOW))
            .await
            .unwrap()
    );
    delete(&fx.pool, a.id, w(NOW)).await.unwrap();
    assert_eq!(code(get(&fx.pool, a.id).await), "not_found");
    for table in [
        "core_connection_secrets",
        "core_connection_grants",
        "core_connection_bindings",
    ] {
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {table} WHERE connection_id = {}",
            a.id
        )))
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert_eq!(n, 0, "{table}");
    }
    assert!(get(&fx.pool, b.id).await.is_ok());
    assert_eq!(code(delete(&fx.pool, a.id, w(NOW)).await), "not_found");
    assert_eq!(
        make(&fx, "fake", "a").await.id,
        b.id + 1,
        "an id is never reused"
    );
}

#[tokio::test]
async fn per_user_limits_hold_and_users_are_apart() {
    let fx = fx().await;
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(&fx.pool)
        .await
        .unwrap();
    for i in 0..MAX_PER_USER {
        make(&fx, "fake", &format!("c{i}")).await;
    }
    let new = NewConnection {
        user_id: 1,
        kind: "fake",
        name: "one-more",
        label: "x",
        auth_method: "token",
    };
    let over = create(
        &fx.pool,
        &fx.sealer,
        &fx.reg,
        &new,
        &material(SECRET),
        w(NOW),
    )
    .await;
    assert_eq!(code(over), "limit_reached");
    let other = NewConnection { user_id: 2, ..new };
    let c = create(
        &fx.pool,
        &fx.sealer,
        &fx.reg,
        &other,
        &material(SECRET),
        w(NOW),
    )
    .await
    .unwrap();
    assert_eq!(c.user_id, 2, "another user's own budget");
    assert_eq!(list(&fx.pool, 2, None).await.unwrap().len(), 1);
}

#[tokio::test]
async fn replacing_the_credential_is_a_new_version_and_clears_an_auth_suspicion() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    health::signal(
        &fx.pool,
        c.id,
        health::Signal::Upstream {
            status: ainkrad_proto::v2::UpstreamStatus::AuthFailed,
            retry_after: None,
            reset_at: None,
        },
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(
        get(&fx.pool, c.id).await.unwrap().state_reason.as_deref(),
        Some("auth_suspected")
    );
    let new = Material::new("c1probe-second-0000", None, None).unwrap();
    let c2 = secret::replace(&fx.pool, &fx.sealer, c.id, &new, w(NOW))
        .await
        .unwrap();
    assert_eq!(c2.status, "active");
    let m = secret::open(&fx.pool, &fx.sealer, c.id).await.unwrap();
    assert_eq!((m.access(), m.refresh()), ("c1probe-second-0000", None));
    let v: i64 =
        sqlx::query_scalar("SELECT version FROM core_connection_secrets WHERE connection_id = ?")
            .bind(c.id)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert_eq!(v, 2);
    assert!(
        actions(&fx)
            .await
            .contains(&"connection.secret_replaced".to_owned())
    );
}
