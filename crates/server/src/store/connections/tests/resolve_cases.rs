use super::*;

async fn setup() -> (Fx, Connection, Connection) {
    let fx = fx().await;
    let (a, b) = (
        make(&fx, "fake", "work").await,
        make(&fx, "fake", "personal").await,
    );
    for c in [&a, &b] {
        grant_role(&fx, c.id, "member", None).await;
    }
    (fx, a, b)
}

async fn via(fx: &Fx, c: &Context<'_>) -> Result<(i64, &'static str), &'static str> {
    match resolve::resolve(&fx.pool, &fx.reg, "fake", c, NOW).await {
        Ok(r) => Ok((r.connection.id, r.via)),
        Err(e) => Err(code::<()>(Err(e))),
    }
}

#[tokio::test]
async fn bindings_resolve_session_then_agent_then_project_then_workspace() {
    let (fx, a, b) = setup().await;
    let c3 = make(&fx, "fake", "third").await;
    let c4 = make(&fx, "fake", "fourth").await;
    for c in [&c3, &c4] {
        grant_role(&fx, c.id, "member", None).await;
    }
    let full = Context {
        agent: Some("bot"),
        project: Some("acme/app"),
        session: Some("s1"),
        ..cx("read_items")
    };
    assert_eq!(
        via(&fx, &full).await,
        Err("no_binding"),
        "nothing is picked on its own"
    );
    bind(&fx, a.id, ("workspace", "")).await;
    assert_eq!(via(&fx, &full).await, Ok((a.id, "workspace")));
    bind(&fx, b.id, ("project", "acme/app")).await;
    assert_eq!(via(&fx, &full).await, Ok((b.id, "project")));
    bind(&fx, c3.id, ("agent", "bot")).await;
    assert_eq!(via(&fx, &full).await, Ok((c3.id, "agent")));
    bind(&fx, c4.id, ("session", "s1")).await;
    assert_eq!(via(&fx, &full).await, Ok((c4.id, "session")));
    // Another session, project or agent does not see these.
    let other = Context {
        agent: Some("x"),
        project: Some("y"),
        session: Some("s2"),
        ..cx("read_items")
    };
    assert_eq!(via(&fx, &other).await, Ok((a.id, "workspace")));
    let proj = Context {
        project: Some("acme/app"),
        ..cx("read_items")
    };
    assert_eq!(via(&fx, &proj).await, Ok((b.id, "project")));
    // Replacing a binding changes who is picked; clearing it falls to the next level.
    bind(&fx, a.id, ("session", "s1")).await;
    assert_eq!(via(&fx, &full).await, Ok((a.id, "session")));
    assert!(
        bindings::clear(&fx.pool, 1, "fake", ("session", "s1"), w(NOW))
            .await
            .unwrap()
    );
    assert_eq!(via(&fx, &full).await, Ok((c3.id, "agent")));
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_connection_bindings WHERE scope_kind = 'session'",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn the_most_specific_binding_decides_and_never_falls_through() {
    let (fx, a, b) = setup().await;
    bind(&fx, a.id, ("workspace", "")).await;
    bind(&fx, b.id, ("agent", "bot")).await;
    let cx = Context {
        agent: Some("bot"),
        ..cx("read_items")
    };
    assert_eq!(via(&fx, &cx).await, Ok((b.id, "agent")));
    set_disabled(&fx.pool, b.id, true, w(NOW)).await.unwrap();
    let err = resolve::resolve(&fx.pool, &fx.reg, "fake", &cx, NOW)
        .await
        .unwrap_err();
    assert!(
        err.to_string().starts_with("disabled:") && err.to_string().contains("chosen by agent"),
        "{err}"
    );
    grants::revoke(&fx.pool, b.id, ("role", "member"), w(NOW))
        .await
        .unwrap();
    set_disabled(&fx.pool, b.id, false, w(NOW)).await.unwrap();
    assert_eq!(
        via(&fx, &cx).await,
        Err("not_granted"),
        "still not the workspace default"
    );
}

#[tokio::test]
async fn use_needs_a_grant_that_covers_the_capability_and_the_resource() {
    let (fx, a, _) = setup().await;
    bind(&fx, a.id, ("workspace", "")).await;
    let ok = cx("read_items");
    assert!(via(&fx, &ok).await.is_ok());
    assert_eq!(
        via(&fx, &cx("write_items")).await,
        Err("capability_missing"),
        "read-only by default"
    );
    assert_eq!(via(&fx, &cx("nope")).await, Err("capability_unknown"));
    // A user, a role that is not the caller's, another user.
    assert_eq!(
        via(
            &fx,
            &Context {
                role: "admin",
                ..ok
            }
        )
        .await,
        Err("not_granted"),
        "an admin needs a grant too"
    );
    assert_eq!(
        via(&fx, &Context { user: 7, ..ok }).await.map(drop),
        Ok(()),
        "the role grant covers any member"
    );
    grants::revoke(&fx.pool, a.id, ("role", "member"), w(NOW))
        .await
        .unwrap();
    assert_eq!(via(&fx, &ok).await, Err("not_granted"));
    // A user grant, a write capability, resource limits.
    let caps = ["read_items".to_owned(), "write_items".to_owned()];
    let lim = grants::Limits::from([(
        "projects".to_owned(),
        vec!["P1".to_owned(), "acme/*".to_owned()],
    )]);
    let new = grants::NewGrant {
        grantee_kind: "user",
        grantee: "1",
        capabilities: Some(&caps),
        limits: &lim,
    };
    grants::set(&fx.pool, &fx.reg, a.id, &new, w(NOW))
        .await
        .unwrap();
    let wr = cx("write_items");
    assert_eq!(via(&fx, &wr).await, Err("resource_required"));
    for (res, want) in [
        (("projects", "P1"), true),
        (("projects", "acme/app"), true),
        (("projects", "P2"), false),
        (("projects", "acme2/app"), false),
        (("other", "P1"), false),
    ] {
        let c = Context {
            resource: Some(res),
            ..wr
        };
        let got = via(&fx, &c).await;
        match want {
            true => assert!(got.is_ok(), "{res:?}"),
            false => assert!(
                matches!(got, Err("resource_denied" | "bad_request")),
                "{res:?} {got:?}"
            ),
        }
    }
    let bad = Context {
        resource: Some(("projects", "*")),
        ..wr
    };
    assert_eq!(
        via(&fx, &bad).await,
        Err("bad_request"),
        "a use names a concrete resource"
    );
}

#[tokio::test]
async fn an_agent_grant_adds_to_the_users_and_the_session_allowlist_narrows() {
    let (fx, a, _) = setup().await;
    bind(&fx, a.id, ("workspace", "")).await;
    let caps = ["read_items".to_owned(), "write_items".to_owned()];
    let lim = grants::Limits::new();
    let new = grants::NewGrant {
        grantee_kind: "agent",
        grantee: "bot",
        capabilities: Some(&caps),
        limits: &lim,
    };
    grants::set(&fx.pool, &fx.reg, a.id, &new, w(NOW))
        .await
        .unwrap();
    let bot = Context {
        agent: Some("bot"),
        ..cx("write_items")
    };
    assert!(via(&fx, &bot).await.is_ok());
    assert_eq!(
        via(
            &fx,
            &Context {
                agent: Some("other"),
                ..bot
            }
        )
        .await,
        Err("capability_missing")
    );
    let only_read = ["read_items".to_owned()];
    let narrowed = Context {
        allowlist: Some(&only_read),
        ..bot
    };
    assert_eq!(via(&fx, &narrowed).await, Err("not_allowlisted"));
    assert!(
        via(
            &fx,
            &Context {
                allowlist: Some(&only_read),
                capability: "read_items",
                ..bot
            }
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn another_workspace_and_another_kind_are_refused() {
    let (fx, a, _) = setup().await;
    let o = make(&fx, "other", "o").await;
    grant_role(&fx, o.id, "member", None).await;
    bind(&fx, a.id, ("workspace", "")).await;
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(&fx.pool)
        .await
        .unwrap();
    let theirs = Context {
        workspace: 2,
        ..cx("read_items")
    };
    assert_eq!(
        via(&fx, &theirs).await,
        Err("no_binding"),
        "their bindings are their own"
    );
    let pick = Context {
        pick: Some(a.id),
        ..theirs
    };
    assert_eq!(
        via(&fx, &pick).await,
        Err("not_found"),
        "and so are their connections"
    );
    let wrong_kind = Context {
        pick: Some(o.id),
        ..cx("read_items")
    };
    assert_eq!(via(&fx, &wrong_kind).await, Err("not_found"));
    let explicit = Context {
        pick: Some(a.id),
        ..cx("read_items")
    };
    assert_eq!(via(&fx, &explicit).await, Ok((a.id, "explicit")));
    assert_eq!(
        code(bindings::set(&fx.pool, 2, a.id, ("workspace", ""), w(NOW)).await),
        "not_found"
    );
    bind(&fx, o.id, ("workspace", "")).await;
    assert_eq!(
        via(&fx, &cx("read_items")).await,
        Ok((a.id, "workspace")),
        "bindings are per kind"
    );
}

#[tokio::test]
async fn health_gates_use_and_a_timed_state_recovers_by_itself() {
    let (fx, a, _) = setup().await;
    bind(&fx, a.id, ("workspace", "")).await;
    let limited = health::Signal::Upstream {
        status: ainkrad_proto::v2::UpstreamStatus::RateLimited,
        retry_after: Some(120),
        reset_at: None,
    };
    health::signal(&fx.pool, a.id, limited, NOW).await.unwrap();
    let r = resolve::resolve(&fx.pool, &fx.reg, "fake", &cx("read_items"), &at(30)).await;
    assert_eq!(code(r), "unhealthy");
    let r = resolve::resolve(&fx.pool, &fx.reg, "fake", &cx("read_items"), &at(121)).await;
    assert_eq!(r.unwrap().connection.status, "active");
}

#[tokio::test]
async fn every_use_is_a_record_with_no_payload() {
    let (fx, a, _) = setup().await;
    let c = cx("read_items");
    resolve::record_use(
        &fx.pool,
        Some(a.id),
        "fake",
        ("fake.get_item", "ok", None),
        &c,
    )
    .await
    .unwrap();
    resolve::record_use(
        &fx.pool,
        None,
        "fake",
        ("fake.get_item", "refused", Some("not_granted")),
        &c,
    )
    .await
    .unwrap();
    for bad in [
        ("fake.get_item", "ok", Some("a payload {with} text")),
        ("Fake Get Item", "ok", None),
        ("fake.get_item", "maybe", None),
    ] {
        assert_eq!(
            code(resolve::record_use(&fx.pool, Some(a.id), "fake", bad, &c).await),
            "bad_request"
        );
    }
    let rows: Vec<(Option<i64>, String)> = sqlx::query_as(
        "SELECT entity_id, details FROM audit_events WHERE action = 'connection.used' ORDER BY seq",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, Some(a.id));
    assert_eq!(rows[1].0, None);
    assert!(
        rows[1].1.contains(r#""code":"not_granted""#) && rows[0].1.contains(r#""result":"ok""#),
        "{rows:?}"
    );
}

#[tokio::test]
async fn concurrent_writers_of_one_default_end_with_one_row() {
    let (fx, _, _) = setup().await;
    let mut ids = Vec::new();
    for i in 0..8 {
        ids.push(make(&fx, "fake", &format!("n{i}")).await.id);
    }
    let sets = ids
        .iter()
        .map(|id| bindings::set(&fx.pool, 1, *id, ("workspace", ""), w(NOW)));
    for r in futures_util::future::join_all(sets).await {
        r.unwrap();
    }
    let rows = bindings::list(&fx.pool, 1, Some("fake")).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(ids.contains(&rows[0].connection_id));
    // Concurrent creates of one name: exactly one wins, the rest are conflicts.
    let new = NewConnection {
        user_id: 1,
        kind: "other",
        name: "same",
        label: "x",
        auth_method: "token",
    };
    let m = material(SECRET);
    let makes = (0..6).map(|_| create(&fx.pool, &fx.sealer, &fx.reg, &new, &m, w(NOW)));
    let results = futures_util::future::join_all(makes).await;
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results
            .into_iter()
            .filter_map(Result::err)
            .all(|e| e.to_string().starts_with("conflict:"))
    );
    // And of one grant: one row.
    let none = grants::Limits::new();
    let a = ids[0];
    let gs = (0..6).map(|_| {
        let new = grants::NewGrant {
            grantee_kind: "agent",
            grantee: "bot",
            capabilities: None,
            limits: &none,
        };
        let (pool, reg) = (&fx.pool, &fx.reg);
        async move { grants::set(pool, reg, a, &new, w(NOW)).await }
    });
    for r in futures_util::future::join_all(gs).await {
        r.unwrap();
    }
    assert_eq!(grants::list(&fx.pool, a).await.unwrap().len(), 1);
}

#[tokio::test]
async fn bindings_are_validated_and_limited_per_user() {
    let (fx, a, _) = setup().await;
    for scope in [
        ("workspace", "x"),
        ("project", ""),
        ("agent", "bad agent"),
        ("galaxy", "x"),
        ("session", "*"),
    ] {
        assert_eq!(
            code(bindings::set(&fx.pool, 1, a.id, scope, w(NOW)).await),
            "bad_request",
            "{scope:?}"
        );
    }
    assert_eq!(
        code(bindings::set(&fx.pool, 1, 999, ("workspace", ""), w(NOW)).await),
        "not_found"
    );
    for i in 0..MAX_BINDINGS {
        bind(&fx, a.id, ("project", &format!("p{i}"))).await;
    }
    assert_eq!(
        code(bindings::set(&fx.pool, 1, a.id, ("project", "one-more"), w(NOW)).await),
        "limit_reached"
    );
    bind(&fx, a.id, ("project", "p0")).await;
    assert!(
        !bindings::clear(&fx.pool, 1, "fake", ("project", "nope"), w(NOW))
            .await
            .unwrap()
    );
}
