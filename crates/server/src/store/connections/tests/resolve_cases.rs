use super::*;

fn lim(v: &[&str]) -> grants::Limits {
    grants::Limits::from([(
        "projects".to_owned(),
        v.iter().map(|s| (*s).to_owned()).collect(),
    )])
}

/// Grants `member` read on `id`, limited to `projects` (empty: unlimited).
async fn grant_limited(fx: &Fx, id: i64, projects: &[&str]) {
    let limits = if projects.is_empty() {
        grants::Limits::new()
    } else {
        lim(projects)
    };
    let new = grants::NewGrant {
        grantee_kind: "role",
        grantee: "member",
        capabilities: None,
        limits: &limits,
    };
    grants::set(&fx.pool, &fx.reg, id, &new, w(NOW))
        .await
        .unwrap();
}

/// Two fake connections, `work` (id order first) and `personal`.
async fn two() -> (Fx, Connection, Connection) {
    let fx = fx().await;
    let (a, b) = (
        make(&fx, "fake", "work").await,
        make(&fx, "fake", "personal").await,
    );
    (fx, a, b)
}

async fn via(fx: &Fx, c: &Context<'_>) -> Result<(i64, &'static str), &'static str> {
    match resolve::resolve(&fx.pool, &fx.reg, "fake", c, NOW).await {
        Ok(r) => Ok((r.connection.id, r.via)),
        Err(e) => Err(code::<()>(Err(e))),
    }
}

fn on(project: &str) -> Context<'_> {
    Context {
        resource: Some(("projects", project)),
        ..cx("read_items")
    }
}

#[tokio::test]
async fn a_use_goes_to_the_connection_whose_limits_cover_the_resource() {
    let (fx, a, b) = two().await;
    grant_limited(&fx, a.id, &["P1", "acme/*"]).await;
    grant_limited(&fx, b.id, &["P2"]).await;
    assert_eq!(via(&fx, &on("P1")).await, Ok((a.id, "only")));
    assert_eq!(via(&fx, &on("acme/app")).await, Ok((a.id, "only")));
    assert_eq!(via(&fx, &on("P2")).await, Ok((b.id, "only")));
    assert_eq!(
        via(&fx, &on("P3")).await,
        Err("resource_denied"),
        "none covers it"
    );
    assert_eq!(
        via(&fx, &cx("read_items")).await,
        Err("resource_required"),
        "every grant is limited"
    );
    // Nothing in the context names a connection: a session, an agent's id and a role change nothing here.
    let s = Context {
        session: Some("s1"),
        ..on("P2")
    };
    assert_eq!(via(&fx, &s).await, Ok((b.id, "only")));
}

#[tokio::test]
async fn several_that_cover_it_resolve_to_the_default_or_are_ambiguous() {
    let (fx, a, b) = two().await;
    let c = make(&fx, "fake", "narrow").await;
    for id in [a.id, b.id] {
        grant_limited(&fx, id, &[]).await;
    }
    grant_limited(&fx, c.id, &["P9"]).await;
    let r = resolve::resolve(&fx.pool, &fx.reg, "fake", &on("P1"), NOW)
        .await
        .unwrap_err();
    assert!(
        r.to_string().starts_with("ambiguous:")
            && r.to_string().contains("work")
            && r.to_string().contains("personal"),
        "{r}"
    );
    assert!(
        !r.to_string().contains("narrow"),
        "only those that cover it are named"
    );
    bind(&fx, b.id, ("workspace", "")).await;
    assert_eq!(
        via(&fx, &on("P1")).await,
        Ok((b.id, "default")),
        "the default wins among several"
    );
    assert_eq!(
        via(&fx, &on("P9")).await,
        Ok((b.id, "default")),
        "among a, b and narrow"
    );
    // A default that does not cover the use is no tie-breaker.
    bind(&fx, c.id, ("workspace", "")).await;
    assert_eq!(via(&fx, &on("P1")).await, Err("ambiguous"));
    assert_eq!(via(&fx, &on("P9")).await, Ok((c.id, "default")));
    // Without a default (cleared), several is ambiguous again; a lone cover needs no default.
    assert!(
        bindings::clear(&fx.pool, "fake", ("workspace", ""), w(NOW))
            .await
            .unwrap()
    );
    assert_eq!(via(&fx, &on("P9")).await, Err("ambiguous"));
    // The default is per kind.
    let o = make(&fx, "other", "o").await;
    grant_role(&fx, o.id, "member", None).await;
    bind(&fx, o.id, ("workspace", "")).await;
    assert_eq!(via(&fx, &on("P1")).await, Err("ambiguous"));
    // Project, agent and session bindings route nothing.
    for scope in [("project", "P1"), ("agent", "bot"), ("session", "s1")] {
        bind(&fx, a.id, scope).await;
    }
    let ctx = Context {
        session: Some("s1"),
        ..on("P1")
    };
    assert_eq!(via(&fx, &ctx).await, Err("ambiguous"));
}

#[tokio::test]
async fn an_ungranted_connection_is_never_a_candidate_and_never_described() {
    let (fx, a, b) = two().await;
    grant_limited(&fx, a.id, &[]).await;
    set_disabled(&fx.pool, b.id, true, w(NOW)).await.unwrap();
    assert_eq!(
        via(&fx, &cx("read_items")).await,
        Ok((a.id, "only")),
        "b is not granted, so it is not even ambiguous"
    );
    grants::revoke(&fx.pool, a.id, ("role", "member"), w(NOW))
        .await
        .unwrap();
    // Nothing granted: not_granted, never `disabled` (that would describe b).
    assert_eq!(via(&fx, &cx("read_items")).await, Err("not_granted"));
    let nobody = Context {
        role: "admin",
        ..cx("read_items")
    };
    assert_eq!(
        via(&fx, &nobody).await,
        Err("not_granted"),
        "an admin needs a grant too"
    );
    // Another capability, user and the kind's absence.
    grant_limited(&fx, a.id, &[]).await;
    assert_eq!(
        via(&fx, &cx("write_items")).await,
        Err("capability_missing")
    );
    assert_eq!(
        via(
            &fx,
            &Context {
                user: 7,
                ..cx("read_items")
            }
        )
        .await,
        Err("not_a_member"),
        "a role grant covers members of the workspace, not any caller"
    );
    let r = resolve::resolve(&fx.pool, &fx.reg, "other", &cx("read_things"), NOW).await;
    assert_eq!(code(r), "no_connection");
    assert_eq!(
        code(resolve::resolve(&fx.pool, &fx.reg, "nope", &cx("x"), NOW).await),
        "unknown_kind"
    );
    assert_eq!(via(&fx, &cx("nope")).await, Err("capability_unknown"));
    let bad = Context {
        resource: Some(("projects", "a/../b")),
        ..cx("read_items")
    };
    assert_eq!(via(&fx, &bad).await, Err("bad_request"));
    let other_key = Context {
        resource: Some(("repos", "x")),
        ..cx("read_items")
    };
    assert_eq!(via(&fx, &other_key).await, Err("bad_request"));
}

#[tokio::test]
async fn another_workspaces_connections_are_invisible() {
    let (fx, a, _) = two().await;
    grant_limited(&fx, a.id, &[]).await;
    second_user(&fx).await;
    let theirs = Context {
        workspace: 2,
        user: 2,
        ..cx("read_items")
    };
    assert_eq!(via(&fx, &theirs).await, Err("no_connection"));
    assert_eq!(via(&fx, &cx("read_items")).await, Ok((a.id, "only")));
    assert_eq!(
        code(bindings::set(&fx.pool, a.id, ("workspace", ""), ww(2, NOW)).await),
        "not_found"
    );
}

#[tokio::test]
async fn disabled_and_unhealthy_connections_are_not_candidates() {
    let (fx, a, b) = two().await;
    for id in [a.id, b.id] {
        grant_limited(&fx, id, &[]).await;
    }
    assert_eq!(via(&fx, &on("P1")).await, Err("ambiguous"));
    set_disabled(&fx.pool, a.id, true, w(NOW)).await.unwrap();
    assert_eq!(
        via(&fx, &on("P1")).await,
        Ok((b.id, "only")),
        "the disabled one drops out"
    );
    set_disabled(&fx.pool, b.id, true, w(NOW)).await.unwrap();
    assert_eq!(
        via(&fx, &on("P1")).await,
        Err("disabled"),
        "every cover is unusable: say why"
    );
    set_disabled(&fx.pool, a.id, false, w(NOW)).await.unwrap();
    // A cooling one is out until its window ends, then back (lazily).
    let limited = health::Signal::Upstream {
        status: ainkrad_proto::v2::UpstreamStatus::RateLimited,
        retry_after: Some(120),
        reset_at: None,
    };
    health::signal(&fx.pool, 1, a.id, limited, NOW)
        .await
        .unwrap();
    assert_eq!(
        code(resolve::resolve(&fx.pool, &fx.reg, "fake", &on("P1"), &at(30)).await),
        "unhealthy"
    );
    let r = resolve::resolve(&fx.pool, &fx.reg, "fake", &on("P1"), &at(121))
        .await
        .unwrap();
    assert_eq!(r.connection.id, a.id);
    // An auth failure awaiting a test is out too.
    set_disabled(&fx.pool, b.id, false, w(NOW)).await.unwrap();
    health::signal(
        &fx.pool,
        1,
        b.id,
        health::Signal::Upstream {
            status: ainkrad_proto::v2::UpstreamStatus::AuthFailed,
            retry_after: None,
            reset_at: None,
        },
        &at(200),
    )
    .await
    .unwrap();
    let auth = health::Signal::Upstream {
        status: ainkrad_proto::v2::UpstreamStatus::AuthFailed,
        retry_after: None,
        reset_at: None,
    };
    health::signal(&fx.pool, 1, a.id, auth, &at(200))
        .await
        .unwrap();
    assert_eq!(
        code(resolve::resolve(&fx.pool, &fx.reg, "fake", &on("P1"), &at(201)).await),
        "auth_pending"
    );
}

#[tokio::test]
async fn an_agent_grant_only_narrows_and_a_session_with_an_agent_needs_an_allowlist() {
    let fx = fx().await;
    let a = make(&fx, "fake", "work").await;
    bind(&fx, a.id, ("workspace", "")).await;
    let none = grants::Limits::new();
    let lim = |v: &[&str]| {
        grants::Limits::from([(
            "projects".to_owned(),
            v.iter().map(|s| (*s).to_owned()).collect(),
        )])
    };
    grant_role(&fx, a.id, "member", None).await; // the user side: read only
    grant_agent(&fx, a.id, "bot", Some(&ALL_CAPS), &none).await;
    let bot = |cap| Context {
        agent: Some("bot"),
        allowlist: Some(ALL_CAPS.as_slice()),
        ..cx(cap)
    };
    assert!(via(&fx, &bot("read_items")).await.is_ok());
    assert_eq!(
        via(&fx, &bot("write_items")).await,
        Err("capability_missing"),
        "an agent grant never widens the user's"
    );
    // The user may write: the agent may now too; another agent has no grant, so it may not.
    let user = grants::NewGrant {
        grantee_kind: "user",
        grantee: "1",
        capabilities: Some(&ALL_CAPS),
        limits: &none,
    };
    grants::set(&fx.pool, &fx.reg, a.id, &user, w(NOW))
        .await
        .unwrap();
    assert!(via(&fx, &bot("write_items")).await.is_ok());
    let other = Context {
        agent: Some("other"),
        ..bot("read_items")
    };
    assert_eq!(via(&fx, &other).await, Err("not_granted"));
    // The agent's grant narrows caps and resources; a name is not an identity.
    let read = ["read_items".to_owned()];
    grant_agent(&fx, a.id, "bot", Some(&read), &lim(&["P1"])).await;
    assert_eq!(
        via(&fx, &bot("write_items")).await,
        Err("capability_missing"),
        "the agent's own grant lacks write"
    );
    let on = |p| Context {
        resource: Some(("projects", p)),
        ..bot("read_items")
    };
    assert!(via(&fx, &on("P1")).await.is_ok());
    assert_eq!(via(&fx, &on("P2")).await, Err("resource_denied"));
    assert_eq!(via(&fx, &bot("read_items")).await, Err("resource_required"));
    // An agent grant alone grants nothing.
    grants::revoke(&fx.pool, a.id, ("role", "member"), w(NOW))
        .await
        .unwrap();
    grants::revoke(&fx.pool, a.id, ("user", "1"), w(NOW))
        .await
        .unwrap();
    grant_agent(&fx, a.id, "bot", Some(&ALL_CAPS), &none).await;
    assert_eq!(via(&fx, &bot("read_items")).await, Err("not_granted"));
    // A session with an agent but no allowlist is refused; the allowlist narrows.
    grant_role(&fx, a.id, "member", None).await;
    let open = Context {
        allowlist: None,
        ..bot("read_items")
    };
    assert_eq!(via(&fx, &open).await, Err("allowlist_required"));
    let only_write = ["write_items".to_owned()];
    let narrowed = Context {
        allowlist: Some(&only_write),
        ..bot("read_items")
    };
    assert_eq!(via(&fx, &narrowed).await, Err("not_allowlisted"));
    // A session without an agent is the user's own use: no allowlist needed.
    assert!(via(&fx, &cx("read_items")).await.is_ok());
}

#[tokio::test]
async fn every_use_is_a_record_with_no_payload() {
    let (fx, a, _) = two().await;
    let c = cx("read_items");
    resolve::record_use(
        &fx.pool,
        &fx.reg,
        Some(a.id),
        "fake",
        ("fake.get_item", "ok", None),
        &c,
    )
    .await
    .unwrap();
    resolve::record_use(
        &fx.pool,
        &fx.reg,
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
            code(resolve::record_use(&fx.pool, &fx.reg, Some(a.id), "fake", bad, &c).await),
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
    let (fx, _, _) = two().await;
    let mut ids = Vec::new();
    for i in 0..8 {
        ids.push(make(&fx, "fake", &format!("n{i}")).await.id);
    }
    let sets = ids
        .iter()
        .map(|id| bindings::set(&fx.pool, *id, ("workspace", ""), w(NOW)));
    for r in futures_util::future::join_all(sets).await {
        r.unwrap();
    }
    let rows = bindings::list(&fx.pool, 1, Some("fake")).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(ids.contains(&rows[0].connection_id));
    // Concurrent creates of one name: exactly one wins, the rest are conflicts.
    let new = NewConnection {
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
    assert_eq!(grants::list(&fx.pool, 1, a).await.unwrap().len(), 1);
}

#[tokio::test]
async fn bindings_are_validated_and_limited_per_user() {
    let (fx, a, _) = two().await;
    for scope in [
        ("workspace", "x"),
        ("project", ""),
        ("agent", "bad agent"),
        ("galaxy", "x"),
        ("session", "*"),
    ] {
        assert_eq!(
            code(bindings::set(&fx.pool, a.id, scope, w(NOW)).await),
            "bad_request",
            "{scope:?}"
        );
    }
    assert_eq!(
        code(bindings::set(&fx.pool, 999, ("workspace", ""), w(NOW)).await),
        "not_found"
    );
    for i in 0..MAX_BINDINGS {
        bind(&fx, a.id, ("project", &format!("p{i}"))).await;
    }
    assert_eq!(
        code(bindings::set(&fx.pool, a.id, ("project", "one-more"), w(NOW)).await),
        "limit_reached"
    );
    bind(&fx, a.id, ("project", "p0")).await;
    assert!(
        !bindings::clear(&fx.pool, "fake", ("project", "nope"), w(NOW))
            .await
            .unwrap()
    );
}
