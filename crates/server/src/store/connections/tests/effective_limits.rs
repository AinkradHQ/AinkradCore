//! Effective limits of a resolved use, and self-limited operations.

use super::*;

fn lim(v: &[&str]) -> grants::Limits {
    grants::Limits::from([(
        "projects".to_owned(),
        v.iter().map(|s| (*s).to_owned()).collect(),
    )])
}

async fn role_grant(fx: &Fx, id: i64, limits: &grants::Limits) {
    let new = grants::NewGrant {
        grantee_kind: "role",
        grantee: "member",
        capabilities: None,
        limits,
    };
    grants::set(&fx.pool, &fx.reg, id, &new, w(NOW))
        .await
        .unwrap();
}

fn agent_cx(operation: Option<&'static str>) -> Context<'static> {
    Context {
        agent: Some("bot"),
        allowlist: Some(ALL_CAPS.as_slice()),
        operation,
        ..cx("read_items")
    }
}

async fn resolved(fx: &Fx, c: &Context<'_>) -> Result<resolve::Resolved, &'static str> {
    resolve::resolve(&fx.pool, &fx.reg, "fake", c, NOW)
        .await
        .map_err(|e| code::<()>(Err(e)))
}

#[tokio::test]
async fn the_effective_limits_are_the_users_intersected_with_the_agents() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let none = grants::Limits::new();
    // Unlimited user grant, limited agent grant: the agent narrows it.
    role_grant(&fx, c.id, &none).await;
    grant_agent(&fx, c.id, "bot", None, &lim(&["P1"])).await;
    let at = Context {
        resource: Some(("projects", "P1")),
        ..agent_cx(None)
    };
    assert_eq!(resolved(&fx, &at).await.unwrap().limits, lim(&["P1"]));
    let out = Context {
        resource: Some(("projects", "P2")),
        ..agent_cx(None)
    };
    assert_eq!(resolved(&fx, &out).await.unwrap_err(), "resource_denied");
    // Without an agent the user's own (unlimited) grant stands.
    assert!(
        resolved(&fx, &cx("read_items"))
            .await
            .unwrap()
            .limits
            .is_empty()
    );
    // Both limited: values stay where the other side covers them (exactly or under `prefix/*`).
    role_grant(&fx, c.id, &lim(&["P2", "acme/*", "P9"])).await;
    grant_agent(
        &fx,
        c.id,
        "bot",
        None,
        &lim(&["P2", "acme/app", "P3", "P9"]),
    )
    .await;
    let at = Context {
        resource: Some(("projects", "acme/app")),
        ..agent_cx(None)
    };
    let r = resolved(&fx, &at).await.unwrap();
    assert_eq!(r.limits, lim(&["P2", "P9", "acme/app"]));
    // Disjoint sides allow nothing: the key stays, empty, and every resource is refused.
    role_grant(&fx, c.id, &lim(&["P1"])).await;
    grant_agent(&fx, c.id, "bot", None, &lim(&["P2"])).await;
    let at = Context {
        resource: Some(("projects", "P1")),
        ..agent_cx(None)
    };
    assert_eq!(resolved(&fx, &at).await.unwrap_err(), "resource_denied");
}

#[tokio::test]
async fn a_self_limited_operation_may_omit_the_resource_and_gets_the_effective_limits() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    role_grant(&fx, c.id, &lim(&["P1", "P2"])).await;
    // An ordinary operation under a limited grant still needs a resource.
    let get = Context {
        operation: Some("fake.get_item"),
        ..cx("read_items")
    };
    assert_eq!(resolved(&fx, &get).await.unwrap_err(), "resource_required");
    let none = Context {
        operation: None,
        ..cx("read_items")
    };
    assert_eq!(resolved(&fx, &none).await.unwrap_err(), "resource_required");
    // The self-limited one does not, and is handed the limits to enforce.
    let list = Context {
        operation: Some("fake.list_items"),
        ..cx("read_items")
    };
    assert_eq!(
        resolved(&fx, &list).await.unwrap().limits,
        lim(&["P1", "P2"])
    );
    // With a resource the ordinary check still applies to it.
    let out = Context {
        resource: Some(("projects", "P3")),
        ..list
    };
    assert_eq!(resolved(&fx, &out).await.unwrap_err(), "resource_denied");
    // An agent narrows what a self-limited call is handed.
    grant_agent(&fx, c.id, "bot", None, &lim(&["P2", "P7"])).await;
    let r = resolved(&fx, &agent_cx(Some("fake.list_items")))
        .await
        .unwrap();
    assert_eq!(r.limits, lim(&["P2"]));
    assert_eq!(
        resolved(&fx, &agent_cx(Some("fake.get_item")))
            .await
            .unwrap_err(),
        "resource_required"
    );
    // An operation of another capability is refused.
    let wrong = Context {
        operation: Some("fake.create_item"),
        ..cx("read_items")
    };
    assert_eq!(resolved(&fx, &wrong).await.unwrap_err(), "bad_request");
}

#[test]
fn a_star_is_a_literal_and_only_a_trailing_slash_star_is_a_prefix() {
    let l = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert!(!grants::value_matches(&l(&["a/b"]), "*"));
    assert!(!grants::value_matches(&l(&["a*"]), "ab"));
    assert!(!grants::value_matches(&l(&["*"]), "anything"));
    assert!(!valid_ref("*") && !valid_ref("a/*"));
}

async fn user_one_grant(fx: &Fx, id: i64, limits: &grants::Limits) {
    let new = grants::NewGrant {
        grantee_kind: "user",
        grantee: "1",
        capabilities: None,
        limits,
    };
    grants::set(&fx.pool, &fx.reg, id, &new, w(NOW))
        .await
        .unwrap();
}

fn list_op() -> Context<'static> {
    Context {
        operation: Some("fake.list_items"),
        ..cx("read_items")
    }
}

#[tokio::test]
async fn routing_looks_at_the_limits_the_use_really_gets() {
    let fx = fx().await;
    let (a, b, c) = (
        make(&fx, "fake", "a").await,
        make(&fx, "fake", "b").await,
        make(&fx, "fake", "c").await,
    );
    // A (the default): the user may reach P1 but the agent only P2: nothing is left of it.
    role_grant(&fx, a.id, &lim(&["P1"])).await;
    grant_agent(&fx, a.id, "bot", None, &lim(&["P2"])).await;
    for id in [b.id, c.id] {
        role_grant(&fx, id, &lim(&["P2"])).await;
        grant_agent(&fx, id, "bot", None, &lim(&["P2"])).await;
    }
    bind(&fx, a.id, ("workspace", "")).await;
    bind(&fx, b.id, ("workspace", "")).await;
    let list = Context {
        operation: Some("fake.list_items"),
        ..agent_cx(None)
    };
    // The default is B: it wins, and A, which allows nothing, is no candidate.
    assert_eq!(
        resolved(&fx, &list).await.map(|r| (r.connection.id, r.via)),
        Ok((b.id, "default"))
    );
    // With A the default, B and C are the real candidates and neither is the default: ambiguous.
    bind(&fx, a.id, ("workspace", "")).await;
    assert_eq!(resolved(&fx, &list).await.unwrap_err(), "ambiguous");
    // Without the agent A is a candidate again, with its own limits.
    let r = resolved(&fx, &list_op())
        .await
        .map(|r| (r.connection.id, r.via));
    assert_eq!(
        r,
        Ok((a.id, "default")),
        "without the agent A is a candidate, and the default"
    );
    // Disjoint sides and no resource: nothing is left, and the refusal says so.
    delete_ids(&fx, &[b.id, c.id]).await;
    assert_eq!(resolved(&fx, &list).await.unwrap_err(), "resource_denied");
}

async fn delete_ids(fx: &Fx, ids: &[i64]) {
    for id in ids {
        delete(&fx.pool, *id, w(NOW)).await.unwrap();
    }
}

#[tokio::test]
async fn every_covering_user_and_role_grant_counts() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    role_grant(&fx, c.id, &lim(&["P1"])).await;
    user_one_grant(&fx, c.id, &lim(&["P2"])).await;
    // Without a resource a self-limited call is handed the union, whichever grant has the lower id.
    assert_eq!(
        resolved(&fx, &list_op()).await.unwrap().limits,
        lim(&["P1", "P2"])
    );
    // With one, only the grants that cover it count: here the user grant alone.
    let p2 = Context {
        resource: Some(("projects", "P2")),
        ..list_op()
    };
    assert_eq!(resolved(&fx, &p2).await.unwrap().limits, lim(&["P2"]));
    let p3 = Context {
        resource: Some(("projects", "P3")),
        ..list_op()
    };
    assert_eq!(resolved(&fx, &p3).await.unwrap_err(), "resource_denied");
    // An unlimited grant behind a limited one makes the use unlimited, in either order.
    role_grant(&fx, c.id, &grants::Limits::new()).await;
    assert!(resolved(&fx, &list_op()).await.unwrap().limits.is_empty());
    role_grant(&fx, c.id, &lim(&["P1"])).await;
    user_one_grant(&fx, c.id, &grants::Limits::new()).await;
    assert!(resolved(&fx, &list_op()).await.unwrap().limits.is_empty());
    // An agent still narrows the combined result.
    grant_agent(&fx, c.id, "bot", None, &lim(&["P7"])).await;
    let r = resolved(&fx, &agent_cx(Some("fake.list_items")))
        .await
        .unwrap();
    assert_eq!(r.limits, lim(&["P7"]));
}

#[tokio::test]
async fn two_prefixes_intersect_to_the_narrower_and_disjoint_sides_allow_nothing() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    role_grant(&fx, c.id, &lim(&["acme/*", "P1"])).await;
    grant_agent(&fx, c.id, "bot", None, &lim(&["acme/app/*", "P1"])).await;
    let r = resolved(&fx, &agent_cx(Some("fake.list_items")))
        .await
        .unwrap();
    assert_eq!(r.limits, lim(&["P1", "acme/app/*"]));
    let inside = Context {
        resource: Some(("projects", "acme/app/x")),
        ..agent_cx(None)
    };
    assert!(resolved(&fx, &inside).await.is_ok());
    let outside = Context {
        resource: Some(("projects", "acme/other")),
        ..agent_cx(None)
    };
    assert_eq!(
        resolved(&fx, &outside).await.unwrap_err(),
        "resource_denied"
    );
    // Disjoint values, self-limited, no resource: refused rather than handed an empty list.
    role_grant(&fx, c.id, &lim(&["P1"])).await;
    grant_agent(&fx, c.id, "bot", None, &lim(&["P2"])).await;
    let r = resolved(&fx, &agent_cx(Some("fake.list_items"))).await;
    assert_eq!(r.unwrap_err(), "resource_denied");
}
