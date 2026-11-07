//! Effective limits of a resolved use, and self-limited operations.

use super::*;

fn lim(v: &[&str]) -> grants::Limits {
    grants::Limits::from([(
        "projects".to_owned(),
        v.iter().map(|s| (*s).to_owned()).collect(),
    )])
}

async fn user_grant(fx: &Fx, id: i64, limits: &grants::Limits) {
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
    user_grant(&fx, c.id, &none).await;
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
    user_grant(&fx, c.id, &lim(&["P2", "acme/*", "P9"])).await;
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
    user_grant(&fx, c.id, &lim(&["P1"])).await;
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
    user_grant(&fx, c.id, &lim(&["P1", "P2"])).await;
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
