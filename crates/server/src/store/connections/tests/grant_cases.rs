use std::collections::BTreeMap;

use super::*;

fn limits(key: &str, values: &[&str]) -> grants::Limits {
    BTreeMap::from([(
        key.to_owned(),
        values.iter().map(|v| (*v).to_owned()).collect(),
    )])
}

async fn grant(
    fx: &Fx,
    id: i64,
    kind: &str,
    who_: &str,
    caps: Option<&[String]>,
    l: &grants::Limits,
) -> Result<grants::Grant, crate::store::secrets::Error> {
    let new = grants::NewGrant {
        grantee_kind: kind,
        grantee: who_,
        capabilities: caps,
        limits: l,
    };
    grants::set(&fx.pool, &fx.reg, id, &new, w(NOW)).await
}

#[tokio::test]
async fn a_grant_is_read_only_unless_it_names_write() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let none = grants::Limits::new();
    let g = grant(&fx, c.id, "role", "member", None, &none)
        .await
        .unwrap();
    assert_eq!(g.capabilities, ["read_items"]);
    let both = ["read_items".to_owned(), "write_items".to_owned()];
    let g = grant(&fx, c.id, "user", "1", Some(&both), &none)
        .await
        .unwrap();
    assert_eq!(g.capabilities, both);
    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'connection.granted' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert!(details.contains(r#""writes":["write_items"]"#), "{details}");
}

#[tokio::test]
async fn grants_are_validated() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let none = grants::Limits::new();
    let bogus = ["nope".to_owned()];
    let empty: [String; 0] = [];
    for (kind, g, caps, l, label) in [
        ("role", "owner", None, none.clone(), "unknown role"),
        ("user", "2", None, none.clone(), "no such user"),
        ("user", "x", None, none.clone(), "not an id"),
        ("agent", "bad agent", None, none.clone(), "agent id"),
        ("team", "x", None, none.clone(), "grantee kind"),
        (
            "role",
            "member",
            Some(&bogus[..]),
            none.clone(),
            "unknown capability",
        ),
        (
            "role",
            "member",
            Some(&empty[..]),
            none.clone(),
            "no capability",
        ),
        (
            "role",
            "member",
            None,
            limits("repos", &["a/b"]),
            "limit key of another kind",
        ),
        (
            "role",
            "member",
            None,
            limits("projects", &[]),
            "empty limit",
        ),
        (
            "role",
            "member",
            None,
            limits("projects", &["a b"]),
            "bad value",
        ),
        (
            "role",
            "member",
            None,
            limits("projects", &["*"]),
            "bare wildcard",
        ),
        (
            "role",
            "member",
            None,
            limits("projects", &["/*"]),
            "empty prefix",
        ),
    ] {
        assert_eq!(
            code(grant(&fx, c.id, kind, g, caps, &l).await),
            "bad_request",
            "{label}"
        );
    }
    assert_eq!(
        code(grant(&fx, 999, "role", "member", None, &none).await),
        "not_found"
    );
    assert!(grants::list(&fx.pool, c.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn one_grant_per_grantee_replaced_in_place_and_revocable() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let none = grants::Limits::new();
    let first = grant(&fx, c.id, "agent", "bot", None, &none).await.unwrap();
    let both = ["read_items".to_owned(), "write_items".to_owned()];
    let second = grant(
        &fx,
        c.id,
        "agent",
        "bot",
        Some(&both),
        &limits("projects", &["P1", "acme/*"]),
    )
    .await
    .unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(grants::list(&fx.pool, c.id).await.unwrap(), [second]);
    assert!(
        grants::revoke(&fx.pool, c.id, ("agent", "bot"), w(NOW))
            .await
            .unwrap()
    );
    assert!(
        !grants::revoke(&fx.pool, c.id, ("agent", "bot"), w(NOW))
            .await
            .unwrap(),
        "idempotent"
    );
    assert_eq!(
        actions(&fx)
            .await
            .iter()
            .filter(|a| *a == "connection.grant_revoked")
            .count(),
        1
    );
}

#[tokio::test]
async fn grants_per_connection_are_limited() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let none = grants::Limits::new();
    for i in 0..MAX_GRANTS {
        grant(&fx, c.id, "agent", &format!("bot{i}"), None, &none)
            .await
            .unwrap();
    }
    assert_eq!(
        code(grant(&fx, c.id, "agent", "one-more", None, &none).await),
        "limit_reached"
    );
    grant(&fx, c.id, "agent", "bot0", None, &none)
        .await
        .unwrap();
}

#[test]
fn limit_values_match_exactly_or_under_a_prefix() {
    let l = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert!(grants::value_matches(&l(&["a/b"]), "a/b"));
    assert!(!grants::value_matches(&l(&["a/b"]), "a/bc"));
    assert!(grants::value_matches(&l(&["acme/*"]), "acme/repo"));
    assert!(!grants::value_matches(&l(&["acme/*"]), "acme2/repo"));
    assert!(!grants::value_matches(&l(&["acme/*"]), "acme/"));
    assert!(!grants::value_matches(&l(&["acme/*"]), "acme"));
}
