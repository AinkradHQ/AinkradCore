//! Who may use a connection, the kind's default, and the session's `connection_access` (C5).

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;
use super::*;

const URI: &str = "/api/v1/connections";

#[tokio::test]
async fn a_grant_is_set_replaced_read_and_revoked() {
    let cx = cx().await;
    let id = cx.github("main").await;
    let grants = format!("{URI}/{id}/grants");
    let put = |b: Value| cx.admin(Method::PUT, &grants, b);
    // No capability named: the kind's read-only ones.
    let g = put(json!({"grantee_kind": "role", "grantee": "member"})).await;
    assert_eq!(g.0, StatusCode::OK, "{}", g.1);
    assert_eq!(
        (&g.1["capabilities"], &g.1["limits"]),
        (&json!(["read_repo"]), &json!({}))
    );
    // A write capability is there only because it is named; limits are kept as given.
    let body = json!({"grantee_kind": "user", "grantee": "1", "capabilities": ["read_repo", "pr_write"],
        "limits": {"repos": ["octo/app", "octo/*"]}});
    let g = put(body).await;
    assert_eq!(
        g.1["capabilities"],
        json!(["read_repo", "pr_write"]),
        "{}",
        g.1
    );
    assert_eq!(g.1["limits"], json!({"repos": ["octo/app", "octo/*"]}));
    // One grant per grantee: the same grantee is replaced.
    let g =
        put(json!({"grantee_kind": "user", "grantee": "1", "capabilities": ["read_repo"]})).await;
    assert_eq!(g.1["limits"], json!({}), "{}", g.1);
    let list = cx.ok(Method::GET, &grants, Value::Null).await;
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert_eq!(
        cx.ok(Method::GET, &format!("{URI}/{id}"), Value::Null)
            .await["grant_count"],
        2
    );
    // A grant that names a write capability is audited by name.
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'connection.granted' ORDER BY seq",
    )
    .fetch_all(&cx.fx.app.pool)
    .await
    .unwrap();
    assert!(rows[1].contains("\"writes\":[\"pr_write\"]"), "{}", rows[1]);
    // Revoke, then it is gone.
    let del =
        |k: &str, g: &str| cx.admin(Method::DELETE, &format!("{grants}/{k}/{g}"), Value::Null);
    let r = del("user", "1").await;
    assert_eq!(
        (r.0, &r.1["deleted"]),
        (StatusCode::OK, &json!(true)),
        "{}",
        r.1
    );
    assert_eq!(code(&del("user", "1").await), (404, "not_found".to_owned()));
    assert_eq!(
        cx.ok(Method::GET, &grants, Value::Null)
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );
    cx.assert_clean().await;
}

#[tokio::test]
async fn a_grant_is_validated_against_the_kind() {
    let cx = cx().await;
    let id = cx.github("main").await;
    let jid = cx.jira("acme").await;
    let put = |id: i64, b: Value| cx.admin(Method::PUT, &format!("{URI}/{id}/grants"), b);
    let role = |extra: Value| {
        let mut b = json!({"grantee_kind": "role", "grantee": "member"});
        for (k, v) in extra.as_object().unwrap() {
            b[k] = v.clone();
        }
        b
    };
    let bad = [
        (
            "an unknown capability",
            role(json!({"capabilities": ["delete_everything"]})),
        ),
        (
            "a wildcard capability",
            role(json!({"capabilities": ["*"]})),
        ),
        (
            "an empty capability list",
            role(json!({"capabilities": []})),
        ),
        (
            "another kind's capability",
            role(json!({"capabilities": ["read_issues"]})),
        ),
        (
            "an unknown limit key",
            role(json!({"limits": {"orgs": ["octo"]}})),
        ),
        ("a bare wildcard", role(json!({"limits": {"repos": ["*"]}}))),
        (
            "a parent path",
            role(json!({"limits": {"repos": ["octo/../other"]}})),
        ),
        (
            "a dot path",
            role(json!({"limits": {"repos": ["octo/./app"]}})),
        ),
        ("an empty list", role(json!({"limits": {"repos": []}}))),
        (
            "a long value",
            role(json!({"limits": {"repos": ["a".repeat(101)]}})),
        ),
        (
            "a grantee kind",
            json!({"grantee_kind": "group", "grantee": "x"}),
        ),
        (
            "a role",
            json!({"grantee_kind": "role", "grantee": "owner"}),
        ),
        (
            "a user of another workspace",
            json!({"grantee_kind": "user", "grantee": "2"}),
        ),
        (
            "an agent id",
            json!({"grantee_kind": "agent", "grantee": "bad agent"}),
        ),
        ("no grantee", json!({"grantee_kind": "role"})),
    ];
    for (why, b) in bad {
        let r = put(id, b).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{why}: {}", r.1);
    }
    // Jira's own shape.
    let ok = role(
        json!({"capabilities": ["read_issues", "transition"], "limits": {"projects": ["ABC"]}}),
    );
    assert_eq!(put(jid, ok).await.0, StatusCode::OK);
    assert_eq!(
        put(jid, role(json!({"limits": {"repos": ["a/b"]}})))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    // At most 32 grants on one connection.
    for n in 0..32 {
        let r = put(
            id,
            json!({"grantee_kind": "agent", "grantee": format!("agent-{n}")}),
        )
        .await;
        assert_eq!(r.0, StatusCode::OK, "{n}: {}", r.1);
    }
    let r = put(id, json!({"grantee_kind": "agent", "grantee": "agent-33"})).await;
    assert_eq!(code(&r), (409, "limit_reached".to_owned()), "{}", r.1);
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM core_connection_grants WHERE connection_id = ?")
            .bind(id)
            .fetch_one(&cx.fx.app.pool)
            .await
            .unwrap();
    assert_eq!(n, 32, "refusals wrote nothing");
    cx.assert_clean().await;
}

#[tokio::test]
async fn the_kinds_default_is_set_listed_replaced_and_cleared() {
    let cx = cx().await;
    let (a, b, j) = (
        cx.github("a").await,
        cx.github("b").await,
        cx.jira("acme").await,
    );
    let put = |kind: &str, c: i64| {
        cx.admin(
            Method::PUT,
            &format!("/api/v1/connection-defaults/{kind}"),
            json!({"connection": c}),
        )
    };
    assert_eq!(
        cx.ok(Method::GET, "/api/v1/connection-defaults", Value::Null)
            .await,
        json!([])
    );
    assert_eq!(
        put("github", a).await.1,
        json!({"kind": "github", "connection": a})
    );
    assert_eq!(put("jira", j).await.0, StatusCode::OK);
    assert_eq!(put("github", b).await.1["connection"], b);
    let list = cx
        .ok(Method::GET, "/api/v1/connection-defaults", Value::Null)
        .await;
    assert_eq!(
        list,
        json!([{"kind": "github", "connection": b}, {"kind": "jira", "connection": j}])
    );
    assert_eq!(
        cx.ok(Method::GET, &format!("{URI}/{b}"), Value::Null).await["is_default"],
        true
    );
    assert_eq!(
        cx.ok(Method::GET, &format!("{URI}/{a}"), Value::Null).await["is_default"],
        false
    );
    // A connection of another kind, a missing one, an unknown kind.
    assert_eq!(code(&put("github", j).await).0, 400);
    assert_eq!(
        code(&put("github", 9999).await),
        (404, "not_found".to_owned())
    );
    assert_eq!(code(&put("svn", a).await), (404, "not_found".to_owned()));
    cx.assert_clean().await;
}

// ----- connection_access of a session create -------------------------------------------------

const SESSIONS: &str = "/api/v1/agent-sessions";

async fn create(cx: &Cx, dev: &TestDevice, runner: &str, extra: Value) -> (StatusCode, Value) {
    let mut b = json!({"runner": runner, "harness": "claude"});
    for (k, v) in extra.as_object().unwrap() {
        b[k] = v.clone();
    }
    cx.call(dev, Method::POST, SESSIONS, b).await
}

#[tokio::test]
async fn connection_access_is_admin_only_and_validated_before_anything_is_written() {
    let cx = cx().await;
    let vm = super::secrets::runner(&cx.fx, "vm").await;
    let agent = super::stepup::plain(&cx.fx, "agent", &["agent", "read"], true).await;
    super::stepup::step_up(&cx.fx, &agent).await;
    // A device without `admin` that names the field at all is refused, an empty list included.
    for list in [json!(["read_repo"]), json!([])] {
        let r = create(&cx, &agent, &vm.id, json!({"connection_access": list})).await;
        assert_eq!(code(&r), (403, "forbidden_scope".to_owned()), "{}", r.1);
    }
    // The admin's list is checked against the kinds: capability names only, at most 16.
    let long: Vec<String> = (0..17).map(|_| "read_repo".to_owned()).collect();
    for (why, list) in [
        ("an operation", json!(["github.get_issue"])),
        ("a wildcard", json!(["*"])),
        ("an unknown name", json!(["delete_everything"])),
        ("one bad among good", json!(["read_repo", "nope"])),
        ("too many", json!(long)),
    ] {
        let r = create(&cx, &cx.fx.dev, &vm.id, json!({"connection_access": list})).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{why}: {}", r.1);
    }
    // A good list, and an empty one (the default), pass the checks and meet the offline runner.
    for list in [json!(["read_repo", "issues_write"]), json!([])] {
        let r = create(&cx, &cx.fx.dev, &vm.id, json!({"connection_access": list})).await;
        assert_eq!(code(&r), (409, "runner_offline".to_owned()), "{}", r.1);
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_agent_sessions")
        .fetch_one(&cx.fx.app.pool)
        .await
        .unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM core_session_connections")
        .fetch_one(&cx.fx.app.pool)
        .await
        .unwrap();
    assert_eq!(
        (n, rows),
        (0, 0),
        "a refused create writes no session and no access row"
    );
    cx.assert_clean().await;
}

async fn session(cx: &Cx, runner: &str) -> String {
    let policy = json!({});
    let new = crate::store::agents::NewSession {
        runner,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &cx.fx.dev.id,
    };
    crate::store::agents::create(&cx.fx.app.pool, &new, super::super::BY, NOW)
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn the_allowlist_is_written_before_the_session_starts_and_a_failed_write_ends_it() {
    use crate::api::v1::agents::access;
    let cx = cx().await;
    let vm = super::secrets::runner(&cx.fx, "vm").await;
    let app = &cx.fx.app;
    // Absent or empty: no row; the default (read class) applies at read time.
    assert_eq!(access::checked(app, true, None).unwrap(), None);
    assert_eq!(access::checked(app, true, Some(&[])).unwrap(), None);
    let want = [
        "issues_write".to_owned(),
        "read_repo".to_owned(),
        "issues_write".to_owned(),
    ];
    let list = access::checked(app, true, Some(&want)).unwrap();
    assert_eq!(
        list.as_deref(),
        Some(&want[..2]),
        "duplicates collapse, order is kept"
    );
    let id = session(&cx, &vm.id).await;
    access::apply(app, &id, &None).await.unwrap();
    let loaded = crate::store::connections::access::load(&app.pool, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.grant.allowlist, None);
    access::apply(app, &id, &list).await.unwrap();
    let loaded = crate::store::connections::access::load(&app.pool, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.grant.allowlist.as_deref(), Some(&want[..2]));
    // A write that fails ends the unstarted session: it never runs with other access than asked.
    let other = session(&cx, &vm.id).await;
    let bad = Some(vec!["Not A Name".to_owned()]);
    assert!(access::apply(app, &other, &bad).await.is_err());
    let (state, outcome): (String, String) =
        sqlx::query_as("SELECT state, outcome FROM core_agent_sessions WHERE id = ?")
            .bind(&other)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(state, "ended");
    assert!(outcome.contains("failed"), "{outcome}");
    let ended: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM events WHERE kind = 'agent.ended' AND payload LIKE ?",
    )
    .bind(format!("%{other}%"))
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(ended, 1);
    cx.assert_clean().await;
}
