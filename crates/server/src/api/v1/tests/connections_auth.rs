//! Who may call the connection routes (C5): the non-admin 403, the missing step-up, what a
//! non-admin device sees, another workspace's 404 on every route, and the contract's marks.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;

const URI: &str = "/api/v1/connections";
const FLOW: &str = "cf_00000000000000000000000000";

/// Every admin route with a body where it takes one, and whether it writes (destructive).
fn admin_routes(id: i64) -> Vec<(Method, String, Value, bool)> {
    let r = |m: Method, u: String, b: Value, w: bool| (m, u, b, w);
    vec![
        r(
            Method::POST,
            URI.to_owned(),
            json!({"kind": "github", "auth_method": "token", "token": "t"}),
            true,
        ),
        r(
            Method::POST,
            format!("{URI}/start"),
            json!({"kind": "github"}),
            true,
        ),
        r(
            Method::GET,
            format!("{URI}/flows/{FLOW}"),
            Value::Null,
            false,
        ),
        r(
            Method::DELETE,
            format!("{URI}/flows/{FLOW}"),
            Value::Null,
            false,
        ),
        r(
            Method::POST,
            format!("{URI}/flows/{FLOW}/callback"),
            json!({"code": "c", "state": "s"}),
            false,
        ),
        r(
            Method::POST,
            format!("{URI}/flows/{FLOW}/choose"),
            json!({"site": "s"}),
            false,
        ),
        r(
            Method::PATCH,
            format!("{URI}/{id}"),
            json!({"label": "x"}),
            true,
        ),
        r(Method::DELETE, format!("{URI}/{id}"), Value::Null, true),
        r(
            Method::PUT,
            format!("{URI}/{id}/credential"),
            json!({"token": "t"}),
            true,
        ),
        r(
            Method::GET,
            format!("{URI}/{id}/activity"),
            Value::Null,
            false,
        ),
        r(
            Method::GET,
            format!("{URI}/{id}/grants"),
            Value::Null,
            false,
        ),
        r(
            Method::PUT,
            format!("{URI}/{id}/grants"),
            json!({"grantee_kind": "role", "grantee": "member"}),
            true,
        ),
        r(
            Method::DELETE,
            format!("{URI}/{id}/grants/role/member"),
            Value::Null,
            true,
        ),
        r(
            Method::GET,
            "/api/v1/connection-defaults".to_owned(),
            Value::Null,
            false,
        ),
        r(
            Method::PUT,
            "/api/v1/connection-defaults/github".to_owned(),
            json!({"connection": id}),
            true,
        ),
        r(
            Method::DELETE,
            "/api/v1/connection-defaults/github".to_owned(),
            Value::Null,
            true,
        ),
        r(
            Method::GET,
            "/api/v1/connection-apps/github".to_owned(),
            Value::Null,
            false,
        ),
        r(
            Method::PUT,
            "/api/v1/connection-apps/github".to_owned(),
            json!({"fields": {"client_id": "x"}}),
            true,
        ),
    ]
}

#[tokio::test]
async fn a_non_admin_is_refused_everywhere_and_a_write_needs_a_step_up() {
    let cx = cx().await;
    let id = cx.github("main").await;
    let reader = cx.fx.enroll("reader", &["read", "approve"]).await;
    let agent = super::stepup::plain(&cx.fx, "agent", &["agent", "read"], true).await;
    super::stepup::step_up(&cx.fx, &agent).await;
    // The test route is `admin` too (it asks the service once).
    let mut routes = admin_routes(id);
    routes.push((Method::POST, format!("{URI}/{id}/test"), Value::Null, false));
    for dev in [&reader, &agent] {
        for (m, uri, body, _) in &routes {
            let r = cx.call(dev, m.clone(), uri, body.clone()).await;
            assert_eq!(
                code(&r),
                (403, "forbidden_scope".to_owned()),
                "{m} {uri}: {}",
                r.1
            );
        }
    }
    // An admin that never stepped up: a write needs one, anything else is let through.
    let plain = super::stepup::plain(&cx.fx, "plain", &["read", "admin"], true).await;
    for (m, uri, body, write) in &routes {
        if uri.ends_with("/test") {
            cx.gh.push(200, &[], r#"{"login":"octocat","id":1}"#);
        }
        let r = cx.call(&plain, m.clone(), uri, body.clone()).await;
        match write {
            true => assert_eq!(
                code(&r),
                (403, "step_up_required".to_owned()),
                "{m} {uri}: {}",
                r.1
            ),
            false => assert_ne!(r.0, StatusCode::FORBIDDEN, "{m} {uri}: {}", r.1),
        }
    }
    // Nothing changed: one connection, as it was made, no default, no grant, no app set.
    let all = cx.ok(Method::GET, URI, Value::Null).await;
    assert_eq!(
        (all.as_array().unwrap().len(), &all[0]["label"]),
        (1, &json!("GitHub"))
    );
    assert_eq!(
        cx.ok(Method::GET, "/api/v1/connection-defaults", Value::Null)
            .await,
        json!([])
    );
    assert_eq!(
        cx.ok(Method::GET, &format!("{URI}/{id}/grants"), Value::Null)
            .await,
        json!([])
    );
    let app = cx
        .ok(Method::GET, "/api/v1/connection-apps/github", Value::Null)
        .await;
    assert_eq!(app["configured"], true, "Ainkrad's built-in GitHub app");
    cx.assert_clean().await;
}

#[tokio::test]
async fn the_contract_marks_every_route_with_its_scope_and_whether_it_is_destructive() {
    let spec: Value = serde_json::from_str(&super::super::spec::json()).unwrap();
    let mut want: Vec<(String, &str, &str, bool)> = [
        ("get", "/api/v1/connection-kinds", "read", false),
        ("get", "/api/v1/connections", "read", false),
        ("get", "/api/v1/connections/{id}", "read", false),
        ("post", "/api/v1/connections/{id}/test", "admin", false),
    ]
    .map(|(m, t, s, d)| (m.to_owned(), t, s, d))
    .to_vec();
    let routes = admin_routes(1);
    let templates = [
        "/api/v1/connections",
        "/api/v1/connections/start",
        "/api/v1/connections/flows/{id}",
        "/api/v1/connections/flows/{id}",
        "/api/v1/connections/flows/{id}/callback",
        "/api/v1/connections/flows/{id}/choose",
        "/api/v1/connections/{id}",
        "/api/v1/connections/{id}",
        "/api/v1/connections/{id}/credential",
        "/api/v1/connections/{id}/activity",
        "/api/v1/connections/{id}/grants",
        "/api/v1/connections/{id}/grants",
        "/api/v1/connections/{id}/grants/{grantee_kind}/{grantee}",
        "/api/v1/connection-defaults",
        "/api/v1/connection-defaults/{kind}",
        "/api/v1/connection-defaults/{kind}",
        "/api/v1/connection-apps/{kind}",
        "/api/v1/connection-apps/{kind}",
    ];
    for ((m, _, _, write), t) in routes.iter().zip(templates) {
        want.push((m.as_str().to_ascii_lowercase(), t, "admin", *write));
    }
    for (m, t, scope, destructive) in want {
        let op = &spec["paths"][t][m.as_str()];
        assert_eq!(op["x-ainkrad-scope"], scope, "{m} {t}");
        assert_eq!(
            op["x-ainkrad-destructive"] == json!(true),
            destructive,
            "{m} {t}"
        );
    }
    let session = &spec["paths"]["/api/v1/agent-sessions"]["post"];
    assert!(
        session["requestBody"]
            .to_string()
            .contains("NewAgentSession")
    );
    let schema = &spec["components"]["schemas"]["NewAgentSession"]["properties"];
    assert!(schema["connection_access"].is_object());
}

#[tokio::test]
async fn a_non_admin_sees_only_what_is_granted_to_it_and_never_anyones_grants() {
    let cx = cx().await;
    let (a, b, c) = (
        cx.github("a").await,
        cx.github("b").await,
        cx.github("c").await,
    );
    let grant = |id: i64, body: Value| cx.admin(Method::PUT, &format!("{URI}/{id}/grants"), body);
    for r in [
        grant(a, json!({"grantee_kind": "role", "grantee": "member"})).await,
        grant(
            b,
            json!({"grantee_kind": "user", "grantee": "1", "capabilities": ["read_repo", "pr_write"],
                "limits": {"repos": ["octo/secret-repo"]}}),
        )
        .await,
        grant(c, json!({"grantee_kind": "agent", "grantee": "agent-1"})).await,
        grant(c, json!({"grantee_kind": "role", "grantee": "admin"})).await,
    ] {
        assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    }
    let reader = cx.fx.enroll("reader", &["read"]).await;
    let list = cx.call(&reader, Method::GET, URI, Value::Null).await;
    assert_eq!(list.0, StatusCode::OK, "{}", list.1);
    let ids: Vec<i64> = list
        .1
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [a, b], "c is granted to an agent and to admins only");
    assert_eq!(list.1[0]["my_capabilities"], json!(["read_repo"]));
    assert_eq!(
        list.1[1]["my_capabilities"],
        json!(["pr_write", "read_repo"])
    );
    for v in list.1.as_array().unwrap() {
        assert_eq!(
            (&v["grant_count"], &v["created_by"]),
            (&Value::Null, &Value::Null)
        );
    }
    let text = list.1.to_string();
    assert!(!text.contains("secret-repo") && !text.contains("limits") && !text.contains("agent-1"));
    assert_eq!(
        cx.call(&reader, Method::GET, &format!("{URI}/{a}"), Value::Null)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        code(
            &cx.call(&reader, Method::GET, &format!("{URI}/{c}"), Value::Null)
                .await
        ),
        (404, "not_found".to_owned())
    );
    // The kinds are readable, grants are not.
    assert_eq!(
        cx.call(
            &reader,
            Method::GET,
            "/api/v1/connection-kinds",
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        code(
            &cx.call(
                &reader,
                Method::GET,
                &format!("{URI}/{a}/grants"),
                Value::Null
            )
            .await
        )
        .0,
        403
    );
    // The admin sees all three, with how many grants each has.
    let all = cx.ok(Method::GET, URI, Value::Null).await;
    let counts: Vec<i64> = all
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["grant_count"].as_i64().unwrap())
        .collect();
    assert_eq!(counts, [1, 1, 2]);
    cx.assert_clean().await;
}

#[tokio::test]
async fn another_workspaces_connections_are_not_found_on_every_route() {
    let cx = cx().await;
    let mine = cx.github("mine").await;
    let other = other_admin(&cx).await;
    // Their list is theirs; they make one of their own, which is not mine to see.
    let theirs_list = cx.call(&other, Method::GET, URI, Value::Null).await;
    assert_eq!(theirs_list.1, json!([]));
    cx.gh.push(200, &[], r#"{"login":"octocat","id":1}"#);
    let made = cx
        .call(
            &other,
            Method::POST,
            URI,
            json!({"kind": "github", "name": "mine", "auth_method": "token", "token": GH_TOKEN}),
        )
        .await;
    assert_eq!(
        made.0,
        StatusCode::OK,
        "the same name in another workspace is no conflict: {}",
        made.1
    );
    let theirs = made.1["id"].as_i64().unwrap();
    assert_ne!(theirs, mine);
    let one = format!("{URI}/{mine}");
    let routes = [
        (Method::GET, one.clone(), Value::Null),
        (Method::PATCH, one.clone(), json!({"label": "stolen"})),
        (Method::DELETE, one.clone(), Value::Null),
        (
            Method::PUT,
            format!("{one}/credential"),
            json!({"token": GH_TOKEN2}),
        ),
        (Method::POST, format!("{one}/test"), Value::Null),
        (Method::GET, format!("{one}/activity"), Value::Null),
        (Method::GET, format!("{one}/grants"), Value::Null),
        (
            Method::PUT,
            format!("{one}/grants"),
            json!({"grantee_kind": "role", "grantee": "member"}),
        ),
        (
            Method::DELETE,
            format!("{one}/grants/role/member"),
            Value::Null,
        ),
        (
            Method::PUT,
            "/api/v1/connection-defaults/github".to_owned(),
            json!({"connection": mine}),
        ),
    ];
    for (m, uri, body) in routes {
        let r = cx.call(&other, m.clone(), &uri, body).await;
        assert_eq!(
            code(&r),
            (404, "not_found".to_owned()),
            "{m} {uri}: {}",
            r.1
        );
    }
    // And the other way round.
    let back = cx
        .admin(Method::GET, &format!("{URI}/{theirs}"), Value::Null)
        .await;
    assert_eq!(code(&back).0, 404);
    // Nothing of mine changed.
    let v = cx.ok(Method::GET, &one, Value::Null).await;
    assert_eq!(
        (&v["label"], &v["is_default"]),
        (&json!("GitHub"), &json!(false))
    );
    assert_eq!(
        cx.ok(Method::GET, "/api/v1/connection-defaults", Value::Null)
            .await,
        json!([])
    );
    cx.assert_clean().await;
}
