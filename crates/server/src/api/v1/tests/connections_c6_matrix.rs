//! C6: the cross-workspace and cross-role matrix. The table below must name EVERY connection route
//! of the contract (a new route without a row fails here), and each route is called as an admin of
//! another workspace, a read-only device and an agent-only device. None may read or change a
//! thing of the first workspace, and no response body may carry one of its values.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::connections_fx::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    Kinds,
    List,
    Create,
    One,
    ById,
    Start,
    Flow,
    Defaults,
    Default,
    Apps,
}
use Class::*;

const ROUTES: [(&str, &str, Class); 22] = [
    ("get", "/api/v1/connection-kinds", Kinds),
    ("get", "/api/v1/connections", List),
    ("post", "/api/v1/connections", Create),
    ("get", "/api/v1/connections/{id}", One),
    ("patch", "/api/v1/connections/{id}", ById),
    ("delete", "/api/v1/connections/{id}", ById),
    ("post", "/api/v1/connections/{id}/test", ById),
    ("put", "/api/v1/connections/{id}/credential", ById),
    ("get", "/api/v1/connections/{id}/activity", ById),
    ("get", "/api/v1/connections/{id}/grants", ById),
    ("put", "/api/v1/connections/{id}/grants", ById),
    (
        "delete",
        "/api/v1/connections/{id}/grants/{grantee_kind}/{grantee}",
        ById,
    ),
    ("post", "/api/v1/connections/start", Start),
    ("get", "/api/v1/connections/flows/{id}", Flow),
    ("delete", "/api/v1/connections/flows/{id}", Flow),
    ("post", "/api/v1/connections/flows/{id}/callback", Flow),
    ("post", "/api/v1/connections/flows/{id}/choose", Flow),
    ("get", "/api/v1/connection-defaults", Defaults),
    ("put", "/api/v1/connection-defaults/{kind}", Default),
    ("delete", "/api/v1/connection-defaults/{kind}", Default),
    ("get", "/api/v1/connection-apps/{kind}", Apps),
    ("put", "/api/v1/connection-apps/{kind}", Apps),
];

const NAME: &str = "c6-mine-name";

fn body(m: &str, class: Class, id: i64) -> Value {
    match (m, class) {
        ("post", Create) => {
            json!({"kind": "github", "name": "x", "auth_method": "token", "token": "t"})
        }
        ("post", Start) => json!({"kind": "jira"}),
        ("patch", _) => json!({"label": "hijacked"}),
        ("put", ById) => json!({"grantee_kind": "role", "grantee": "admin", "token": GH_TOKEN2}),
        ("put", Default) => json!({"connection": id}),
        ("put", Apps) => json!({"fields": {"client_id": "hijacked"}}),
        ("post", Flow) => json!({"code": "c", "state": "s", "site": "s"}),
        _ => Value::Null,
    }
}

fn uri(template: &str, id: i64, flow: &str) -> String {
    let flow_route = template.contains("/flows/");
    template
        .replace(
            "{id}",
            &if flow_route {
                flow.to_owned()
            } else {
                id.to_string()
            },
        )
        .replace("{kind}", "github")
        .replace("{grantee_kind}", "role")
        .replace("{grantee}", "member")
}

#[tokio::test]
async fn the_table_names_every_connection_route_of_the_contract() {
    let spec: Value = serde_json::from_str(&super::super::spec::json()).unwrap();
    let mut found: Vec<String> = Vec::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        if !path.starts_with("/api/v1/connection") {
            continue;
        }
        for m in ["get", "post", "put", "patch", "delete"] {
            if item.get(m).is_some() {
                found.push(format!("{m} {path}"));
            }
        }
    }
    let mut table: Vec<String> = ROUTES.iter().map(|(m, p, _)| format!("{m} {p}")).collect();
    found.sort();
    table.sort();
    assert_eq!(
        found, table,
        "a connection route is missing from the matrix, or gone"
    );
}

#[tokio::test]
async fn no_other_workspace_reader_or_agent_device_reads_or_changes_anything_of_a_workspace() {
    let cx = cx().await;
    cx.configure().await;
    let mine = cx.github(NAME).await;
    cx.ok(
        Method::PUT,
        &format!("/api/v1/connections/{mine}/grants"),
        json!({"grantee_kind": "role", "grantee": "admin"}),
    )
    .await;
    cx.ok(
        Method::PUT,
        "/api/v1/connection-defaults/github",
        json!({"connection": mine}),
    )
    .await;
    let flow = start(&cx, "jira", json!({})).await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let before = snapshot(&cx, mine, &flow).await;
    let other = other_admin(&cx).await;
    let reader = cx.fx.enroll("reader", &["read"]).await;
    let agent = super::stepup::plain(&cx.fx, "agent-only", &["agent"], true).await;
    let mut seen = String::new();
    for (m, template, class) in ROUTES {
        let method = Method::from_bytes(m.to_uppercase().as_bytes()).unwrap();
        let u = uri(template, mine, &flow);
        let b = body(m, class, mine);
        // An agent-only device holds no connection scope at all.
        let r = cx.call(&agent, method.clone(), &u, b.clone()).await;
        assert_eq!(
            code(&r),
            (403, "forbidden_scope".to_owned()),
            "agent {m} {u}: {}",
            r.1
        );
        // A read-only device: kinds and its own (empty) list are all it has.
        let r = cx.call(&reader, method.clone(), &u, b.clone()).await;
        seen.push_str(&r.1.to_string());
        match class {
            Kinds => assert_eq!(r.0, StatusCode::OK, "reader {m} {u}"),
            List => assert_eq!((r.0, &r.1), (StatusCode::OK, &json!([])), "reader {m} {u}"),
            One => assert_eq!(
                code(&r),
                (404, "not_found".to_owned()),
                "reader {m} {u}: {}",
                r.1
            ),
            _ => assert_eq!(
                code(&r),
                (403, "forbidden_scope".to_owned()),
                "reader {m} {u}: {}",
                r.1
            ),
        }
        // An admin of another workspace.
        if matches!(class, Create | Start) {
            continue;
        }
        let r = cx.call(&other, method.clone(), &u, b.clone()).await;
        seen.push_str(&r.1.to_string());
        match class {
            Kinds => assert_eq!(r.0, StatusCode::OK, "other {m} {u}"),
            List | Defaults => {
                assert_eq!((r.0, &r.1), (StatusCode::OK, &json!([])), "other {m} {u}")
            }
            One | ById | Flow => {
                assert_eq!(
                    code(&r),
                    (404, "not_found".to_owned()),
                    "other {m} {u}: {}",
                    r.1
                )
            }
            Default => match m {
                "put" => assert_eq!(
                    code(&r),
                    (404, "not_found".to_owned()),
                    "other {m} {u}: {}",
                    r.1
                ),
                // Clearing a default they do not have: nothing of ours.
                _ => assert!(r.0.as_u16() < 500, "other {m} {u}: {}", r.1),
            },
            Apps => match m {
                "get" => assert_eq!(r.0, StatusCode::OK, "other {m} {u}: {}", r.1),
                _ => assert_eq!(r.0, StatusCode::FORBIDDEN, "other {m} {u}: {}", r.1),
            },
            Create | Start => unreachable!(),
        }
    }
    for leak in [
        NAME,
        "octocat",
        GH_TOKEN,
        GH_TOKEN2,
        API_TOKEN,
        CLIENT_SECRET,
    ] {
        assert!(
            !seen.contains(leak),
            "{leak} reached a device that must not see it"
        );
    }
    assert_eq!(
        snapshot(&cx, mine, &flow).await,
        before,
        "something of the workspace changed"
    );
    let rows: Vec<Value> = connections(&cx).await;
    assert_eq!(rows.len(), 1);
    cx.assert_clean().await;
}

/// What the workspace holds that a stranger must not change (the flow's clock ticks: its step only).
async fn snapshot(cx: &Cx, mine: i64, flow: &str) -> Vec<Value> {
    let mut all = Vec::new();
    for u in [
        format!("/api/v1/connections/{mine}"),
        format!("/api/v1/connections/{mine}/grants"),
        "/api/v1/connection-defaults".to_owned(),
        "/api/v1/connection-apps/jira".to_owned(),
        format!("/api/v1/connections/flows/{flow}"),
    ] {
        let v = cx.ok(Method::GET, &u, Value::Null).await;
        all.push(match u.contains("/flows/") {
            true => v["step"].clone(),
            false => v,
        });
    }
    all
}
