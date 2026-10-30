//! Company scope (E15.14, pain #12) through the Core's gate: a client that names a company with
//! `X-Citadel-Company` never reaches another company's data, by path or by list, and a read-only
//! device reads only what the routes declare `read`.

mod common;

use ainkrad_core_server::store::gov::SCOPES;
use axum::http::{Method, StatusCode};
use citadel_module::domain::org::{AgentStatus, CompanyId, Harness, NewAgent, OrgRole};
use citadel_module::store::org;
use common::*;
use serde_json::json;

struct Two {
    fx: Fx,
    a: i64,
    b: i64,
    agent_a: i64,
    dept_a: i64,
    team_a: i64,
}

async fn two() -> Two {
    let fx = fx().await;
    let (r, d) = (&fx, Some(&fx.dev));
    let mk = |name| async move {
        let (s, c) = call(
            r,
            d,
            Method::POST,
            "/companies",
            Some(json!({"name": name})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{c}");
        c["id"].as_i64().unwrap()
    };
    let (a, b) = (mk("A").await, mk("B").await);
    let (_, dept) = call(
        &fx,
        d,
        Method::POST,
        &format!("/companies/{a}/departments"),
        Some(json!({"name": "Eng"})),
    )
    .await;
    let dept_a = dept["id"].as_i64().unwrap();
    let (_, team) = call(
        &fx,
        d,
        Method::POST,
        &format!("/departments/{dept_a}/teams"),
        Some(json!({"name": "T"})),
    )
    .await;
    let agent = org::create_agent(
        &fx.app.pool,
        &NewAgent {
            company_id: CompanyId(a),
            name: "Ann".into(),
            role: "dev".into(),
            org_role: OrgRole::None,
            reports_to: None,
            harness: Harness::Claude,
            model: "m".into(),
            runner_tags: vec![],
            status: AgentStatus::Active,
        },
    )
    .await
    .unwrap();
    Two {
        fx,
        a,
        b,
        agent_a: agent.id.0,
        dept_a,
        team_a: team["id"].as_i64().unwrap(),
    }
}

#[tokio::test]
async fn another_companys_ids_are_a_404_and_its_own_are_served() {
    let t = two().await;
    let (fx, d) = (&t.fx, Some(&t.fx.dev));
    let (a, b) = (t.a.to_string(), t.b.to_string());
    let reads = [
        format!("/companies/{}", t.a),
        format!("/companies/{}/agents", t.a),
        format!("/companies/{}/departments", t.a),
        format!("/agents/{}", t.agent_a),
        format!("/departments/{}/teams", t.dept_a),
    ];
    for path in &reads {
        // Without the header the admin sees everything; in A it is served; in B it is not there.
        assert_eq!(
            call(fx, d, Method::GET, path, None).await.0,
            StatusCode::OK,
            "{path}"
        );
        assert_eq!(
            call_in(fx, d, Some(&a), Method::GET, path, None).await.0,
            StatusCode::OK,
            "{path}"
        );
        let (s, body) = call_in(fx, d, Some(&b), Method::GET, path, None).await;
        assert_eq!(
            (s, &body["code"]),
            (StatusCode::NOT_FOUND, &json!("not_found")),
            "{path}"
        );
    }
    // Writes are scoped the same way, and write nothing.
    let writes = [
        (
            Method::PUT,
            format!("/companies/{}", t.a),
            json!({"name": "X"}),
        ),
        (
            Method::POST,
            format!("/companies/{}/departments", t.a),
            json!({"name": "X"}),
        ),
        (
            Method::PUT,
            format!("/departments/{}", t.dept_a),
            json!({"name": "X"}),
        ),
        (
            Method::DELETE,
            format!("/departments/{}", t.dept_a),
            json!({}),
        ),
        (
            Method::POST,
            format!("/departments/{}/teams", t.dept_a),
            json!({"name": "X"}),
        ),
        (
            Method::PUT,
            format!("/teams/{}", t.team_a),
            json!({"name": "X"}),
        ),
        (Method::DELETE, format!("/teams/{}", t.team_a), json!({})),
    ];
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action LIKE 'citadel.%'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    for (m, path, body) in writes {
        let body = (m != Method::DELETE).then_some(body);
        let (s, _) = call_in(fx, d, Some(&b), m.clone(), &path, body).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{m} {path}");
    }
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action LIKE 'citadel.%'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(
        before, after,
        "a refused cross-company write left no audit row"
    );
}

#[tokio::test]
async fn the_company_list_shows_only_the_acting_company_and_a_bad_header_is_refused() {
    let t = two().await;
    let (fx, d) = (&t.fx, Some(&t.fx.dev));
    let (_, all) = call(fx, d, Method::GET, "/companies", None).await;
    assert_eq!(all.as_array().unwrap().len(), 2);
    let (_, mine) = call_in(
        fx,
        d,
        Some(&t.b.to_string()),
        Method::GET,
        "/companies",
        None,
    )
    .await;
    let ids: Vec<_> = mine
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [t.b]);
    for bad in ["abc", "", "1.5"] {
        assert_eq!(
            call_in(fx, d, Some(bad), Method::GET, "/companies", None)
                .await
                .0,
            StatusCode::BAD_REQUEST,
            "{bad:?}"
        );
    }
    assert_eq!(
        call_in(fx, d, Some("999"), Method::GET, "/companies", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

/// The read-only device (a phone): every GET the module's contract declares `read` is served, and
/// every write, and any route the table does not list, is a 403 `forbidden_scope`.
#[tokio::test]
async fn a_read_only_device_reads_and_cannot_write() {
    let t = two().await;
    let fx = &t.fx;
    let phone = enroll(&fx.app, "phone", &["read"], true).await;
    let admin = Some(&fx.dev);
    let denied = |r: (StatusCode, serde_json::Value)| {
        r.0 == StatusCode::FORBIDDEN && r.1["code"] == "forbidden_scope"
    };
    let spec: serde_json::Value =
        serde_json::from_str(&ainkrad_core_server::api::v1::spec::json_for(&[
            std::sync::Arc::new(citadel_module::Citadel),
        ]))
        .unwrap();
    let mut seen = 0;
    for (path, item) in spec["paths"].as_object().unwrap() {
        let Some(rel) = path.strip_prefix("/modules/citadel/v1") else {
            continue;
        };
        let uri = rel.replace("{id}", &t.a.to_string());
        for (m, op) in item.as_object().unwrap() {
            let method: Method = m.to_uppercase().parse().unwrap();
            let scope = op["x-ainkrad-scope"].as_str().unwrap();
            let body =
                (method == Method::POST || method == Method::PUT).then(|| json!({"name": "Z"}));
            let r = call(fx, Some(&phone), method.clone(), &uri, body.clone()).await;
            assert_eq!(denied(r.clone()), scope != "read", "phone {m} {uri}: {r:?}");
            // The admin device is never refused on scope.
            let r = call(fx, admin, method, &uri, body).await;
            assert!(!denied(r.clone()), "admin {m} {uri}: {r:?}");
            seen += 1;
        }
    }
    assert!(seen >= 14, "{seen} operations");
    // An unknown route and the platform's are not opened by the module's table.
    assert!(denied(
        call(fx, Some(&phone), Method::GET, "/nothing", None).await
    ));
    let _ = SCOPES;
}

/// The structural guard: `Acting` runs before any `Path` or `Json` extractor, so every operation
/// of the contract answers a malformed `X-Citadel-Company` with 400, unless a handler forgot it.
/// A new route that fails here needs `_: Acting` as its first parameter after `State`.
#[tokio::test]
async fn every_operation_takes_the_company_scope() {
    let fx = fx().await;
    let spec: serde_json::Value =
        serde_json::from_str(&ainkrad_core_server::api::v1::spec::json_for(&[
            std::sync::Arc::new(citadel_module::Citadel),
        ]))
        .unwrap();
    let mut seen = 0;
    for (path, item) in spec["paths"].as_object().unwrap() {
        let Some(rel) = path.strip_prefix("/modules/citadel/v1") else {
            continue;
        };
        let uri = rel.replace("{id}", "1");
        for m in item.as_object().unwrap().keys() {
            let method: Method = m.to_uppercase().parse().unwrap();
            let (s, body) = call_in(&fx, Some(&fx.dev), Some("abc"), method, &uri, None).await;
            assert_eq!(
                (s, &body["code"]),
                (StatusCode::BAD_REQUEST, &json!("bad_request")),
                "{m} {rel} does not take the company scope"
            );
            seen += 1;
        }
    }
    assert!(seen >= 14, "{seen} operations");
}
