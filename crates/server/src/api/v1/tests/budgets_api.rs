//! The budget routes (KAN-448): reading is `read`, every change is `admin` plus a step-up, a list can be
//! filtered by company, and nothing reserves or releases headroom over HTTP.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

fn body(kind: &str, subject: &str, company: Option<&str>) -> Value {
    json!({"kind": kind, "subject": subject, "company": company, "period": "day", "token_cap": 1000,
           "usd_cap_micros": 5_000_000})
}

#[tokio::test]
async fn every_change_needs_admin_and_a_step_up_and_a_phone_reads_and_filters_by_company() {
    let fx = fx().await;
    let phone = fx.enroll("phone", &["read"]).await;
    let plain = TestDevice::enroll(
        &fx.app.pool,
        "plain",
        "device",
        &["read", "admin"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    let sess = fx.app.auth.issue_session(&plain.id, fx.clock.unix());
    plain.set_session(Some(sess.id));
    let writes = [
        (Method::PUT, "/api/v1/budgets", body("agent", "a1", None)),
        (Method::DELETE, "/api/v1/budgets/1", Value::Null),
        (
            Method::POST,
            "/api/v1/budgets/1/raise",
            json!({"period_key": "total", "tokens": 5}),
        ),
    ];
    for (m, uri, b) in &writes {
        let (st, r) = call(&fx, &phone, m.clone(), uri, b.clone()).await;
        assert_eq!(
            (st, r["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("forbidden_scope")),
            "{m} {uri}"
        );
        let (st, r) = call(&fx, &plain, m.clone(), uri, b.clone()).await;
        assert_eq!(
            (st, r["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("step_up_required")),
            "{m} {uri}"
        );
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_budgets")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "nothing was written");

    let (st, a) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        "/api/v1/budgets",
        body("project", "p1", Some("7")),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{a}");
    assert_eq!(
        (
            a["kind"].as_str(),
            a["company"].as_str(),
            a["warn_at_percent"].as_i64(),
            a["hard_stop"].as_bool()
        ),
        (Some("project"), Some("7"), Some(80), Some(true))
    );
    assert_eq!(
        (a["spent"].as_i64(), a["exhausted"].as_bool()),
        (Some(0), Some(false))
    );
    call(
        &fx,
        &fx.dev,
        Method::PUT,
        "/api/v1/budgets",
        body("company", "8", None),
    )
    .await;
    // Changing it keeps the id.
    let mut again = body("project", "p1", Some("7"));
    again["token_cap"] = json!(2000);
    let (_, changed) = call(&fx, &fx.dev, Method::PUT, "/api/v1/budgets", again).await;
    assert_eq!(
        (changed["id"].as_i64(), changed["token_cap"].as_i64()),
        (a["id"].as_i64(), Some(2000))
    );

    let (st, all) = call(&fx, &phone, Method::GET, "/api/v1/budgets", Value::Null).await;
    assert_eq!(
        (st, all.as_array().map(Vec::len)),
        (StatusCode::OK, Some(2))
    );
    let (_, mine) = call(
        &fx,
        &phone,
        Method::GET,
        "/api/v1/budgets?company=7",
        Value::Null,
    )
    .await;
    assert_eq!(
        mine.as_array()
            .unwrap()
            .iter()
            .map(|b| b["subject"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["p1"]
    );
    let (_, c8) = call(
        &fx,
        &phone,
        Method::GET,
        "/api/v1/budgets?kind=company&subject=8",
        Value::Null,
    )
    .await;
    assert_eq!(c8[0]["company"], "8");
    let (_, none) = call(
        &fx,
        &phone,
        Method::GET,
        "/api/v1/budgets?company=9",
        Value::Null,
    )
    .await;
    assert_eq!(none, json!([]));

    // Raise a period, see it in the standing; then delete.
    let id = a["id"].as_i64().unwrap();
    let (st, r) = call(
        &fx,
        &fx.dev,
        Method::POST,
        &format!("/api/v1/budgets/{id}/raise"),
        json!({"period_key": "2026-10-21", "tokens": 5}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{r}");
    assert_eq!(
        (r["period_key"].as_str(), r["raised"].as_i64()),
        (Some("2026-10-21"), Some(5))
    );
    let (_, listed) = call(
        &fx,
        &phone,
        Method::GET,
        "/api/v1/budgets?kind=project",
        Value::Null,
    )
    .await;
    assert_eq!(listed[0]["id"].as_i64(), Some(id));
    let (st, d) = call(
        &fx,
        &fx.dev,
        Method::DELETE,
        &format!("/api/v1/budgets/{id}"),
        Value::Null,
    )
    .await;
    assert_eq!((st, d["deleted"].as_bool()), (StatusCode::OK, Some(true)));
    let (_, d) = call(
        &fx,
        &fx.dev,
        Method::DELETE,
        &format!("/api/v1/budgets/{id}"),
        Value::Null,
    )
    .await;
    assert_eq!(d["deleted"].as_bool(), Some(false));
}

#[tokio::test]
async fn bad_budgets_and_raises_are_refused_and_there_is_no_route_to_reserve() {
    let fx = fx().await;
    for (b, want) in [
        (body("team", "x", None), StatusCode::BAD_REQUEST),
        (
            json!({"kind": "agent", "subject": "a", "period": "hour", "token_cap": 1}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"kind": "agent", "subject": "a", "period": "day", "token_cap": -5}),
            StatusCode::BAD_REQUEST,
        ),
        (body("account", "99", None), StatusCode::NOT_FOUND),
        (body("company", "7", Some("8")), StatusCode::BAD_REQUEST),
    ] {
        let (st, r) = call(&fx, &fx.dev, Method::PUT, "/api/v1/budgets", b.clone()).await;
        assert_eq!(st, want, "{b}: {r}");
    }
    let (st, _) = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/budgets/999/raise",
        json!({"period_key": "total", "tokens": 1}),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (_, made) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        "/api/v1/budgets",
        body("agent", "a1", None),
    )
    .await;
    let uri = format!("/api/v1/budgets/{}/raise", made["id"]);
    for bad in [
        json!({"period_key": "total"}),
        json!({"period_key": "total", "tokens": 0}),
        json!({"period_key": "x y", "tokens": 1}),
        json!({"period_key": "2026-10", "tokens": 1}),
    ] {
        let (st, _) = call(&fx, &fx.dev, Method::POST, &uri, bad).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
    for uri in [
        "/api/v1/budgets/reserve",
        "/api/v1/budgets/1/reserve",
        "/api/v1/budgets/1/release",
    ] {
        let (st, _) = call(&fx, &fx.dev, Method::POST, uri, json!({"session": "s"})).await;
        assert!(
            [
                StatusCode::FORBIDDEN,
                StatusCode::NOT_FOUND,
                StatusCode::METHOD_NOT_ALLOWED
            ]
            .contains(&st),
            "{uri}: {st}"
        );
    }
}
