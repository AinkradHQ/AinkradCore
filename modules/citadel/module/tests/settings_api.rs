//! The module's settings routes through the Core's gate (re-audit PR72-T1): `PUT` is a step-up
//! route and `GET` is `admin`, an unknown name or a value out of bounds is refused, and a refused
//! write changes nothing.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;

#[tokio::test]
async fn settings_need_admin_and_a_step_up_and_refuse_bad_names_and_values() {
    let fx = fx().await;
    let laptop = enroll(&fx.app, "laptop", &["admin"], true).await;
    let phone = enroll(&fx.app, "phone", &["read"], true).await;
    let put = |v: i64| Some(json!({"value": v}));

    // Unelevated admin: the write wants a step-up. The read does not.
    let r = call(
        &fx,
        Some(&laptop),
        Method::PUT,
        "/settings/mcp.enabled",
        put(1),
    )
    .await;
    assert_eq!(r.0, StatusCode::FORBIDDEN, "{r:?}");
    assert_eq!(r.1["code"], "step_up_required", "{r:?}");
    assert_eq!(
        call(&fx, Some(&laptop), Method::GET, "/settings", None)
            .await
            .0,
        StatusCode::OK
    );

    // A read device may neither list nor set.
    for (m, p, b) in [
        (Method::GET, "/settings", None),
        (Method::PUT, "/settings/mcp.enabled", put(1)),
    ] {
        let r = call(&fx, Some(&phone), m.clone(), p, b).await;
        assert_eq!(r.0, StatusCode::FORBIDDEN, "{m} {p}: {r:?}");
        assert_eq!(r.1["code"], "forbidden_scope", "{m} {p}: {r:?}");
    }

    // Elevated admin: unknown name 404, below min and above max 400, and nothing changed.
    let list = fx.ok("/settings").await;
    let mcp = list
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "mcp.max_calls_per_run")
        .expect("a bounded setting");
    let (min, max, value) = (
        mcp["min"].as_i64().unwrap(),
        mcp["max"].as_i64().unwrap(),
        mcp["value"].clone(),
    );
    let r = call(
        &fx,
        Some(&fx.dev),
        Method::PUT,
        "/settings/no.such.setting",
        put(1),
    )
    .await;
    assert_eq!(r.0, StatusCode::NOT_FOUND, "{r:?}");
    for bad in [min - 1, max + 1] {
        let r = call(
            &fx,
            Some(&fx.dev),
            Method::PUT,
            "/settings/mcp.max_calls_per_run",
            put(bad),
        )
        .await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{bad}: {r:?}");
    }
    let after = fx.ok("/settings").await;
    let same = after
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "mcp.max_calls_per_run")
        .unwrap();
    assert_eq!(same["value"], value, "a refused write changed the value");
    // A valid one is applied (the test would pass vacuously if every write were refused).
    let r = call(
        &fx,
        Some(&fx.dev),
        Method::PUT,
        "/settings/mcp.max_calls_per_run",
        put(max),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{r:?}");
    assert_eq!(r.1["value"], max);
}
