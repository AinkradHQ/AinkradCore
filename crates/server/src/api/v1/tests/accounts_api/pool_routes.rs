//! Pool, binding and provider routes.

use super::*;

#[tokio::test]
async fn pools_and_bindings_work_through_the_routes() {
    let (fx, vm, phone) = setup().await;
    let a = create(&fx, &vm, "a", V1).await["account"]["id"]
        .as_i64()
        .unwrap();
    let (s, pool) = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/pools",
        json!({"name": "main", "provider": "anthropic"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{pool}");
    let p = pool["id"].as_i64().unwrap();
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &format!("/api/v1/pools/{p}/members/{a}"),
        Value::Null,
    )
    .await;
    assert_eq!((s, b["members"].clone()), (StatusCode::OK, json!([a])));
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &format!("/api/v1/pools/{p}/default"),
        Value::Null,
    )
    .await;
    assert_eq!((s, b["is_default"].as_bool()), (StatusCode::OK, Some(true)));
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        "/api/v1/bindings",
        json!({"agent": "ag1", "pool_id": p}),
    )
    .await;
    assert_eq!(
        (s, b["provider"].as_str()),
        (StatusCode::OK, Some("anthropic"))
    );
    let (_, list) = call(&fx, &phone, Method::GET, "/api/v1/bindings", Value::Null).await;
    assert_eq!(
        list,
        json!([{"agent": "ag1", "provider": "anthropic", "pool_id": p}])
    );
    let (s, _) = call(
        &fx,
        &fx.dev,
        Method::DELETE,
        &format!("/api/v1/pools/{p}"),
        Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "the default pool is not deleted");
    let (s, _) = call(
        &fx,
        &fx.dev,
        Method::DELETE,
        "/api/v1/bindings/ag1/anthropic",
        Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::DELETE,
        "/api/v1/bindings/ag1/anthropic",
        Value::Null,
    )
    .await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    let (s, _) = call(
        &fx,
        &fx.dev,
        Method::DELETE,
        &format!("/api/v1/pools/{p}/members/{a}"),
        Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &format!("/api/v1/pools/{p}/members/999"),
        Value::Null,
    )
    .await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
}

#[tokio::test]
async fn provider_definitions_are_validated_and_built_ins_are_fixed() {
    let (fx, _vm, phone) = setup().await;
    let (_, all) = call(
        &fx,
        &phone,
        Method::GET,
        "/api/v1/accounts/providers",
        Value::Null,
    )
    .await;
    let ids: Vec<_> = all
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["anthropic", "openai", "google"]);
    let def = json!({"id": "router", "name": "Router", "harness": "codex", "auth_var": "OPENAI_API_KEY",
        "base_url": "https://router.example.com/v1", "usage_parser": "openai", "delivery": ["env"],
        "login_methods": ["paste"], "models": [], "priced_at": null});
    let (s, b) = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/accounts/providers",
        def.clone(),
    )
    .await;
    assert_eq!((s, b["version"].as_i64()), (StatusCode::OK, Some(1)), "{b}");
    let mut proxied = def.clone();
    proxied["auth_var"] = json!("HTTPS_PROXY");
    let (s, _) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        "/api/v1/accounts/providers/router",
        proxied,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let mut other = def.clone();
    other["id"] = json!("elsewhere");
    let (s, _) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        "/api/v1/accounts/providers/router",
        other,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "the body's id must be the path's"
    );
    let (s, _) = call(
        &fx,
        &fx.dev,
        Method::DELETE,
        "/api/v1/accounts/providers/openai",
        Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(
        &fx,
        &fx.dev,
        Method::DELETE,
        "/api/v1/accounts/providers/router",
        Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}
