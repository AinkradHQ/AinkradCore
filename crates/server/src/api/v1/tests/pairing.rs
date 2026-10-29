//! Device pairing: a code is good once, until it expires, and wrong codes are rate limited.

use serde_json::json;

use super::*;

async fn audited(fx: &Fx, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn pair(fx: &Fx, code: &str) -> (StatusCode, Value) {
    let body = json!({"code": code, "name": "iPad"});
    send(
        &fx.app,
        req(Method::POST, "/api/v1/devices/pair", None, Some(body)),
    )
    .await
}

#[tokio::test]
async fn a_device_pairs_once_with_a_code_and_wrong_codes_are_limited() {
    let mut fx = fx().await;
    let (_, started) = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/devices/pairing",
            Some(&fx.key),
            Some(json!({})),
        ),
    )
    .await;
    let code = started["code"].as_str().unwrap().to_owned();
    assert_eq!(code.len(), 6);
    assert_eq!(started["expires_at"], "2026-10-22T10:05:00.000Z");
    let (status, got) = pair(&fx, &code.to_lowercase()).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let key = got["key"].as_str().unwrap().to_owned();
    assert_eq!(got["device"]["name"], "iPad");
    let (status, _) = send(
        &fx.app,
        req(Method::GET, "/api/v1/devices", Some(&key), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the new key works");
    assert_eq!(
        pair(&fx, &code).await.0,
        StatusCode::NOT_FOUND,
        "a code works once"
    );
    assert_eq!(pair(&fx, "ZZZZZZ").await.0, StatusCode::NOT_FOUND);
    assert_eq!(audited(&fx, "device.paired").await, 1);
    assert_eq!(audited(&fx, "device.pairing_started").await, 1);

    // Expired.
    let (_, started) = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/devices/pairing",
            Some(&fx.key),
            Some(json!({})),
        ),
    )
    .await;
    *fx.clock.0.lock().unwrap() = "2026-10-22T10:06:00.000Z".to_owned();
    assert_eq!(
        pair(&fx, started["code"].as_str().unwrap()).await.0,
        StatusCode::NOT_FOUND
    );

    // Wrong codes run out: then 429, even for a right one.
    fx.app.limits = Arc::new(Limits {
        failures: Limiter::new(2, 0.001),
        requests: Limiter::new(1000, 1.0),
    });
    *fx.clock.0.lock().unwrap() = NOW.to_owned();
    let (_, started) = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/devices/pairing",
            Some(&fx.key),
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(pair(&fx, "AAAAAA").await.0, StatusCode::NOT_FOUND);
    assert_eq!(pair(&fx, "BBBBBB").await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        pair(&fx, started["code"].as_str().unwrap()).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}
