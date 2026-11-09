//! The push-token routes (E2-12.1, E2-12.3): a device's token and opt-in are its own, nothing
//! echoes a token back, and another device can neither take a token nor read or change a
//! choice. The delivery rules themselves are in `push::tests_*`.

use super::*;
use crate::store::gov::push_targets;

const KINDS: &str = "/api/v1/push-token/kinds";

async fn put(fx: &Fx, by: &TestDevice, uri: &str, body: Value) -> (StatusCode, Value) {
    send(&fx.app, req(Method::PUT, uri, Some(by), Some(body))).await
}

async fn get(fx: &Fx, by: &TestDevice, uri: &str) -> (StatusCode, Value) {
    send(&fx.app, req(Method::GET, uri, Some(by), None)).await
}

#[tokio::test]
async fn a_devices_token_and_opt_in_are_its_own() {
    let fx = fx().await;
    let phone = fx.enroll("iPhone", &["read"]).await;
    let (a, b) = ("0a".repeat(32), "0b".repeat(32));

    // Registering needs only `read`; the token is never echoed, to the owner or to an admin.
    let (status, body) = put(&fx, &phone, "/api/v1/push-token", json!({"token": a})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.to_string().contains(&a), "{body}");
    let (_, list) = get(&fx, &fx.dev, "/api/v1/devices").await;
    assert!(
        !list.to_string().contains(&a),
        "the device list echoed a token"
    );
    let (_, one) = get(&fx, &fx.dev, &format!("/api/v1/devices/{}", phone.id)).await;
    assert!(
        !one.to_string().contains(&a),
        "a device read echoed a token"
    );
    let (_, me) = get(&fx, &phone, "/api/v1/me").await;
    assert!(!me.to_string().contains(&a), "me echoed a token");

    // Another device cannot register that token, so the phone keeps it; nor can it clear it.
    let (status, _) = put(&fx, &fx.dev, "/api/v1/push-token", json!({"token": a})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let held = push_targets(&fx.app.pool).await.unwrap();
    assert_eq!(
        (held.len(), held[0].device_id.as_str()),
        (1, phone.id.as_str())
    );
    let (status, _) = send(
        &fx.app,
        req(Method::DELETE, "/api/v1/push-token", Some(&fx.dev), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "clears the caller's own (none), not the phone's"
    );
    assert_eq!(push_targets(&fx.app.pool).await.unwrap().len(), 1);
    let (status, _) = put(&fx, &fx.dev, "/api/v1/push-token", json!({"token": b})).await;
    assert_eq!(status, StatusCode::OK, "its own token is fine");

    // The opt-in: default all; set by the phone; the admin's view of it is its own.
    assert_eq!(get(&fx, &phone, KINDS).await.1, json!({"kinds": null}));
    let (status, body) = put(
        &fx,
        &phone,
        KINDS,
        json!({"kinds": ["agent_finished", "agent_finished"]}),
    )
    .await;
    assert_eq!(
        (status, &body),
        (StatusCode::OK, &json!({"kinds": ["agent_finished"]}))
    );
    assert_eq!(get(&fx, &fx.dev, KINDS).await.1, json!({"kinds": null}));
    for bad in [
        json!({"kinds": ["a b"]}),
        json!({"kinds": [""]}),
        json!({"kinds": "x"}),
    ] {
        let (status, _) = put(&fx, &phone, KINDS, bad).await;
        assert!(status.is_client_error(), "{status}");
    }
    assert_eq!(
        get(&fx, &phone, KINDS).await.1,
        json!({"kinds": ["agent_finished"]})
    );
    assert_eq!(
        put(&fx, &phone, KINDS, json!({"kinds": null})).await.1,
        json!({"kinds": null})
    );

    // A revoked device is refused like a stranger.
    put(&fx, &phone, KINDS, json!({"kinds": []})).await;
    let uri = format!("/api/v1/devices/{}", phone.id);
    send(&fx.app, req(Method::DELETE, &uri, Some(&fx.dev), None)).await;
    let (status, _) = get(&fx, &phone, KINDS).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM core_push_kinds")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
    assert_eq!(
        push_targets(&fx.app.pool).await.unwrap().len(),
        1,
        "only the admin's own"
    );
}
