//! Settings (E15.17): listed with bounds, value and source; set, refused with the reason,
//! reset to what it inherits, and the history of changes. The rate limits read them.

use axum::http::{Method, StatusCode};
use serde_json::json;

use super::*;

impl Fx {
    async fn put(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        send(
            &self.app,
            req(Method::PUT, uri, Some(&self.key), Some(body)),
        )
        .await
    }

    async fn delete(&self, uri: &str) -> (StatusCode, Value) {
        send(&self.app, req(Method::DELETE, uri, Some(&self.key), None)).await
    }
}

#[tokio::test]
async fn settings_are_listed_set_refused_reset_and_their_history_read() {
    let fx = fx().await;
    let all = fx.ok("/api/v1/settings").await;
    assert_eq!(all, fx.ok("/api/v1/settings/server").await);
    let burst = all
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["key"] == "api.request_burst")
        .unwrap()
        .clone();
    assert_eq!(
        burst,
        json!({"key": "api.request_burst", "unit": "count", "default": 120, "min": 10,
               "max": 10_000, "scopes": ["server"], "value": 120, "source": null,
               "description": burst["description"]})
    );

    let uri = |scope: &str| format!("/api/v1/settings/{scope}/api.request_burst");
    let set = fx.put(&uri("server"), json!({"value": 500})).await;
    assert_eq!(set.0, StatusCode::OK, "{}", set.1);
    assert_eq!(
        (&set.1["value"], &set.1["source"]),
        (&json!(500), &json!("server"))
    );
    let refused = [
        (
            uri("server"),
            json!({"value": 5}),
            StatusCode::BAD_REQUEST,
            "out_of_bounds",
        ),
        (
            uri("server"),
            json!({"value": "500"}),
            StatusCode::BAD_REQUEST,
            "not_integer",
        ),
        (
            uri("company:1"),
            json!({"value": 500}),
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            "/api/v1/settings/server/no.such".to_owned(),
            json!({"value": 1}),
            StatusCode::NOT_FOUND,
            "not_found",
        ),
    ];
    for (u, body, status, code) in refused {
        let (got, err) = fx.put(&u, body).await;
        assert_eq!(
            (got, err["code"].as_str()),
            (status, Some(code)),
            "{u}: {err}"
        );
    }
    let reset = fx.delete(&uri("server")).await.1;
    assert_eq!(
        (&reset["value"], &reset["source"]),
        (&json!(120), &Value::Null)
    );
    let history = fx.ok(&format!("{}/history", uri("server"))).await;
    assert_eq!(
        history,
        json!([
            {"seq": history[0]["seq"], "at": NOW, "actor": {"kind": "user", "user_id": 1},
             "scope": "server", "old": 500, "new": null},
            {"seq": history[1]["seq"], "at": NOW, "actor": {"kind": "user", "user_id": 1},
             "scope": "server", "old": null, "new": 500},
        ])
    );
    assert_eq!(fx.ok(&uri("server")).await["value"], 120);
}

#[tokio::test]
async fn the_rate_limits_are_read_from_settings() {
    use ainkrad_core::settings::{Key, Scope};
    let fx = fx().await;
    let pool = &fx.app.pool;
    let by = super::super::BY;
    crate::store::settings::set(pool, Key::ApiRequestBurst, Scope::Server, "10", by, NOW)
        .await
        .unwrap();
    crate::store::settings::set(pool, Key::ApiAuthFailureBurst, Scope::Server, "3", by, NOW)
        .await
        .unwrap();
    let limits = Limits::from_settings(pool).await.unwrap();
    assert_eq!((limits.requests.burst, limits.failures.burst), (10.0, 3.0));
    assert_eq!(limits.requests.per_sec, 20.0, "the default 1200 a minute");
    let defaults = Limits::default();
    assert_eq!(
        (defaults.requests.burst, defaults.failures.burst),
        (120.0, 10.0)
    );
    assert!((defaults.failures.per_sec - 1.0 / 6.0).abs() < 1e-9);
}
