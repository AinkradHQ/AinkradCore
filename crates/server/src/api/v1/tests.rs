//! The client API's gate (E10.3): host, origin, query names, device keys, rate limits. The
//! route groups (E10.1) are tested on the same fixture in their own files.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use sqlx::SqlitePool;

use super::Limits;
use crate::api::limit::Limiter;
use crate::api::{App, router};
use crate::scheduler::Clock;
use crate::store::connect;
use crate::store::gov::issue_device_key;

mod events;
mod me;
mod modules;
mod pairing;
mod settings;

pub(super) const NOW: &str = "2026-10-22T10:00:00.000Z";
pub(super) const HOST: &str = "core.test";

pub(super) struct FixedClock(pub Mutex<String>);

impl Clock for FixedClock {
    fn now(&self) -> String {
        self.0.lock().unwrap().clone()
    }
}

/// A migrated database in its own temp dir (removed on drop), an app on it, and a device key.
pub(super) struct Fx {
    pub app: App,
    pub clock: Arc<FixedClock>,
    pub key: String,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub(super) async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-v1-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let clock = Arc::new(FixedClock(Mutex::new(NOW.to_owned())));
    let app = App::new(pool, clock.clone(), HOST.to_owned());
    let (_, key) = issue_device_key(&app.pool, "test", super::BY)
        .await
        .unwrap();
    Fx {
        app,
        clock,
        key,
        dir,
    }
}

/// A request as the app sends it: our host, the bearer, JSON.
pub(super) fn req(
    method: Method,
    uri: &str,
    key: Option<&str>,
    body: Option<Value>,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, HOST);
    if let Some(key) = key {
        b = b.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    match body {
        Some(v) => b
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

/// Sends `r` and returns the status and the JSON body (`null` when empty or not JSON).
pub(super) async fn send(app: &App, r: Request<Body>) -> (StatusCode, Value) {
    let res = router(app.clone()).oneshot(r).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

impl Fx {
    pub async fn get(&self, uri: &str) -> (StatusCode, Value) {
        send(&self.app, req(Method::GET, uri, Some(&self.key), None)).await
    }

    pub async fn post(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        send(
            &self.app,
            req(Method::POST, uri, Some(&self.key), Some(body)),
        )
        .await
    }

    /// `get` that must answer 200.
    pub async fn ok(&self, uri: &str) -> Value {
        let (status, body) = self.get(uri).await;
        assert_eq!(status, StatusCode::OK, "GET {uri}: {body}");
        body
    }

    /// `post` that must answer 200.
    pub async fn ok_post(&self, uri: &str, body: Value) -> Value {
        let (status, got) = self.post(uri, body).await;
        assert_eq!(status, StatusCode::OK, "POST {uri}: {got}");
        got
    }
}

/// Every operation in the contract is routed, and answers 401 without a key.
#[tokio::test]
async fn every_operation_in_the_contract_is_routed_and_needs_a_key() {
    let mut fx = fx().await;
    fx.app.limits = Arc::new(Limits {
        failures: Limiter::new(1000, 1.0),
        requests: Limiter::new(1000, 1.0),
    });
    let spec: Value = serde_json::from_str(&super::spec::json()).unwrap();
    let mut n = 0;
    for (path, item) in spec["paths"].as_object().unwrap() {
        let uri = path.replace("{id}", "1");
        for (method, op) in item.as_object().unwrap() {
            let m: Method = method.to_uppercase().parse().unwrap();
            // `security: [{}]`: an operation that needs no key (pairing a device).
            if op["security"] == json!([{}]) {
                n += 1;
                continue;
            }
            let (status, body) = send(&fx.app, req(m.clone(), &uri, None, None)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{m} {uri}: {body}");
            // Unrouted is a bare 404 or 405; a route's own 404 says what is missing.
            let (status, body) = send(&fx.app, req(m.clone(), &uri, Some(&fx.key), None)).await;
            let routed = status != StatusCode::METHOD_NOT_ALLOWED
                && (status != StatusCode::NOT_FOUND || body["code"] == "not_found");
            assert!(routed, "{m} {uri} is not routed: {status}");
            n += 1;
        }
    }
    assert!(n >= 18, "{n} operations");
}

#[tokio::test]
async fn a_live_key_lists_adds_and_revokes_devices() {
    let fx = fx().await;
    let list = fx.ok("/api/v1/devices").await;
    assert_eq!(list[0]["name"], "test");
    assert_eq!(list[0]["last_used_at"], NOW, "use is recorded");
    let later = "2026-10-22T10:05:00.000Z";
    *fx.clock.0.lock().unwrap() = later.to_owned();
    assert_eq!(fx.ok("/api/v1/devices").await[0]["last_used_at"], later);
    *fx.clock.0.lock().unwrap() = NOW.to_owned();
    assert!(!list.to_string().contains(&fx.key), "never a key");

    // The calling device registers its APNs token, and clears it.
    let push = |m: Method, body| req(m, "/api/v1/push-token", Some(&fx.key), body);
    let hex = "0a".repeat(32);
    let (status, _) = send(&fx.app, push(Method::PUT, Some(json!({"token": hex})))).await;
    assert_eq!(status, StatusCode::OK);
    let targets = crate::store::gov::push_targets(&fx.app.pool).await.unwrap();
    assert_eq!(targets[0].token, hex);
    let bad = Some(json!({"token": "zz", "sandbox": true}));
    assert_eq!(
        send(&fx.app, push(Method::PUT, bad)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(&fx.app, push(Method::DELETE, None)).await.0,
        StatusCode::OK
    );
    assert!(
        crate::store::gov::push_targets(&fx.app.pool)
            .await
            .unwrap()
            .is_empty()
    );

    let added = fx
        .ok_post("/api/v1/devices", json!({"name": "iPhone"}))
        .await;
    let key = added["key"].as_str().unwrap().to_owned();
    assert!(key.starts_with("cit_device_"));
    let id = added["device"]["id"].as_i64().unwrap();
    let (status, _) = send(
        &fx.app,
        req(Method::GET, "/api/v1/devices", Some(&key), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send(
        &fx.app,
        req(
            Method::DELETE,
            &format!("/api/v1/devices/{id}"),
            Some(&fx.key),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked_at"], NOW);
    let (status, body) = send(
        &fx.app,
        req(Method::GET, "/api/v1/devices", Some(&key), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked key: {body}");
    assert_eq!(body["code"], "unauthorized");
    let (status, _) = send(
        &fx.app,
        req(
            Method::DELETE,
            &format!("/api/v1/devices/{id}"),
            Some(&fx.key),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "already revoked");
    let (status, _) = fx.post("/api/v1/devices", json!({"name": "  "})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_gate_refuses_hosts_origins_query_keys_and_bad_bearers() {
    let fx = fx().await;
    let with = |f: &dyn Fn(&mut Request<Body>)| {
        let mut r = req(Method::GET, "/api/v1/devices", Some(&fx.key), None);
        f(&mut r);
        r
    };
    let foreign = with(&|r| {
        r.headers_mut()
            .insert(header::HOST, "evil.example".parse().unwrap());
    });
    assert_eq!(send(&fx.app, foreign).await.0, StatusCode::FORBIDDEN);
    let origin = with(&|r| {
        r.headers_mut()
            .insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    });
    assert_eq!(send(&fx.app, origin).await.0, StatusCode::FORBIDDEN);

    let in_query = format!("/api/v1/devices?token={}", fx.key);
    let (status, body) = send(&fx.app, req(Method::GET, &in_query, None, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, _) = send(
        &fx.app,
        req(
            Method::GET,
            "/api/v1/devices?limit=5&after=2",
            Some(&fx.key),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "paging names pass");

    let res = router(fx.app.clone())
        .oneshot(req(Method::GET, "/api/v1/devices", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(res.headers()[header::WWW_AUTHENTICATE], "Bearer");
    let (status, _) = send(
        &fx.app,
        req(
            Method::GET,
            "/api/v1/devices",
            Some("cit_device_0123"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

fn from(peer: &str, r: Request<Body>) -> Request<Body> {
    let mut r = r;
    let addr: SocketAddr = format!("{peer}:50000").parse().unwrap();
    r.extensions_mut().insert(ConnectInfo(addr));
    r
}

#[tokio::test]
async fn failed_keys_and_busy_devices_are_rate_limited() {
    let mut fx = fx().await;
    let bad = || {
        req(
            Method::GET,
            "/api/v1/devices",
            Some("cit_device_wrong"),
            None,
        )
    };
    for _ in 0..10 {
        let (status, _) = send(&fx.app, from("10.0.0.1", bad())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let res = router(fx.app.clone())
        .oneshot(from("10.0.0.1", bad()))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().contains_key(header::RETRY_AFTER));
    // While the address is limited, even a good key from it waits; other addresses do not.
    let good = |peer| {
        from(
            peer,
            req(Method::GET, "/api/v1/devices", Some(&fx.key), None),
        )
    };
    assert_eq!(
        send(&fx.app, good("10.0.0.1")).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(send(&fx.app, good("10.0.0.2")).await.0, StatusCode::OK);

    fx.app.limits = Arc::new(Limits {
        failures: Limiter::new(10, 1.0),
        requests: Limiter::new(3, 0.001),
    });
    for _ in 0..3 {
        assert_eq!(send(&fx.app, good("10.0.0.3")).await.0, StatusCode::OK);
    }
    let (status, body) = send(&fx.app, good("10.0.0.4")).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "per key, any address"
    );
    assert_eq!(body["code"], "rate_limited");
}

#[tokio::test]
async fn behind_a_trusted_proxy_each_forwarded_client_has_its_own_failure_bucket() {
    let fx = fx().await;
    let bad = |peer, xff: &str| {
        let mut r = req(Method::GET, "/api/v1/devices", Some("cit_device_x"), None);
        r.headers_mut()
            .insert("x-forwarded-for", xff.parse().unwrap());
        from(peer, r)
    };
    for _ in 0..10 {
        send(&fx.app, bad("127.0.0.1", "198.51.100.1")).await;
    }
    let limited = send(&fx.app, bad("127.0.0.1", "198.51.100.1")).await.0;
    assert_eq!(limited, StatusCode::TOO_MANY_REQUESTS);
    // Another client through the same proxy is not limited.
    let other = send(&fx.app, bad("127.0.0.1", "198.51.100.2")).await.0;
    assert_eq!(other, StatusCode::UNAUTHORIZED);
    // An untrusted peer's header is ignored: it cannot borrow a fresh bucket.
    for _ in 0..10 {
        send(&fx.app, bad("10.0.0.9", "198.51.100.3")).await;
    }
    let spoofed = send(&fx.app, bad("10.0.0.9", "198.51.100.4")).await.0;
    assert_eq!(spoofed, StatusCode::TOO_MANY_REQUESTS);
}
