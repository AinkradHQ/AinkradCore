//! The client API's gate (handshake spec §5.3): host, origin, Authorization, query names,
//! signatures, lockouts and request limits. The route groups (E10.1) and the signed-request
//! cases of spec §17 are tested on the same fixture in their own files.

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
use crate::auth::Identity;
use crate::auth::testing::TestDevice;
use crate::scheduler::Clock;
use crate::store::connect;

mod abuse;
mod agents;
mod audit_growth;
mod devices;
mod events;
mod me;
mod modules;
mod pairing;
mod pairing_abuse;
mod passkeys;
mod preauth;
mod revocation;
mod runners;
mod scoped;
mod scopes;
mod secrets;
mod sessions;
mod settings;
mod signed;
mod stepup;
mod token;
mod web;
mod web_socket;

pub(super) const NOW: &str = "2026-10-22T10:00:00.000Z";
pub(super) const HOST: &str = "core.test";
/// Every scope: the fixture device is the admin's Mac.
pub(super) const ALL: [&str; 6] = crate::store::gov::SCOPES;

pub(super) struct FixedClock(pub Mutex<String>);

impl Clock for FixedClock {
    fn now(&self) -> String {
        self.0.lock().unwrap().clone()
    }
}

impl FixedClock {
    pub fn set(&self, at: &str) {
        *self.0.lock().unwrap() = at.to_owned();
    }

    /// Moves the clock by `secs`.
    pub fn advance(&self, secs: i64) {
        let at = crate::scheduler::iso_of_unix(self.unix() + secs);
        self.set(&at);
    }
}

/// A migrated database in its own temp dir (removed on drop), an app on it, and an enrolled
/// device with a session.
pub(super) struct Fx {
    pub app: App,
    pub clock: Arc<FixedClock>,
    pub dev: TestDevice,
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
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    // The kinds and actions the route tests write, as a module would declare them.
    let actions = [
        "thing.started",
        "thing.done",
        "thing.archived",
        "thing.reopened",
    ];
    crate::store::kinds::allow(&pool, &["ops.line", "ops.blob"], &actions).await;
    let clock = Arc::new(FixedClock(Mutex::new(NOW.to_owned())));
    let identity = Arc::new(Identity::load_or_create(&dir).unwrap());
    let app = App::new(pool, clock.clone(), HOST.to_owned(), identity);
    let dev = enroll(&app, &clock, "test", &ALL).await;
    Fx {
        app,
        clock,
        dev,
        dir,
    }
}

/// A new device enrolled with `scopes` and logged in (a session issued directly), elevated as
/// if it had stepped up (`stepup` tests the real thing).
async fn enroll(app: &App, clock: &Arc<FixedClock>, name: &str, scopes: &[&str]) -> TestDevice {
    let dev = TestDevice::enroll(
        &app.pool,
        name,
        "device",
        scopes,
        &app.auth.identity.fp,
        clock.clone(),
    )
    .await;
    let s = app.auth.issue_session(&dev.id, clock.unix());
    app.auth
        .elevate(&s.id, &dev.id, clock.unix() + 10 * 365 * 86_400);
    dev.set_session(Some(s.id));
    dev
}

impl Fx {
    pub async fn enroll(&self, name: &str, scopes: &[&str]) -> TestDevice {
        enroll(&self.app, &self.clock, name, scopes).await
    }

    /// A device the Core has never seen, signing for this Core.
    pub fn stranger(&self) -> TestDevice {
        let dev = TestDevice::new(&self.app.auth.identity.fp, self.clock.clone());
        dev.set_session(Some(crate::auth::crypto::random_id("s_")));
        dev
    }

    /// The Core restarted: the same database and identity key, nothing in memory.
    pub fn restart(&mut self) {
        let identity = Arc::clone(&self.app.auth.identity);
        self.app.auth = Arc::new(crate::auth::Auth::new(identity));
    }
}

/// A request as the app sends it: our host, JSON, signed by `dev` (if any) over the exact
/// body bytes.
pub(super) fn req(
    method: Method,
    uri: &str,
    dev: Option<&TestDevice>,
    body: Option<Value>,
) -> Request<Body> {
    let bytes = body.map(|v| v.to_string()).unwrap_or_default();
    let mut b = Request::builder()
        .method(method.clone())
        .uri(uri)
        .header(header::HOST, HOST);
    if let Some(dev) = dev {
        for (name, value) in dev.headers(method.as_str(), uri, bytes.as_bytes()) {
            b = b.header(name, value);
        }
    }
    if !bytes.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(Body::from(bytes)).unwrap()
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
        send(&self.app, req(Method::GET, uri, Some(&self.dev), None)).await
    }

    /// `get` that must answer 200.
    pub async fn ok(&self, uri: &str) -> Value {
        let (status, body) = self.get(uri).await;
        assert_eq!(status, StatusCode::OK, "GET {uri}: {body}");
        body
    }
}

/// Every operation in the contract is routed, and answers 401 unsigned.
#[tokio::test]
async fn every_operation_in_the_contract_is_routed_and_needs_a_signature() {
    let mut fx = fx().await;
    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(1000, 1.0),
    });
    let spec: Value = serde_json::from_str(&super::spec::json()).unwrap();
    let mut n = 0;
    for (path, item) in spec["paths"].as_object().unwrap() {
        let uri = path.replace("{id}", &fx.stranger().id);
        for (method, op) in item.as_object().unwrap() {
            let m: Method = method.to_uppercase().parse().unwrap();
            // `security: [{}]`: an operation that needs no session (the handshake).
            if op["security"] == json!([{}]) {
                n += 1;
                continue;
            }
            let (status, body) = send(&fx.app, req(m.clone(), &uri, None, None)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{m} {uri}: {body}");
            // Unrouted is a bare 404 or 405; a route's own 404 says what is missing.
            let (status, body) = send(&fx.app, req(m.clone(), &uri, Some(&fx.dev), None)).await;
            let routed = status != StatusCode::METHOD_NOT_ALLOWED
                && (status != StatusCode::NOT_FOUND || body["code"] == "not_found");
            assert!(routed, "{m} {uri} is not routed: {status}");
            n += 1;
        }
    }
    assert!(n >= 18, "{n} operations");
}

#[tokio::test]
async fn a_device_lists_and_revokes_devices_and_sets_its_push_token() {
    let fx = fx().await;
    let list = fx.ok("/api/v1/devices").await;
    assert_eq!(list[0]["name"], "test");
    assert_eq!(list[0]["id"], fx.dev.id.as_str());
    assert_eq!(list[0]["kind"], "device");
    assert_eq!(list[0]["status"], "active");
    assert_eq!(list[0]["scopes"], json!(ALL));
    assert_eq!(list[0]["fingerprint"].as_str().unwrap().len(), 43);
    assert_eq!(list[0]["last_used_at"], NOW, "use is recorded");
    let later = "2026-10-22T10:05:00.000Z";
    fx.clock.set(later);
    assert_eq!(fx.ok("/api/v1/devices").await[0]["last_used_at"], later);
    fx.clock.set(NOW);

    // The calling device registers its APNs token, and clears it.
    let push = |m: Method, body| req(m, "/api/v1/push-token", Some(&fx.dev), body);
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

    // Another device works until it is revoked; then it is refused like a stranger.
    let phone = fx.enroll("iPhone", &["read", "approve"]).await;
    let (status, _) = send(&fx.app, req(Method::GET, "/api/v1/me", Some(&phone), None)).await;
    assert_eq!(status, StatusCode::OK);
    let uri = format!("/api/v1/devices/{}", phone.id);
    let (status, body) = send(&fx.app, req(Method::DELETE, &uri, Some(&fx.dev), None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked_at"], NOW);
    let (status, body) = send(&fx.app, req(Method::GET, "/api/v1/me", Some(&phone), None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked: {body}");
    assert_eq!(body["code"], "auth_failed");
    let (status, _) = send(&fx.app, req(Method::DELETE, &uri, Some(&fx.dev), None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "already revoked");
    let (status, _) = send(
        &fx.app,
        req(Method::DELETE, "/api/v1/devices/42", Some(&fx.dev), None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "not a device id");
}

#[tokio::test]
async fn the_gate_refuses_hosts_origins_authorization_and_query_names() {
    let fx = fx().await;
    let with = |f: &dyn Fn(&mut Request<Body>)| {
        let mut r = req(Method::GET, "/api/v1/devices", Some(&fx.dev), None);
        f(&mut r);
        r
    };
    let foreign = with(&|r| {
        r.headers_mut()
            .insert(header::HOST, "evil.example".parse().unwrap());
    });
    let (status, body) = send(&fx.app, foreign).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("unknown_host"))
    );
    let origin = with(&|r| {
        r.headers_mut()
            .insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    });
    let (status, body) = send(&fx.app, origin).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("origin_refused"))
    );
    let bearer = with(&|r| {
        r.headers_mut().insert(
            header::AUTHORIZATION,
            "Bearer cit_device_x".parse().unwrap(),
        );
    });
    let (status, body) = send(&fx.app, bearer).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("bad_request"))
    );

    let (status, body) = send(
        &fx.app,
        req(Method::GET, "/api/v1/devices?token=x", Some(&fx.dev), None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, _) = send(
        &fx.app,
        req(
            Method::GET,
            "/api/v1/devices?limit=5&after=2",
            Some(&fx.dev),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "paging names pass, signed");

    let res = router(fx.app.clone())
        .oneshot(req(Method::GET, "/api/v1/devices", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no signing headers");
    let stranger = fx.stranger();
    let res = router(fx.app.clone())
        .oneshot(req(Method::GET, "/api/v1/devices", Some(&stranger), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(res.headers()[header::WWW_AUTHENTICATE], "Ainkrad-ES256");
}

pub(super) fn from(peer: &str, r: Request<Body>) -> Request<Body> {
    let mut r = r;
    let addr: SocketAddr = format!("{peer}:50000").parse().unwrap();
    r.extensions_mut().insert(ConnectInfo(addr));
    r
}

#[tokio::test]
async fn failed_signatures_lock_the_address_and_busy_devices_are_rate_limited() {
    let mut fx = fx().await;
    // A new stranger each time, so the address lock (20) comes before any (address, device)
    // lock (5).
    let bad = || req(Method::GET, "/api/v1/devices", Some(&fx.stranger()), None);
    for _ in 0..20 {
        let (status, body) = send(&fx.app, from("10.0.0.1", bad())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
    let res = router(fx.app.clone())
        .oneshot(from("10.0.0.1", bad()))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res.headers()[header::RETRY_AFTER], "60");
    // While the address is locked, even a good device from it waits; other addresses do not.
    let good = |peer| {
        from(
            peer,
            req(Method::GET, "/api/v1/devices", Some(&fx.dev), None),
        )
    };
    assert_eq!(
        send(&fx.app, good("10.0.0.1")).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(send(&fx.app, good("10.0.0.2")).await.0, StatusCode::OK);

    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(3, 0.001),
    });
    for _ in 0..3 {
        assert_eq!(send(&fx.app, good("10.0.0.3")).await.0, StatusCode::OK);
    }
    let (status, body) = send(&fx.app, good("10.0.0.4")).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "per device, any address"
    );
    assert_eq!(body["code"], "rate_limited");
}

#[tokio::test]
async fn forwarded_for_counts_only_from_a_configured_proxy() {
    let mut fx = fx().await;
    let bad = |fx: &Fx, peer, xff: &str| {
        let mut r = req(Method::GET, "/api/v1/devices", Some(&fx.stranger()), None);
        r.headers_mut()
            .insert("x-forwarded-for", xff.parse().unwrap());
        from(peer, r)
    };
    // By default no proxy is trusted: a spoofed header does not pick another limiter key.
    for n in 0..20 {
        send(&fx.app, bad(&fx, "10.0.0.9", &format!("198.51.100.{n}"))).await;
    }
    let spoofed = send(&fx.app, bad(&fx, "10.0.0.9", "198.51.100.99")).await.0;
    assert_eq!(spoofed, StatusCode::TOO_MANY_REQUESTS);

    // Behind a configured proxy each forwarded client has its own key.
    fx.app.trusted_proxies = Arc::new(crate::api::limit::Cidr::LOOPBACK);
    for _ in 0..20 {
        send(&fx.app, bad(&fx, "127.0.0.1", "198.51.100.1")).await;
    }
    let limited = send(&fx.app, bad(&fx, "127.0.0.1", "198.51.100.1")).await.0;
    assert_eq!(limited, StatusCode::TOO_MANY_REQUESTS);
    let other = send(&fx.app, bad(&fx, "127.0.0.1", "198.51.100.2")).await.0;
    assert_eq!(other, StatusCode::UNAUTHORIZED);
}

async fn refusals(pool: &SqlitePool) -> Vec<Value> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'api.refused' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    rows.iter()
        .map(|d| serde_json::from_str(d).unwrap())
        .collect()
}

/// Every error carries an id; a refused write is audited with it, a refused read or an
/// unauthenticated request is not.
#[tokio::test]
async fn every_error_carries_an_id_and_only_refused_writes_are_audited() {
    let fx = fx().await;
    let (status, body) = fx.get("/api/v1/settings/server/no.such").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error_id"].as_str().unwrap().starts_with("err_"));
    let (_, again) = fx.get("/api/v1/settings/server/no.such").await;
    assert_ne!(body["error_id"], again["error_id"]);
    let stranger = fx.stranger();
    let unsigned = req(Method::PUT, "/api/v1/push-token", Some(&stranger), None);
    assert_eq!(send(&fx.app, unsigned).await.0, StatusCode::UNAUTHORIZED);
    assert!(
        refusals(&fx.app.pool).await.is_empty(),
        "a read and an unauthenticated request are no refused writes"
    );

    let bad = req(
        Method::PUT,
        "/api/v1/push-token",
        Some(&fx.dev),
        Some(json!({"token": "zz"})),
    );
    let (status, body) = send(&fx.app, bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let refused = refusals(&fx.app.pool).await;
    assert_eq!(refused.len(), 1);
    assert_eq!(
        refused[0]["error_id"], body["error_id"],
        "the id finds its audit row"
    );
    assert_eq!(
        (
            &refused[0]["method"],
            &refused[0]["path"],
            &refused[0]["code"],
            &refused[0]["device"]
        ),
        (
            &json!("PUT"),
            &json!("/api/v1/push-token"),
            &json!("bad_request"),
            &json!(fx.dev.id)
        )
    );
}
