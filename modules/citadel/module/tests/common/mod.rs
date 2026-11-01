//! Shared fixtures for the module's gate tests: a Core with Citadel mounted and migrated, devices
//! with chosen scopes, and a signed request helper.
#![allow(dead_code, unused_imports)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, gov, migrate};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use citadel_module::Citadel;
use serde_json::{Value, json};
use tower::ServiceExt;

pub const HOST: &str = "core.test";
pub const BASE: &str = "/modules/citadel/v1";

pub struct Fx {
    pub app: App,
    pub dev: TestDevice,
    pub dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A Core with Citadel mounted and migrated, and an admin device logged in and elevated.
pub async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("citadel-api-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Citadel::default())];
    migrate::migrate_modules(&pool, &modules).await.unwrap();
    let identity = Arc::new(Identity::load_or_create(&dir, &ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32])).unwrap());
    let clock = Arc::new(SystemClock);
    let mut app = App::new(pool, clock.clone(), HOST.to_owned(), identity);
    app.modules = Arc::from(modules);
    let dev = enroll(&app, "mac", &gov::SCOPES, true).await;
    let session = dev.session.lock().unwrap().clone().unwrap();
    app.auth.elevate(&session, &dev.id, clock.unix() + 3600);
    Fx { app, dev, dir }
}

/// A device with `scopes` and a session that is not elevated.
pub async fn enroll(app: &App, name: &str, scopes: &[&str], stepup: bool) -> TestDevice {
    let clock = Arc::new(SystemClock);
    let dev = TestDevice::enroll_keys(
        &app.pool,
        name,
        "device",
        scopes,
        &app.auth.identity.fp,
        clock.clone(),
        stepup,
    )
    .await;
    let s = app.auth.issue_session(&dev.id, clock.unix());
    dev.set_session(Some(s.id));
    dev
}

pub async fn call(
    fx: &Fx,
    dev: Option<&TestDevice>,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    call_in(fx, dev, None, method, path, body).await
}

/// [`call`] working in company `company` (`X-Citadel-Company`), when given.
pub async fn call_in(
    fx: &Fx,
    dev: Option<&TestDevice>,
    company: Option<&str>,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let uri = format!("{BASE}{path}");
    let bytes = body.map(|v| v.to_string()).unwrap_or_default();
    let mut b = Request::builder()
        .method(method.clone())
        .uri(&uri)
        .header(header::HOST, HOST);
    if let Some(company) = company {
        b = b.header("x-citadel-company", company);
    }
    if let Some(dev) = dev {
        for (name, value) in dev.headers(method.as_str(), &uri, bytes.as_bytes()) {
            b = b.header(name, value);
        }
    }
    if !bytes.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

impl Fx {
    /// A GET as the admin device that must answer 200: the body.
    pub async fn ok(&self, path: &str) -> Value {
        let (status, body) = call(self, Some(&self.dev), Method::GET, path, None).await;
        assert_eq!(status, StatusCode::OK, "GET {path}: {body}");
        body
    }

    /// A POST as the admin device that must answer 200: the body.
    pub async fn ok_post(&self, path: &str, body: Value) -> Value {
        let (status, got) = call(self, Some(&self.dev), Method::POST, path, Some(body)).await;
        assert_eq!(status, StatusCode::OK, "POST {path}: {got}");
        got
    }
}
