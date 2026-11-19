#![allow(dead_code, unused_imports)] // each test file uses part of this
//! Shared fixture for the Y4-02 review-fix tests (the same one tests/commands.rs builds).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ainkrad_core_server::api::v1::Caller;
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, gov, migrate};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use leyline_module::Leyline;
use leyline_module::gate::{Action, Principal, authorize, finish, still_valid};
use serde_json::{Value, json};
use tower::ServiceExt;

pub const HOST: &str = "core.test";
pub const BASE: &str = "/modules/leyline/v1";

pub struct Fx {
    pub app: App,
    pub admin: TestDevice,
    pub weak: TestDevice,
    pub dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub async fn enroll(app: &App, name: &str, scopes: &[&str]) -> TestDevice {
    let clock = Arc::new(SystemClock);
    let dev = TestDevice::enroll_keys(
        &app.pool,
        name,
        "device",
        scopes,
        &app.auth.identity.fp,
        clock.clone(),
        true,
    )
    .await;
    dev.set_session(Some(app.auth.issue_session(&dev.id, clock.unix()).id));
    dev
}

pub async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "leyline-cmds-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Leyline)];
    migrate::migrate_modules(&pool, &modules).await.unwrap();
    let identity = Arc::new(
        Identity::load_or_create(
            &dir,
            &ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32]),
        )
        .unwrap(),
    );
    let clock = Arc::new(SystemClock);
    let mut app = App::new(pool, clock.clone(), HOST.to_owned(), identity);
    app.modules = Arc::from(modules);
    let admin = enroll(&app, "admin", &["admin", "read"]).await;
    let session = admin.session.lock().unwrap().clone().unwrap();
    app.auth.elevate(&session, &admin.id, clock.unix() + 3600);
    app.auth.unlock(&admin.id, clock.unix() + 3600);
    let weak = enroll(&app, "weak", &["admin", "read"]).await; // never stepped up
    Fx {
        app,
        admin,
        weak,
        dir,
    }
}

pub async fn call(
    fx: &Fx,
    dev: &TestDevice,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let uri = format!("{BASE}{path}");
    let bytes = body.map(|b| b.to_string()).unwrap_or_default();
    let mut b = Request::builder()
        .method(method.clone())
        .uri(&uri)
        .header(header::HOST, HOST);
    for (n, v) in dev.headers(method.as_str(), &uri, bytes.as_bytes()) {
        b = b.header(n, v);
    }
    if !bytes.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let raw = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (status, serde_json::from_slice(&raw).unwrap_or(Value::Null))
}

pub async fn add(fx: &Fx, name: &str, rule: &str) -> String {
    let body = json!({"name": name, "address": format!("{name}.example.com"), "username": "deploy", "ai_rule": rule});
    let (s, v) = call(fx, &fx.admin, Method::POST, "/hosts", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["id"].as_str().unwrap().to_owned()
}

/// A live AI session whose creator and runner is a fresh device.
pub async fn session(fx: &Fx, id: &str) -> (Principal, String) {
    let dev = enroll(&fx.app, &format!("creator-{id}"), &["read"]).await;
    sqlx::query(
        "INSERT INTO core_agent_sessions (id, runner, harness, state, created_by, created_at, updated_at) \
         VALUES (?, ?, 'claude', 'running', ?, '2026-11-17T00:00:00Z', '2026-11-17T00:00:00Z')",
    )
    .bind(id)
    .bind(&dev.id)
    .bind(&dev.id)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let me = caller(fx, &dev.id, &format!("code_mode:{id}")).await;
    (Principal::of(&me), dev.id)
}

pub async fn caller(fx: &Fx, device: &str, session: &str) -> Caller {
    Caller {
        device: gov::get_device(&fx.app.pool, device)
            .await
            .unwrap()
            .unwrap(),
        session: session.to_owned(),
    }
}

pub async fn person(fx: &Fx) -> Principal {
    Principal::of(&caller(fx, &fx.admin.id, "a-real-session").await)
}

pub async fn states(fx: &Fx, sql: &'static str, bind: &str) -> Vec<String> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql)) // test-only literals
        .bind(bind.to_owned())
        .fetch_all(&fx.app.pool)
        .await
        .unwrap()
}

pub fn who() -> ainkrad_core_server::store::projects::Who<'static> {
    ainkrad_core_server::store::projects::Who {
        by_device: "d_test",
        actor: ainkrad_core_server::api::v1::BY,
        now: "2026-11-17T00:00:00Z",
    }
}

pub async fn project(fx: &Fx, slug: &str) -> i64 {
    ainkrad_core_server::store::projects::create(&fx.app.pool, slug, slug, "", "manual", who())
        .await
        .unwrap()
        .id
}

/// Creates a command as the stepped-up admin; the body's `name` and `steps` are the caller's.
/// Creates a command as the stepped-up admin.
pub async fn mk(fx: &Fx, body: Value) -> Value {
    let (s, v) = call(fx, &fx.admin, Method::POST, "/commands", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

/// A request to the module's routes as `me` directly (how Code Mode reaches them: no HTTP auth).
pub async fn as_caller(
    fx: &Fx,
    me: Caller,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let bytes = body.map(|b| b.to_string()).unwrap_or_default();
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST);
    if !bytes.is_empty() {
        req = req.header(header::CONTENT_TYPE, "application/json");
    }
    let mut req = req.body(Body::from(bytes)).unwrap();
    req.extensions_mut().insert(me);
    let res = Leyline
        .routes()
        .with_state(fx.app.clone())
        .oneshot(req)
        .await
        .unwrap();
    let status = res.status();
    let raw = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (status, serde_json::from_slice(&raw).unwrap_or(Value::Null))
}

/// Runs command `cmd` on `host` as the stepped-up admin, confirmed.
pub async fn run_of(fx: &Fx, cmd: &str, host: &str) -> (StatusCode, Value) {
    let body = json!({"host": host, "confirm": true});
    call(
        fx,
        &fx.admin,
        Method::POST,
        &format!("/commands/{cmd}/run"),
        Some(body),
    )
    .await
}
