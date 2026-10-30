//! The org routes end to end through the Core's client gate: signed, scoped, step-up on the
//! destructive ones, audited, and the module's migrations applied on top of the platform's.

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

const HOST: &str = "core.test";
const BASE: &str = "/modules/citadel/v1";

struct Fx {
    app: App,
    dev: TestDevice,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A Core with Citadel mounted and migrated, and an admin device logged in and elevated.
async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("citadel-api-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Citadel)];
    migrate::migrate_modules(&pool, &modules).await.unwrap();
    let identity = Arc::new(Identity::load_or_create(&dir).unwrap());
    let clock = Arc::new(SystemClock);
    let mut app = App::new(pool, clock.clone(), HOST.to_owned(), identity);
    app.modules = Arc::from(modules);
    let dev = enroll(&app, "mac", &gov::SCOPES, true).await;
    let session = dev.session.lock().unwrap().clone().unwrap();
    app.auth.elevate(&session, &dev.id, clock.unix() + 3600);
    Fx { app, dev, dir }
}

/// A device with `scopes` and a session that is not elevated.
async fn enroll(app: &App, name: &str, scopes: &[&str], stepup: bool) -> TestDevice {
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

async fn call(
    fx: &Fx,
    dev: Option<&TestDevice>,
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

async fn actions(fx: &Fx) -> Vec<String> {
    sqlx::query_scalar("SELECT action FROM audit_events WHERE action LIKE 'citadel.%' ORDER BY seq")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_company_is_created_listed_changed_and_audited() {
    let fx = fx().await;
    let d = Some(&fx.dev);
    let (status, c) = call(
        &fx,
        d,
        Method::POST,
        "/companies",
        Some(json!({"name": " Ainkrad ", "kind": "client"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{c}");
    assert_eq!(
        (&c["name"], &c["kind"]),
        (&json!("Ainkrad"), &json!("client"))
    );
    let id = c["id"].as_i64().unwrap();

    let (_, list) = call(&fx, d, Method::GET, "/companies", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (status, c) = call(
        &fx,
        d,
        Method::PUT,
        &format!("/companies/{id}"),
        Some(json!({"name": "Ainkrad HQ"})),
    )
    .await;
    assert_eq!(
        (status, &c["name"], &c["kind"]),
        (StatusCode::OK, &json!("Ainkrad HQ"), &json!("client"))
    );
    assert_eq!(
        call(&fx, d, Method::GET, "/companies/99", None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        actions(&fx).await,
        ["citadel.company.created", "citadel.company.updated"]
    );
}

#[tokio::test]
async fn bad_input_is_refused_before_anything_is_written() {
    let fx = fx().await;
    let d = Some(&fx.dev);
    let blank = call(
        &fx,
        d,
        Method::POST,
        "/companies",
        Some(json!({"name": "  "})),
    )
    .await;
    assert_eq!(blank.0, StatusCode::BAD_REQUEST);
    let kind = call(
        &fx,
        d,
        Method::POST,
        "/companies",
        Some(json!({"name": "A", "kind": "x"})),
    )
    .await;
    assert_eq!(kind.0, StatusCode::BAD_REQUEST);
    assert!(actions(&fx).await.is_empty());
    // A duplicate department name is a conflict, and writes no audit row.
    let (_, c) = call(
        &fx,
        d,
        Method::POST,
        "/companies",
        Some(json!({"name": "A"})),
    )
    .await;
    let path = format!("/companies/{}/departments", c["id"]);
    assert_eq!(
        call(&fx, d, Method::POST, &path, Some(json!({"name": "Eng"})))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&fx, d, Method::POST, &path, Some(json!({"name": "Eng"})))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        actions(&fx).await,
        ["citadel.company.created", "citadel.department.added"]
    );
}

#[tokio::test]
async fn departments_and_teams_nest_and_deleting_one_takes_its_teams() {
    let fx = fx().await;
    let d = Some(&fx.dev);
    let (_, c) = call(
        &fx,
        d,
        Method::POST,
        "/companies",
        Some(json!({"name": "A"})),
    )
    .await;
    let (_, dep) = call(
        &fx,
        d,
        Method::POST,
        &format!("/companies/{}/departments", c["id"]),
        Some(json!({"name": "Eng"})),
    )
    .await;
    let teams = format!("/departments/{}/teams", dep["id"]);
    let (_, team) = call(&fx, d, Method::POST, &teams, Some(json!({"name": "Core"}))).await;
    let (status, team) = call(
        &fx,
        d,
        Method::PUT,
        &format!("/teams/{}", team["id"]),
        Some(json!({"name": "Platform"})),
    )
    .await;
    assert_eq!(
        (status, &team["name"]),
        (StatusCode::OK, &json!("Platform"))
    );
    assert_eq!(
        call(&fx, d, Method::GET, &teams, None)
            .await
            .1
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let gone = format!("/departments/{}", dep["id"]);
    assert_eq!(
        call(&fx, d, Method::DELETE, &gone, None).await.0,
        StatusCode::OK
    );
    assert!(
        call(&fx, d, Method::GET, &teams, None)
            .await
            .1
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        call(&fx, d, Method::DELETE, &gone, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&fx, d, Method::GET, "/agents/1", None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_core_gate_covers_the_module_scope_and_step_up() {
    let fx = fx().await;
    let (_, c) = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        "/companies",
        Some(json!({"name": "A"})),
    )
    .await;
    assert_eq!(
        call(&fx, None, Method::GET, "/companies", None).await.0,
        StatusCode::UNAUTHORIZED
    );

    let phone = enroll(&fx.app, "phone", &["read"], true).await;
    let (status, body) = call(&fx, Some(&phone), Method::GET, "/companies", None).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
    );

    // Deleting a department is destructive: admin scope is not enough without a step-up.
    let (_, dep) = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        &format!("/companies/{}/departments", c["id"]),
        Some(json!({"name": "Eng"})),
    )
    .await;
    let plain = enroll(&fx.app, "laptop", &["admin"], true).await;
    let gone = format!("/departments/{}", dep["id"]);
    let (status, body) = call(&fx, Some(&plain), Method::DELETE, &gone, None).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    assert_eq!(
        call(&fx, Some(&fx.dev), Method::DELETE, &gone, None)
            .await
            .0,
        StatusCode::OK
    );
}
