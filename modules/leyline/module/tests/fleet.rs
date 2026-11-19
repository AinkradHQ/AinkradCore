//! Fleet runs (Y4-03) end to end: targets resolve to hosts, one run holds one result row per host,
//! and a cancel ends the run so no later step passes `still_valid`. Each test fails if the property
//! it names stops holding.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, gov, migrate};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use leyline_module::Leyline;
use leyline_module::gate::{Action, Principal, authorize_many, still_valid};
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "core.test";
const BASE: &str = "/modules/leyline/v1";

struct Fx {
    app: App,
    admin: TestDevice,
    #[allow(dead_code)]
    weak: TestDevice,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn enroll(app: &App, name: &str, scopes: &[&str]) -> TestDevice {
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

async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "leyline-fleet-{}-{}",
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
    admin.unlock(&app.auth, clock.unix() + 3600);
    let weak = enroll(&app, "weak", &["admin", "read"]).await; // never stepped up
    Fx {
        app,
        admin,
        weak,
        dir,
    }
}

async fn call(
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

/// Creates a command as the stepped-up admin; the body's `name` and `steps` are the caller's.
async fn mk(fx: &Fx, body: Value) -> Value {
    let (s, v) = call(fx, &fx.admin, Method::POST, "/commands", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

async fn tagged(fx: &Fx, name: &str, group: &str) -> String {
    let body = json!({"name": name, "address": format!("{name}.example.com"), "username": "deploy",
        "ai_rule": "ask", "group": group});
    let (s, v) = call(fx, &fx.admin, Method::POST, "/hosts", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["id"].as_str().unwrap().to_owned()
}

async fn finished(fx: &Fx, run: &str) -> Value {
    for _ in 0..300 {
        let (_, r) = call(fx, &fx.admin, Method::GET, &format!("/runs/{run}"), None).await;
        if r["state"] == "done" {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the run never finished");
}

#[tokio::test]
async fn a_fleet_is_one_run_with_one_result_per_host() {
    let fx = fx().await;
    let (a, b) = (
        tagged(&fx, "web1", "web").await,
        tagged(&fx, "web2", "web").await,
    );
    let other = tagged(&fx, "db1", "db").await;
    let c = mk(
        &fx,
        json!({"name": "c", "steps": ["first-step", "second-step"]}),
    )
    .await;
    let cid = c["id"].as_str().unwrap();
    // Group + a named host that is also in the group: the host is run once.
    let body = json!({"command": cid, "group": "web", "hosts": ["web1"]});
    let (s, v) = call(&fx, &fx.admin, Method::POST, "/fleet/runs", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v["started"].as_u64(), v["refused"].as_u64()),
        (Some(2), Some(0)),
        "{v}"
    );
    let got = finished(&fx, v["run"].as_str().unwrap()).await;
    let hosts = got["hosts"].as_array().unwrap();
    let ids: Vec<&str> = hosts
        .iter()
        .map(|h| h["host_id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&a.as_str()) && ids.contains(&b.as_str()) && !ids.contains(&other.as_str())
    );
    // This Core has no runner: every host fails at step 1 on its own and never tries step 2.
    for h in hosts {
        assert_eq!(
            (&h["state"], &h["step"]),
            (&json!("failed"), &json!(1)),
            "{h}"
        );
        let out = h["output"].as_str().unwrap();
        assert!(
            out.contains("$ first-step") && !out.contains("second-step"),
            "{out}"
        );
    }
    // Nothing named, an unknown host and a missing confirm are refused before the gate.
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/fleet/runs",
        Some(json!({"command": cid})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let body = json!({"command": cid, "hosts": ["nope"]});
    let (s, _) = call(&fx, &fx.admin, Method::POST, "/fleet/runs", Some(body)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let m = mk(&fx, json!({"name": "m", "steps": ["x"], "confirm": true})).await;
    let body = json!({"command": m["id"], "group": "web"});
    let (s, _) = call(&fx, &fx.admin, Method::POST, "/fleet/runs", Some(body)).await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn cancel_ends_a_running_run_and_stops_its_later_steps() {
    let fx = fx().await;
    let h = tagged(&fx, "web1", "web").await;
    let c = mk(&fx, json!({"name": "c", "steps": ["a", "b"]})).await;
    let me = gov::get_device(&fx.app.pool, &fx.admin.id)
        .await
        .unwrap()
        .unwrap();
    let who = Principal::of(&ainkrad_core_server::api::v1::Caller {
        device: me,
        session: "a-real-session".into(),
    });
    // A gated run with no driver, so the test decides when it ends.
    let g = authorize_many(
        &fx.app,
        &who,
        &[&h],
        &Action::Preset(c["id"].as_str().unwrap().into()),
    )
    .await
    .unwrap();
    assert_eq!(g.authorized.len(), 1);
    still_valid(&fx.app, &g.authorized[0]).await.unwrap();
    let path = format!("/runs/{}/cancel", g.run);
    let (s, v) = call(&fx, &fx.admin, Method::POST, &path, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(still_valid(&fx.app, &g.authorized[0]).await.is_err());
    let (s, _) = call(&fx, &fx.admin, Method::POST, &path, None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _) = call(&fx, &fx.admin, Method::POST, "/runs/lr_nope/cancel", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, r) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/runs/{}", g.run),
        None,
    )
    .await;
    assert_eq!(r["state"], "cancelled");
}
