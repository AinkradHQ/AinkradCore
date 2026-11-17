//! The Leyline gate (Y4-01) end to end: the step-up rules on host writes, and `gate::authorize`
//! against a real store with real Core-held approvals. Each test fails if the property it names
//! stops holding.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::ops_catalog::{Decided, decide_approval, pending};
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, migrate};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use leyline_module::Leyline;
use leyline_module::gate::{Action, Principal, authorize, authorize_many, finish};
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "core.test";
const BASE: &str = "/modules/leyline/v1";

struct Fx {
    app: App,
    admin: TestDevice,
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
        "leyline-cgate-{}-{}",
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

async fn add(fx: &Fx, name: &str, rule: &str) -> String {
    let body = json!({"name": name, "address": format!("{name}.example.com"), "username": "deploy", "ai_rule": rule});
    let (s, v) = call(fx, &fx.admin, Method::POST, "/hosts", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["id"].as_str().unwrap().to_owned()
}

/// A live AI session whose creator and runner is a fresh device.
async fn session(fx: &Fx, id: &str) -> (Principal, String) {
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
    (Principal::Session(id.to_owned()), dev.id)
}

async fn states(fx: &Fx, sql: &'static str, bind: &str) -> Vec<String> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql)) // test-only literals
        .bind(bind.to_owned())
        .fetch_all(&fx.app.pool)
        .await
        .unwrap()
}

/// The request id the session waits on, once parked.
async fn parked(fx: &Fx, session: &str) -> String {
    for _ in 0..200 {
        if let Some(p) = pending(&fx.app, session).await.unwrap().pop() {
            return p.id;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("nothing is waiting for approval");
}

fn exec() -> Action {
    Action::Exec("uptime".to_owned())
}

#[tokio::test]
async fn allowed_and_repointing_need_a_step_up_and_other_changes_do_not() {
    let fx = fx().await;
    let mut body =
        json!({"name": "a", "address": "a.example.com", "username": "u", "ai_rule": "allowed"});
    let (s, v) = call(&fx, &fx.weak, Method::POST, "/hosts", Some(body.clone())).await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    body["ai_rule"] = json!("ask");
    let (s, v) = call(&fx, &fx.weak, Method::POST, "/hosts", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "a new host starts at ask: {v}");
    let path = format!("/hosts/{}", v["id"].as_str().unwrap());
    for patch in [
        json!({"ai_rule": "allowed"}),
        json!({"address": "10.0.0.9"}),
        json!({"port": 2222}),
        json!({"username": "root"}),
        json!({"via_runner": "d_0123456789abcdef"}),
    ] {
        let (s, v) = call(&fx, &fx.weak, Method::PATCH, &path, Some(patch.clone())).await;
        assert_eq!(
            (s, &v["code"]),
            (StatusCode::FORBIDDEN, &json!("step_up_required")),
            "{patch}"
        );
    }
    for patch in [
        json!({"ai_rule": "read_only"}),
        json!({"tags": ["x"]}),
        json!({"name": "b"}),
        json!({"port": 22}),
    ] {
        let (s, v) = call(&fx, &fx.weak, Method::PATCH, &path, Some(patch.clone())).await;
        assert_eq!(s, StatusCode::OK, "{patch}: {v}");
    }
    let both = json!({"ai_rule": "allowed", "address": "10.0.0.9"});
    let (s, v) = call(&fx, &fx.admin, Method::PATCH, &path, Some(both)).await;
    assert_eq!((s, &v["ai_rule"]), (StatusCode::OK, &json!("allowed")));
}

#[tokio::test]
async fn a_person_is_allowed_and_leaves_a_run_and_audit() {
    let fx = fx().await;
    let id = add(&fx, "web", "read_only").await;
    let who = Principal::Person(fx.admin.id.clone());
    let a = authorize(&fx.app, &who, "web", &exec()).await.unwrap();
    assert_eq!(a.host_id(), id);
    let run = a.run_id().to_owned();
    assert_eq!(
        states(&fx, "SELECT state FROM leyline_runs WHERE id = ?", &run).await,
        ["running"]
    );
    let o: Vec<String> = sqlx::query_scalar(
        "SELECT origin FROM audit_events WHERE action LIKE 'leyline.run.%' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(o, ["person", "person"]);
    finish(&fx.app, a, true).await.unwrap();
    assert_eq!(
        states(&fx, "SELECT state FROM leyline_runs WHERE id = ?", &run).await,
        ["done"]
    );
    assert_eq!(
        states(
            &fx,
            "SELECT state FROM leyline_run_hosts WHERE run_id = ?",
            &run
        )
        .await,
        ["ok"]
    );
    assert!(authorize(&fx.app, &who, "nope", &exec()).await.is_err());
}

#[tokio::test]
async fn read_only_hosts_refuse_an_ai_without_asking_anyone() {
    let fx = fx().await;
    add(&fx, "ro", "read_only").await;
    let (ai, _) = session(&fx, "as_ro").await;
    let write = Action::Preset {
        id: "c".into(),
        read_only: false,
    };
    for a in [
        exec(),
        Action::Terminal,
        Action::FileWrite("/x".into()),
        write,
    ] {
        let e = authorize(&fx.app, &ai, "ro", &a).await.unwrap_err();
        assert_eq!(
            (e.status, e.code),
            (StatusCode::FORBIDDEN, "gate_refused"),
            "{a:?}"
        );
    }
    let read = Action::Preset {
        id: "c".into(),
        read_only: true,
    };
    authorize(
        &fx.app,
        &ai,
        "ro",
        &Action::FileRead("/etc/hostname".into()),
    )
    .await
    .unwrap();
    authorize(&fx.app, &ai, "ro", &read).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_code_mode_approvals")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "a refusal never parks an approval");
    assert_eq!(
        states(
            &fx,
            "SELECT CAST(count(*) AS TEXT) FROM leyline_runs WHERE principal = ? AND state = 'denied'",
            "session:as_ro"
        )
        .await,
        ["4"]
    );
}

#[tokio::test]
async fn an_ai_never_trusts_a_key_or_leases_direct_whatever_the_rule() {
    let fx = fx().await;
    add(&fx, "open", "allowed").await;
    let (ai, _) = session(&fx, "as_nt").await;
    for a in [Action::Trust, Action::Direct] {
        assert!(authorize(&fx.app, &ai, "open", &a).await.is_err(), "{a:?}");
    }
    assert!(
        authorize(&fx.app, &Principal::Health, "open", &exec())
            .await
            .is_err()
    );
    authorize(&fx.app, &Principal::Health, "open", &Action::Probe)
        .await
        .unwrap();
    // `allowed` runs at once and is audited as the AI session.
    authorize(&fx.app, &ai, "open", &exec()).await.unwrap();
    let o: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT origin, origin_ref FROM audit_events WHERE action = 'leyline.run.allowed' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert!(
        o.contains(&("ai_session".to_owned(), Some("as_nt".to_owned()))),
        "{o:?}"
    );
}

#[tokio::test]
async fn an_ended_session_runs_nothing() {
    let fx = fx().await;
    add(&fx, "open", "allowed").await;
    let (ai, _) = session(&fx, "as_end").await;
    sqlx::query("UPDATE core_agent_sessions SET state = 'ended' WHERE id = 'as_end'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert!(authorize(&fx.app, &ai, "open", &exec()).await.is_err());
}

#[tokio::test]
async fn one_approval_runs_exactly_one_execution() {
    let fx = fx().await;
    let id = add(&fx, "ask-1", "ask").await;
    let (ai, dev) = session(&fx, "as_ask").await;
    let app = fx.app.clone();
    let who = ai.clone();
    let h = tokio::spawn(async move { authorize(&app, &who, "ask-1", &exec()).await });
    let req = parked(&fx, "as_ask").await;
    // The card names the op and the host label, never key material.
    let p = pending(&fx.app, "as_ask").await.unwrap().pop().unwrap();
    assert_eq!(p.tool, "ainkrad.leylineExec");
    assert_eq!(p.args["hosts"], json!(["ask-1"]));
    assert_eq!(
        decide_approval(&fx.app, "as_ask", &req, true, &dev)
            .await
            .unwrap(),
        Decided::Done
    );
    let a = tokio::time::timeout(Duration::from_secs(10), h)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(a.host_id(), id);
    assert_eq!(
        states(
            &fx,
            "SELECT state FROM core_code_mode_approvals WHERE id = ?",
            &req
        )
        .await,
        ["used"]
    );
    // Spent: it cannot be decided or consumed again.
    assert_eq!(
        decide_approval(&fx.app, "as_ask", &req, true, &dev)
            .await
            .unwrap(),
        Decided::Closed
    );
    // A second call asks again, with a new approval.
    let app = fx.app.clone();
    let h2 = tokio::spawn(async move { authorize(&app, &ai, "ask-1", &exec()).await });
    let req2 = parked(&fx, "as_ask").await;
    assert_ne!(req, req2);
    h2.abort();
}

#[tokio::test]
async fn a_denied_approval_runs_nothing() {
    let fx = fx().await;
    add(&fx, "ask-2", "ask").await;
    let (ai, dev) = session(&fx, "as_deny").await;
    let app = fx.app.clone();
    let h = tokio::spawn(async move { authorize(&app, &ai, "ask-2", &exec()).await });
    let req = parked(&fx, "as_deny").await;
    decide_approval(&fx.app, "as_deny", &req, false, &dev)
        .await
        .unwrap();
    let e = tokio::time::timeout(Duration::from_secs(10), h)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!((e.status, e.code), (StatusCode::FORBIDDEN, "gate_refused"));
    assert_eq!(
        states(
            &fx,
            "SELECT state FROM leyline_runs WHERE principal = ?",
            "session:as_deny"
        )
        .await,
        ["denied"]
    );
}

#[tokio::test]
async fn a_fleet_with_ask_hosts_asks_once_and_refuses_the_read_only_one() {
    let fx = fx().await;
    let a = add(&fx, "f-a", "ask").await;
    let b = add(&fx, "f-b", "ask").await;
    let c = add(&fx, "f-c", "read_only").await;
    let d = add(&fx, "f-d", "allowed").await;
    let (ai, dev) = session(&fx, "as_fleet").await;
    let app = fx.app.clone();
    let h = tokio::spawn(async move {
        authorize_many(&app, &ai, &["f-a", "f-b", "f-c", "f-d"], &exec()).await
    });
    let req = parked(&fx, "as_fleet").await;
    let p = pending(&fx.app, "as_fleet").await.unwrap();
    assert_eq!(p.len(), 1, "one approval for the whole run");
    assert_eq!(p[0].args["hosts"], json!(["f-a", "f-b"]));
    decide_approval(&fx.app, "as_fleet", &req, true, &dev)
        .await
        .unwrap();
    let g = tokio::time::timeout(Duration::from_secs(10), h)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut got: Vec<&str> = g.authorized.iter().map(|x| x.host_id()).collect();
    got.sort_unstable();
    let mut want = vec![a.as_str(), b.as_str(), d.as_str()];
    want.sort_unstable();
    assert_eq!(got, want);
    assert_eq!(g.refused.len(), 1);
    assert_eq!(g.refused[0].0, c);
}
