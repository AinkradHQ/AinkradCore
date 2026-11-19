//! Pre-set commands (Y4-02) end to end: the CRUD and its step-up rules, scopes, the gate reading a
//! command's flag and steps itself, a run that stops at its first failure, and a run in flight
//! that an edit cannot change. Each test fails if the property it names stops holding.

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
    let me = caller(fx, &dev.id, &format!("code_mode:{id}")).await;
    (Principal::of(&me), dev.id)
}

async fn caller(fx: &Fx, device: &str, session: &str) -> Caller {
    Caller {
        device: gov::get_device(&fx.app.pool, device)
            .await
            .unwrap()
            .unwrap(),
        session: session.to_owned(),
    }
}

async fn person(fx: &Fx) -> Principal {
    Principal::of(&caller(fx, &fx.admin.id, "a-real-session").await)
}

#[allow(dead_code)] // the shared helper's twin: kept so the files read alike
async fn states(fx: &Fx, sql: &'static str, bind: &str) -> Vec<String> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql)) // test-only literals
        .bind(bind.to_owned())
        .fetch_all(&fx.app.pool)
        .await
        .unwrap()
}

fn who() -> ainkrad_core_server::store::projects::Who<'static> {
    ainkrad_core_server::store::projects::Who {
        by_device: "d_test",
        actor: ainkrad_core_server::api::v1::BY,
        now: "2026-11-17T00:00:00Z",
    }
}

async fn project(fx: &Fx, slug: &str) -> i64 {
    ainkrad_core_server::store::projects::create(&fx.app.pool, slug, slug, "", "manual", who())
        .await
        .unwrap()
        .id
}

/// Creates a command as the stepped-up admin; the body's `name` and `steps` are the caller's.
async fn mk(fx: &Fx, body: Value) -> Value {
    let (s, v) = call(fx, &fx.admin, Method::POST, "/commands", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

async fn run_of(fx: &Fx, cmd: &str, host: &str) -> (StatusCode, Value) {
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

#[tokio::test]
async fn commands_are_validated_listed_changed_and_deleted() {
    let fx = fx().await;
    let steps = |n: usize| (0..n).map(|i| format!("echo {i}")).collect::<Vec<_>>();
    for bad in [
        json!({"name": "a", "steps": []}),
        json!({"name": "a", "steps": steps(21)}),
        json!({"name": "a", "steps": [" "]}),
        json!({"name": "a", "steps": ["x\u{0}y"]}),
        json!({"name": "a", "steps": ["x".repeat(1001)]}),
        json!({"name": " a", "steps": ["ls"]}),
        json!({"name": "a", "steps": ["ls"], "scope": {"kind": "planet", "value": "x"}}),
        json!({"name": "a", "steps": ["ls"], "scope": {"kind": "tag", "value": "a b"}}),
        json!({"name": "a", "steps": ["ls"], "scope": {"kind": "tag", "value": "web", "role": "production"}}),
        json!({"name": "a", "steps": ["ls"], "scope": {"kind": "host", "value": "nope"}}),
        json!({"name": "a", "steps": ["ls"], "scope": {"kind": "project", "value": "99"}}),
    ] {
        let (s, v) = call(&fx, &fx.admin, Method::POST, "/commands", Some(bad.clone())).await;
        assert!(s.is_client_error(), "{bad} -> {s} {v}");
    }
    let c = mk(&fx, json!({"name": "Deploy", "steps": steps(20)})).await;
    assert_eq!(c["steps"].as_array().unwrap().len(), 20);
    assert!(c["scope"].is_null() && c["read_only"] == false && c["confirm"] == false);
    let id = c["id"].as_str().unwrap().to_owned();
    assert!(id.starts_with("lc_"));
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/commands",
        Some(json!({"name": "deploy", "steps": ["ls"]})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::CONFLICT,
        "names are unique, case-insensitive"
    );
    // by name; a host scope given by label is stored as the id
    let h = add(&fx, "web1", "ask").await;
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        "/commands/deploy",
        Some(json!({"steps": ["ls"], "scope": {"kind": "host", "value": "web1"}})),
    )
    .await;
    assert_eq!(
        (s, &v["scope"]["value"], &v["steps"]),
        (StatusCode::OK, &json!(h), &json!(["ls"])),
        "{v}"
    );
    let (_, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/commands/{id}"),
        Some(json!({"scope": null})),
    )
    .await;
    assert!(v["scope"].is_null());
    let (s, v) = call(&fx, &fx.admin, Method::GET, "/commands", None).await;
    assert_eq!((s, v.as_array().unwrap().len()), (StatusCode::OK, 1));
    let (s, v) = call(&fx, &fx.admin, Method::DELETE, "/commands/Deploy", None).await;
    assert_eq!((s, &v["deleted"]), (StatusCode::OK, &json!(id)));
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/commands/{id}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // ids only in the audit rows, never a step
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action LIKE 'leyline.command.%'",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert!(
        rows.len() >= 4
            && rows
                .iter()
                .all(|r| !r.contains("echo") && !r.contains("\"ls\"")),
        "{rows:?}"
    );
}

#[tokio::test]
async fn a_read_only_command_is_a_grant_so_it_needs_a_step_up_to_make_or_change() {
    let fx = fx().await;
    let ro = json!({"name": "ro", "steps": ["uptime"], "read_only": true});
    let (s, v) = call(&fx, &fx.weak, Method::POST, "/commands", Some(ro.clone())).await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    // a write command needs none; making it read-only, or changing a read-only one's steps, does
    let (s, w) = call(
        &fx,
        &fx.weak,
        Method::POST,
        "/commands",
        Some(json!({"name": "rw", "steps": ["rm x"]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{w}");
    let rw = w["id"].as_str().unwrap();
    let (s, v) = call(
        &fx,
        &fx.weak,
        Method::PATCH,
        &format!("/commands/{rw}"),
        Some(json!({"read_only": true})),
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    let c = mk(&fx, ro).await;
    let id = c["id"].as_str().unwrap();
    let (s, v) = call(
        &fx,
        &fx.weak,
        Method::PATCH,
        &format!("/commands/{id}"),
        Some(json!({"steps": ["rm -rf /"]})),
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    let (s, v) = call(
        &fx,
        &fx.weak,
        Method::PATCH,
        &format!("/commands/{id}"),
        Some(json!({"description": "d", "confirm": true})),
    )
    .await;
    assert_eq!((s, &v["description"]), (StatusCode::OK, &json!("d")), "{v}");
    let (s, v) = call(
        &fx,
        &fx.weak,
        Method::PATCH,
        &format!("/commands/{id}"),
        Some(json!({"read_only": false})),
    )
    .await;
    assert_eq!((s, &v["read_only"]), (StatusCode::OK, &json!(false)), "{v}");
}

#[tokio::test]
async fn the_gate_reads_the_flag_and_the_steps_itself() {
    let fx = fx().await;
    add(&fx, "ro", "read_only").await;
    let ro = mk(
        &fx,
        json!({"name": "r", "steps": ["uptime"], "read_only": true}),
    )
    .await;
    let rw = mk(&fx, json!({"name": "w", "steps": ["reboot"]})).await;
    let (ai, _) = session(&fx, "as_cmd").await;
    let a = authorize(
        &fx.app,
        &ai,
        "ro",
        &Action::Preset(ro["id"].as_str().unwrap().into()),
    )
    .await
    .unwrap();
    assert_eq!(a.steps(), ["uptime"]);
    let e = authorize(
        &fx.app,
        &ai,
        "ro",
        &Action::Preset(rw["id"].as_str().unwrap().into()),
    )
    .await
    .unwrap_err();
    assert_eq!((e.status, e.code), (StatusCode::FORBIDDEN, "gate_refused"));
    let e = authorize(&fx.app, &ai, "ro", &Action::Preset("lc_nope".into()))
        .await
        .unwrap_err();
    assert_eq!(e.status, StatusCode::NOT_FOUND);
    // the person path takes the steps from the store too
    let p = authorize(
        &fx.app,
        &person(&fx).await,
        "ro",
        &Action::Preset(rw["id"].as_str().unwrap().into()),
    )
    .await
    .unwrap();
    assert_eq!(p.steps(), ["reboot"]);
}

#[tokio::test]
async fn editing_a_command_never_changes_a_run_in_flight() {
    let fx = fx().await;
    let h = add(&fx, "web", "ask").await;
    let c = mk(&fx, json!({"name": "c", "steps": ["one", "two"]})).await;
    let id = c["id"].as_str().unwrap();
    let a = authorize(&fx.app, &person(&fx).await, &h, &Action::Preset(id.into()))
        .await
        .unwrap();
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/commands/{id}"),
        Some(json!({"steps": ["evil"]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(a.steps(), ["one", "two"]);
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::DELETE,
        &format!("/commands/{id}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(a.steps(), ["one", "two"]);
}

#[tokio::test]
async fn still_valid_holds_until_the_host_or_the_run_changes() {
    let fx = fx().await;
    let h = add(&fx, "web", "ask").await;
    let c = mk(&fx, json!({"name": "c", "steps": ["one"]})).await;
    let id = c["id"].as_str().unwrap();
    let who = person(&fx).await;
    let a = authorize(&fx.app, &who, &h, &Action::Preset(id.into()))
        .await
        .unwrap();
    still_valid(&fx.app, &a).await.unwrap();
    // a change that keeps the connection (a tag) is fine; one that repoints it is not
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/hosts/{h}"),
        Some(json!({"tags": ["x"]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    still_valid(&fx.app, &a).await.unwrap();
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/hosts/{h}"),
        Some(json!({"address": "evil.example.com"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        still_valid(&fx.app, &a).await.unwrap_err().code,
        "gate_refused"
    );
    // the rule is part of what was decided
    let h2 = add(&fx, "db", "ask").await;
    let b = authorize(&fx.app, &who, &h2, &Action::Preset(id.into()))
        .await
        .unwrap();
    let (_, _) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/hosts/{h2}"),
        Some(json!({"ai_rule": "read_only"})),
    )
    .await;
    assert!(still_valid(&fx.app, &b).await.is_err());
    // a gone host, and a run that has ended
    let h3 = add(&fx, "gone", "ask").await;
    let g = authorize(&fx.app, &who, &h3, &Action::Preset(id.into()))
        .await
        .unwrap();
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::DELETE,
        &format!("/hosts/{h3}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(still_valid(&fx.app, &g).await.is_err());
    let h4 = add(&fx, "ended", "ask").await;
    let e = authorize(&fx.app, &who, &h4, &Action::Preset(id.into()))
        .await
        .unwrap();
    finish(&fx.app, e, true).await.unwrap();
    let again = authorize(&fx.app, &who, &h4, &Action::Preset(id.into()))
        .await
        .unwrap();
    sqlx::query("UPDATE leyline_runs SET state = 'cancelled' WHERE id = ?")
        .bind(again.run_id())
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert!(still_valid(&fx.app, &again).await.is_err());
}

#[tokio::test]
async fn scopes_decide_which_hosts_a_command_is_for() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let body = |name: &str, extra: Value| {
        let mut v =
            json!({"name": name, "address": format!("{name}.example.com"), "username": "u"});
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        v
    };
    for (n, extra) in [
        ("prod", json!({"group": "eu", "tags": ["web"]})),
        ("stage", json!({"group": "us"})),
        ("loose", json!({})),
    ] {
        let (s, v) = call(&fx, &fx.admin, Method::POST, "/hosts", Some(body(n, extra))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    for (h, role) in [("prod", "production"), ("stage", "staging")] {
        let (s, v) = call(
            &fx,
            &fx.admin,
            Method::PUT,
            &format!("/projects/{p}/hosts/{h}"),
            Some(json!({"role": role})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let cases = [
        (
            json!({"kind": "group", "value": "EU"}),
            [true, false, false],
        ),
        (json!({"kind": "tag", "value": "Web"}), [true, false, false]),
        (
            json!({"kind": "host", "value": "loose"}),
            [false, false, true],
        ),
        (
            json!({"kind": "project", "value": p.to_string()}),
            [true, true, false],
        ),
        (
            json!({"kind": "project", "value": p.to_string(), "role": "production"}),
            [true, false, false],
        ),
    ];
    for (i, (sc, want)) in cases.into_iter().enumerate() {
        let c = mk_scoped(
            &fx,
            json!({"name": format!("c{i}"), "steps": ["true"], "scope": sc.clone()}),
        )
        .await;
        for (h, ok) in ["prod", "stage", "loose"].into_iter().zip(want) {
            let (s, v) = run_of(&fx, &c, h).await;
            assert_eq!(s == StatusCode::OK, ok, "{sc} on {h}: {s} {v}");
            if !ok {
                assert_eq!(s, StatusCode::CONFLICT, "{sc} on {h}");
            }
        }
    }
}

async fn mk_scoped(fx: &Fx, body: Value) -> String {
    mk(fx, body).await["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn a_confirm_command_runs_only_when_confirmed() {
    let fx = fx().await;
    add(&fx, "web", "ask").await;
    let c = mk_scoped(
        &fx,
        json!({"name": "c", "steps": ["true"], "confirm": true}),
    )
    .await;
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/commands/{c}/run"),
        Some(json!({"host": "web"})),
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("confirm_required"))
    );
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/commands/{c}/run"),
        Some(json!({"host": "web", "confirm": false})),
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("confirm_required"))
    );
    let (s, _) = run_of(&fx, &c, "web").await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn a_run_stops_at_its_first_failure_and_stores_a_fixed_result() {
    let fx = fx().await;
    let h = add(&fx, "web", "ask").await;
    // This Core has no runner: the first step cannot be sent, so the second must never be tried.
    let c = mk_scoped(
        &fx,
        json!({"name": "c", "steps": ["first-step", "second-step"]}),
    )
    .await;
    let (s, v) = run_of(&fx, &c, "web").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let run = v["run"].as_str().unwrap().to_owned();
    let mut got = Value::Null;
    for _ in 0..200 {
        let (_, r) = call(&fx, &fx.admin, Method::GET, &format!("/runs/{run}"), None).await;
        if r["state"] == "done" {
            got = r;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(got["state"], "done", "{got}");
    assert_eq!(got["command_id"], json!(c));
    let host = &got["hosts"][0];
    assert_eq!(
        (&host["host_id"], &host["state"], &host["step"]),
        (&json!(h), &json!("failed"), &json!(1))
    );
    let out = host["output"].as_str().unwrap();
    assert!(
        out.contains("$ first-step") && out.contains("[not run:"),
        "{out}"
    );
    assert!(!out.contains("second-step"), "{out}");
    let (s, _) = call(&fx, &fx.admin, Method::GET, "/runs/lr_nope", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}
