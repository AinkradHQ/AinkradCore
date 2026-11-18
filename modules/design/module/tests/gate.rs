//! Design docs through the Core's real gate (signed requests into `api::router`), so scope,
//! step-up, classification and the registries are the Core's own code. Each test fails if the
//! property it names stops holding.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::projects::{self, Who};
use ainkrad_core_server::store::{connect, events, migrate};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use design_module::Design;
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "core.test";
const BASE: &str = "/modules/design/v1";

struct Fx {
    app: App,
    admin: TestDevice,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A Core with Design migrated and mounted (or, `on = false`, a Core that does not carry it).
async fn fx_with(on: bool) -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "design-gate-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = if on { vec![Arc::new(Design)] } else { vec![] };
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
    Fx { app, admin, dir }
}

async fn fx() -> Fx {
    fx_with(true).await
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

/// Status, parsed body and the raw body text.
async fn call_raw(
    fx: &Fx,
    dev: &TestDevice,
    method: Method,
    path: &str,
    body: Option<&str>,
) -> (StatusCode, Value, String) {
    let uri = format!("{BASE}{path}");
    let bytes = body.unwrap_or_default().to_owned();
    let mut b = Request::builder()
        .method(method.clone())
        .uri(&uri)
        .header(header::HOST, HOST);
    for (name, value) in dev.headers(method.as_str(), &uri, bytes.as_bytes()) {
        b = b.header(name, value);
    }
    if !bytes.is_empty() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let text =
        String::from_utf8_lossy(&to_bytes(res.into_body(), 1 << 22).await.unwrap()).into_owned();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    )
}

async fn call(
    fx: &Fx,
    dev: &TestDevice,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (s, v, _) = call_raw(
        fx,
        dev,
        method,
        path,
        body.map(|b| b.to_string()).as_deref(),
    )
    .await;
    (s, v)
}

fn doc(name: &str) -> Value {
    json!({"kind": "design", "name": name})
}

async fn add(fx: &Fx, body: Value) -> Value {
    let (s, v) = call(fx, &fx.admin, Method::POST, "/docs", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

async fn count(fx: &Fx, table: &str) -> i64 {
    let sql = sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")); // test-only, a literal table name
    sqlx::query_scalar(sql)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn project(fx: &Fx, slug: &str) -> String {
    let who = Who {
        by_device: "d_test",
        actor: AuditActor::System,
        now: "2026-11-17T00:00:00.000Z",
    };
    projects::create(&fx.app.pool, slug, slug, "", "manual", who)
        .await
        .unwrap()
        .id
        .to_string()
}

#[tokio::test]
async fn scopes_and_step_up_follow_the_modules_tables() {
    let fx = fx().await;
    let reader = enroll(&fx.app, "reader", &["read"]).await;
    let laptop = enroll(&fx.app, "laptop", &["admin"]).await; // admin, not elevated
    assert_eq!(
        call(&fx, &reader, Method::GET, "/docs", None).await.0,
        StatusCode::OK
    );
    let (s, b) = call(&fx, &reader, Method::POST, "/docs", Some(doc("a"))).await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
    );
    let (s, made) = call(&fx, &laptop, Method::POST, "/docs", Some(doc("a"))).await;
    assert_eq!(s, StatusCode::OK, "{made}");
    let id = made["id"].as_str().unwrap();
    assert!(
        made["created_by"]
            .as_str()
            .unwrap()
            .starts_with("person:d_")
    );
    let archive = format!("/docs/{id}/archive");
    let (s, b) = call(&fx, &laptop, Method::POST, &archive, None).await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    assert_eq!(
        call(&fx, &fx.admin, Method::POST, &archive, None).await.0,
        StatusCode::OK
    );
    let anon = Request::builder()
        .uri(format!("{BASE}/docs"))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router(fx.app.clone()).oneshot(anon).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn create_read_change_and_list_with_filters() {
    let fx = fx().await;
    let sys = add(&fx, json!({"kind": "system", "name": "House"})).await;
    let sys_id = sys["id"].as_str().unwrap().to_owned();
    let d = add(
        &fx,
        json!({"kind": "design", "name": "Home", "system": sys_id}),
    )
    .await;
    let id = d["id"].as_str().unwrap().to_owned();
    assert_eq!(d["state"], json!("active"));
    assert_eq!(d["system"], json!(sys_id));
    add(&fx, json!({"kind": "mockup", "name": "Old"})).await;
    let (_, v) = call(&fx, &fx.admin, Method::GET, &format!("/docs/{id}"), None).await;
    assert_eq!(v["name"], json!("Home"));
    let (_, v) = call(&fx, &fx.admin, Method::GET, "/docs?kind=design", None).await;
    assert_eq!(v.as_array().unwrap().len(), 1);
    let (_, v) = call(&fx, &fx.admin, Method::GET, "/docs", None).await;
    assert_eq!(v.as_array().unwrap().len(), 3);
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/docs/{id}"),
        Some(json!({"name": "Home 2", "system": null})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!((&v["name"], &v["system"]), (&json!("Home 2"), &Value::Null));
    // Refusals: bad kind or name, a system that is no system, a system on a non-design.
    for body in [
        json!({"kind": "poster", "name": "x"}),
        json!({"kind": "design", "name": " x"}),
        json!({"kind": "design", "name": ""}),
        json!({"kind": "design", "name": "x", "system": id}),
        json!({"kind": "design", "name": "x", "system": "dd_0000000000000000"}),
        json!({"kind": "mockup", "name": "x", "system": sys_id}),
    ] {
        let (s, v) = call(&fx, &fx.admin, Method::POST, "/docs", Some(body.clone())).await;
        assert_eq!(
            (s, &v["code"]),
            (StatusCode::BAD_REQUEST, &json!("bad_request")),
            "{body}"
        );
    }
    assert_eq!(
        count(&fx, "design_docs").await,
        3,
        "a refusal stores nothing"
    );
    assert_eq!(
        call(
            &fx,
            &fx.admin,
            Method::GET,
            "/docs/dd_ffffffffffffffff",
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&fx, &fx.admin, Method::GET, "/docs?state=bogus", None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn an_unknown_project_is_refused_and_a_known_one_is_linked() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    for bad in ["9999", "abc", "-1", "1; DROP TABLE design_docs", ""] {
        let body = json!({"kind": "design", "name": "x", "project": bad});
        let (s, v) = call(&fx, &fx.admin, Method::POST, "/docs", Some(body)).await;
        assert_eq!(
            (s, &v["code"]),
            (StatusCode::BAD_REQUEST, &json!("bad_request")),
            "{bad}"
        );
    }
    assert_eq!(count(&fx, "design_docs").await, 0);
    assert_eq!(count(&fx, "design_links").await, 0);
    let a = add(&fx, json!({"kind": "design", "name": "a", "project": p})).await;
    assert_eq!(a["projects"], json!([p]));
    let b = add(&fx, doc("b")).await;
    let b_id = b["id"].as_str().unwrap();
    let bad_url = format!("/docs/{b_id}/projects/9999");
    assert_eq!(
        call(&fx, &fx.admin, Method::PUT, &bad_url, None).await.0,
        StatusCode::BAD_REQUEST
    );
    let url = format!("/docs/{b_id}/projects/{p}");
    for _ in 0..2 {
        let (s, v) = call(&fx, &fx.admin, Method::PUT, &url, None).await;
        assert_eq!((s, &v["projects"]), (StatusCode::OK, &json!([p])));
    }
    let (_, v) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/docs?project={p}"),
        None,
    )
    .await;
    assert_eq!(v.as_array().unwrap().len(), 2);
    let (s, v) = call(&fx, &fx.admin, Method::DELETE, &url, None).await;
    assert_eq!((s, &v["projects"]), (StatusCode::OK, &json!([])));
    assert_eq!(
        call(&fx, &fx.admin, Method::DELETE, &url, None).await.0,
        StatusCode::NOT_FOUND
    );
    // The table refuses a non-numeric project written around the API.
    let direct = sqlx::query(
        "INSERT INTO design_links (item_kind, item, project) VALUES ('doc', 'x', 'abc')",
    )
    .execute(&fx.app.pool)
    .await;
    assert!(direct.is_err());
}

#[tokio::test]
async fn archive_keeps_every_row_and_blocks_edits() {
    let fx = fx().await;
    let p = project(&fx, "beta").await;
    let d = add(&fx, json!({"kind": "design", "name": "keep", "project": p})).await;
    let id = d["id"].as_str().unwrap().to_owned();
    for sql in [
        "INSERT INTO design_updates (doc, seq, data, origin) VALUES (?, 1, x'01', 'person:d_x')",
        "INSERT INTO design_versions (id, doc, kind, state, origin) VALUES ('v1', ?, 'named', x'02', 'person:d_x')",
        "INSERT INTO design_screens (doc, screen) VALUES (?, 'n_aaaaaaaaaaaa')",
        "INSERT INTO design_session_docs (session, doc, purpose) VALUES ('as_1', ?, 'edit')",
    ] {
        sqlx::query(sql)
            .bind(&id)
            .execute(&fx.app.pool)
            .await
            .unwrap();
    }
    let tables = [
        "design_docs",
        "design_links",
        "design_updates",
        "design_versions",
        "design_screens",
        "design_session_docs",
    ];
    for t in tables {
        assert_eq!(count(&fx, t).await, 1, "{t}");
    }
    let url = format!("/docs/{id}/archive");
    for _ in 0..2 {
        let (s, v) = call(&fx, &fx.admin, Method::POST, &url, None).await;
        assert_eq!((s, &v["state"]), (StatusCode::OK, &json!("archived")));
    }
    for t in tables {
        assert_eq!(count(&fx, t).await, 1, "{t} survives the archive");
    }
    let (_, v) = call(&fx, &fx.admin, Method::GET, "/docs", None).await;
    assert!(
        v.as_array().unwrap().is_empty(),
        "hidden from the default list"
    );
    let (_, v) = call(&fx, &fx.admin, Method::GET, "/docs?state=archived", None).await;
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(
        call(&fx, &fx.admin, Method::GET, &format!("/docs/{id}"), None)
            .await
            .0,
        StatusCode::OK
    );
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/docs/{id}"),
        Some(json!({"name": "z"})),
    )
    .await;
    assert_eq!((s, &v["code"]), (StatusCode::CONFLICT, &json!("conflict")));
    let link = format!("/docs/{id}/projects/{p}");
    assert_eq!(
        call(&fx, &fx.admin, Method::PUT, &link, None).await.0,
        StatusCode::CONFLICT
    );
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'design.doc.archived'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(n, 1, "archiving twice records once");
}

#[tokio::test]
async fn events_replay_the_story_by_id_and_audit_names_no_label() {
    let fx = fx().await;
    let p = project(&fx, "gamma").await;
    let d = add(&fx, doc("private-name-77")).await;
    let id = d["id"].as_str().unwrap().to_owned();
    let link = format!("/docs/{id}/projects/{p}");
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/docs/{id}"),
        Some(json!({"name": "other-private-88"})),
    )
    .await;
    call(&fx, &fx.admin, Method::PUT, &link, None).await;
    call(&fx, &fx.admin, Method::DELETE, &link, None).await;
    call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/docs/{id}/archive"),
        None,
    )
    .await;
    let design: Vec<_> = events::list_events(&fx.app.pool, 0, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "design.doc")
        .collect();
    let ops: Vec<String> = design
        .iter()
        .map(|e| {
            let v: Value = e.payload.0.clone();
            assert_eq!(v["id"], json!(id));
            v["op"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(
        ops,
        ["created", "changed", "linked", "unlinked", "archived"]
    );
    // Replaying from a cursor resumes after it, in order.
    let rest = events::list_events(&fx.app.pool, design[1].seq, 1000)
        .await
        .unwrap();
    assert_eq!(rest.iter().filter(|e| e.kind == "design.doc").count(), 3);
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'design.%' ORDER BY rowid",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "design.doc.created",
            "design.doc.changed",
            "design.doc.linked",
            "design.doc.unlinked",
            "design.doc.archived"
        ]
    );
    let all = format!(
        "{:?}{:?}",
        sqlx::query_scalar::<_, String>(
            "SELECT details FROM audit_events WHERE action LIKE 'design.%'"
        )
        .fetch_all(&fx.app.pool)
        .await
        .unwrap(),
        design
    );
    for private in ["private-name-77", "other-private-88"] {
        assert!(!all.contains(private), "{private} leaked: {all}");
    }
    let mut conn = fx.app.pool.acquire().await.unwrap();
    assert!(
        events::append(&mut conn, "design.undeclared", &json!({}))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn errors_never_echo_what_the_caller_sent() {
    let fx = fx().await;
    let secret = "SECRET-seed-4f1c9";
    for body in [
        format!("{{\"kind\": \"{secret}\", \"name\": \"x\"}}"),
        format!("{{\"kind\": \"design\", \"name\": 5, \"x\": \"{secret}\"}}"),
        format!("{{\"kind\": \"design\", \"name\": \"x\", \"project\": \"{secret}\"}}"),
    ] {
        let (s, _, raw) = call_raw(&fx, &fx.admin, Method::POST, "/docs", Some(&body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(!raw.contains(secret), "{raw}");
    }
}

#[tokio::test]
async fn module_off_the_core_has_no_design_tables_or_routes() {
    let off = fx_with(false).await;
    let tables: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name LIKE 'design_%'")
            .fetch_one(&off.app.pool)
            .await
            .unwrap();
    assert_eq!(tables, 0);
    assert_eq!(
        call(&off, &off.admin, Method::GET, "/docs", None).await.0,
        StatusCode::FORBIDDEN
    );
    // Switching it on adds only its own namespace; the Core keeps working without it.
    let on = fx().await;
    let core = |fx: &Fx| {
        let pool = fx.app.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE '%design%' ORDER BY name",
            )
            .fetch_all(&pool)
            .await
            .unwrap()
        }
    };
    assert_eq!(core(&on).await, core(&off).await);
    assert_eq!(count(&off, "core_projects").await, 0);
}

#[tokio::test]
async fn the_migration_goes_down_and_up_again() {
    let fx = fx().await;
    for m in design_module::MIGRATIONS.iter().rev() {
        for stmt in m.down.split(';').filter(|s| !s.trim().is_empty()) {
            sqlx::query(stmt).execute(&fx.app.pool).await.unwrap();
        }
    }
    let left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name LIKE 'design_%'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(left, 0);
    for m in design_module::MIGRATIONS {
        sqlx::raw_sql(m.up).execute(&fx.app.pool).await.unwrap();
    }
    assert_eq!(count(&fx, "design_docs").await, 0);
}

#[test]
fn the_contract_marks_scope_and_step_up() {
    let spec: Value =
        serde_json::from_str(&ainkrad_core_server::api::v1::spec::json_for(&[Arc::new(
            Design,
        )]))
        .unwrap();
    let p = &spec["paths"];
    assert_eq!(
        p["/modules/design/v1/docs"]["get"]["x-ainkrad-scope"],
        "read"
    );
    assert_eq!(
        p["/modules/design/v1/docs"]["post"]["x-ainkrad-scope"],
        "admin"
    );
    assert_eq!(
        p["/modules/design/v1/docs/{doc}/archive"]["post"]["x-ainkrad-destructive"],
        true
    );
    assert!(p["/modules/design/v1/docs/{doc}"]["patch"]["x-ainkrad-destructive"].is_null());
}
