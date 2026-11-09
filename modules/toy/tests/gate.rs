//! The toy module through the Core's real gate: signed requests into `api::router`, so scope,
//! step-up, classification, the migration guard and the registries are the Core's own code, not
//! a stand-in. Each test fails if the property it names stops holding.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::jobs::{self, Engine};
use ainkrad_core_server::module::{self, Module};
use ainkrad_core_server::scheduler::{Clock, SystemClock, iso_of_unix};
use ainkrad_core_server::store::modsettings::ModuleSettings;
use ainkrad_core_server::store::{Migration, connect, events, migrate};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use toy_module::Toy;

const HOST: &str = "core.test";
const BASE: &str = "/modules/toy/v1";

struct Fx {
    app: App,
    toy: Toy,
    admin: TestDevice,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A Core with the toy module migrated and mounted, and an admin device that is elevated.
async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "toy-gate-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let toy = Toy::default();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(toy.clone())];
    migrate::migrate_modules(&pool, &modules).await.unwrap();
    let identity = Arc::new(Identity::load_or_create(&dir, &ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32])).unwrap());
    let clock = Arc::new(SystemClock);
    let mut app = App::new(pool, clock.clone(), HOST.to_owned(), identity);
    app.modules = Arc::from(modules);
    toy.attach(&app);
    let admin = enroll(&app, "admin", &["admin"]).await;
    let session = admin.session.lock().unwrap().clone().unwrap();
    app.auth.elevate(&session, &admin.id, clock.unix() + 3600);
    Fx {
        app,
        toy,
        admin,
        dir,
    }
}

/// A device with `scopes` and a session that is not elevated.
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

async fn call(
    fx: &Fx,
    dev: &TestDevice,
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
    let bytes = to_bytes(res.into_body(), 1 << 22).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn note(title: &str, body: &str) -> Option<Value> {
    Some(json!({"title": title, "body": body}))
}

#[tokio::test]
async fn a_device_without_the_routes_scope_is_refused_and_a_reader_may_only_read() {
    let fx = fx().await;
    let reader = enroll(&fx.app, "reader", &["read"]).await;
    let terminal = enroll(&fx.app, "terminal", &["terminal"]).await;
    // `read` is the scope the GET declares; the module-wide default is `admin`.
    assert_eq!(
        call(&fx, &reader, Method::GET, "/notes", None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(&fx, &terminal, Method::GET, "/notes", None).await.0,
        StatusCode::FORBIDDEN
    );
    // The POST is not listed in `route_scopes`: deny by default, so a reader is refused for its
    // scope (not for a missing step-up).
    let (status, body) = call(&fx, &reader, Method::POST, "/notes", note("a", "b")).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
    );
    // No signature at all never reaches the module.
    let anon = Request::builder()
        .uri(format!("{BASE}/notes"))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let res = router(fx.app.clone()).oneshot(anon).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_destructive_route_needs_a_step_up_and_the_plain_write_does_not() {
    let fx = fx().await;
    let laptop = enroll(&fx.app, "laptop", &["admin"]).await; // admin scope, session not elevated
    let (s, made) = call(&fx, &laptop, Method::POST, "/notes", note("a", "b")).await;
    assert_eq!(s, StatusCode::OK, "{made}");
    let path = format!("/notes/{}", made["id"]);
    let (s, body) = call(&fx, &laptop, Method::DELETE, &path, None).await;
    assert_eq!(
        (s, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    let still: i64 = sqlx::query_scalar("SELECT count(*) FROM toy_notes")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(still, 1, "a refused delete deletes nothing");
    // The elevated admin deletes; a second delete is a 404, not a second audit row.
    assert_eq!(
        call(&fx, &fx.admin, Method::DELETE, &path, None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(&fx, &fx.admin, Method::DELETE, &path, None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn audit_and_event_rows_name_the_note_and_never_carry_its_text() {
    let fx = fx().await;
    let text = "private-body-text-9f3a";
    let (s, made) = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/notes",
        note("t-title-77", text),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{made}");
    let id = made["id"].as_i64().unwrap();
    let rows: Vec<(String, Option<String>, Option<i64>, String)> = sqlx::query_as(
        "SELECT action, entity_kind, entity_id, details FROM audit_events WHERE action LIKE 'toy.%'",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].0.as_str(), rows[0].1.as_deref(), rows[0].2),
        ("toy.note.created", Some("note"), Some(id))
    );
    let everything = format!(
        "{rows:?}{:?}",
        events::list_events(&fx.app.pool, 0, 1000).await.unwrap()
    );
    assert!(everything.contains("toy.note"));
    assert!(
        !everything.contains(text) && !everything.contains("t-title-77"),
        "{everything}"
    );
}

#[tokio::test]
async fn a_name_the_module_did_not_declare_is_refused_at_append() {
    let fx = fx().await;
    let mut conn = fx.app.pool.acquire().await.unwrap();
    assert!(
        events::append(&mut conn, "toy.note", &json!({}))
            .await
            .is_ok()
    );
    assert!(
        events::append(&mut conn, "toy.undeclared", &json!({}))
            .await
            .is_err()
    );
    assert!(
        sqlx::query(
            "INSERT INTO audit_events (actor_kind, action) VALUES ('system', 'toy.undeclared')"
        )
        .execute(&mut *conn)
        .await
        .is_err()
    );
}

#[tokio::test]
async fn inputs_are_bounded() {
    let fx = fx().await;
    for (title, body) in [("", "b"), (&"t".repeat(101), "b"), ("a", &"b".repeat(4001))] {
        let (s, _) = call(&fx, &fx.admin, Method::POST, "/notes", note(title, body)).await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "{} / {}",
            title.len(),
            body.len()
        );
    }
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/notes",
        Some(json!({"title": "x"})),
    )
    .await;
    assert!(s.is_client_error());
}

/// The toy with its write classification dropped: the Core must refuse to mount it.
struct Forgetful(Toy);

impl Module for Forgetful {
    fn id(&self) -> &'static str {
        self.0.id()
    }
    fn routes(&self) -> Router<App> {
        self.0.routes()
    }
    fn openapi(&self) -> Value {
        self.0.openapi()
    }
    fn non_destructive(&self) -> Option<&'static [(&'static str, &'static str)]> {
        Some(&[]) // the POST is now in neither list
    }
    fn destructive(&self) -> &'static [(&'static str, &'static str)] {
        self.0.destructive()
    }
}

#[test]
fn the_toy_mounts_and_an_unclassified_write_stops_the_core_at_start() {
    // `mount` is what `serve` calls: a panic there is a refused start.
    let _ = module::mount(&[Arc::new(Toy::default()) as Arc<dyn Module>]);
    let refused = std::panic::catch_unwind(|| {
        module::mount(&[Arc::new(Forgetful(Toy::default())) as Arc<dyn Module>])
    });
    let why = *refused
        .expect_err("an unclassified write must stop the start")
        .downcast::<String>()
        .unwrap();
    assert!(
        why.contains("is not classified") && why.contains("post"),
        "{why}"
    );
}

/// A module that stays in its namespace (`toy_extra`) or leaves it (`notes`).
struct Migrating(&'static [Migration]);

impl Module for Migrating {
    fn id(&self) -> &'static str {
        "toy"
    }
    fn routes(&self) -> Router<App> {
        Router::new()
    }
    fn migrations(&self) -> &'static [Migration] {
        self.0
    }
}

#[tokio::test]
async fn the_migration_namespace_guard_refuses_a_table_outside_toy() {
    static OUT: &[Migration] = &[Migration {
        version: 1,
        name: "toy_0001",
        up: "CREATE TABLE notes (id INTEGER PRIMARY KEY);",
        down: "DROP TABLE notes;",
    }];
    static IN: &[Migration] = &[Migration {
        version: 1,
        name: "toy_0001",
        up: "CREATE TABLE toy_extra (id INTEGER PRIMARY KEY);",
        down: "DROP TABLE toy_extra;",
    }];
    let dir = std::env::temp_dir().join(format!("toy-migrate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let outside = connect(&dir.join("out.db")).await.unwrap();
    let err = migrate::migrate_modules(&outside, &[Arc::new(Migrating(OUT)) as Arc<dyn Module>])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("module toy"), "{err}");
    let made: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name = 'notes'")
        .fetch_one(&outside)
        .await
        .unwrap();
    assert_eq!(made, 0, "a refused migration creates nothing");
    let inside = connect(&dir.join("in.db")).await.unwrap();
    migrate::migrate_modules(&inside, &[Arc::new(Migrating(IN)) as Arc<dyn Module>])
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

struct Fixed(AtomicI64);

impl Clock for Fixed {
    fn now(&self) -> String {
        iso_of_unix(self.0.load(Ordering::SeqCst))
    }
}

#[tokio::test]
async fn the_scheduler_runs_the_trim_job_and_it_honours_the_setting() {
    let fx = fx().await;
    for n in 0..5 {
        sqlx::query("INSERT INTO toy_notes (title, body) VALUES (?, '')")
            .bind(format!("n{n}"))
            .execute(&fx.app.pool)
            .await
            .unwrap();
    }
    let t0 = SystemClock.unix();
    let clock = Arc::new(Fixed(AtomicI64::new(t0)));
    let mods: Vec<Arc<dyn Module>> = vec![Arc::new(fx.toy.clone())];
    jobs::register(&fx.app.pool, &clock.now(), &mods)
        .await
        .unwrap();
    ModuleSettings::of(&fx.toy)
        .set(
            &fx.app.pool,
            "notes.max",
            "2",
            AuditActor::System,
            &clock.now(),
        )
        .await
        .unwrap();
    // Out of bounds is refused by the Core's registry, not by the module.
    assert!(
        ModuleSettings::of(&fx.toy)
            .set(
                &fx.app.pool,
                "notes.max",
                "0",
                AuditActor::System,
                &clock.now()
            )
            .await
            .is_err()
    );
    let engine = Engine::new(
        fx.app.pool.clone(),
        clock.clone(),
        &mods,
        jobs::Config::default(),
    );
    engine.tick().await.unwrap();
    let kept = |pool| async move {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM toy_notes")
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    assert_eq!(kept(fx.app.pool.clone()).await, 5, "not due yet");
    clock.0.store(t0 + 3601, Ordering::SeqCst);
    engine.tick().await.unwrap();
    assert_eq!(
        kept(fx.app.pool.clone()).await,
        2,
        "the oldest three are trimmed"
    );
    let titles: Vec<String> = sqlx::query_scalar("SELECT title FROM toy_notes ORDER BY id")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(titles, ["n3", "n4"]);
}

#[test]
fn the_contract_marks_the_scope_and_step_up_from_the_modules_tables() {
    let spec: Value =
        serde_json::from_str(&ainkrad_core_server::api::v1::spec::json_for(&[Arc::new(
            Toy::default(),
        )]))
        .unwrap();
    let paths = &spec["paths"];
    assert_eq!(
        paths["/modules/toy/v1/notes"]["get"]["x-ainkrad-scope"],
        "read"
    );
    assert_eq!(
        paths["/modules/toy/v1/notes"]["post"]["x-ainkrad-scope"],
        "admin"
    );
    assert_eq!(
        paths["/modules/toy/v1/notes/{id}"]["delete"]["x-ainkrad-destructive"],
        true
    );
    assert!(paths["/modules/toy/v1/notes"]["post"]["x-ainkrad-destructive"].is_null());
}
