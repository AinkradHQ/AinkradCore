//! Lore notes through the Core's real gate (signed requests into `api::router`), so scope and the
//! registries are the Core's own code. Each test fails if the property it names stops holding.

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
use lore_module::Lore;
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "core.test";
const BASE: &str = "/modules/lore/v1";

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

/// A Core with Lore migrated and mounted (or, `on = false`, a Core that does not carry it).
async fn fx_with(on: bool) -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "lore-gate-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = if on {
        vec![Arc::new(Lore::default())]
    } else {
        vec![]
    };
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

async fn add(fx: &Fx, body: Value) -> Value {
    let (s, v) = call(fx, &fx.admin, Method::POST, "/notes", Some(body)).await;
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
async fn scopes_follow_the_modules_tables() {
    let fx = fx().await;
    let reader = enroll(&fx.app, "reader", &["read"]).await;
    let note = add(&fx, json!({"text": "# Hello"})).await;
    let id = note["id"].as_str().unwrap();
    assert_eq!(note["title"], json!("Hello"));
    assert_eq!(note["rev"], json!(1));
    assert!(
        note["created_by"]
            .as_str()
            .unwrap()
            .starts_with("person:d_")
    );
    for path in ["/notes".to_owned(), format!("/notes/{id}")] {
        assert_eq!(
            call(&fx, &reader, Method::GET, &path, None).await.0,
            StatusCode::OK
        );
    }
    // A reader cannot write, and `today` may create so it needs admin too.
    for (m, p, b) in [
        (Method::POST, "/notes", Some(json!({}))),
        (
            Method::PATCH,
            &format!("/notes/{id}"),
            Some(json!({"trashed": true})),
        ),
        (Method::GET, "/today?day=2026-11-17", None),
    ] {
        let (s, v) = call(&fx, &reader, m, p, b).await;
        assert_eq!(
            (s, &v["code"]),
            (StatusCode::FORBIDDEN, &json!("forbidden_scope")),
            "{p}"
        );
    }
    assert_eq!(count(&fx, "lore_notes").await, 1);
    let anon = Request::builder()
        .uri(format!("{BASE}/notes"))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router(fx.app.clone()).oneshot(anon).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn create_read_list_and_refusals() {
    let fx = fx().await;
    let a = add(&fx, json!({"text": "first line\nbody"})).await;
    assert_eq!(a["title"], json!("first line"));
    let b = add(&fx, json!({})).await;
    assert_eq!((&b["title"], &b["text"]), (&json!("Untitled"), &json!("")));
    let id = a["id"].as_str().unwrap();
    let (_, v) = call(&fx, &fx.admin, Method::GET, &format!("/notes/{id}"), None).await;
    assert_eq!(v["text"], json!("first line\nbody"));
    let (_, list) = call(&fx, &fx.admin, Method::GET, "/notes", None).await;
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert!(list[0].get("text").is_none(), "the list carries no text");
    assert_eq!(
        call(&fx, &fx.admin, Method::GET, "/notes/ln_aaaaaaaaaaaa", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    for q in ["/notes?state=bogus", "/notes?kind=poster"] {
        assert_eq!(
            call(&fx, &fx.admin, Method::GET, q, None).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let huge = json!({"text": "x".repeat(2_000_001)});
    // The gate's signed-body cap answers first (a different status); either way nothing is stored.
    assert_ne!(
        call(&fx, &fx.admin, Method::POST, "/notes", Some(huge))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        count(&fx, "lore_notes").await,
        2,
        "a refusal stores nothing"
    );
}

#[tokio::test]
async fn an_unknown_project_is_refused_and_a_known_one_is_linked() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let q = project(&fx, "beta").await;
    for bad in ["9999", "abc", "-1", "1; DROP TABLE lore_notes", ""] {
        let (s, v) = call(
            &fx,
            &fx.admin,
            Method::POST,
            "/notes",
            Some(json!({"project": bad})),
        )
        .await;
        assert_eq!(
            (s, &v["code"]),
            (StatusCode::BAD_REQUEST, &json!("bad_request")),
            "{bad}"
        );
    }
    assert_eq!(count(&fx, "lore_notes").await, 0);
    let n = add(&fx, json!({"text": "# P", "project": p})).await;
    let id = n["id"].as_str().unwrap().to_owned();
    assert_eq!(n["project"], json!(p));
    let (_, v) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/notes?project={p}"),
        None,
    )
    .await;
    assert_eq!(v.as_array().unwrap().len(), 1);
    // Move: to another project, to an unknown one (refused), to personal.
    let url = format!("/notes/{id}");
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &url,
        Some(json!({"project": q})),
    )
    .await;
    assert_eq!(
        (s, &v["project"], &v["rev"]),
        (StatusCode::OK, &json!(q), &json!(2))
    );
    assert_eq!(
        call(
            &fx,
            &fx.admin,
            Method::PATCH,
            &url,
            Some(json!({"project": "9999"}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (_, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &url,
        Some(json!({"project": null})),
    )
    .await;
    assert_eq!(v["project"], Value::Null);
    // A daily note is personal: the table and the API both refuse a project for it.
    let (_, day) = call(&fx, &fx.admin, Method::GET, "/today?day=2026-11-17", None).await;
    let day_url = format!("/notes/{}", day["id"].as_str().unwrap());
    assert_eq!(
        call(
            &fx,
            &fx.admin,
            Method::PATCH,
            &day_url,
            Some(json!({"project": p}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let direct = sqlx::query("UPDATE lore_notes SET project = '1' WHERE kind = 'daily'")
        .execute(&fx.app.pool)
        .await;
    assert!(
        direct.is_err(),
        "the table refuses a project on a daily note"
    );
}

#[tokio::test]
async fn today_is_one_note_even_under_a_race() {
    let fx = fx().await;
    let calls = (0..8).map(|_| call(&fx, &fx.admin, Method::GET, "/today?day=2026-11-17", None));
    let all = futures_join(calls).await;
    let first = all[0].1["id"].as_str().unwrap().to_owned();
    for (s, v) in &all {
        assert_eq!(
            (*s, v["id"].as_str().unwrap()),
            (StatusCode::OK, first.as_str())
        );
        assert_eq!(
            (&v["kind"], &v["day"]),
            (&json!("daily"), &json!("2026-11-17"))
        );
        assert_eq!(v["title"], json!("Tuesday, 17 November 2026"));
        assert_eq!(v["project"], Value::Null);
    }
    assert_eq!(count(&fx, "lore_notes").await, 1);
    let (_, other) = call(&fx, &fx.admin, Method::GET, "/today?day=2026-11-18", None).await;
    assert_ne!(other["id"], json!(first));
    for bad in [
        "",
        "?day=",
        "?day=2026-02-30",
        "?day=17-11-2026",
        "?day=2026-11-17'",
    ] {
        let (s, _) = call(&fx, &fx.admin, Method::GET, &format!("/today{bad}"), None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(count(&fx, "lore_notes").await, 2);
    // A trashed daily note comes back when today is opened again.
    let url = format!("/notes/{first}");
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &url,
        Some(json!({"trashed": true})),
    )
    .await;
    let (_, v) = call(&fx, &fx.admin, Method::GET, "/today?day=2026-11-17", None).await;
    assert_eq!((&v["id"], &v["trashed_at"]), (&json!(first), &Value::Null));
}

/// Runs the futures concurrently on this task (no extra dependency).
async fn futures_join<F: std::future::Future>(fs: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let mut set = Vec::new();
    for f in fs {
        set.push(Box::pin(f));
    }
    let mut out: Vec<Option<F::Output>> = set.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (i, f) in set.iter_mut().enumerate() {
            if out[i].is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => out[i] = Some(v),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    out.into_iter().map(Option::unwrap).collect()
}

#[tokio::test]
async fn trash_keeps_rows_restore_returns_and_the_sweep_purges() {
    let fx = fx().await;
    let keep = add(&fx, json!({"text": "# Keep"})).await;
    let old = add(&fx, json!({"text": "# Old"})).await;
    let (keep, old) = (keep["id"].as_str().unwrap(), old["id"].as_str().unwrap());
    // A satellite row proves the sweep cascades.
    sqlx::query("INSERT INTO lore_tags (note, tag) VALUES (?, 'x')")
        .bind(old)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let url = format!("/notes/{old}");
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &url,
        Some(json!({"trashed": true})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["trashed_at"].is_string());
    assert_eq!(count(&fx, "lore_notes").await, 2, "trash keeps the row");
    let (_, active) = call(&fx, &fx.admin, Method::GET, "/notes", None).await;
    assert_eq!(active.as_array().unwrap().len(), 1);
    let (_, trashed) = call(&fx, &fx.admin, Method::GET, "/notes?state=trashed", None).await;
    assert_eq!(trashed[0]["id"], json!(old));
    let (_, all) = call(&fx, &fx.admin, Method::GET, "/notes?state=all", None).await;
    assert_eq!(all.as_array().unwrap().len(), 2);
    assert_eq!(
        call(
            &fx,
            &fx.admin,
            Method::PATCH,
            &url,
            Some(json!({"project": null}))
        )
        .await
        .0,
        StatusCode::CONFLICT,
        "a trashed note can only be restored"
    );
    // Nothing is old enough yet.
    assert_eq!(lore_module::sweep(&fx.app.pool).await.unwrap(), 0);
    let (_, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &url,
        Some(json!({"trashed": false})),
    )
    .await;
    assert_eq!(v["trashed_at"], Value::Null);
    // Trash again, backdate past 30 days (and one inside it), sweep.
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &url,
        Some(json!({"trashed": true})),
    )
    .await;
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/notes/{keep}"),
        Some(json!({"trashed": true})),
    )
    .await;
    sqlx::query("UPDATE lore_notes SET trashed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-31 days') WHERE id = ?")
        .bind(old)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE lore_notes SET trashed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-29 days') WHERE id = ?")
        .bind(keep)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(lore_module::sweep(&fx.app.pool).await.unwrap(), 1);
    assert_eq!(count(&fx, "lore_notes").await, 1);
    assert_eq!(
        count(&fx, "lore_tags").await,
        0,
        "satellite rows go with the note"
    );
    assert_eq!(
        call(&fx, &fx.admin, Method::GET, &url, None).await.0,
        StatusCode::NOT_FOUND
    );
    let job = Lore::default().jobs();
    assert_eq!(job.len(), 1);
    assert_eq!(job[0].name, "sweep");
}

#[tokio::test]
async fn events_and_audit_carry_ids_only() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let n = add(
        &fx,
        json!({"text": "# private-title-77\nprivate-body-88", "project": p}),
    )
    .await;
    let id = n["id"].as_str().unwrap();
    let url = format!("/notes/{id}");
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &url,
        Some(json!({"project": null})),
    )
    .await;
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &url,
        Some(json!({"trashed": true})),
    )
    .await;
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &url,
        Some(json!({"trashed": false})),
    )
    .await;
    let ev: Vec<_> = events::list_events(&fx.app.pool, 0, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind.starts_with("lore."))
        .collect();
    let kinds: Vec<&str> = ev.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "lore.note.changed",
            "lore.note.changed",
            "lore.note.trashed",
            "lore.note.changed"
        ]
    );
    for e in &ev {
        assert_eq!(e.payload.0["id"], json!(id));
    }
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'lore.%' ORDER BY rowid",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "lore.note.created",
            "lore.note.moved",
            "lore.note.trashed",
            "lore.note.restored"
        ]
    );
    let all = format!(
        "{:?}{:?}",
        sqlx::query_scalar::<_, String>(
            "SELECT details FROM audit_events WHERE action LIKE 'lore.%'"
        )
        .fetch_all(&fx.app.pool)
        .await
        .unwrap(),
        ev
    );
    for private in ["private-title-77", "private-body-88"] {
        assert!(!all.contains(private), "{private} leaked: {all}");
    }
    let mut conn = fx.app.pool.acquire().await.unwrap();
    assert!(
        events::append(&mut conn, "lore.undeclared", &json!({}))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn errors_never_echo_what_the_caller_sent() {
    let fx = fx().await;
    let secret = "SECRET-seed-4f1c9";
    for body in [
        format!("{{\"text\": 5, \"x\": \"{secret}\"}}"),
        format!("{{\"project\": \"{secret}\"}}"),
    ] {
        let (s, _, raw) = call_raw(&fx, &fx.admin, Method::POST, "/notes", Some(&body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(!raw.contains(secret), "{raw}");
    }
}

#[tokio::test]
async fn module_off_the_core_has_no_lore_tables_or_routes() {
    let off = fx_with(false).await;
    let tables: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name LIKE 'lore_%'")
            .fetch_one(&off.app.pool)
            .await
            .unwrap();
    assert_eq!(tables, 0);
    assert_eq!(
        call(&off, &off.admin, Method::GET, "/notes", None).await.0,
        StatusCode::FORBIDDEN
    );
    // Switching it on adds only its own namespace; the Core keeps working without it.
    let on = fx().await;
    let core = |fx: &Fx| {
        let pool = fx.app.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE '%lore%' ORDER BY name",
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
    for stmt in lore_module::MIGRATIONS[0]
        .down
        .split(';')
        .filter(|s| !s.trim().is_empty())
    {
        sqlx::query(stmt).execute(&fx.app.pool).await.unwrap();
    }
    let left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name LIKE 'lore_%'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(left, 0);
    sqlx::raw_sql(lore_module::MIGRATIONS[0].up)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(count(&fx, "lore_notes").await, 0);
}

#[test]
fn the_contract_marks_scope() {
    let spec: Value =
        serde_json::from_str(&ainkrad_core_server::api::v1::spec::json_for(&[Arc::new(
            Lore::default(),
        )]))
        .unwrap();
    let p = &spec["paths"];
    assert_eq!(
        p["/modules/lore/v1/notes"]["get"]["x-ainkrad-scope"],
        "read"
    );
    assert_eq!(
        p["/modules/lore/v1/notes"]["post"]["x-ainkrad-scope"],
        "admin"
    );
    assert_eq!(
        p["/modules/lore/v1/today"]["get"]["x-ainkrad-scope"],
        "admin"
    );
    assert!(p["/modules/lore/v1/notes/{note}"]["patch"]["x-ainkrad-destructive"].is_null());
}
