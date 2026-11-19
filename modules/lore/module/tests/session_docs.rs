//! Tags, the tag filter and AI session documents (E10-2) through the Core's real gate.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, migrate};
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
async fn fx() -> Fx {
    let on = true;
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

#[tokio::test]
async fn tags_filter_the_list_and_a_save_marks_a_session_doc_dirty() {
    let fx = fx().await;
    let a = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/notes",
        Some(json!({"text": "# A\n\n#plans"})),
    )
    .await
    .1;
    let b = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/notes",
        Some(json!({"text": "# B\n\n#ideas"})),
    )
    .await
    .1;
    let (s, tags) = call(&fx, &fx.admin, Method::GET, "/tags", None).await;
    assert_eq!(s, StatusCode::OK, "{tags}");
    let names: Vec<&str> = tags
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tag"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"plans") && names.contains(&"ideas"),
        "{tags}"
    );
    let (_, only) = call(&fx, &fx.admin, Method::GET, "/notes?tag=plans", None).await;
    let ids: Vec<&str> = only
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![a["id"].as_str().unwrap()],
        "only the tagged note: {only}"
    );
    // A note imported from a session file: its save must be marked for the write-back.
    let id = b["id"].as_str().unwrap();
    sqlx::query("INSERT INTO lore_session_docs (note, session, runner, path, file_hash) VALUES (?, 'as_x', 'r', 'plan.md', 'h')")
        .bind(id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let (s, docs) = call(&fx, &fx.admin, Method::GET, "/session-docs", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(docs[0]["path"], "plan.md", "{docs}");
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PUT,
        &format!("/notes/{id}/text"),
        Some(json!({"base_rev": 1, "text": "# B\n\nchanged"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let dirty: i64 = sqlx::query_scalar("SELECT dirty FROM lore_session_docs WHERE note = ?")
        .bind(id)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(dirty, 1, "the save is waiting to be written back");
}
