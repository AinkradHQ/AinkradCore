//! Lore attachments (R1-05) through the Core's real gate: allow-list, caps, dedupe, serving, sweep.

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
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
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

async fn send(
    fx: &Fx,
    method: Method,
    path: &str,
    bytes: Vec<u8>,
) -> (StatusCode, Value, Vec<u8>, HeaderMap) {
    let uri = format!("{BASE}{path}");
    let mut b = Request::builder()
        .method(method.clone())
        .uri(&uri)
        .header(header::HOST, HOST)
        .header(header::CONTENT_LENGTH, bytes.len());
    for (name, value) in fx.admin.headers(method.as_str(), &uri, &bytes) {
        b = b.header(name, value);
    }
    if !bytes.is_empty() {
        b = b.header(
            header::CONTENT_TYPE,
            if path.starts_with("/attachments") {
                "application/octet-stream"
            } else {
                "application/json"
            },
        );
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let raw = to_bytes(res.into_body(), 1 << 24).await.unwrap().to_vec();
    (
        status,
        serde_json::from_slice(&raw).unwrap_or(Value::Null),
        raw,
        headers,
    )
}

async fn upload(fx: &Fx, bytes: Vec<u8>) -> (StatusCode, Value) {
    let (s, v, _, _) = send(fx, Method::POST, "/attachments", bytes).await;
    (s, v)
}

fn png(extra: u8) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.extend([extra; 64]);
    v
}

async fn count(fx: &Fx) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM lore_attachments")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn note(fx: &Fx, text: &str) -> String {
    let (s, v, _, _) = send(
        fx,
        Method::POST,
        "/notes",
        json!({"text": text}).to_string().into_bytes(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn a_spoofed_type_is_refused_and_stores_nothing() {
    let fx = fx().await;
    for bytes in [
        b"MZ\x90\x00 an executable named a.png".to_vec(),
        b"<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>".to_vec(),
        b"<html><script>1</script></html>".to_vec(),
        b"PK\x03\x04 a zip".to_vec(),
        [&b"\x89PNG\r\n\x1a\n"[..], b"<svg onload=alert(1)>"].concat(), // a polyglot
    ] {
        let (s, v) = upload(&fx, bytes).await;
        assert_eq!(
            (s, &v["code"]),
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &json!("unsupported_type")
            )
        );
    }
    assert_eq!(upload(&fx, vec![]).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(count(&fx).await, 0);
}

#[tokio::test]
async fn over_ten_mb_is_413_and_stores_nothing() {
    let fx = fx().await;
    let big = png(1)
        .into_iter()
        .chain(vec![0u8; 10 * 1024 * 1024])
        .collect::<Vec<u8>>();
    assert_eq!(upload(&fx, big).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    let mut near = png(7);
    near.resize(10 * 1024 * 1024 + 1, 0);
    let (s, v) = upload(&fx, near).await; // inside the gate's slack: the handler's own refusal
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::PAYLOAD_TOO_LARGE, &json!("too_large"))
    );
    // Exactly at the cap is fine.
    let mut at = png(2);
    at.resize(10 * 1024 * 1024, 0);
    assert_eq!(upload(&fx, at).await.0, StatusCode::OK);
    assert_eq!(count(&fx).await, 1);
}

#[tokio::test]
async fn the_same_file_twice_is_one_row_and_is_served_safely() {
    let fx = fx().await;
    let (s, a) = upload(&fx, png(3)).await;
    assert_eq!(
        (s, &a["duplicate"], &a["content_type"]),
        (StatusCode::OK, &json!(false), &json!("image/png"))
    );
    let (_, b) = upload(&fx, png(3)).await;
    assert_eq!(
        (&b["sha256"], &b["duplicate"]),
        (&a["sha256"], &json!(true))
    );
    assert_eq!(count(&fx).await, 1);
    let sha = a["sha256"].as_str().unwrap();
    let (s, _, raw, h) = send(&fx, Method::GET, &format!("/attachments/{sha}"), vec![]).await;
    assert_eq!((s, raw), (StatusCode::OK, png(3)));
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(h[header::CONTENT_TYPE], "image/png");
    assert_eq!(h[header::CONTENT_DISPOSITION], "attachment");
    assert!(
        h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("sandbox")
    );
    for bad in ["nothex", &"A".repeat(64), &"0".repeat(64)] {
        assert_eq!(
            send(&fx, Method::GET, &format!("/attachments/{bad}"), vec![])
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn a_trashed_note_keeps_its_attachment_until_the_sweep_purges_the_note() {
    let fx = fx().await;
    let (_, used) = upload(&fx, png(4)).await;
    let (_, young) = upload(&fx, png(5)).await;
    let (_, old) = upload(&fx, png(6)).await;
    let sha = |v: &Value| v["sha256"].as_str().unwrap().to_owned();
    let id = note(
        &fx,
        &format!("# Pic\n\n![a](lore-attachment:{})", sha(&used)),
    )
    .await;
    // Everything but `young` is past the grace day.
    sqlx::query(
        "UPDATE lore_attachments SET created_at = '2020-01-01T00:00:00.000Z' WHERE sha256 != ?",
    )
    .bind(sha(&young))
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let (s, _, _, _) = send(
        &fx,
        Method::PATCH,
        &format!("/notes/{id}"),
        json!({"trashed": true}).to_string().into_bytes(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    lore_module::sweep(&fx.app.pool).await.unwrap();
    let held = |sha: String| {
        let pool = fx.app.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM lore_attachments WHERE sha256 = ?")
                .bind(sha)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(held(sha(&used)).await, 1, "referenced by a trashed note");
    assert_eq!(held(sha(&young)).await, 1, "inside the grace day");
    assert_eq!(held(sha(&old)).await, 0, "unreferenced and old");
    // The note leaves the trash for good; the next sweep takes its attachment too.
    sqlx::query("UPDATE lore_notes SET trashed_at = '2020-01-01T00:00:00.000Z' WHERE id = ?")
        .bind(&id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM lore_versions")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    lore_module::sweep(&fx.app.pool).await.unwrap();
    assert_eq!(held(sha(&used)).await, 0);
    assert_eq!(held(sha(&young)).await, 1);
}
