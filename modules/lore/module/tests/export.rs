//! Lore export (R1-06) through the Core's real gate: the zip, its front matter, names, scoping and bounds.

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
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "lore-gate-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Lore::default())];
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

async fn upload(fx: &Fx, bytes: Vec<u8>) -> String {
    let (s, v, _, _) = send(fx, Method::POST, "/attachments", bytes).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["sha256"].as_str().unwrap().to_owned()
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

fn le(b: &[u8], at: usize, n: usize) -> usize {
    (0..n).fold(0, |a, i| a | (usize::from(b[at + i]) << (8 * i)))
}

/// Reads the zip through its central directory: (name, bytes) per entry, checking sizes agree.
fn unzip(z: &[u8]) -> Vec<(String, Vec<u8>)> {
    let end = z.len() - 22;
    assert_eq!(&z[end..end + 4], b"PK\x05\x06");
    let (n, mut at) = (le(z, end + 10, 2), le(z, end + 16, 4));
    let mut out = Vec::new();
    for _ in 0..n {
        assert_eq!(&z[at..at + 4], b"PK\x01\x02");
        let (size, nl, local) = (le(z, at + 24, 4), le(z, at + 28, 2), le(z, at + 42, 4));
        let name = String::from_utf8(z[at + 46..at + 46 + nl].to_vec()).unwrap();
        assert_eq!(&z[local..local + 4], b"PK\x03\x04");
        let start = local + 30 + le(z, local + 26, 2) + le(z, local + 28, 2);
        out.push((name, z[start..start + size].to_vec()));
        at += 46 + nl;
    }
    out
}

async fn export(fx: &Fx, query: &str) -> (StatusCode, Vec<(String, Vec<u8>)>, HeaderMap) {
    let (s, _, raw, h) = send(fx, Method::GET, &format!("/export{query}"), vec![]).await;
    let files = if s == StatusCode::OK {
        unzip(&raw)
    } else {
        vec![]
    };
    (s, files, h)
}

fn text<'a>(files: &'a [(String, Vec<u8>)], name: &str) -> &'a str {
    std::str::from_utf8(
        &files
            .iter()
            .find(|f| f.0 == name)
            .unwrap_or_else(|| panic!("{name}"))
            .1,
    )
    .unwrap()
}

#[tokio::test]
async fn everything_is_exported_with_front_matter_attachments_and_kept_links() {
    let fx = fx().await;
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend([5u8; 64]);
    let sha = upload(&fx, png.clone()).await;
    let a = note(
        &fx,
        &format!("# Plan\nSee [[Other note|x]] #work\n![p](lore-attachment:{sha})\n"),
    )
    .await;
    note(&fx, "# Plan\nsame title").await;
    note(&fx, "---\ntags: [kept]\nowner: me\n---\n# Other note\nbody").await;
    let (s, files, h) = export(&fx, "").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h[header::CONTENT_TYPE], "application/zip");
    let names: Vec<&str> = files.iter().map(|f| f.0.as_str()).collect();
    assert_eq!(
        names
            .iter()
            .filter(|n| n.starts_with("personal/plan"))
            .count(),
        2
    );
    assert!(names.contains(&"personal/plan.md") && names.contains(&"personal/plan-2.md"));
    assert!(names.contains(&"personal/other-note.md"));
    let att = format!("attachments/{sha}.png");
    assert_eq!(files.iter().find(|f| f.0 == att).unwrap().1, png);
    for n in &names {
        assert!(
            !n.contains("..") && !n.starts_with('/') && !n.chars().any(char::is_control),
            "{n}"
        );
    }
    let plan = names.iter().find(|n| text(&files, n).contains(&a)).unwrap();
    let t = text(&files, plan);
    assert!(
        t.starts_with(&format!(
            "---\nid: {a}\nproject: null\ntags: [work]\ncreated: "
        )),
        "{t}"
    );
    assert!(t.contains("[[Other note|x]]") && t.contains(&format!("lore-attachment:{sha}")));
    let o = text(&files, "personal/other-note.md");
    assert!(
        o.contains("tags: [kept]")
            && o.ends_with("---\n# Other note\nbody")
            && !o.contains("owner")
    );
}

#[tokio::test]
async fn scoping_trash_and_refusals() {
    let fx = fx().await;
    let a = note(&fx, "# One\nx").await;
    let b = note(&fx, "# Two\nx").await;
    let (s, files, _) = export(&fx, &format!("?note={a}")).await;
    assert_eq!((s, files.len()), (StatusCode::OK, 1));
    let (s, files, _) = export(&fx, "?project=999").await;
    assert_eq!((s, files.len()), (StatusCode::OK, 0));
    assert_eq!(
        export(&fx, "?note=ln_aaaaaaaaaaaa").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(export(&fx, "?note=../x").await.0, StatusCode::NOT_FOUND);
    assert_eq!(export(&fx, "?project=abc").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        export(&fx, &format!("?project=1&note={a}")).await.0,
        StatusCode::BAD_REQUEST
    );
    sqlx::query("UPDATE lore_notes SET trashed_at = datetime('now') WHERE id = ?")
        .bind(&b)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let (_, files, _) = export(&fx, "").await;
    assert_eq!(files.len(), 1);
    assert_eq!(
        export(&fx, &format!("?note={b}")).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn hostile_titles_cannot_escape_the_folder() {
    let fx = fx().await;
    for t in [
        "# ../../etc/passwd",
        "# /abs/olute",
        "# a\\b\u{7}c",
        "# CON",
        "# \u{202e}evil",
    ] {
        note(&fx, &format!("{t}\nx")).await;
    }
    let (s, files, _) = export(&fx, "").await;
    assert_eq!((s, files.len()), (StatusCode::OK, 5));
    for (n, _) in &files {
        assert!(n.starts_with("personal/") && n.ends_with(".md"), "{n}");
        let stem = &n["personal/".len()..];
        assert!(
            !stem.contains(['/', '\\', '.']) || stem.matches('.').count() == 1,
            "{n}"
        );
        assert!(!n.contains("..") && !n.chars().any(char::is_control), "{n}");
    }
}
