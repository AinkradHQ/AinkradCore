//! Mockup packages through the Core's real gate (signed requests into `api::router`): path validation,
//! limits, inert serving, the drafted manifest and the one-off import. Each test fails if the property it
//! names stops holding.

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
    let modules: Vec<Arc<dyn Module>> = if on {
        vec![Arc::new(Design::default())]
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

/// Status, parsed JSON body (null when it is not JSON), raw body and headers.
async fn send(
    fx: &Fx,
    dev: &TestDevice,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, Value, Vec<u8>, HeaderMap) {
    send_as(fx, dev, method, path, body, "application/octet-stream").await
}

async fn send_as(
    fx: &Fx,
    dev: &TestDevice,
    method: Method,
    path: &str,
    body: Vec<u8>,
    content_type: &str,
) -> (StatusCode, Value, Vec<u8>, HeaderMap) {
    let uri = format!("{BASE}{path}");
    let mut b = Request::builder()
        .method(method.clone())
        .uri(&uri)
        .header(header::HOST, HOST)
        .header(header::CONTENT_LENGTH, body.len());
    if !body.is_empty() {
        b = b.header(header::CONTENT_TYPE, content_type);
    }
    for (name, value) in dev.headers(method.as_str(), &uri, &body) {
        b = b.header(name, value);
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let raw = to_bytes(res.into_body(), 1 << 28).await.unwrap().to_vec();
    let json = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    (status, json, raw, headers)
}

async fn call(fx: &Fx, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let b = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
    let (s, v, _, _) = send_as(fx, &fx.admin, method, path, b, "application/json").await;
    (s, v)
}

async fn new_mockup(fx: &Fx) -> String {
    let (s, v) = call(
        fx,
        Method::POST,
        "/docs",
        Some(json!({"kind": "mockup", "name": "Pkg"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["id"].as_str().unwrap().to_owned()
}

async fn put(fx: &Fx, doc: &str, path: &str, body: Vec<u8>) -> (StatusCode, Value) {
    let (s, v, _, _) = send(
        fx,
        &fx.admin,
        Method::PUT,
        &format!("/docs/{doc}/package/files?path={path}"),
        body,
    )
    .await;
    (s, v)
}

async fn count(fx: &Fx, table: &str) -> i64 {
    let sql = sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")); // test-only, a literal table name
    sqlx::query_scalar(sql)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn files(fx: &Fx) -> i64 {
    count(fx, "design_mockup_files").await
}

fn png() -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.extend([7u8; 64]);
    v
}

#[tokio::test]
async fn hostile_paths_are_refused_and_nothing_is_stored() {
    let fx = fx().await;
    let doc = new_mockup(&fx).await;
    for p in [
        "..%2Fx.html",
        "a%2F..%2Fb.html",
        "a/../b.html",
        "../x.html",
        "%2Fetc%2Fx.html",
        "/etc/x.html",
        "a%00b.html",
        "a%5Cb.html",
        "C:%5Cx.html",
        "%2e%2e/x.html",
        ".hidden.html",
        "a//b.html",
        "a%0Ab.html",
        "noext",
        "",
    ] {
        let (s, v) = put(&fx, &doc, p, b"<p>x</p>".to_vec()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{p:?} -> {v}");
    }
    assert_eq!(
        (files(&fx).await, count(&fx, "design_assets").await),
        (0, 0)
    );
}

#[tokio::test]
async fn a_package_is_drafted_sealed_and_served_only_as_an_inert_attachment() {
    let fx = fx().await;
    let doc = new_mockup(&fx).await;
    let html = b"<!doctype html><script>fetch('https://evil.test')</script>";
    for (p, b) in [
        ("index.html", html.to_vec()),
        ("sub/b.html", b"<p>b</p>".to_vec()),
        ("app.css", b"a{}".to_vec()),
        ("art/x.png", png()),
    ] {
        let (s, v) = put(&fx, &doc, p, b).await;
        assert_eq!(s, StatusCode::OK, "{p} {v}");
    }
    let (s, v) = put(&fx, &doc, "INDEX.html", b"<p>again</p>".to_vec()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        files(&fx).await,
        4,
        "a path that differs by case is the same file"
    );
    let (_, v, _, _) = send(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/docs/{doc}/package"),
        vec![],
    )
    .await;
    assert_eq!(v["sealed"], json!(false));
    let (s, v, _, _) = send(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/docs/{doc}/package/manifest"),
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let names: Vec<&str> = v["manifest"]["screens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        // putting `INDEX.html` replaced `index.html` (one file, the later spelling kept), and it still sorts first
        ["INDEX.html", "sub/b.html"],
        "root index first, only html"
    );
    assert_eq!(v["sealed"], json!(true));
    let (s, v) = put(&fx, &doc, "c.html", b"<p>c</p>".to_vec()).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, _, _, _) = send(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/docs/{doc}/package/manifest"),
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // Served: never an HTML type, always an attachment.
    let (s, _, raw, h) = send(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/docs/{doc}/package/files?path=sub/b.html"),
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(raw, b"<p>b</p>");
    let get = |n: &str| h.get(n).unwrap().to_str().unwrap().to_owned();
    assert_eq!(get("content-type"), "application/octet-stream");
    assert_eq!(get("content-disposition"), "attachment");
    assert_eq!(get("x-content-type-options"), "nosniff");
    assert!(get("content-security-policy").contains("sandbox"));
    let (s, _, _, _) = send(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/docs/{doc}/package/files?path=nope.html"),
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A package's bytes are not library assets (the asset routes do not see them), so they cannot be deleted there.
    let sha: String =
        sqlx::query_scalar("SELECT sha256 FROM design_mockup_files WHERE path = 'app.css'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    let (s, _) = call(&fx, Method::DELETE, &format!("/assets/{sha}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(files(&fx).await, 4, "the package still holds its files");
    // Not a mockup, and audit carries ids only.
    let (_, d) = call(
        &fx,
        Method::POST,
        "/docs",
        Some(json!({"kind": "design", "name": "D"})),
    )
    .await;
    let (s, _) = put(&fx, d["id"].as_str().unwrap(), "a.html", b"<p/>".to_vec()).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let audit: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action LIKE 'design.%'")
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    assert!(
        audit
            .iter()
            .all(|d| !d.contains("index.html") && !d.contains("evil")),
        "{audit:?}"
    );
}

#[tokio::test]
async fn bytes_must_match_the_type_and_only_the_fixed_types_are_taken() {
    let fx = fx().await;
    let doc = new_mockup(&fx).await;
    let mut polyglot = png();
    polyglot.extend(b"<svg onload=alert(1)>");
    for (p, b) in [
        ("a.png", b"MZ\x90\x00 an exe".to_vec()),
        ("b.png", polyglot),
        ("c.jpg", png()),
        ("d.html", b"<p>\x00</p>".to_vec()),
        ("e.html", vec![0xff, 0xfe, b'<']),
        ("f.woff2", b"wOF2....".to_vec()),
        ("g.zip", b"PK\x03\x04".to_vec()),
        ("h.exe", b"x".to_vec()),
    ] {
        let (s, v) = put(&fx, &doc, p, b).await;
        assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{p} {v}");
    }
    // (an SVG with a script is not refused: it is stored sanitised, below)
    let (s, v) = put(
        &fx,
        &doc,
        "ok.svg",
        b"<svg xmlns='http://www.w3.org/2000/svg'><script>1</script><rect/></svg>".to_vec(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, _, raw, _) = send(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/docs/{doc}/package/files?path=ok.svg"),
        vec![],
    )
    .await;
    assert!(!String::from_utf8(raw).unwrap().contains("script"));
    assert_eq!(files(&fx).await, 1);
}

#[tokio::test]
async fn more_than_200_files_or_100_mib_is_refused() {
    let fx = fx().await;
    let doc = new_mockup(&fx).await;
    for i in 0..200 {
        let (s, v) = put(
            &fx,
            &doc,
            &format!("p{i}.html"),
            format!("<p>{i}</p>").into_bytes(),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{i} {v}");
    }
    let (s, v) = put(&fx, &doc, "p200.html", b"<p>x</p>".to_vec()).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{v}");
    // Replacing one of the 200 is not an extra file.
    let (s, v) = put(&fx, &doc, "p0.html", b"<p>new</p>".to_vec()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(files(&fx).await, 200);

    let doc = new_mockup(&fx).await;
    for i in 0..4u8 {
        let (s, v) = put(
            &fx,
            &doc,
            &format!("big{i}.js"),
            vec![b'a' + i; 25 * 1024 * 1024],
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{i} {v}");
    }
    let (s, v) = put(&fx, &doc, "one-more.js", b"x".to_vec()).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{v}");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM design_mockup_files WHERE doc = ?")
        .bind(&doc)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 4);
    // A single file over the asset cap is refused before anything is stored.
    let (s, _, _, _) = send(
        &fx,
        &fx.admin,
        Method::PUT,
        &format!("/docs/{doc}/package/files?path=huge.js"),
        vec![b'a'; 25 * 1024 * 1024 + 1],
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn the_import_refuses_symlinks_and_takes_a_clean_folder_whole() {
    let fx = fx().await;
    let dir = fx.dir.join("pkg");
    std::fs::create_dir_all(dir.join("shots")).unwrap();
    std::fs::write(dir.join("index.html"), "<p>hi</p>").unwrap();
    std::fs::write(dir.join("a.css"), "a{}").unwrap();
    std::fs::write(dir.join("notes.md"), "skipped").unwrap();
    std::fs::write(dir.join(".DS_Store"), "skipped").unwrap();
    std::fs::write(dir.join("shots/s.png"), png()).unwrap();
    let skip = vec!["shots".to_owned()];
    let (doc, n) = design_module::import_dir(&fx.app.pool, &dir, "Imported", &skip)
        .await
        .unwrap();
    assert_eq!(n, 2);
    let (_, v, _, _) = send(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/docs/{doc}/package"),
        vec![],
    )
    .await;
    assert_eq!(
        (v["sealed"].clone(), v["files"].as_array().unwrap().len()),
        (json!(true), 2)
    );

    // A symlink anywhere (here to a file outside the folder) refuses the whole folder.
    std::os::unix::fs::symlink("/etc/hosts", dir.join("link.html")).unwrap();
    let docs_before = count(&fx, "design_docs").await;
    let e = design_module::import_dir(&fx.app.pool, &dir, "Bad", &skip)
        .await
        .unwrap_err();
    assert!(e.contains("symlink"), "{e}");
    assert_eq!(count(&fx, "design_docs").await, docs_before);
    // A folder with a bad path (a name with a space) refuses and rolls back too.
    std::fs::remove_file(dir.join("link.html")).unwrap();
    std::fs::write(dir.join("bad name.html"), "x").unwrap();
    assert!(
        design_module::import_dir(&fx.app.pool, &dir, "Bad", &skip)
            .await
            .is_err()
    );
    assert_eq!(count(&fx, "design_docs").await, docs_before);
}

#[tokio::test]
async fn a_read_only_device_reads_but_cannot_change_a_package() {
    let fx = fx().await;
    let doc = new_mockup(&fx).await;
    let reader = enroll(&fx.app, "reader", &["read"]).await;
    let (s, _, _, _) = send(
        &fx,
        &reader,
        Method::GET,
        &format!("/docs/{doc}/package"),
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _, _) = send(
        &fx,
        &reader,
        Method::PUT,
        &format!("/docs/{doc}/package/files?path=a.html"),
        b"<p/>".to_vec(),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _, _) = send(
        &fx,
        &reader,
        Method::POST,
        &format!("/docs/{doc}/package/manifest"),
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_mockup_file_is_never_a_library_asset() {
    let fx = fx().await;
    let doc = new_mockup(&fx).await;
    let (s, v) = put(&fx, &doc, "a.png", png()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let sha = v["sha256"].as_str().unwrap().to_owned();
    // The asset routes do not see it.
    for path in [format!("/assets/{sha}"), format!("/assets/{sha}/data")] {
        let (s, _, _, _) = send(&fx, &fx.admin, Method::GET, &path, vec![]).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
    }
    // The same bytes as an ordinary upload are refused and the row never joins the library.
    let (s, _, _, _) = send(&fx, &fx.admin, Method::POST, "/assets?name=x.png", png()).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let lib: i64 = sqlx::query_scalar("SELECT library FROM design_assets WHERE sha256 = ?")
        .bind(&sha)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(lib, 0);
    let (s, v, _, _) = send(&fx, &fx.admin, Method::GET, "/assets", vec![]).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!v.to_string().contains(&sha));
}

#[tokio::test]
async fn the_import_skips_hidden_dirs_and_refuses_hard_links_and_a_symlinked_root() {
    let fx = fx().await;
    let dir = fx.dir.join("pkg-hard");
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::os::unix::fs::symlink("/etc/hosts", dir.join(".git/link")).unwrap();
    std::fs::write(dir.join("index.html"), "<p>hi</p>").unwrap();
    let (_, n) = design_module::import_dir(&fx.app.pool, &dir, "Hidden", &[])
        .await
        .unwrap();
    assert_eq!(n, 1);
    std::fs::hard_link(dir.join("index.html"), dir.join("again.html")).unwrap();
    let e = design_module::import_dir(&fx.app.pool, &dir, "Hard", &[])
        .await
        .unwrap_err();
    assert!(e.contains("hard link"), "{e}");
    let root = fx.dir.join("root-link");
    std::os::unix::fs::symlink(&dir, &root).unwrap();
    assert!(
        design_module::import_dir(&fx.app.pool, &root, "Root", &[])
            .await
            .is_err()
    );
}
