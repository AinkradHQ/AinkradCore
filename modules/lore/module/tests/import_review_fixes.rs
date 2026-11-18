//! Review fixes for the import runs (R4-01): undo never trashes work done after the import, a recycled repo id
//! cannot cross projects, conflict versions are never shared between items, Unicode format characters are
//! refused in paths, and zip reads are limited to two at a time.

use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::projects::{self, Who};
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

async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "lore-import-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(
        Lore::default().with_mirror_root(dir.join("mirrors")),
    )];
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
    let dev = TestDevice::enroll_keys(
        &app.pool,
        "admin",
        "device",
        &["admin", "read"],
        &app.auth.identity.fp,
        clock.clone(),
        true,
    )
    .await;
    dev.set_session(Some(app.auth.issue_session(&dev.id, clock.unix()).id));
    Fx {
        app,
        admin: dev,
        dir,
    }
}

async fn send(
    fx: &Fx,
    method: Method,
    path: &str,
    body: Vec<u8>,
    ctype: &str,
) -> (StatusCode, Value) {
    let uri = format!("{BASE}{path}");
    let mut b = Request::builder()
        .method(method.clone())
        .uri(&uri)
        .header(header::HOST, HOST);
    for (name, value) in fx.admin.headers(method.as_str(), &uri, &body) {
        b = b.header(name, value);
    }
    if !body.is_empty() {
        b = b.header(header::CONTENT_TYPE, ctype);
    }
    let res = router(fx.app.clone())
        .oneshot(b.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let text =
        String::from_utf8_lossy(&to_bytes(res.into_body(), 1 << 22).await.unwrap()).into_owned();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

async fn call(fx: &Fx, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
    send(fx, method, path, bytes, "application/json").await
}

async fn ok(fx: &Fx, method: Method, path: &str, body: Option<Value>) -> Value {
    let (s, v) = call(fx, method, path, body).await;
    assert_eq!(s, StatusCode::OK, "{path}: {v}");
    v
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

async fn scalar(fx: &Fx, sql: &str) -> String {
    sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

/// A finished upload run of `files` into `project`.
async fn upload(fx: &Fx, project: &str, files: &[(&str, &str)]) -> Value {
    let run = ok(
        fx,
        Method::POST,
        "/imports",
        Some(json!({"source": "upload", "project": project})),
    )
    .await;
    let id = run["id"].as_str().unwrap().to_owned();
    let items: Vec<Value> = files
        .iter()
        .map(|(p, t)| json!({"path": p, "text": t}))
        .collect();
    ok(
        fx,
        Method::POST,
        &format!("/imports/{id}/items"),
        Some(json!({"items": items})),
    )
    .await;
    ok(fx, Method::POST, &format!("/imports/{id}/finish"), None).await
}

async fn note_by_title(fx: &Fx, title: &str) -> Value {
    let list = ok(fx, Method::GET, "/notes", None).await;
    let n = list
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["title"] == title)
        .unwrap_or_else(|| panic!("{title}"));
    ok(
        fx,
        Method::GET,
        &format!("/notes/{}", n["id"].as_str().unwrap()),
        None,
    )
    .await
}

fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opt =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in files {
        z.start_file(*name, opt).unwrap();
        z.write_all(data).unwrap();
    }
    z.finish().unwrap().into_inner()
}


fn git(dir: &std::path::Path, args: &[&str]) {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "protocol.file.allow=always",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn mirror_repo(fx: &Fx, project: &str, id: i64, doc: &str) {
    let work = fx.dir.join(format!("work{id}-{project}"));
    std::fs::create_dir_all(work.join("Docs")).unwrap();
    git(&work, &["init", "-q", "-b", "main"]);
    std::fs::write(work.join("Docs/a.md"), doc).unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "x"]);
    let mirrors = fx.dir.join("mirrors");
    std::fs::create_dir_all(&mirrors).unwrap();
    let bare = format!("{id}.git");
    let _ = std::fs::remove_dir_all(mirrors.join(&bare));
    git(
        &mirrors,
        &["clone", "-q", "--bare", work.to_str().unwrap(), &bare],
    );
    let remote = format!("https://example.test/{project}.git");
    std::fs::write(
        mirrors.join(&bare).join("ainkrad-remote"),
        format!("{project}\n{remote}"),
    )
    .unwrap();
}

async fn add_repo(fx: &Fx, project: &str, id: i64) {
    sqlx::query(
        "INSERT INTO core_project_repos (id, project_id, name, remote_url, default_branch, is_primary) VALUES (?, ?, 'main', ?, 'main', 1)",
    )
    .bind(id)
    .bind(project.parse::<i64>().unwrap())
    .bind(format!("https://example.test/{project}.git"))
    .execute(&fx.app.pool)
    .await
    .unwrap();
}

async fn commit(fx: &Fx, run: &Value) -> Value {
    let id = run["id"].as_str().unwrap();
    ok(fx, Method::POST, &format!("/imports/{id}/commit"), None).await
}

async fn undo(fx: &Fx, run: &Value) -> Value {
    let id = run["id"].as_str().unwrap();
    ok(fx, Method::POST, &format!("/imports/{id}/undo"), None).await
}

async fn live_notes(fx: &Fx) -> usize {
    ok(fx, Method::GET, "/notes", None)
        .await
        .as_array()
        .unwrap()
        .len()
}

#[tokio::test]
async fn undo_keeps_a_created_note_that_was_edited_after_the_import() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let run = upload(&fx, &p, &[("a.md", "# Alpha\nfirst\n")]).await;
    commit(&fx, &run).await;
    let a = note_by_title(&fx, "Alpha").await;
    let aid = a["id"].as_str().unwrap();
    ok(
        &fx,
        Method::PUT,
        &format!("/notes/{aid}/text"),
        Some(json!({"base_rev": a["rev"], "text": "# Alpha\nmine\n"})),
    )
    .await;
    let undone = undo(&fx, &run).await;
    assert_eq!(undone["state"], "undone");
    assert_eq!(live_notes(&fx).await, 1);
    assert_eq!(note_by_title(&fx, "Alpha").await["text"], "# Alpha\nmine\n");
}

#[tokio::test]
async fn undoing_a_run_keeps_what_a_later_run_updated() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let a = upload(&fx, &p, &[("a.md", "# Alpha\nfirst\n")]).await;
    commit(&fx, &a).await;
    let b = upload(&fx, &p, &[("a.md", "# Alpha\nsecond\n")]).await;
    let done = commit(&fx, &b).await;
    assert_eq!(done["results"]["updated"], 1);
    undo(&fx, &a).await;
    assert_eq!(live_notes(&fx).await, 1);
    assert!(
        note_by_title(&fx, "Alpha").await["text"]
            .as_str()
            .unwrap()
            .contains("second")
    );
    // And an untouched created note is still trashed.
    let c = upload(&fx, &p, &[("c.md", "# Gamma\n")]).await;
    commit(&fx, &c).await;
    undo(&fx, &c).await;
    assert_eq!(live_notes(&fx).await, 1);
}

#[tokio::test]
async fn a_recycled_repo_id_does_not_cross_projects() {
    let fx = fx().await;
    let p1 = project(&fx, "alpha").await;
    let p2 = project(&fx, "beta").await;
    mirror_repo(&fx, &p1, 1, "# Alpha\nfrom one\n");
    add_repo(&fx, &p1, 1).await;
    let r1 = ok(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"source": "mirror", "project": p1})),
    )
    .await;
    assert_eq!(r1["state"], "review", "{r1}");
    commit(&fx, &r1).await;
    // The repo goes away and its id is handed to another project, with the same path in its Docs.
    sqlx::query("DELETE FROM core_project_repos WHERE id = 1")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    mirror_repo(&fx, &p2, 1, "# Beta\nfrom two\n");
    add_repo(&fx, &p2, 1).await;
    let r2 = ok(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"source": "mirror", "project": p2})),
    )
    .await;
    assert_eq!(r2["state"], "review", "{r2}");
    assert_eq!(r2["flags"]["changed"].as_i64().unwrap_or(0), 0, "{r2}");
    assert_eq!(r2["flags"]["conflict"].as_i64().unwrap_or(0), 0, "{r2}");
    let done = commit(&fx, &r2).await;
    assert_eq!(done["results"]["created"], 1);
    assert_eq!(live_notes(&fx).await, 2);
    assert!(
        note_by_title(&fx, "Alpha").await["text"]
            .as_str()
            .unwrap()
            .contains("from one")
    );
}

#[tokio::test]
async fn undo_never_removes_a_conflict_version_another_item_holds() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let first = upload(&fx, &p, &[("a.md", "# Alpha\nfirst\n")]).await;
    commit(&fx, &first).await;
    let a = note_by_title(&fx, "Alpha").await;
    let aid = a["id"].as_str().unwrap();
    ok(
        &fx,
        Method::PUT,
        &format!("/notes/{aid}/text"),
        Some(json!({"base_rev": a["rev"], "text": "# Alpha\nmine\n"})),
    )
    .await;
    // Two runs bring the very same incoming text; each keeps its own version of it.
    let r1 = upload(&fx, &p, &[("a.md", "# Alpha\nfile\n")]).await;
    commit(&fx, &r1).await;
    let r2 = upload(&fx, &p, &[("a.md", "# Alpha\nfile\n")]).await;
    commit(&fx, &r2).await;
    let kept = |run: &Value| {
        format!(
            "SELECT version FROM lore_import_items WHERE run = '{}' AND result = 'conflict'",
            run["id"].as_str().unwrap()
        )
    };
    let (v1, v2) = (scalar(&fx, &kept(&r1)).await, scalar(&fx, &kept(&r2)).await);
    assert_ne!(v1, v2);
    undo(&fx, &r1).await;
    assert_eq!(
        scalar(
            &fx,
            &format!("SELECT count(*) || '' FROM lore_versions WHERE id = '{v2}'")
        )
        .await,
        "1"
    );
    assert_eq!(
        scalar(
            &fx,
            &format!("SELECT count(*) || '' FROM lore_versions WHERE id = '{v1}'")
        )
        .await,
        "0"
    );
}

#[tokio::test]
async fn unicode_format_characters_in_a_path_are_refused() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let run = upload(
        &fx,
        &p,
        &[
            ("evil\u{202E}dm.md", "# One\n"),
            ("zero\u{200B}width.md", "# Two\n"),
            ("fine.md", "# Three\n"),
        ],
    )
    .await;
    assert_eq!(
        (run["refused"].as_i64(), run["items"].as_i64()),
        (Some(2), Some(1))
    );
}

#[tokio::test]
async fn parallel_zip_uploads_all_finish() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let mut runs = Vec::new();
    for i in 0..5 {
        let r = ok(
            &fx,
            Method::POST,
            "/imports",
            Some(json!({"source": "upload", "project": p})),
        )
        .await;
        runs.push((r["id"].as_str().unwrap().to_owned(), i));
    }
    let sends = runs.iter().map(|(id, i)| {
        let body = zip_of(&[("a.md", format!("# Doc {i}\n").as_bytes())]);
        let fx = &fx;
        async move {
            send(
                fx,
                Method::POST,
                &format!("/imports/{id}/zip"),
                body,
                "application/zip",
            )
            .await
        }
    });
    for (s, v) in futures_util::future::join_all(sends).await {
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["items"], 1);
    }
}
