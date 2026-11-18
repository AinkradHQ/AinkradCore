//! Import runs through the Core's real gate (R4-01): upload items and zips, a hostile repo copy, review, commit,
//! re-import (unedited notes update, edited ones are kept with a version), undo, and the refusals. Each test fails
//! if the property it names stops holding.

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
        // A bulk route (the zip) needs the declared length, as every real client sends it.
        b = b
            .header(header::CONTENT_TYPE, ctype)
            .header(header::CONTENT_LENGTH, body.len());
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

#[tokio::test]
async fn upload_review_commit_reimport_and_undo() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let run = upload(
        &fx,
        &p,
        &[
            ("Plans/a.md", "# Alpha\nsee [[Beta]]\n"),
            ("Plans/b.md", "# Beta\nfirst\n"),
            ("notes.txt", "not markdown"),
            ("../x.md", "# escape"),
            ("/abs.md", "# absolute"),
            ("c.md", "bad\u{0}nul"),
        ],
    )
    .await;
    let id = run["id"].as_str().unwrap().to_owned();
    assert_eq!(
        (run["state"].as_str(), run["items"].as_i64()),
        (Some("review"), Some(2))
    );
    assert_eq!(
        (run["refused"].as_i64(), run["ignored"].as_i64()),
        (Some(3), Some(1))
    );
    // Nothing is a note before commit.
    assert!(
        ok(&fx, Method::GET, "/notes", None)
            .await
            .as_array()
            .unwrap()
            .is_empty()
    );
    // A run in review takes no more items.
    let (s, _) = call(
        &fx,
        Method::POST,
        &format!("/imports/{id}/items"),
        Some(json!({"items": []})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);

    let done = ok(&fx, Method::POST, &format!("/imports/{id}/commit"), None).await;
    assert_eq!(done["state"], "committed");
    assert_eq!(done["results"]["created"], 2);
    let a = note_by_title(&fx, "Alpha").await;
    assert!(
        a["text"]
            .as_str()
            .unwrap()
            .starts_with("---\ntags: [plans]\n---\n"),
        "{a}"
    );
    assert_eq!(a["project"], json!(p));
    // The link written before its target existed is resolved once the target landed.
    assert_eq!(
        scalar(
            &fx,
            "SELECT count(*) || '' FROM lore_links WHERE target IS NOT NULL"
        )
        .await,
        "1"
    );

    // The person edits Alpha; the files change in the repo; import again.
    let aid = a["id"].as_str().unwrap();
    ok(
        &fx,
        Method::PUT,
        &format!("/notes/{aid}/text"),
        Some(json!({"base_rev": a["rev"], "text": "# Alpha\nmy own words\n"})),
    )
    .await;
    let b_before = note_by_title(&fx, "Beta").await;
    let again = upload(
        &fx,
        &p,
        &[
            ("Plans/a.md", "# Alpha\nsee [[Beta]]\nnew\n"),
            ("Plans/b.md", "# Beta\nsecond\n"),
        ],
    )
    .await;
    assert_eq!(
        (
            again["flags"]["conflict"].as_i64(),
            again["flags"]["changed"].as_i64()
        ),
        (Some(1), Some(1))
    );
    let id2 = again["id"].as_str().unwrap().to_owned();
    let done2 = ok(&fx, Method::POST, &format!("/imports/{id2}/commit"), None).await;
    assert_eq!(
        (
            done2["results"]["conflict"].as_i64(),
            done2["results"]["updated"].as_i64()
        ),
        (Some(1), Some(1))
    );
    // One note per origin: nothing was created twice.
    assert_eq!(
        ok(&fx, Method::GET, "/notes", None)
            .await
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // The edited note is untouched and holds the incoming text as a version; the unedited one is updated.
    assert_eq!(
        note_by_title(&fx, "Alpha").await["text"],
        "# Alpha\nmy own words\n"
    );
    let versions = ok(&fx, Method::GET, &format!("/notes/{aid}/versions"), None).await;
    assert!(
        versions
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["kind"] == "conflict")
    );
    let b = note_by_title(&fx, "Beta").await;
    assert!(b["text"].as_str().unwrap().contains("second"));
    let bid = b["id"].as_str().unwrap();
    let bv = ok(&fx, Method::GET, &format!("/notes/{bid}/versions"), None).await;
    assert!(bv.as_array().unwrap().iter().any(|v| v["kind"] == "auto"));

    // Undo the second run: the exact prior state, no conflict version left.
    let undone = ok(&fx, Method::POST, &format!("/imports/{id2}/undo"), None).await;
    assert_eq!(undone["state"], "undone");
    assert_eq!(note_by_title(&fx, "Beta").await["text"], b_before["text"]);
    let versions = ok(&fx, Method::GET, &format!("/notes/{aid}/versions"), None).await;
    assert!(
        !versions
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["kind"] == "conflict")
    );
    // Undo the first: both notes changed after it (Alpha by the person, Beta by the second run and its undo), so
    // both are left alone (R4-01 review fix) and nothing is trashed or deleted.
    ok(&fx, Method::POST, &format!("/imports/{id}/undo"), None).await;
    let live = ok(&fx, Method::GET, "/notes", None).await;
    assert_eq!(live.as_array().unwrap().len(), 2);
    assert_eq!(
        scalar(
            &fx,
            "SELECT count(*) || '' FROM lore_notes WHERE trashed_at IS NOT NULL"
        )
        .await,
        "0"
    );
    let runs = ok(&fx, Method::GET, "/imports", None).await;
    assert_eq!(runs.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn the_same_content_is_flagged_and_skipped() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let first = upload(&fx, &p, &[("a.md", "# One\n"), ("copy.md", "# One\n")]).await;
    // Repeated inside the run: the second is a duplicate, skipped by default.
    assert_eq!(first["flags"]["duplicate"], 1);
    assert_eq!(first["include"], 1);
    let id = first["id"].as_str().unwrap();
    ok(&fx, Method::POST, &format!("/imports/{id}/commit"), None).await;
    let again = upload(&fx, &p, &[("a.md", "# One\n")]).await;
    assert_eq!(again["include"], 0);
    let id2 = again["id"].as_str().unwrap();
    let done = ok(&fx, Method::POST, &format!("/imports/{id2}/commit"), None).await;
    assert_eq!(done["results"]["skipped"], 1);
    assert_eq!(
        ok(&fx, Method::GET, "/notes", None)
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_review_can_skip_items_and_an_unknown_project_is_refused() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let run = upload(&fx, &p, &[("a.md", "# A\n"), ("b.md", "# B\n")]).await;
    let id = run["id"].as_str().unwrap();
    let (s, _) = call(
        &fx,
        Method::PATCH,
        &format!("/imports/{id}/items"),
        Some(json!({"seqs": [1], "project": "9999"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let after = ok(
        &fx,
        Method::PATCH,
        &format!("/imports/{id}/items"),
        Some(json!({"seqs": [1], "mark": "skip"})),
    )
    .await;
    assert_eq!(after["include"], 1);
    let done = ok(&fx, Method::POST, &format!("/imports/{id}/commit"), None).await;
    assert_eq!(
        (
            done["results"]["created"].as_i64(),
            done["results"]["skipped"].as_i64()
        ),
        (Some(1), Some(1))
    );
    let (s, _) = call(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"source": "upload", "project": "9999"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"source": "ftp"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
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

/// Marks the central-directory entry called `name` as a unix symlink.
fn make_symlink(zip: &mut [u8], name: &[u8]) {
    let mut i = 0;
    while i + 46 < zip.len() {
        if zip[i..i + 4] == *b"PK\x01\x02" {
            let n = u16::from_le_bytes([zip[i + 28], zip[i + 29]]) as usize;
            if zip[i + 46..i + 46 + n] == *name {
                zip[i + 5] = 3; // made by: unix
                zip[i + 38..i + 42].copy_from_slice(&(0o120777u32 << 16).to_le_bytes());
            }
        }
        i += 1;
    }
}

#[tokio::test]
async fn a_hostile_zip_is_refused_entry_by_entry() {
    let fx = fx().await;
    let mut z = zip_of(&[
        ("Docs/ok.md", b"# Fine\n"),
        ("../evil.md", b"# up"),
        ("/abs.md", b"# abs"),
        ("link.md", b"/etc/passwd"),
        ("bin.md", b"a\0b"),
        ("node_modules/x.md", b"# dep"),
        ("pic.png", b"png"),
    ]);
    make_symlink(&mut z, b"link.md");
    let run = ok(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"source": "upload"})),
    )
    .await;
    let id = run["id"].as_str().unwrap();
    let (s, v) = send(
        &fx,
        Method::POST,
        &format!("/imports/{id}/zip"),
        z,
        "application/zip",
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (
            v["items"].as_i64(),
            v["refused"].as_i64(),
            v["ignored"].as_i64()
        ),
        (Some(1), Some(4), Some(2))
    );
    ok(&fx, Method::POST, &format!("/imports/{id}/finish"), None).await;
    let items = ok(&fx, Method::GET, &format!("/imports/{id}/items"), None).await;
    assert_eq!(items[0]["path"], "Docs/ok.md");
    assert_eq!(items[0]["tags"], json!(["docs"]));
    // Not a zip at all.
    let run = ok(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"source": "upload"})),
    )
    .await;
    let id = run["id"].as_str().unwrap();
    let (s, _) = send(
        &fx,
        Method::POST,
        &format!("/imports/{id}/zip"),
        b"not a zip".to_vec(),
        "application/zip",
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn too_large_files_are_flagged_not_read() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    // Past the signed-body cap an item cannot arrive as JSON, so the big file comes in a zip (16 MiB cap).
    let big = "x".repeat(1_100_000);
    let z = zip_of(&[("big.md", big.as_bytes()), ("ok.md", b"# Ok\n")]);
    let run = ok(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"source": "upload", "project": p})),
    )
    .await;
    let id = run["id"].as_str().unwrap();
    let (s, v) = send(
        &fx,
        Method::POST,
        &format!("/imports/{id}/zip"),
        z,
        "application/zip",
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let run = ok(&fx, Method::POST, &format!("/imports/{id}/finish"), None).await;
    assert_eq!(run["flags"]["too_large"], 1);
    assert_eq!(run["include"], 1);
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

#[tokio::test]
async fn a_hostile_repo_copy_yields_only_docs_markdown() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let work = fx.dir.join("work");
    std::fs::create_dir_all(work.join("Docs/.hidden")).unwrap();
    std::fs::create_dir_all(work.join("Docs/Plans")).unwrap();
    std::fs::create_dir_all(work.join("Docs/node_modules")).unwrap();
    git(&work, &["init", "-q", "-b", "main"]);
    std::fs::write(work.join("Docs/Plans/ok.md"), "# Fine\n").unwrap();
    std::fs::write(work.join("Docs/bin.md"), b"a\0b").unwrap();
    std::fs::write(work.join("Docs/big.md"), "y".repeat(1_500_000)).unwrap();
    std::fs::write(work.join("Docs/.hidden/x.md"), "# hidden").unwrap();
    std::fs::write(work.join("Docs/node_modules/x.md"), "# dep").unwrap();
    std::fs::write(work.join("README.md"), "# outside Docs").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", work.join("Docs/link.md")).unwrap();
    git(&work, &["add", "-A"]);
    // A submodule entry: a commit id in the tree, not a file.
    git(
        &work,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            "160000,1111111111111111111111111111111111111111,Docs/sub",
        ],
    );
    git(&work, &["commit", "-q", "-m", "x"]);
    let mirrors = fx.dir.join("mirrors");
    std::fs::create_dir_all(&mirrors).unwrap();
    git(
        &mirrors,
        &["clone", "-q", "--bare", work.to_str().unwrap(), "1.git"],
    );
    let remote = "https://example.test/x.git";
    std::fs::write(
        mirrors.join("1.git/ainkrad-remote"),
        format!("{p}\n{remote}"),
    )
    .unwrap();
    sqlx::query(
        "INSERT INTO core_project_repos (id, project_id, name, remote_url, default_branch, is_primary) VALUES (1, ?, 'main', ?, 'main', 1)",
    )
    .bind(p.parse::<i64>().unwrap())
    .bind(remote)
    .execute(&fx.app.pool)
    .await
    .unwrap();

    let run = ok(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"source": "mirror", "project": p})),
    )
    .await;
    assert_eq!(run["state"], "review", "{run}");
    assert_eq!(
        (
            run["items"].as_i64(),
            run["refused"].as_i64(),
            run["ignored"].as_i64()
        ),
        (Some(2), Some(3), Some(2))
    );
    let id = run["id"].as_str().unwrap();
    let items = ok(&fx, Method::GET, &format!("/imports/{id}/items"), None).await;
    let paths: Vec<&str> = items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["Docs/Plans/ok.md", "Docs/big.md"]);
    assert_eq!(items[0]["tags"], json!(["plans"]));
    let done = ok(&fx, Method::POST, &format!("/imports/{id}/commit"), None).await;
    assert_eq!(done["results"]["created"], 1);
    // The copy changed: re-import updates the unedited note instead of adding another.
    std::fs::write(work.join("Docs/Plans/ok.md"), "# Fine\nmore\n").unwrap();
    git(&work, &["commit", "-qam", "y"]);
    git(
        &mirrors.join("1.git"),
        &[
            "fetch",
            "-q",
            work.to_str().unwrap(),
            "+refs/heads/main:refs/heads/main",
        ],
    );
    let again = ok(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"source": "mirror", "project": p})),
    )
    .await;
    assert_eq!(again["flags"]["changed"], 1);
    let id2 = again["id"].as_str().unwrap();
    ok(&fx, Method::POST, &format!("/imports/{id2}/commit"), None).await;
    assert_eq!(
        ok(&fx, Method::GET, "/notes", None)
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // A repo with no copy says so and leaves an abandoned run, not a half-read one.
    sqlx::query("INSERT INTO core_project_repos (id, project_id, name, remote_url, default_branch) VALUES (2, ?, 'other', 'https://example.test/o.git', 'main')")
        .bind(p.parse::<i64>().unwrap())
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let none = ok(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"source": "mirror", "project": p, "repo": "2"})),
    )
    .await;
    assert_eq!(none["state"], "abandoned");
}

#[tokio::test]
async fn apple_notes_run_has_its_own_origins() {
    let fx = fx().await;
    let p = project(&fx, "alpha").await;
    let _ = upload(&fx, &p, &[("a.md", "# Same\n")]).await;
    let run = ok(
        &fx,
        Method::POST,
        "/imports",
        Some(json!({"source": "apple_notes", "project": p})),
    )
    .await;
    assert_eq!(
        (run["source"].as_str(), run["state"].as_str()),
        (Some("apple_notes"), Some("staging"))
    );
    let id = run["id"].as_str().unwrap().to_owned();
    ok(
        &fx,
        Method::POST,
        &format!("/imports/{id}/items"),
        Some(json!({"items": [{"path": "Work/a.md", "text": "# Same\n"}]})),
    )
    .await;
    let run = ok(&fx, Method::POST, &format!("/imports/{id}/finish"), None).await;
    assert_eq!(run["state"], "review");
    let origin = scalar(
        &fx,
        &format!("SELECT origin FROM lore_import_items WHERE run = '{id}'"),
    )
    .await;
    assert_eq!(origin, format!("apple_notes:{p}:Work/a.md"));
}
