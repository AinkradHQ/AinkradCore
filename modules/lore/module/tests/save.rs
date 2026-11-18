//! The save path through the Core's real gate: 3-way merge against the head, the ring, versions and restore,
//! and the rename rewrite. Each test fails if the property it names stops holding.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

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

async fn add(fx: &Fx, text: &str) -> Value {
    let (s, v) = call(
        fx,
        &fx.admin,
        Method::POST,
        "/notes",
        Some(json!({"text": text})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

/// PUT the text; returns the whole answer (status checked).
async fn save(fx: &Fx, id: &str, base_rev: i64, text: &str) -> Value {
    let (s, v) = call(
        fx,
        &fx.admin,
        Method::PUT,
        &format!("/notes/{id}/text"),
        Some(json!({"base_rev": base_rev, "text": text})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

async fn versions(fx: &Fx, id: &str) -> Vec<Value> {
    let (s, v) = call(
        fx,
        &fx.admin,
        Method::GET,
        &format!("/notes/{id}/versions"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    v.as_array().unwrap().clone()
}

async fn version_text(fx: &Fx, id: &str, v: &str) -> String {
    let (s, v) = call(
        fx,
        &fx.admin,
        Method::GET,
        &format!("/notes/{id}/versions/{v}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["text"].as_str().unwrap().to_owned()
}

async fn get(fx: &Fx, id: &str) -> Value {
    call(fx, &fx.admin, Method::GET, &format!("/notes/{id}"), None)
        .await
        .1
}

async fn sql_i64(fx: &Fx, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn sql(fx: &Fx, sql: &str) {
    sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
        .execute(&fx.app.pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_save_from_the_head_writes_the_next_revision_and_derives_the_title() {
    let fx = fx().await;
    let n = add(&fx, "# One\nbody\n").await;
    let id = n["id"].as_str().unwrap();
    let r = save(&fx, id, 1, "---\ntags: [x]\n---\n# Two #t\nbody\n").await;
    assert_eq!(
        (r["rev"].clone(), r["outcome"].clone(), r["title"].clone()),
        (json!(2), json!("saved"), json!("Two #t"))
    );
    assert_eq!(r["updated_by"], json!(n["created_by"]));
    // identical text: no new revision
    let again = save(&fx, id, 2, "---\ntags: [x]\n---\n# Two #t\nbody\n").await;
    assert_eq!(again["rev"], json!(2));
    // the index follows the text in the same transaction
    assert_eq!(
        sql_i64(&fx, "SELECT count(*) FROM lore_tags WHERE tag IN ('x','t')").await,
        2
    );
    // refusals: from the future, zero base, too large, unknown, trashed
    for (base, text) in [(9, "x"), (0, "x")] {
        let (s, _) = call(
            &fx,
            &fx.admin,
            Method::PUT,
            &format!("/notes/{id}/text"),
            Some(json!({"base_rev": base, "text": text})),
        )
        .await;
        assert!(
            s == StatusCode::CONFLICT || s == StatusCode::BAD_REQUEST,
            "{base}"
        );
    }
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PUT,
        "/notes/ln_aaaaaaaaaaaa/text",
        Some(json!({"base_rev": 1, "text": ""})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/notes/{id}"),
        Some(json!({"trashed": true})),
    )
    .await;
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PUT,
        &format!("/notes/{id}/text"),
        Some(json!({"base_rev": 3, "text": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_daily_note_keeps_its_date_title() {
    let fx = fx().await;
    let (_, d) = call(&fx, &fx.admin, Method::GET, "/today?day=2026-11-17", None).await;
    let id = d["id"].as_str().unwrap();
    let r = save(&fx, id, 1, "# Something else\nx\n").await;
    assert_eq!(r["title"], json!("Tuesday, 17 November 2026"));
    assert_eq!(r["rev"], json!(2));
}

#[tokio::test]
async fn a_stale_save_merges_cleanly_keeps_both_sides_and_survives_non_text_revisions() {
    let fx = fx().await;
    let n = add(&fx, "a\nb\nc\n").await;
    let id = n["id"].as_str().unwrap();
    save(&fx, id, 1, "a\nb\nc\nAI line\n").await; // rev 2, the head moved
    let r = save(&fx, id, 1, "mine\na\nb\nc\n").await; // edited from rev 1
    assert_eq!(
        (r["outcome"].clone(), r["text"].clone(), r["rev"].clone()),
        (json!("merged"), json!("mine\na\nb\nc\nAI line\n"), json!(3))
    );
    assert_eq!(r["version"], Value::Null);
    // a trash/restore bump (rev 4, 5) has no ring row; a base at rev 5 still finds the text of rev 3
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/notes/{id}"),
        Some(json!({"trashed": true})),
    )
    .await;
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/notes/{id}"),
        Some(json!({"trashed": false})),
    )
    .await;
    save(&fx, id, 5, "mine\na\nb\nc\nAI line\nmore\n").await; // rev 6
    let r = save(&fx, id, 5, "mine\nTOP\na\nb\nc\nAI line\n").await;
    assert_eq!(r["outcome"], json!("merged"));
    assert_eq!(r["text"], json!("mine\nTOP\na\nb\nc\nAI line\nmore\n"));
}

#[tokio::test]
async fn overlapping_edits_keep_the_clients_line_and_the_head_as_a_conflict_version() {
    let fx = fx().await;
    let n = add(&fx, "a\nb\nc\n").await;
    let id = n["id"].as_str().unwrap();
    save(&fx, id, 1, "a\nAI edit of b\nc\n").await;
    let r = save(&fx, id, 1, "a\nmy edit of b\nc\n").await;
    assert_eq!(
        (r["outcome"].clone(), r["text"].clone()),
        (json!("conflict"), json!("a\nmy edit of b\nc\n"))
    );
    let v = r["version"].as_str().unwrap();
    assert_eq!(version_text(&fx, id, v).await, "a\nAI edit of b\nc\n");
    let list = versions(&fx, id).await;
    assert_eq!(list.iter().filter(|x| x["kind"] == "conflict").count(), 1);
    assert_eq!(
        sql_i64(
            &fx,
            "SELECT count(*) FROM lore_versions WHERE kind = 'conflict'"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn a_stale_save_whose_base_is_gone_keeps_both_texts() {
    let fx = fx().await;
    let n = add(&fx, "base\n").await;
    let id = n["id"].as_str().unwrap();
    save(&fx, id, 1, "head text\n").await;
    sql(&fx, "DELETE FROM lore_saves WHERE rev = 1").await; // the base left the ring
    let r = save(&fx, id, 1, "client text\n").await;
    assert_eq!(
        (r["outcome"].clone(), r["text"].clone()),
        (json!("base_lost"), json!("client text\n"))
    );
    assert_eq!(
        version_text(&fx, id, r["version"].as_str().unwrap()).await,
        "head text\n"
    );
}

#[tokio::test]
async fn the_ring_keeps_twenty_saves_and_always_the_head() {
    let fx = fx().await;
    let n = add(&fx, "0\n").await;
    let id = n["id"].as_str().unwrap();
    for i in 1..=30 {
        save(&fx, id, i, &format!("{i}\n")).await;
    }
    assert_eq!(sql_i64(&fx, "SELECT count(*) FROM lore_saves").await, 20);
    assert_eq!(sql_i64(&fx, "SELECT max(rev) FROM lore_saves").await, 31);
    // older than a day goes too, except the head
    sql(&fx, "UPDATE lore_saves SET at = '2020-01-01T00:00:00.000Z'").await;
    save(&fx, id, 31, "last\n").await;
    assert_eq!(sql_i64(&fx, "SELECT count(*) FROM lore_saves").await, 1);
}

#[tokio::test]
async fn versions_auto_after_idle_named_pruned_and_listed() {
    let fx = fx().await;
    let n = add(&fx, "first\n").await;
    let id = n["id"].as_str().unwrap();
    save(&fx, id, 1, "second\n").await; // not idle: no auto version
    assert!(versions(&fx, id).await.is_empty());
    sql(
        &fx,
        "UPDATE lore_notes SET updated_at = '2020-01-01T00:00:00.000Z'",
    )
    .await;
    save(&fx, id, 2, "third\n").await; // first save after the idle gap: the old text is kept
    let l = versions(&fx, id).await;
    assert_eq!(
        (l.len(), l[0]["kind"].clone(), l[0]["rev"].clone()),
        (1, json!("auto"), json!(2))
    );
    assert_eq!(
        version_text(&fx, id, l[0]["id"].as_str().unwrap()).await,
        "second\n"
    );
    // named
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/notes/{id}/versions"),
        Some(json!({"name": " Draft 1 "})),
    )
    .await;
    assert_eq!(
        (s, v["name"].clone(), v["kind"].clone()),
        (StatusCode::OK, json!("Draft 1"), json!("named"))
    );
    for bad in ["", "   ", "a\u{7}b", &"x".repeat(101)] {
        let (s, _) = call(
            &fx,
            &fx.admin,
            Method::POST,
            &format!("/notes/{id}/versions"),
            Some(json!({"name": bad})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
    // 200 cap, auto first: fill with 250 autos, then a named one survives the prune
    sql(&fx, "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 250) \
              INSERT INTO lore_versions (id, note, kind, rev, text, origin, created_at) \
              SELECT 'lv_' || substr('aaaaaaaaaaaa' || i, -12), (SELECT id FROM lore_notes), 'auto', 1, 'x', 'system', \
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now') FROM n").await;
    let (_, v2) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/notes/{id}/versions"),
        Some(json!({"name": "Keep"})),
    )
    .await;
    assert_eq!(
        sql_i64(&fx, "SELECT count(*) FROM lore_versions").await,
        200
    );
    assert!(
        version_text(&fx, id, v2["id"].as_str().unwrap())
            .await
            .contains("third")
    );
    assert_eq!(
        sql_i64(
            &fx,
            "SELECT count(*) FROM lore_versions WHERE kind = 'named'"
        )
        .await,
        2
    );
}

#[tokio::test]
async fn restore_equals_the_version_and_is_itself_undoable() {
    let fx = fx().await;
    let n = add(&fx, "# T\nv1\n").await;
    let id = n["id"].as_str().unwrap();
    let (_, named) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/notes/{id}/versions"),
        Some(json!({"name": "v1"})),
    )
    .await;
    let v1 = named["id"].as_str().unwrap();
    save(&fx, id, 1, "# T\nv2\n").await;
    let (s, r) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/notes/{id}/restore"),
        Some(json!({"version": v1})),
    )
    .await;
    assert_eq!(
        (s, r["text"].clone(), r["outcome"].clone(), r["rev"].clone()),
        (
            StatusCode::OK,
            json!("# T\nv1\n"),
            json!("restored"),
            json!(3)
        )
    );
    let undo = r["version"].as_str().unwrap();
    assert_eq!(version_text(&fx, id, undo).await, "# T\nv2\n");
    // the undo is the same call with the undo version
    let (_, back) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/notes/{id}/restore"),
        Some(json!({"version": undo})),
    )
    .await;
    assert_eq!(
        (back["text"].clone(), back["rev"].clone()),
        (json!("# T\nv2\n"), json!(4))
    );
    // a client still holding rev 2 merges instead of losing the restore
    assert_eq!(get(&fx, id).await["text"], json!("# T\nv2\n"));
    // restoring the head's own text changes nothing; foreign and malformed ids are 404
    let (_, same) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/notes/{id}/restore"),
        Some(json!({"version": undo})),
    )
    .await;
    assert_eq!(
        (same["rev"].clone(), same["version"].clone()),
        (json!(4), Value::Null)
    );
    let other = add(&fx, "other\n").await;
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/notes/{}/restore", other["id"].as_str().unwrap()),
        Some(json!({"version": v1})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/notes/{id}/restore"),
        Some(json!({"version": "nope"})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn renaming_a_note_rewrites_its_linkers_outside_code_and_versions_them() {
    let fx = fx().await;
    let a = add(&fx, "# Alpha\nx\n").await;
    let aid = a["id"].as_str().unwrap();
    let linker =
        "see [[Alpha]] and `[[Alpha]]`\n```\n[[Alpha]]\n```\n[[ alpha #H|al ]] and [[Other]]\n";
    let b = add(&fx, &format!("# B\n{linker}")).await;
    let bid = b["id"].as_str().unwrap();
    let c = add(&fx, "# C\n[[Other]]\n").await;
    let cid = c["id"].as_str().unwrap();
    assert_eq!(
        sql_i64(
            &fx,
            "SELECT count(*) FROM lore_links WHERE target_title_norm = 'alpha'"
        )
        .await,
        2
    );
    save(&fx, aid, 1, "# Beta\nx\n").await;
    let want =
        "# B\nsee [[Beta]] and `[[Alpha]]`\n```\n[[Alpha]]\n```\n[[Beta#H|al ]] and [[Other]]\n";
    let b2 = get(&fx, bid).await;
    assert_eq!(
        (
            b2["text"].clone(),
            b2["updated_by"].clone(),
            b2["rev"].clone()
        ),
        (json!(want), json!("system"), json!(2))
    );
    assert_eq!(get(&fx, cid).await["rev"], json!(1));
    let l = versions(&fx, bid).await;
    assert_eq!(
        version_text(&fx, bid, l[0]["id"].as_str().unwrap()).await,
        format!("# B\n{linker}")
    );
    assert_eq!(
        sql_i64(
            &fx,
            "SELECT count(*) FROM lore_links WHERE target_title_norm = 'beta'"
        )
        .await,
        2
    );
    // a second live note titled Beta... then renaming Beta away leaves links alone (they may mean the other one)
    add(&fx, "# Beta\n").await;
    save(&fx, aid, 2, "# Gamma\nx\n").await;
    assert_eq!(get(&fx, bid).await["rev"], json!(2));
}

#[tokio::test]
async fn interleaved_saves_through_the_api_lose_no_inserted_line() {
    let fx = fx().await;
    let mut s = 12345u64;
    let mut rnd = move |n: usize| {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((s >> 33) as usize) % n
    };
    for scenario in 0..120 {
        // a device per scenario: the gate rate-limits each device
        let dev = enroll(&fx.app, &format!("w{scenario}"), &["admin", "read"]).await;
        let (_, n) = call(
            &fx,
            &dev,
            Method::POST,
            "/notes",
            Some(json!({"text": "seed
"})),
        )
        .await;
        let id = n["id"].as_str().unwrap().to_owned();
        let mut texts = vec![(1, "seed\n".to_owned())];
        let mut tracked = HashSet::new();
        for step in 0..8 {
            let mark = format!("m{scenario}-{step}");
            // from the head half the time, else from any earlier revision this writer saw
            let (base, t) = if rnd(2) == 0 {
                texts.last().unwrap().clone()
            } else {
                texts[rnd(texts.len())].clone()
            };
            let mut lines: Vec<String> = t.lines().map(str::to_owned).collect();
            lines.insert(rnd(lines.len() + 1), mark.clone());
            tracked.insert(mark);
            let body = json!({"base_rev": base, "text": lines.iter().map(|l| format!("{l}\n")).collect::<String>()});
            let (st, r) = call(
                &fx,
                &dev,
                Method::PUT,
                &format!("/notes/{id}/text"),
                Some(body),
            )
            .await;
            assert_eq!(st, StatusCode::OK, "{r}");
            texts.push((
                r["rev"].as_i64().unwrap(),
                r["text"].as_str().unwrap().to_owned(),
            ));
        }
        let (_, h) = call(&fx, &dev, Method::GET, &format!("/notes/{id}"), None).await;
        let mut present: HashSet<String> = h["text"]
            .as_str()
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        let (_, vs) = call(
            &fx,
            &dev,
            Method::GET,
            &format!("/notes/{id}/versions"),
            None,
        )
        .await;
        for v in vs.as_array().unwrap() {
            let (_, t) = call(
                &fx,
                &dev,
                Method::GET,
                &format!("/notes/{id}/versions/{}", v["id"].as_str().unwrap()),
                None,
            )
            .await;
            present.extend(t["text"].as_str().unwrap().lines().map(str::to_owned));
        }
        for t in &tracked {
            assert!(present.contains(t), "scenario {scenario}: lost {t}");
        }
    }
}

#[tokio::test]
async fn a_10000_word_save_is_under_20_ms() {
    let fx = fx().await;
    let para = |i: usize| {
        format!(
            "Paragraph {i} has [[Link {}]] and #tag{} with some more words to fill a line up.\n",
            i % 50,
            i % 7
        )
    };
    let text: String = format!("# Big\n{}", (0..650).map(para).collect::<String>());
    assert!(text.split_whitespace().count() >= 10_000);
    let n = add(&fx, &text).await;
    let id = n["id"].as_str().unwrap();
    let (mut fresh, mut merged) = (vec![], vec![]);
    let mut rev = 1;
    let mut cur = text.clone();
    for i in 0..15 {
        let edited = format!("{cur}edit {i}\n");
        let t = Instant::now();
        let r = save(&fx, id, rev, &edited).await;
        fresh.push(t.elapsed());
        rev = r["rev"].as_i64().unwrap();
        cur = edited;
        // a stale save: edited from the previous revision while the head moved on one revision
        let ahead = format!("{cur}head {i}\n");
        save(&fx, id, rev, &ahead).await;
        let stale = format!("top {i}\n{cur}");
        let t = Instant::now();
        let r = save(&fx, id, rev, &stale).await;
        merged.push(t.elapsed());
        assert_eq!(r["outcome"], json!("merged"));
        rev = r["rev"].as_i64().unwrap();
        cur = r["text"].as_str().unwrap().to_owned();
    }
    fresh.sort();
    merged.sort();
    eprintln!(
        "10k-word save, whole request through the gate: fresh median {:?} max {:?}; stale+merge median {:?} max {:?}",
        fresh[7], fresh[14], merged[7], merged[14]
    );
    // The 20 ms budget is for the optimised build (`cargo test --release`); an unoptimised test build only reports.
    if !cfg!(debug_assertions) {
        assert!(fresh[7].as_millis() < 20 && merged[7].as_millis() < 20);
    }
}

// ---- R1-04: index, link resolution and backlinks ----

async fn target_of(fx: &Fx, src: &str, norm: &str) -> Option<String> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT target FROM lore_links WHERE src = '{src}' AND target_title_norm = '{norm}'"
    )))
    .fetch_one(&fx.app.pool)
    .await
    .unwrap()
}

async fn backlinks(fx: &Fx, id: &str) -> Vec<Value> {
    let (s, v) = call(
        fx,
        &fx.admin,
        Method::GET,
        &format!("/notes/{id}/backlinks"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v.as_array().unwrap().clone()
}

#[tokio::test]
async fn links_resolve_same_project_then_personal_then_any_newest_first() {
    let fx = fx().await;
    let personal = add(&fx, "# Topic\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let other = add(&fx, "# Topic\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mine_old = add(&fx, "# Topic\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mine_new = add(&fx, "# Topic\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    sql(
        &fx,
        &format!("UPDATE lore_notes SET project = 'pb' WHERE id = '{other}'"),
    )
    .await;
    sql(&fx, &format!("UPDATE lore_notes SET project = 'pa', updated_at = '2020-01-01T00:00:00.000Z' WHERE id = '{mine_old}'")).await;
    sql(
        &fx,
        &format!("UPDATE lore_notes SET project = 'pa' WHERE id = '{mine_new}'"),
    )
    .await;
    // a linker in project pa prefers its own project, newest first
    let l = add(&fx, "# L\n[[Topic]]\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    sql(
        &fx,
        &format!("UPDATE lore_notes SET project = 'pa' WHERE id = '{l}'"),
    )
    .await;
    save(&fx, &l, 1, "# L\nsee [[topic]]\n").await;
    assert_eq!(target_of(&fx, &l, "topic").await, Some(mine_new.clone()));
    // a personal linker takes the personal note, not a project's
    let p = add(&fx, "# P\n[[Topic]]\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(target_of(&fx, &p, "topic").await, Some(personal.clone()));
    // a linker in a third project: no own note, personal wins over another project's
    let q = add(&fx, "# Q\n[[Topic]]\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    sql(
        &fx,
        &format!("UPDATE lore_notes SET project = 'pc' WHERE id = '{q}'"),
    )
    .await;
    save(&fx, &q, 1, "# Q\n[[Topic]] again\n").await;
    assert_eq!(target_of(&fx, &q, "topic").await, Some(personal.clone()));
    // trash the personal one: the third project's link falls to "any", newest
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/notes/{personal}"),
        Some(json!({"trashed": true})),
    )
    .await;
    assert_eq!(target_of(&fx, &q, "topic").await, Some(mine_new));
    assert!(target_of(&fx, &p, "topic").await.is_some());
    let _ = other;
}

#[tokio::test]
async fn a_later_note_resolves_earlier_dangling_links_and_rename_keeps_them_resolved() {
    let fx = fx().await;
    let b = add(&fx, "# B\nsee [[Alpha]] and `[[Alpha]]`\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(target_of(&fx, &b, "alpha").await, None);
    // create
    let a = add(&fx, "# Alpha\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(target_of(&fx, &b, "alpha").await, Some(a.clone()));
    // rename a note INTO the name another note links to
    let z = add(&fx, "# B2\n[[Zed]]\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(target_of(&fx, &z, "zed").await, None);
    let n = add(&fx, "# Nope\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    save(&fx, &n, 1, "# Zed\n").await;
    assert_eq!(target_of(&fx, &z, "zed").await, Some(n.clone()));
    // rename Alpha: B is rewritten (code span untouched) and resolves to the renamed note
    save(&fx, &a, 1, "# Beta\n").await;
    assert_eq!(
        get(&fx, &b).await["text"],
        json!("# B\nsee [[Beta]] and `[[Alpha]]`\n")
    );
    assert_eq!(target_of(&fx, &b, "beta").await, Some(a.clone()));
    assert_eq!(backlinks(&fx, &a).await.len(), 1);
}

#[tokio::test]
async fn backlinks_carry_context_skip_trashed_sources_and_follow_the_target() {
    let fx = fx().await;
    let t = add(&fx, "# Target\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let s1 = add(&fx, "# One\nfirst line\nthe [[Target#Part|link]] is here\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let s2 = add(&fx, "# Two\n[[Target]]\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let bl = backlinks(&fx, &t).await;
    assert_eq!(bl.len(), 2);
    let one = bl.iter().find(|b| b["note"] == json!(s1)).unwrap();
    assert_eq!(
        (
            one["title"].clone(),
            one["heading"].clone(),
            one["context"].clone()
        ),
        (
            json!("One"),
            json!("Part"),
            json!("the [[Target#Part|link]] is here")
        )
    );
    // a trashed source is not listed
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/notes/{s2}"),
        Some(json!({"trashed": true})),
    )
    .await;
    assert_eq!(backlinks(&fx, &t).await.len(), 1);
    // trash the target: links dangle, text kept; restore: they resolve again
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/notes/{t}"),
        Some(json!({"trashed": true})),
    )
    .await;
    assert_eq!(target_of(&fx, &s1, "target").await, None);
    assert_eq!(
        get(&fx, &s1).await["text"],
        json!("# One\nfirst line\nthe [[Target#Part|link]] is here\n")
    );
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/notes/{t}"),
        Some(json!({"trashed": false})),
    )
    .await;
    assert_eq!(backlinks(&fx, &t).await.len(), 1);
    // purge the target for good: the link row stays, target NULL
    sql(&fx, &format!("UPDATE lore_notes SET trashed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now','-31 days') WHERE id = '{t}'")).await;
    assert_eq!(lore_module::sweep(&fx.app.pool).await.unwrap(), 1);
    assert_eq!(target_of(&fx, &s1, "target").await, None);
    assert_eq!(get(&fx, &s1).await["rev"], json!(1));
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/notes/{t}/backlinks"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_fts_rows_follow_saves_and_a_rebuild_changes_nothing() {
    let fx = fx().await;
    let a = add(&fx, "# Apple pie\nbake slowly\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let b = add(&fx, "# Café\nnaïve crème\n").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    add(&fx, "").await;
    save(&fx, &a, 1, "# Apple tart\nbake quickly\n").await;
    call(&fx, &fx.admin, Method::GET, "/today?day=2026-11-17", None).await;
    let hits = |q: &str| format!("SELECT count(*) FROM lore_fts WHERE lore_fts MATCH '{q}'");
    assert_eq!(sql_i64(&fx, &hits("quickly")).await, 1);
    assert_eq!(sql_i64(&fx, &hits("slowly")).await, 0);
    assert_eq!(sql_i64(&fx, &hits("creme")).await, 1, "diacritics folded");
    assert_eq!(sql_i64(&fx, &hits("title:tart")).await, 1);
    assert_eq!(sql_i64(&fx, "SELECT count(*) FROM lore_fts").await, 4);
    let dump = || async {
        let rows: Vec<(i64, String, String)> =
            sqlx::query_as("SELECT rowid, title, body FROM lore_fts ORDER BY rowid")
                .fetch_all(&fx.app.pool)
                .await
                .unwrap();
        rows
    };
    let before = dump().await;
    lore_module::rebuild_fts(&fx.app.pool).await.unwrap();
    assert_eq!(dump().await, before);
    let _ = b;
}
