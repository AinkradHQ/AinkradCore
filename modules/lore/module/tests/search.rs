//! Note search through the Core's real gate (R2-02): text ranking, filters, snippets, meaning ranking with a
//! fake embedder, and the model-absent fallback. Each test fails if the property it names stops holding.

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
async fn fx(lore: Lore) -> Fx {
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
    let modules: Vec<Arc<dyn Module>> = if on { vec![Arc::new(lore)] } else { vec![] };
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

/// Words fold into 8 buckets; "car" and "automobile" share one, so a note that never says "car" still
/// lands next to the query "car". A stand-in for meaning that is exact and needs no model file.
struct Fake;
impl ainkrad_embed::Embedder for Fake {
    fn model_id(&self) -> &str {
        "fake-v1"
    }
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        Ok(texts
            .iter()
            .map(|t| {
                let mut v = vec![0.01f32; 8];
                for w in t.to_lowercase().split(|c: char| !c.is_alphanumeric()) {
                    let b = match w {
                        "car" | "automobile" | "vehicle" => 0,
                        "" => continue,
                        w => 1 + w.len() % 7,
                    };
                    v[b] += if b == 0 { 1.0 } else { 0.1 };
                }
                v
            })
            .collect())
    }
}

async fn put(fx: &Fx, text: &str) -> String {
    let (s, v) = call(
        fx,
        &fx.admin,
        Method::POST,
        "/notes",
        Some(json!({"text": text})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["id"].as_str().unwrap().to_owned()
}

async fn find(fx: &Fx, query: &str) -> Value {
    let (s, v) = call(
        fx,
        &fx.admin,
        Method::GET,
        &format!("/search?{query}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

fn titles(v: &Value) -> Vec<String> {
    v["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["title"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn text_search_prefix_phrase_arabic_and_snippets() {
    let fx = fx(Lore::default()).await;
    put(&fx, "# Garden plan\nPlant tomatoes near the south fence.\n").await;
    put(&fx, "# Tomato soup\nA warm bowl, tomatoes and basil.\n").await;
    put(&fx, "# مرحبا بالعالم\nملاحظة عن البرمجة والعمل\n").await;
    let v = find(&fx, "q=tomat").await;
    assert_eq!(v["semantic"], false);
    assert_eq!(titles(&v).len(), 2);
    // A phrase must match in order.
    assert_eq!(
        titles(&find(&fx, "q=%22warm%20bowl%22").await),
        ["Tomato soup"]
    );
    assert!(titles(&find(&fx, "q=%22bowl%20warm%22").await).is_empty());
    // Arabic, by prefix; the highlight is the whole word at a byte range.
    let v = find(&fx, "q=%D8%A7%D9%84%D8%A8%D8%B1").await;
    let h = &v["results"][0];
    assert_eq!(h["title"], "مرحبا بالعالم");
    let s = h["snippet"]["text"].as_str().unwrap();
    let m = &h["snippet"]["matches"][0];
    assert_eq!(
        &s[m["start"].as_u64().unwrap() as usize..m["end"].as_u64().unwrap() as usize],
        "البرمجة"
    );
    // Syntax typed by a person is not FTS syntax: this must be a normal (empty) search, not an error.
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::GET,
        "/search?q=%22%20OR%20NEAR(",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    for bad in [
        "",
        "q=",
        "q=a&state=x",
        "q=a&kind=x",
        "q=a&limit=0",
        "q=a&limit=51",
    ] {
        let (s, _) = call(&fx, &fx.admin, Method::GET, &format!("/search?{bad}"), None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn filters_and_the_trash() {
    let fx = fx(Lore::default()).await;
    let a = put(&fx, "# Alpha\nshared words #work\n").await;
    put(&fx, "# Beta\nshared words #home\n").await;
    let (s, today) = call(&fx, &fx.admin, Method::GET, "/today?day=2026-11-17", None).await;
    assert_eq!(s, StatusCode::OK, "{today}");
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PUT,
        &format!("/notes/{}/text", today["id"].as_str().unwrap()),
        Some(json!({"base_rev": today["rev"], "text": "# Day\nshared words daily\n"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        find(&fx, "q=shared").await["results"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(titles(&find(&fx, "q=shared&tag=%23work").await), ["Alpha"]);
    assert_eq!(titles(&find(&fx, "q=shared&tag=HOME").await), ["Beta"]);
    assert_eq!(
        titles(&find(&fx, "q=shared&kind=daily").await),
        ["Tuesday, 17 November 2026"]
    );
    assert_eq!(
        find(&fx, "q=shared&kind=note").await["results"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(
        find(&fx, "q=shared&project=pr_nope").await["results"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // Trash: excluded by default, found with state=trashed, both with all; restore brings it back.
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/notes/{a}"),
        Some(json!({"trashed": true})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(!titles(&find(&fx, "q=shared").await).contains(&"Alpha".to_owned()));
    assert_eq!(
        titles(&find(&fx, "q=shared&state=trashed").await),
        ["Alpha"]
    );
    assert_eq!(
        find(&fx, "q=shared&state=all").await["results"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/notes/{a}"),
        Some(json!({"trashed": false})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(titles(&find(&fx, "q=shared").await).contains(&"Alpha".to_owned()));
}

#[tokio::test]
async fn meaning_finds_what_text_cannot_and_survives_edits_and_trash() {
    let lore = Lore::with_embedder(Arc::new(Fake));
    let fx = fx(lore.clone()).await;
    let a = put(&fx, "# Garage\nAutomobile oil change schedule.\n").await;
    put(&fx, "# Recipes\nPasta with garlic.\n").await;
    // Nothing is embedded yet: text only for this query finds nothing, but the answer says meaning is on.
    let v = find(&fx, "q=car").await;
    assert_eq!(v["semantic"], true);
    assert!(titles(&v).is_empty());
    assert_eq!(lore.embed_now(&fx.app.pool).await.unwrap(), 2);
    assert_eq!(
        lore.embed_now(&fx.app.pool).await.unwrap(),
        0,
        "nothing stale is embedded twice"
    );
    let v = find(&fx, "q=car").await;
    assert_eq!(titles(&v), ["Garage"]);
    assert_eq!(v["results"][0]["via"], "meaning");
    assert_eq!(v["results"][0]["heading"], "Garage");
    // Both rankings agree: via = both.
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PUT,
        &format!("/notes/{a}/text"),
        Some(json!({"base_rev": 1, "text": "# Garage\nCar oil change schedule.\n"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        lore.embed_now(&fx.app.pool).await.unwrap(),
        1,
        "an edited note is embedded again"
    );
    assert_eq!(find(&fx, "q=car").await["results"][0]["via"], "both");
    // Trashed notes drop out of the meaning ranking too.
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/notes/{a}"),
        Some(json!({"trashed": true})),
    )
    .await;
    assert!(titles(&find(&fx, "q=car").await).is_empty());
    assert_eq!(titles(&find(&fx, "q=car&state=trashed").await), ["Garage"]);
}

#[tokio::test]
async fn the_quiet_time_debounces_embedding() {
    let lore = Lore::with_embedder(Arc::new(Fake));
    let fx = fx(lore.clone()).await;
    put(&fx, "# Fresh\nwritten just now\n").await;
    // The job's 10 s quiet time: a note written a moment ago is left alone.
    assert_eq!(ainkrad_lore_pass(&fx, &lore).await, 0);
}

async fn ainkrad_lore_pass(fx: &Fx, lore: &Lore) -> usize {
    lore.embed_quiet(&fx.app.pool, 10).await.unwrap()
}

#[tokio::test]
async fn without_a_model_search_is_text_only_and_nothing_is_embedded() {
    let lore = Lore::default();
    let fx = fx(lore.clone()).await;
    put(&fx, "# Garage\nAutomobile oil.\n").await;
    assert_eq!(lore.embed_now(&fx.app.pool).await.unwrap(), 0);
    let v = find(&fx, "q=automobile").await;
    assert_eq!(v["semantic"], false);
    assert_eq!(titles(&v), ["Garage"]);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM lore_chunks")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

/// R2-02 latency on a made-up 5 000-note fixture, with the real model:
/// `AINKRAD_E5_DIR=<dir> cargo test --release -p lore-module --features semantic --test search bench -- --ignored --nocapture`.
/// The stored vectors are random (search cost does not depend on their values); the query embedding is real, and
/// 30 notes are really embedded to time the background job.
#[cfg(feature = "semantic")]
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_5000_notes() {
    use ainkrad_embed::Embedder;
    use std::time::Instant;
    let dir = std::env::var("AINKRAD_E5_DIR").expect("AINKRAD_E5_DIR");
    let model = ainkrad_embed::shared(std::path::Path::new(&dir)).expect("model");
    let lore = Lore::with_embedder(model.clone());
    let fx = fx(lore.clone()).await;
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let syl = [
        "ka", "lo", "ver", "min", "tas", "ro", "qel", "dun", "ari", "sol", "pek", "zu",
    ];
    let vocab: Vec<String> = (0..3000)
        .map(|i| {
            (0..2 + i % 3)
                .map(|k| syl[(i * 7 + k * 5 + i / 12) % syl.len()])
                .collect()
        })
        .chain(
            [
                "مشروع",
                "ملاحظة",
                "اجتماع",
                "تصميم",
                "خطة",
                "برمجة",
                "تقرير",
                "فكرة",
            ]
            .map(str::to_owned),
        )
        .collect();
    let mid = ainkrad_embed::MODEL_ID;
    let mut tx = ainkrad_core_server::store::begin_write(&fx.app.pool)
        .await
        .unwrap();
    for i in 0..5000 {
        let id = format!(
            "ln_{}",
            format!("{i:012}")
                .bytes()
                .map(|b| (b'a' + b - b'0') as char)
                .collect::<String>()
        );
        let mut text = format!(
            "# {} {}\n",
            vocab[(rnd() % 3008) as usize],
            vocab[(rnd() % 3008) as usize]
        );
        for s in 0..4 {
            text.push_str(&format!("## {}\n", vocab[(rnd() % 3008) as usize]));
            for _ in 0..(120 + s * 10) {
                text.push_str(&vocab[(rnd() % 3008) as usize]);
                text.push(' ');
            }
            text.push('\n');
        }
        let title = text
            .lines()
            .next()
            .unwrap()
            .trim_start_matches("# ")
            .to_owned();
        sqlx::query("INSERT INTO lore_notes (id, title, title_norm, text, created_by, updated_by) VALUES (?, ?, ?, ?, 'system', 'system')")
            .bind(&id).bind(&title).bind(title.to_lowercase()).bind(&text).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO lore_fts (rowid, title, body) SELECT rowid, title, text FROM lore_notes WHERE id = ?")
            .bind(&id).execute(&mut *tx).await.unwrap();
        for seq in 0..5 {
            let v: Vec<f32> = (0..384)
                .map(|_| (rnd() % 2000) as f32 / 1000.0 - 1.0)
                .collect();
            let blob: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
            sqlx::query("INSERT INTO lore_chunks (note, seq, heading, start, len, model, vec) VALUES (?, ?, 'h', 0, 10, ?, ?)")
                .bind(&id).bind(seq).bind(mid).bind(blob).execute(&mut *tx).await.unwrap();
        }
    }
    tx.commit().await.unwrap();
    let queries: Vec<String> = (0..60)
        .map(|i| match i % 4 {
            0 => format!("{}", &vocab[(i * 37) % 3000][..3]),
            1 => format!("{} {}", vocab[(i * 11) % 3000], vocab[(i * 13) % 3000]),
            2 => format!(
                "%22{}%20{}%22",
                vocab[(i * 5) % 3000],
                vocab[(i * 5 + 1) % 3000]
            ),
            _ => vocab[3000 + i % 8].clone(),
        })
        .collect();
    let q = |s: &str| s.replace(' ', "%20");
    find(&fx, &format!("q={}", q(&queries[0]))).await; // warm: tokenizer, pool, page cache
    let mut ms: Vec<f64> = Vec::new();
    for round in 0..3 {
        for s in &queries {
            let t = Instant::now();
            let v = find(&fx, &format!("q={}", q(s))).await;
            ms.push(t.elapsed().as_secs_f64() * 1000.0);
            assert_eq!(v["semantic"], true, "round {round}");
        }
    }
    ms.sort_by(f64::total_cmp);
    let p = |x: f64| ms[((ms.len() as f64 * x) as usize).min(ms.len() - 1)];
    let t = Instant::now();
    model.embed(&["car".to_owned()]).unwrap();
    println!(
        "query embed alone: {:.1} ms",
        t.elapsed().as_secs_f64() * 1000.0
    );
    println!(
        "search 5000 notes / 25000 chunks, {} queries: p50 {:.1} ms, p95 {:.1} ms, max {:.1} ms",
        ms.len(),
        p(0.5),
        p(0.95),
        p(1.0)
    );
    // The background job: real embedding of 30 notes (1 thread).
    // Every note but 30 counts as embedded; the job then embeds those 30 for real.
    sqlx::query("INSERT INTO lore_embedded SELECT id, rev, ? FROM lore_notes WHERE id NOT IN (SELECT id FROM lore_notes ORDER BY id LIMIT 30)").bind(mid).execute(&fx.app.pool).await.unwrap();
    let t = Instant::now();
    let n = lore.embed_now(&fx.app.pool).await.unwrap();
    println!("embedded {n} notes in {:.1} s", t.elapsed().as_secs_f64());
}
