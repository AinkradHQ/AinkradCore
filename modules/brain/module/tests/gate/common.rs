use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::ops::secretbox::SecretBox;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, migrate, settings};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use brain_model::item::hash_of;
use brain_module::Brain;
use serde_json::{Value, json};
use tower::ServiceExt;

pub const HOST: &str = "core.test";
pub const BASE: &str = "/modules/brain/v1";

pub struct Fx {
    pub app: App,
    pub brain: Brain,
    pub admin: TestDevice,
    /// Admin scope, session not elevated.
    pub laptop: TestDevice,
    pub dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub async fn fx() -> Fx {
    init_log();
    fx_with(Brain::default(), 1).await
}

/// A Core with the Brain mounted, `secrets.mode` at `mode` and a master key loaded.
pub async fn fx_with(brain: Brain, mode: i64) -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "brain-gate-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(brain.clone())];
    migrate::migrate_modules(&pool, &modules).await.unwrap();
    settings::set(
        &pool,
        Key::SecretsMode,
        Scope::Server,
        &mode.to_string(),
        AuditActor::System,
        &SystemClock.now(),
    )
    .await
    .unwrap();
    let sealer = SecretBox::new(&[7; 32]);
    let identity = Arc::new(Identity::load_or_create(&dir, &sealer).unwrap());
    let clock = Arc::new(SystemClock);
    let mut app = App::new(pool, clock.clone(), HOST.to_owned(), identity);
    app.modules = Arc::from(modules);
    app.secrets = Some(Arc::new(sealer));
    brain.attach(&app);
    let admin = enroll(&app, "admin", &["admin", "read"]).await;
    let session = admin.session.lock().unwrap().clone().unwrap();
    app.auth.elevate(&session, &admin.id, clock.unix() + 3600);
    let laptop = enroll(&app, "laptop", &["admin", "read"]).await;
    Fx {
        app,
        brain,
        admin,
        laptop,
        dir,
    }
}

pub async fn enroll(app: &App, name: &str, scopes: &[&str]) -> TestDevice {
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

pub async fn call(
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

pub async fn ok(fx: &Fx, method: Method, path: &str, body: Option<Value>) -> Value {
    let (s, v) = call(fx, &fx.admin, method, path, body).await;
    assert_eq!(s, StatusCode::OK, "{path}: {v}");
    v
}

/// A synthetic item as a collector would send it.
pub fn item(n: u32, hint: &str, title: &str, text: &str) -> Value {
    json!({
        "item_id": format!("01JD{n:022}"),
        "source_kind": "claude_code",
        "content_hash": hash_of(text),
        "origin": {"device": "mac-1", "path": format!("/synthetic/sessions/s{n}.jsonl")},
        "project_hint": hint,
        "author": {"kind": "person", "name": "dev"},
        "title": title,
        "text": text,
        "links": [],
        "started_at": format!("2026-11-{:02}T09:30:00Z", 1 + n % 28),
    })
}

pub async fn start(fx: &Fx) -> String {
    let v = ok(
        fx,
        Method::POST,
        "/imports",
        Some(json!({"kind": "full", "sources": ["claude_code"]})),
    )
    .await;
    v["run"].as_str().unwrap().to_owned()
}

pub async fn send(fx: &Fx, run: &str, items: Vec<Value>) -> Value {
    ok(
        fx,
        Method::POST,
        &format!("/imports/{run}/items"),
        Some(json!({"items": items})),
    )
    .await
}

/// Closes the collector, so discovery runs.
pub async fn finish(fx: &Fx, run: &str) -> Value {
    ok(
        fx,
        Method::POST,
        &format!("/imports/{run}/collected"),
        Some(json!({"source": "claude_code"})),
    )
    .await
}

pub async fn proposals(fx: &Fx, run: &str) -> Vec<Value> {
    ok(fx, Method::GET, &format!("/imports/{run}/proposals"), None)
        .await
        .as_array()
        .unwrap()
        .clone()
}

pub fn by_name<'a>(p: &'a [Value], name: &str) -> &'a Value {
    p.iter()
        .find(|x| x["name"] == name)
        .unwrap_or_else(|| panic!("no proposal {name}: {p:?}"))
}

/// The brain key, read the way a restarted process would.
pub async fn key_of(fx: &Fx) -> [u8; 32] {
    let v = ainkrad_core_server::store::secrets::open_for_module(
        &fx.app.pool,
        fx.app.secrets.as_deref().unwrap(),
        "brain",
        "brain.key",
        "test",
    )
    .await
    .unwrap();
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&v[i * 2..i * 2 + 2], 16).unwrap();
    }
    k
}

pub async fn staging_pool(fx: &Fx, run: &str) -> sqlx::SqlitePool {
    let key = key_of(fx).await;
    brain_module::files::open_migrated(
        &brain_module::files::staging_path(&brain_module::files::root(&fx.app), run),
        &key,
        false,
        brain_module::files::STAGING,
    )
    .await
    .unwrap()
}

/// Every decrypted `canon.db` and staging file text in one string, for "never stored" checks.
pub async fn everything_stored(fx: &Fx) -> String {
    let key = key_of(fx).await;
    let root = brain_module::files::root(&fx.app);
    let mut out = String::new();
    for entry in walk(&root) {
        let pool = brain_module::files::open_migrated(
            &entry,
            &key,
            false,
            if entry.ends_with("canon.db") {
                brain_module::files::CANON
            } else {
                brain_module::files::STAGING
            },
        )
        .await
        .unwrap();
        let table = if entry.ends_with("canon.db") {
            "sources"
        } else {
            "items"
        };
        let rows: Vec<(String, String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT title, text, coalesce(project_hint,'') FROM {table}"
        )))
        .fetch_all(&pool)
        .await
        .unwrap();
        out.push_str(&format!("{rows:?}"));
        pool.close().await;
    }
    out
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut v = vec![];
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            v.extend(walk(&p));
        } else if p.extension().is_some_and(|x| x == "db") {
            v.push(p);
        }
    }
    v
}
#[allow(dead_code)]
pub fn init_log() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
}

/// A committed personal/product room holding one source per `(title, text)`, not opened.
pub async fn committed_room(fx: &Fx, texts: &[(&str, &str)]) -> String {
    committed_room_named(fx, "Alpha", texts).await
}

/// As `committed_room`, for the project folder `name` (its texts must differ from every other room's).
pub async fn committed_room_named(fx: &Fx, name: &str, texts: &[(&str, &str)]) -> String {
    let run = start(fx).await;
    let items = texts
        .iter()
        .enumerate()
        .map(|(i, (t, x))| item(i as u32 + 1, &format!("/h/Projects/{name}/a"), t, x))
        .collect();
    send(fx, &run, items).await;
    finish(fx, &run).await;
    let id = proposals(fx, &run).await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        fx,
        Method::PATCH,
        &format!("/imports/{run}/proposals/{id}"),
        Some(json!({"state": "accepted"})),
    )
    .await;
    ok(fx, Method::POST, &format!("/imports/{run}/commit"), None).await["rooms"][0]["room"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A fallback chain of one pool per provider, in order.
pub async fn make_chain(fx: &Fx, providers: &[&str]) -> i64 {
    use ainkrad_core_server::api::v1::BY;
    use ainkrad_core_server::store::chains::{self as ch, EntrySpec};
    use ainkrad_core_server::store::pools;
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let now = fx.app.clock.now();
    let mut specs = vec![];
    for (i, p) in providers.iter().enumerate() {
        let pool = pools::create(&fx.app.pool, &format!("p{n}x{i}"), p, "d_x", BY, &now)
            .await
            .unwrap();
        specs.push(EntrySpec {
            pool: pool.id,
            model: None,
            harness: None,
        });
    }
    ch::create(&fx.app.pool, 1, &format!("c{n}"), &specs, "d_x", BY, &now)
        .await
        .unwrap()
        .id
}

/// Makes `chain` the one the distillation agent walks.
pub async fn bind_distil_chain(fx: &Fx, chain: i64) {
    ainkrad_core_server::store::chains::bind(
        &fx.app.pool,
        "brain-distil",
        chain,
        "d_x",
        ainkrad_core_server::api::v1::BY,
        &fx.app.clock.now(),
    )
    .await
    .unwrap();
}

/// An AI session (not started) that walks a chain of one pool per provider, in order.
pub async fn chain_session(fx: &Fx, providers: &[&str]) -> String {
    use ainkrad_core_server::api::v1::BY;
    use ainkrad_core_server::store::agents::NewSession;
    use ainkrad_core_server::store::chains::{self as ch, Request};
    let c = make_chain(fx, providers).await;
    let now = fx.app.clock.now();
    let policy = json!({"mode": "ask"});
    let new = NewSession {
        runner: &fx.admin.id,
        harness: "",
        model: None,
        prompt: Some("SECRET SOURCE TEXT"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.admin.id,
    };
    let req = Request {
        user_id: 1,
        chain: Some(c),
        agent: None,
    };
    ch::create_session(&fx.app.pool, &new, None, None, req, BY, &now)
        .await
        .unwrap()
        .id
}

/// The room's decrypted `canon.db`.
pub async fn canon_pool(fx: &Fx, room: &str) -> sqlx::SqlitePool {
    let key = key_of(fx).await;
    brain_module::files::open_migrated(
        &brain_module::files::room_path(&brain_module::files::root(&fx.app), room),
        &key,
        false,
        brain_module::files::CANON,
    )
    .await
    .unwrap()
}
