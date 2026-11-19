//! Leyline hosts through the Core's real gate (signed requests into `api::router`), so scope,
//! step-up, classification and the registries are the Core's own code. Each test fails if the
//! property it names stops holding.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, events, migrate};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use leyline_module::Leyline;
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "core.test";
const BASE: &str = "/modules/leyline/v1";

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

/// A Core with Leyline migrated and mounted (or, `on = false`, a Core that does not carry it).
async fn fx_with(on: bool) -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "leyline-gate-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = if on { vec![Arc::new(Leyline)] } else { vec![] };
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
    admin.unlock(&app.auth, clock.unix() + 3600);
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

/// Status, parsed body and the raw body text.
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

fn host(name: &str) -> Value {
    json!({"name": name, "address": format!("{name}.example.com"), "username": "deploy"})
}

async fn add(fx: &Fx, body: Value) -> Value {
    let (s, v) = call(fx, &fx.admin, Method::POST, "/hosts", Some(body)).await;
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

#[tokio::test]
async fn scopes_follow_the_modules_tables_and_a_delete_needs_no_step_up() {
    let fx = fx().await;
    let reader = enroll(&fx.app, "reader", &["read"]).await;
    let laptop = enroll(&fx.app, "laptop", &["admin"]).await; // admin, not elevated
    assert_eq!(
        call(&fx, &reader, Method::GET, "/hosts", None).await.0,
        StatusCode::OK
    );
    let (s, b) = call(&fx, &reader, Method::POST, "/hosts", Some(host("a"))).await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
    );
    let made = {
        let (s, v) = call(&fx, &laptop, Method::POST, "/hosts", Some(host("a"))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v
    };
    let path = format!("/hosts/{}", made["id"].as_str().unwrap());
    let (s, b) = call(
        &fx,
        &laptop,
        Method::PATCH,
        &path,
        Some(json!({"tags": ["x"]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "a plain change needs no step-up: {b}");
    let (s, b) = call(&fx, &laptop, Method::DELETE, &path, None).await;
    assert_eq!(s, StatusCode::OK, "a delete needs no step-up: {b}");
    assert_eq!(count(&fx, "leyline_hosts").await, 0);
    assert_eq!(
        call(&fx, &fx.admin, Method::DELETE, &path, None).await.0,
        StatusCode::NOT_FOUND
    );
    let anon = Request::builder()
        .uri(format!("{BASE}/hosts"))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router(fx.app.clone()).oneshot(anon).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

/// (address, username, port) triples: the same verdict from the API and from the table's CHECKs.
const CASES: &[(&str, &str, i64, bool)] = &[
    ("example.com", "deploy", 22, true),
    ("10.0.0.5", "root", 65535, true),
    ("fe80::1%en0", "a.b_c-d", 1, true),
    ("-oProxyCommand=id", "deploy", 22, false),
    ("-host", "deploy", 22, false),
    ("a b", "deploy", 22, false),
    ("host -o ProxyCommand=touch /tmp/x", "deploy", 22, false),
    ("ProxyCommand=id", "deploy", 22, false),
    ("a;id", "deploy", 22, false),
    ("a\nb", "deploy", 22, false),
    ("h\u{e9}st", "deploy", 22, false),
    ("", "deploy", 22, false),
    ("example.com", "-oProxyCommand=id", 22, false),
    ("example.com", "-x", 22, false),
    ("example.com", "dep loy", 22, false),
    ("example.com", "u=1", 22, false),
    ("example.com", "", 22, false),
    (
        "example.com",
        "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu",
        22,
        false,
    ),
    ("example.com", "deploy", 0, false),
    ("example.com", "deploy", -1, false),
    ("example.com", "deploy", 65536, false),
];

#[tokio::test]
async fn a_bad_address_user_or_port_is_refused_by_the_api_and_by_the_table() {
    let fx = fx().await;
    for (i, (address, username, port, ok)) in CASES.iter().enumerate() {
        let name = format!("h{i}");
        // API layer.
        let body = json!({"name": name, "address": address, "username": username, "port": port});
        let (s, v, raw) = call_raw(
            &fx,
            &fx.admin,
            Method::POST,
            "/hosts",
            Some(&body.to_string()),
        )
        .await;
        assert_eq!(
            s == StatusCode::OK,
            *ok,
            "api {address:?} {username:?} {port}: {v}"
        );
        if !ok {
            assert_eq!(s, StatusCode::BAD_REQUEST);
            // Errors never echo input.
            for echoed in [*address, *username] {
                assert!(
                    echoed.is_empty() || !raw.contains(echoed),
                    "echoed {echoed:?}: {raw}"
                );
            }
        }
        // Table layer: the same row written around the API.
        let direct = sqlx::query(
            "INSERT INTO leyline_hosts (id, name, address, port, username) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(format!("h_{i:016x}"))
        .bind(format!("direct{i}"))
        .bind(address)
        .bind(port)
        .bind(username)
        .execute(&fx.app.pool)
        .await;
        assert_eq!(direct.is_ok(), *ok, "table {address:?} {username:?} {port}");
    }
    let accepted = CASES.iter().filter(|c| c.3).count() as i64;
    assert_eq!(
        count(&fx, "leyline_hosts").await,
        accepted * 2,
        "a refusal stores nothing"
    );
}

#[tokio::test]
async fn an_id_wins_over_a_label_equal_to_it_and_a_label_addresses_a_host() {
    let fx = fx().await;
    let a = add(&fx, host("alpha")).await;
    let a_id = a["id"].as_str().unwrap().to_owned();
    let b = add(&fx, host(&a_id)).await; // a label that IS another host's id
    assert_eq!(b["name"], json!(a_id));
    let (s, v) = call(&fx, &fx.admin, Method::GET, &format!("/hosts/{a_id}"), None).await;
    assert_eq!(
        (s, &v["name"]),
        (StatusCode::OK, &json!("alpha")),
        "the id wins"
    );
    let (s, v) = call(&fx, &fx.admin, Method::GET, "/hosts/ALPHA", None).await;
    assert_eq!(
        (s, &v["id"]),
        (StatusCode::OK, &json!(a_id)),
        "labels match case-insensitively"
    );
    let (s, v, raw) = call_raw(&fx, &fx.admin, Method::GET, "/hosts/nosuchhost-77", None).await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::NOT_FOUND, &json!("not_found"))
    );
    assert!(!raw.contains("nosuchhost-77"), "{raw}");
    // A duplicate label (any case) is a conflict, never a second host.
    let (s, v) = call(&fx, &fx.admin, Method::POST, "/hosts", Some(host("ALPHA"))).await;
    assert_eq!((s, &v["code"]), (StatusCode::CONFLICT, &json!("conflict")));
}

#[tokio::test]
async fn errors_never_echo_what_the_caller_sent() {
    let fx = fx().await;
    let secret = "SECRET-seed-4f1c9";
    for body in [
        format!("{{\"name\": \"{secret}\", \"address\": 5}}"),
        format!(
            "{{\"name\": \"x\", \"address\": \"a.com\", \"username\": \"u\", \"port\": \"{secret}\"}}"
        ),
        format!(
            "{{\"name\": \"x\", \"address\": \"a.com\", \"username\": \"u\", \"ai_rule\": \"{secret}\"}}"
        ),
        format!(
            "{{\"name\": \"x\", \"address\": \"a.com\", \"username\": \"u\", \"key_id\": \"{secret}\"}}"
        ),
        format!(
            "{{\"name\": \"x\", \"address\": \"a.com\", \"username\": \"u\", \"tags\": [\"{secret}!\"]}}"
        ),
        format!(
            "{{\"name\": \"x\", \"address\": \"a.com\", \"username\": \"u\", \"jump_chain\": [\"{secret}\"]}}"
        ),
        format!("not json {secret}"),
    ] {
        let (s, _, raw) = call_raw(&fx, &fx.admin, Method::POST, "/hosts", Some(&body)).await;
        assert!(s.is_client_error(), "{body}: {s}");
        assert!(!raw.contains(secret), "{body}: {raw}");
    }
    let (s, _, raw) = call_raw(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("/hosts/{secret}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(!raw.contains(secret));
    assert_eq!(count(&fx, "leyline_hosts").await, 0);
}

#[tokio::test]
async fn hosts_groups_tags_and_filters() {
    let fx = fx().await;
    let mut w = host("web-1");
    w["group"] = json!("Prod");
    w["tags"] = json!(["Web", "eu", "web"]);
    let w = add(&fx, w).await;
    assert_eq!(
        w["tags"],
        json!(["web", "eu"]),
        "tags are lowercased and de-duplicated"
    );
    assert_eq!(
        (w["port"].clone(), w["ai_rule"].clone()),
        (json!(22), json!("ask"))
    );
    let mut d = host("db-1");
    d["group"] = json!("prod");
    d["tags"] = json!(["db"]);
    add(&fx, d).await;
    add(&fx, host("lone")).await;
    let names = |v: &Value| {
        v.as_array()
            .unwrap()
            .iter()
            .map(|h| h["name"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    let (_, all) = call(&fx, &fx.admin, Method::GET, "/hosts", None).await;
    assert_eq!(
        names(&all),
        ["db-1", "web-1", "lone"],
        "grouped first, ungrouped last"
    );
    let (_, g) = call(&fx, &fx.admin, Method::GET, "/hosts?group=PROD", None).await;
    assert_eq!(names(&g), ["db-1", "web-1"]);
    let (_, t) = call(&fx, &fx.admin, Method::GET, "/hosts?tag=WEB", None).await;
    assert_eq!(names(&t), ["web-1"]);
    let (_, groups) = call(&fx, &fx.admin, Method::GET, "/groups", None).await;
    assert_eq!(groups.as_array().unwrap().len(), 1);
    assert_eq!(groups[0]["hosts"], json!(2));
    let (_, tags) = call(&fx, &fx.admin, Method::GET, "/tags", None).await;
    assert_eq!(
        tags,
        json!([{"name": "db", "hosts": 1}, {"name": "eu", "hosts": 1}, {"name": "web", "hosts": 1}])
    );
    // null clears a nullable field, an absent field keeps it.
    let path = format!("/hosts/{}", w["id"].as_str().unwrap());
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &path,
        Some(json!({"group": null, "name": "web-one"})),
    )
    .await;
    assert_eq!(
        (s, &v["group"], &v["name"], &v["tags"]),
        (
            StatusCode::OK,
            &Value::Null,
            &json!("web-one"),
            &json!(["web", "eu"])
        )
    );
}

#[tokio::test]
async fn keys_runners_rules_and_jump_chains_are_checked() {
    let fx = fx().await;
    // An unknown rule is refused (`allowed` is real since Y4-01; see command_gate.rs).
    let mut h = host("a");
    h["ai_rule"] = json!("anything");
    assert_eq!(
        call(&fx, &fx.admin, Method::POST, "/hosts", Some(h))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut h = host("a");
    h["ai_rule"] = json!("read_only");
    let a = add(&fx, h).await;
    let (a_id, b_id, c_id, d_id) = (
        a["id"].as_str().unwrap().to_owned(),
        add(&fx, host("b")).await["id"].as_str().unwrap().to_owned(),
        add(&fx, host("c")).await["id"].as_str().unwrap().to_owned(),
        add(&fx, host("d")).await["id"].as_str().unwrap().to_owned(),
    );
    // Unknown key: refused. A key row (metadata only) is accepted.
    let mut k = host("k");
    k["key_id"] = json!("k_0123456789abcdef");
    assert_eq!(
        call(&fx, &fx.admin, Method::POST, "/hosts", Some(k.clone()))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    sqlx::query("INSERT INTO leyline_keys (id, name, algo, public_key, fingerprint, secret, origin) VALUES ('k_0123456789abcdef', 'main', 'ed25519', 'ssh-ed25519 AAAA', 'SHA256:x', 'leyline-key-main', 'generated')")
        .execute(&fx.app.pool).await.unwrap();
    assert_eq!(
        call(&fx, &fx.admin, Method::POST, "/hosts", Some(k))
            .await
            .0,
        StatusCode::OK
    );
    // Jump chains: up to 3 known hosts, no repeats, never itself, nothing unknown.
    let path = format!("/hosts/{a_id}");
    for chain in [json!([&b_id, &c_id, &d_id]), json!([&b_id])] {
        let (s, v) = call(
            &fx,
            &fx.admin,
            Method::PATCH,
            &path,
            Some(json!({"jump_chain": chain})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    for chain in [
        json!([&b_id, &c_id, &d_id, "h_00000000000000aa"]),
        json!([&b_id, &b_id]),
        json!([&a_id]),
        json!(["h_00000000000000aa"]),
        json!(["-oProxyCommand=id"]),
    ] {
        let (s, _) = call(
            &fx,
            &fx.admin,
            Method::PATCH,
            &path,
            Some(json!({"jump_chain": chain})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{chain}");
    }
    // A host another host jumps through cannot be deleted.
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::DELETE,
        &format!("/hosts/{b_id}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // Runner ids are shaped, not looked up.
    for (runner, ok) in [
        ("d_0123456789abcdefghijklmnop", true),
        ("x_1", false),
        ("d_a b", false),
        ("d_-oProxyCommand=1", false),
    ] {
        let (s, _) = call(
            &fx,
            &fx.admin,
            Method::PATCH,
            &path,
            Some(json!({"via_runner": runner})),
        )
        .await;
        assert_eq!(s == StatusCode::OK, ok, "{runner}");
    }
}

#[tokio::test]
async fn deleting_a_host_cascades_to_its_pinned_keys_and_attachments() {
    let fx = fx().await;
    let id = add(&fx, host("a")).await["id"].as_str().unwrap().to_owned();
    sqlx::query("INSERT INTO leyline_host_keys (host_id, algo, key_b64, fingerprint, state, first_seen) VALUES (?, 'ssh-ed25519', 'AAAA', 'SHA256:y', 'seen', '2026-11-17T00:00:00Z')")
        .bind(&id).execute(&fx.app.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO leyline_project_hosts (project, host_id, role) VALUES ('p1', ?, 'production')",
    )
    .bind(&id)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    assert!(
        sqlx::query(
            "INSERT INTO leyline_project_hosts (project, host_id, role) VALUES ('p1', ?, 'prod')"
        )
        .bind(&id)
        .execute(&fx.app.pool)
        .await
        .is_err()
    );
    assert_eq!(
        call(
            &fx,
            &fx.admin,
            Method::DELETE,
            &format!("/hosts/{id}"),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        (
            count(&fx, "leyline_host_keys").await,
            count(&fx, "leyline_project_hosts").await
        ),
        (0, 0)
    );
}

#[tokio::test]
async fn audit_and_events_name_the_host_by_id_and_nothing_else() {
    let fx = fx().await;
    let made = add(&fx, host("private-label-91")).await;
    let id = made["id"].as_str().unwrap();
    call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/hosts/{id}"),
        Some(json!({"address": "10.9.8.7"})),
    )
    .await;
    call(
        &fx,
        &fx.admin,
        Method::DELETE,
        &format!("/hosts/{id}"),
        None,
    )
    .await;
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'leyline.%' ORDER BY rowid",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "leyline.host.created",
            "leyline.host.changed",
            "leyline.host.deleted"
        ]
    );
    let all = format!(
        "{:?}{:?}",
        sqlx::query_scalar::<_, String>(
            "SELECT details FROM audit_events WHERE action LIKE 'leyline.%'"
        )
        .fetch_all(&fx.app.pool)
        .await
        .unwrap(),
        events::list_events(&fx.app.pool, 0, 1000).await.unwrap()
    );
    assert!(all.contains("leyline.host") && all.contains(id), "{all}");
    for private in ["private-label-91", "10.9.8.7", "example.com", "deploy"] {
        assert!(!all.contains(private), "{private} leaked: {all}");
    }
    let mut conn = fx.app.pool.acquire().await.unwrap();
    assert!(
        events::append(&mut conn, "leyline.undeclared", &json!({}))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn module_off_the_core_has_no_leyline_tables_or_routes() {
    let off = fx_with(false).await;
    let tables: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name LIKE 'leyline_%'")
            .fetch_one(&off.app.pool)
            .await
            .unwrap();
    assert_eq!(tables, 0);
    // An unmounted module's path is denied by default, never served.
    assert_eq!(
        call(&off, &off.admin, Method::GET, "/hosts", None).await.0,
        StatusCode::FORBIDDEN
    );
    // And switching it on adds only its own namespace: the platform's tables are the same.
    let on = fx().await;
    let core = |fx: &Fx| {
        let pool = fx.app.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>("SELECT name FROM sqlite_master WHERE name NOT LIKE 'leyline_%' AND name NOT LIKE '%leyline%' ORDER BY name")
                .fetch_all(&pool).await.unwrap()
        }
    };
    assert_eq!(core(&on).await, core(&off).await);
}

#[tokio::test]
async fn the_migration_goes_down_and_up_again() {
    let fx = fx().await;
    for m in leyline_module::MIGRATIONS.iter().rev() {
        for stmt in m.down.split(';').filter(|s| !s.trim().is_empty()) {
            sqlx::query(stmt).execute(&fx.app.pool).await.unwrap();
        }
    }
    let left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name LIKE 'leyline_%'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(left, 0);
    for m in leyline_module::MIGRATIONS {
        sqlx::raw_sql(m.up).execute(&fx.app.pool).await.unwrap();
    }
    assert_eq!(count(&fx, "leyline_hosts").await, 0);
    assert_eq!(count(&fx, "leyline_runs").await, 0);
}

#[test]
fn the_contract_marks_scope_and_step_up_and_carries_no_key_material_routes() {
    let spec: Value =
        serde_json::from_str(&ainkrad_core_server::api::v1::spec::json_for(&[Arc::new(
            Leyline,
        )]))
        .unwrap();
    let p = &spec["paths"];
    assert_eq!(
        p["/modules/leyline/v1/hosts"]["get"]["x-ainkrad-scope"],
        "read"
    );
    assert_eq!(
        p["/modules/leyline/v1/hosts"]["post"]["x-ainkrad-scope"],
        "admin"
    );
    assert!(p["/modules/leyline/v1/hosts/{host}"]["delete"]["x-ainkrad-destructive"].is_null());
    assert!(p["/modules/leyline/v1/hosts/{host}"]["patch"]["x-ainkrad-destructive"].is_null());
}

fn who() -> ainkrad_core_server::store::projects::Who<'static> {
    ainkrad_core_server::store::projects::Who {
        by_device: "d_test",
        actor: ainkrad_core_server::api::v1::BY,
        now: "2026-11-17T00:00:00Z",
    }
}

async fn project(fx: &Fx, slug: &str) -> i64 {
    ainkrad_core_server::store::projects::create(&fx.app.pool, slug, slug, "", "manual", who())
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn projects_attach_hosts_with_a_role_and_both_sides_list_them() {
    let fx = fx().await;
    let reader = enroll(&fx.app, "reader", &["read"]).await;
    let (p, q) = (project(&fx, "alpha").await, project(&fx, "beta").await);
    let a = add(&fx, host("a")).await["id"].as_str().unwrap().to_owned();
    let path = format!("/projects/{p}/hosts/{a}");
    let staging = || Some(json!({"role": "staging"}));
    let (s, b) = call(&fx, &reader, Method::PUT, &path, staging()).await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::FORBIDDEN, &json!("forbidden_scope"))
    );
    for bad in ["prod", ""] {
        let (s, _) = call(
            &fx,
            &fx.admin,
            Method::PUT,
            &path,
            Some(json!({"role": bad})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
    let (s, b) = call(&fx, &fx.admin, Method::PUT, &path, staging()).await;
    assert_eq!(
        (s, b["role"].as_str()),
        (StatusCode::OK, Some("staging")),
        "{b}"
    );
    // a label addresses the host; re-attaching changes the role, not the count
    let by_label = format!("/projects/{p}/hosts/a");
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PUT,
        &by_label,
        Some(json!({"role": "production"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let other = format!("/projects/{q}/hosts/{a}");
    call(
        &fx,
        &fx.admin,
        Method::PUT,
        &other,
        Some(json!({"role": "other"})),
    )
    .await;
    let (s, l) = call(
        &fx,
        &reader,
        Method::GET,
        &format!("/projects/{p}/hosts"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        l,
        json!([{"host_id": a, "name": "a", "role": "production"}])
    );
    let (_, h) = call(&fx, &reader, Method::GET, &format!("/hosts/{a}"), None).await;
    assert_eq!(
        h["projects"],
        json!([{"project": p.to_string(), "role": "production"}, {"project": q.to_string(), "role": "other"}])
    );
    let (_, all) = call(&fx, &reader, Method::GET, "/hosts", None).await;
    assert_eq!(all[0]["projects"].as_array().unwrap().len(), 2);
    // archiving a project leaves its attachments
    ainkrad_core_server::store::projects::archive(&fx.app.pool, p, who())
        .await
        .unwrap();
    assert_eq!(count(&fx, "leyline_project_hosts").await, 2);
    // ...but nothing new attaches to it (409); detach stays allowed
    let (s, b) = call(&fx, &fx.admin, Method::PUT, &path, staging()).await;
    assert_eq!((s, &b["code"]), (StatusCode::CONFLICT, &json!("conflict")));
    let (s, _) = call(&fx, &fx.admin, Method::DELETE, &path, None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&fx, &fx.admin, Method::DELETE, &path, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // deleting the host takes the rest
    call(&fx, &fx.admin, Method::DELETE, &format!("/hosts/{a}"), None).await;
    assert_eq!(count(&fx, "leyline_project_hosts").await, 0);
}

#[tokio::test]
async fn an_unknown_project_is_refused_and_attach_detach_are_audited() {
    let fx = fx().await;
    let a = add(&fx, host("a")).await["id"].as_str().unwrap().to_owned();
    let staging = || Some(json!({"role": "staging"}));
    for p in ["999", "0", "-1", "x", "1;2"] {
        let (s, _) = call(
            &fx,
            &fx.admin,
            Method::PUT,
            &format!("/projects/{p}/hosts/{a}"),
            staging(),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{p}");
        let (s, _) = call(
            &fx,
            &fx.admin,
            Method::GET,
            &format!("/projects/{p}/hosts"),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
    let p = project(&fx, "alpha").await;
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PUT,
        &format!("/projects/{p}/hosts/nope"),
        staging(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(count(&fx, "leyline_project_hosts").await, 0);
    assert_eq!(
        count(&fx, "audit_events WHERE action = 'leyline.host.attached'").await,
        0
    );
    call(
        &fx,
        &fx.admin,
        Method::PUT,
        &format!("/projects/{p}/hosts/{a}"),
        staging(),
    )
    .await;
    call(
        &fx,
        &fx.admin,
        Method::DELETE,
        &format!("/projects/{p}/hosts/{a}"),
        None,
    )
    .await;
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action IN ('leyline.host.attached','leyline.host.detached') ORDER BY rowid",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(actions, ["leyline.host.attached", "leyline.host.detached"]);
    let ev = format!(
        "{:?}",
        events::list_events(&fx.app.pool, 0, 1000).await.unwrap()
    );
    assert!(
        ev.contains("attached") && ev.contains("detached") && !ev.contains("example.com"),
        "{ev}"
    );
}

/// Review H3, M3: every Leyline route that runs code on a host or reads its files is refused
/// to a device that never unlocked the app, before the route looks at the request.
#[tokio::test]
async fn the_unlock_routes_are_refused_without_the_unlock() {
    let fx = fx().await;
    let locked = enroll(&fx.app, "locked", &["admin", "read", "terminal"]).await;
    let routes = [
        (Method::POST, "/hosts/h_x/terminals"),
        (Method::PUT, "/hosts/h_x/files/content"),
        (Method::POST, "/hosts/h_x/runner"),
        (Method::POST, "/commands"),
        (Method::PATCH, "/commands/c_x"),
        (Method::POST, "/commands/c_x/run"),
        (Method::POST, "/fleet/runs"),
        (Method::GET, "/hosts/h_x/files"),
        (Method::GET, "/hosts/h_x/files/content"),
    ];
    for (m, path) in routes {
        let (s, v, _) = call_raw(&fx, &locked, m.clone(), path, Some("{}")).await;
        assert_eq!((s, &v["code"]), (StatusCode::FORBIDDEN, &json!("unlock_required")), "{m} {path}");
        let (_, v, _) = call_raw(&fx, &fx.admin, m.clone(), path, Some("{}")).await;
        assert_ne!(v["code"], json!("unlock_required"), "{m} {path}: the unlocked admin passes the gate");
    }
}

/// A Leyline command run needs the app unlock, so Code Mode treats it as risky (an approval each
/// time): the classification the dispatcher reads.
#[test]
fn leyline_command_runs_and_shells_are_unlock_routes_for_code_mode() {
    use ainkrad_core_server::api::v1::scopes::needs_unlock;
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Leyline)];
    for (m, p) in [
        (Method::POST, "/modules/leyline/v1/commands/c_x/run"),
        (Method::POST, "/modules/leyline/v1/fleet/runs"),
        (Method::POST, "/modules/leyline/v1/hosts/h_x/terminals"),
    ] {
        assert!(needs_unlock(&m, p, &modules), "{m} {p}");
    }
    assert!(!needs_unlock(&Method::GET, "/modules/leyline/v1/hosts", &modules));
}
