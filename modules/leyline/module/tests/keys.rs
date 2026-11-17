//! Leyline keys (Y1-02) through the Core's real gate. Each test fails if the property it names
//! stops holding. The harness is `gate.rs`'s, plus the secret store, a runner and a log capture.

mod fixtures;

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::api::v1::BY;
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::module::Module;
use ainkrad_core_server::ops::secretbox::SecretBox;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{connect, events, migrate, settings};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use fixtures::*;
use leyline_module::Leyline;
use serde_json::{Value, json};
use ssh_key::PrivateKey;
use tower::ServiceExt;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::util::SubscriberInitExt;

const HOST: &str = "core.test";
const BASE: &str = "/modules/leyline/v1";

struct Fx {
    app: App,
    admin: TestDevice,
    runner: TestDevice,
    dir: PathBuf,
    /// Every response body but a redemption's (which legitimately carries a key).
    seen: Mutex<Vec<String>>,
    logs: Arc<Mutex<Vec<u8>>>,
    _log: Box<dyn std::any::Any>,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Cap(Arc<Mutex<Vec<u8>>>);

impl Write for Cap {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn enroll(app: &App, name: &str, kind: &str, scopes: &[&str]) -> TestDevice {
    let clock = Arc::new(SystemClock);
    let dev = TestDevice::enroll_keys(
        &app.pool,
        name,
        kind,
        scopes,
        &app.auth.identity.fp,
        clock.clone(),
        true,
    )
    .await;
    dev.set_session(Some(app.auth.issue_session(&dev.id, clock.unix()).id));
    dev
}

async fn set_mode(app: &App, mode: i64) {
    settings::set(
        &app.pool,
        Key::SecretsMode,
        Scope::Server,
        &mode.to_string(),
        BY,
        &app.clock.now(),
    )
    .await
    .unwrap();
}

/// A Core with Leyline and a master key, `secrets.mode` 2 (real keys), a runner and a log capture.
async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "leyline-keys-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Leyline)];
    migrate::migrate_modules(&pool, &modules).await.unwrap();
    let sealer = SecretBox::new(&[7; 32]);
    let identity = Arc::new(Identity::load_or_create(&dir, &sealer).unwrap());
    let clock = Arc::new(SystemClock);
    let mut app = App::new(pool, clock.clone(), HOST.to_owned(), identity);
    app.modules = Arc::from(modules);
    app.secrets = Some(Arc::new(sealer));
    set_mode(&app, 2).await;
    let admin = enroll(&app, "admin", "device", &["admin", "read"]).await;
    let session = admin.session.lock().unwrap().clone().unwrap();
    app.auth.elevate(&session, &admin.id, clock.unix() + 3600);
    let runner = enroll(&app, "runner-1", "runner", &["runner"]).await;
    // Captured on this thread (a `#[tokio::test]` runs on one): any log line the Core writes.
    let logs = Arc::new(Mutex::new(Vec::new()));
    let sink = logs.clone();
    let guard = tracing_subscriber::fmt()
        .with_max_level(LevelFilter::TRACE)
        .with_ansi(false)
        .with_writer(move || Cap(sink.clone()))
        .finish()
        .set_default();
    Fx {
        app,
        admin,
        runner,
        dir,
        seen: Mutex::new(Vec::new()),
        logs,
        _log: Box::new(guard),
    }
}

async fn send(
    fx: &Fx,
    dev: &TestDevice,
    method: Method,
    uri: &str,
    body: Option<Value>,
    keep: bool,
) -> (StatusCode, Value) {
    let bytes = body.map(|b| b.to_string()).unwrap_or_default();
    let mut b = Request::builder()
        .method(method.clone())
        .uri(uri)
        .header(header::HOST, HOST);
    for (name, value) in dev.headers(method.as_str(), uri, bytes.as_bytes()) {
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
    if keep {
        fx.seen.lock().unwrap().push(text.clone());
    }
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

async fn call(fx: &Fx, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    send(fx, &fx.admin, method, &format!("{BASE}{path}"), body, true).await
}

async fn generate(fx: &Fx, name: &str) -> Value {
    let (s, v) = call(fx, Method::POST, "/keys", Some(json!({"name": name}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

async fn import(fx: &Fx, name: &str, pem: &str, pass: Option<&str>) -> (StatusCode, Value) {
    let body = json!({"name": name, "private_key": pem, "passphrase": pass});
    call(fx, Method::POST, "/keys/import", Some(body)).await
}

async fn import_ok(fx: &Fx, name: &str, pem: &str, pass: Option<&str>) -> Value {
    let (s, v) = import(fx, name, pem, pass).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

/// A host that logs in with `key` through `runner`.
async fn host_with(fx: &Fx, name: &str, key: &str, runner: Option<&str>) -> String {
    let body = json!({"name": name, "address": "a.example.com", "username": "deploy",
                      "key_id": key, "via_runner": runner});
    let (s, v) = call(fx, Method::POST, "/hosts", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["id"].as_str().unwrap().to_owned()
}

async fn count(fx: &Fx, table: &str) -> i64 {
    let sql = sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")); // test-only, a literal table name
    sqlx::query_scalar(sql)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

/// The runners the key's own secret lists; the group's own list must stay empty.
async fn key_runners(fx: &Fx, key_id: &str) -> Vec<String> {
    let group: String =
        sqlx::query_scalar("SELECT runners FROM core_secret_groups WHERE name = 'leyline-keys'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(group, "[]");
    let json: String = sqlx::query_scalar("SELECT runners FROM core_secrets WHERE name = ?")
        .bind(format!("leyline.{key_id}"))
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    serde_json::from_str(&json).unwrap()
}

/// The runner leases the key's secret through the Core's own lease path and redeems it once.
/// Returns the redeemed key, or the status that refused.
async fn lease_and_redeem(fx: &Fx, key_id: &str) -> Result<PrivateKey, StatusCode> {
    lease_and_redeem_as(fx, key_id, &fx.runner).await
}

async fn lease_and_redeem_as(
    fx: &Fx,
    key_id: &str,
    runner: &TestDevice,
) -> Result<PrivateKey, StatusCode> {
    let secret = format!("leyline.{key_id}");
    let body = json!({"runner": runner.id, "ttl_secs": 60});
    let uri = format!("/api/v1/secrets/{secret}/leases");
    let (s, v) = send(fx, &fx.admin, Method::POST, &uri, Some(body), true).await;
    if s != StatusCode::OK {
        return Err(s);
    }
    let body = json!({"lease": v["lease"]});
    let uri = "/api/v1/secret-leases/redeem";
    let (s, v) = send(fx, runner, Method::POST, uri, Some(body.clone()), false).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["kind"], "file");
    assert_eq!(v["file_name"], "id_leyline");
    assert_eq!(v["file_mode"], "0600");
    // A lease is one redemption.
    let (again, _) = send(fx, runner, Method::POST, uri, Some(body), false).await;
    assert_eq!(again, StatusCode::GONE);
    let pem = STANDARD.decode(v["value"].as_str().unwrap()).unwrap();
    Ok(PrivateKey::from_openssh(&pem).unwrap())
}

fn public_of(key: &PrivateKey) -> String {
    key.public_key().to_openssh().unwrap()
}

#[tokio::test]
async fn a_generated_key_is_sealed_and_leases_only_to_the_runner_of_a_host_that_uses_it() {
    let fx = fx().await;
    let made = generate(&fx, "deploy key").await;
    let id = made["id"].as_str().unwrap().to_owned();
    assert_eq!(made["algo"], "ed25519");
    assert_eq!(made["origin"], "generated");
    assert!(made["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
    let mut fields: Vec<&str> = made
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "algo",
            "created_at",
            "fingerprint",
            "id",
            "name",
            "origin",
            "public_key"
        ]
    );
    // No host uses the key yet: nobody can be leased it.
    assert!(key_runners(&fx, &id).await.is_empty());
    assert_eq!(
        lease_and_redeem(&fx, &id).await.err(),
        Some(StatusCode::BAD_REQUEST)
    );
    // A host that uses the key through the runner puts the runner on the key.
    let h = host_with(&fx, "web", &id, Some(&fx.runner.id)).await;
    assert_eq!(
        key_runners(&fx, &id).await,
        std::slice::from_ref(&fx.runner.id)
    );
    let key = lease_and_redeem(&fx, &id).await.unwrap();
    assert_eq!(public_of(&key), made["public_key"]);
    assert_eq!(
        key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        made["fingerprint"]
    );
    assert!(!key.is_encrypted());
    // The runner follows the host: repointed at the built-in runner (none enrolled here) or
    // gone, the list empties again.
    let (s, _) = call(
        &fx,
        Method::PATCH,
        &format!("/hosts/{h}"),
        Some(json!({"via_runner": null})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(key_runners(&fx, &id).await.is_empty());
    let (s, _) = call(
        &fx,
        Method::PATCH,
        &format!("/hosts/{h}"),
        Some(json!({"via_runner": fx.runner.id})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        key_runners(&fx, &id).await,
        std::slice::from_ref(&fx.runner.id)
    );
    call(&fx, Method::DELETE, &format!("/hosts/{h}"), None).await;
    assert!(key_runners(&fx, &id).await.is_empty());
}

#[tokio::test]
async fn ed25519_and_ecdsa_import_and_the_passphrase_is_used_once_and_not_kept() {
    let fx = fx().await;
    let a = import_ok(&fx, "plain", ED, None).await;
    assert_eq!(
        (a["algo"].as_str(), a["public_key"].as_str()),
        (Some("ed25519"), Some(ED_PUB))
    );
    assert_eq!(a["origin"], "imported");
    let e = import_ok(&fx, "locked", ED_ENC, Some(PASS)).await;
    assert_eq!(e["public_key"], ED_ENC_PUB);
    let p = import_ok(&fx, "p256", P256, None).await;
    assert_eq!(
        (p["algo"].as_str(), p["public_key"].as_str()),
        (Some("ecdsa-p256"), Some(P256_PUB))
    );
    let q = import_ok(&fx, "p384", P384, None).await;
    assert_eq!(q["algo"], "ecdsa-p384");
    // What was sealed for the encrypted key is the decrypted key: no passphrase is needed again.
    host_with(&fx, "web", e["id"].as_str().unwrap(), Some(&fx.runner.id)).await;
    let stored = lease_and_redeem(&fx, e["id"].as_str().unwrap())
        .await
        .unwrap();
    assert!(!stored.is_encrypted());
    assert_eq!(public_of(&stored), ED_ENC_PUB);
    let (s, list) = call(&fx, Method::GET, "/keys", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn rsa_dsa_and_unreadable_keys_are_refused_and_nothing_is_left_behind() {
    let fx = fx().await;
    let (s, v) = import(&fx, "old", RSA, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let msg = v["message"].as_str().unwrap();
    assert!(
        msg.contains("RSA keys are not supported; generate an ed25519 key")
            && msg.contains("DSA")
            && msg.contains("Generate Key"),
        "{msg}"
    );
    // An encrypted RSA key is refused before its passphrase is looked at (DSA is the same
    // branch: the algorithm is public on an encrypted key).
    assert_eq!(
        import(&fx, "old2", RSA, Some(PASS)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        import(&fx, "p521", P521, None).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        import(&fx, "junk", "not a key", None).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        import(&fx, "big", &"A".repeat(20_000), None).await.0,
        StatusCode::BAD_REQUEST
    );
    // Encrypted: no passphrase, a wrong one, an oversized one.
    let (s, v) = import(&fx, "e", ED_ENC, None).await;
    assert_eq!(
        (s, v["message"].as_str().unwrap().contains("passphrase")),
        (StatusCode::BAD_REQUEST, true)
    );
    assert_eq!(
        import(&fx, "e", ED_ENC, Some("wrong")).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        import(&fx, "e", ED_ENC, Some(&"p".repeat(2000))).await.0,
        StatusCode::BAD_REQUEST
    );
    // Bad labels.
    for name in ["", " x", "a\nb", &"n".repeat(65)] {
        assert_eq!(
            import(&fx, name, ED, None).await.0,
            StatusCode::BAD_REQUEST,
            "{name:?}"
        );
    }
    assert_eq!(
        count(&fx, "leyline_keys").await + count(&fx, "core_secrets").await,
        0
    );
    // Duplicates: the same key, the same name.
    import_ok(&fx, "one", ED, None).await;
    assert_eq!(import(&fx, "two", ED, None).await.0, StatusCode::CONFLICT);
    assert_eq!(import(&fx, "ONE", P256, None).await.0, StatusCode::CONFLICT);
    assert_eq!(
        (
            count(&fx, "leyline_keys").await,
            count(&fx, "core_secrets").await
        ),
        (1, 1)
    );
}

#[tokio::test]
async fn the_secret_gate_governs_keys_and_a_refusal_stores_nothing() {
    let fx = fx().await;
    // Mode 1 takes throwaway values only: a key shaped like a real one waits for mode 2.
    set_mode(&fx.app, 1).await;
    let (s, v) = import(&fx, "k", ED, None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("real_secret_refused"))
    );
    // Mode 0: the broker is off.
    set_mode(&fx.app, 0).await;
    let (s, v) = call(&fx, Method::POST, "/keys", Some(json!({"name": "k"}))).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("secrets_disabled"))
    );
    assert_eq!(
        (
            count(&fx, "leyline_keys").await,
            count(&fx, "core_secrets").await
        ),
        (0, 0)
    );
}

#[tokio::test]
async fn a_key_in_use_cannot_be_deleted_and_an_unused_one_goes_with_its_secret() {
    let fx = fx().await;
    let id = generate(&fx, "k").await["id"].as_str().unwrap().to_owned();
    let h = host_with(&fx, "web", &id, None).await;
    let (s, _) = call(&fx, Method::DELETE, &format!("/keys/{id}"), None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(
        (
            count(&fx, "leyline_keys").await,
            count(&fx, "core_secrets").await
        ),
        (1, 1)
    );
    call(&fx, Method::DELETE, &format!("/hosts/{h}"), None).await;
    let (s, v) = call(&fx, Method::DELETE, &format!("/keys/{id}"), None).await;
    assert_eq!(
        (s, v["deleted"].as_str()),
        (StatusCode::OK, Some(id.as_str()))
    );
    assert_eq!(
        (
            count(&fx, "leyline_keys").await,
            count(&fx, "core_secrets").await
        ),
        (0, 0)
    );
    assert_eq!(
        call(&fx, Method::GET, &format!("/keys/{id}"), None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&fx, Method::DELETE, &format!("/keys/{id}"), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

/// Every needle that would show private material: the PEM's base64 body (whole and by line) and,
/// for an ed25519 key, its seed in hex and base64.
/// `publics` is every public key the API shows: a private-key line that is only public bytes is
/// not private material.
fn needles(pem: &str, publics: &str, out: &mut Vec<String>) {
    let lines: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    out.push(lines.concat());
    let own = |l: &&&str| l.len() >= 20 && !publics.contains(**l);
    out.extend(lines.iter().filter(own).map(|l| (*l).to_owned()));
    if let Ok(k) = PrivateKey::from_openssh(pem)
        && let Some(ed) = k.key_data().ed25519()
    {
        let seed = ed.private.to_bytes();
        out.push(seed.iter().map(|b| format!("{b:02x}")).collect());
        out.push(STANDARD.encode(seed));
    }
}

fn leak<'a>(haystack: &str, needles: &'a [String]) -> Option<&'a String> {
    needles.iter().find(|n| haystack.contains(n.as_str()))
}

#[tokio::test]
async fn no_response_event_audit_row_table_or_log_holds_private_material_or_a_passphrase() {
    let wrong = "WRONG-PASSPHRASE-5521";
    let fx = fx().await;
    // Everything the module does with keys, including refusals that carry a secret.
    let g = generate(&fx, "gen").await;
    let gid = g["id"].as_str().unwrap();
    let ids: Vec<String> = [
        import_ok(&fx, "a", ED, None).await,
        import_ok(&fx, "b", ED_ENC, Some(PASS)).await,
        import_ok(&fx, "c", P256, None).await,
        import_ok(&fx, "d", P384, None).await,
    ]
    .iter()
    .map(|v| v["id"].as_str().unwrap().to_owned())
    .collect();
    import(&fx, "r", RSA, Some(PASS)).await;
    import(&fx, "w", ED_ENC, Some(wrong)).await;
    import(&fx, "n", ED_ENC, None).await;
    host_with(&fx, "web", gid, Some(&fx.runner.id)).await;
    // The generated key's own private bytes are known only after the Core made them: take them
    // through the lease path (that response is the one not scanned) and seed them too.
    let key = lease_and_redeem(&fx, gid).await.unwrap();
    let (_, listed) = call(&fx, Method::GET, "/keys", None).await;
    let publics: String = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["public_key"].as_str().unwrap())
        .collect();
    let mut seeded: Vec<String> = vec![PASS.to_owned(), wrong.to_owned()];
    for pem in [
        ED,
        ED_ENC,
        P256,
        P384,
        RSA,
        &key.to_openssh(ssh_key::LineEnding::LF).unwrap(),
    ] {
        needles(pem, &publics, &mut seeded);
    }
    assert!(seeded.len() > 20);
    for id in ids.iter().chain([&gid.to_owned()]) {
        call(&fx, Method::GET, &format!("/keys/{id}"), None).await;
    }
    call(&fx, Method::DELETE, &format!("/keys/{}", ids[0]), None).await;

    // The scan can see: a text holding a seed is caught.
    assert!(leak(&format!("x {PASS} y"), &seeded).is_some());

    let mut all = fx.seen.lock().unwrap().join("\n");
    all += &format!(
        "{:?}",
        events::list_events(&fx.app.pool, 0, 10_000).await.unwrap()
    );
    for (table, cols) in [
        ("audit_events", "action || ' ' || details"),
        (
            "leyline_keys",
            "id || name || algo || public_key || fingerprint || secret || origin",
        ),
        (
            "core_secrets",
            "name || owner || description || coalesce(file_name, '')",
        ),
        ("core_secret_groups", "name || description || runners"),
        ("core_secret_leases", "runner"),
    ] {
        let sql = sqlx::AssertSqlSafe(format!("SELECT {cols} FROM {table}")); // test-only literals
        let rows: Vec<String> = sqlx::query_scalar(sql)
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
        all += &rows.join("\n");
    }
    all += &String::from_utf8_lossy(&fx.logs.lock().unwrap());
    assert!(
        all.contains("leyline.key.created"),
        "the scan reads the audit rows"
    );
    assert_eq!(leak(&all, &seeded), None);
}

#[tokio::test]
async fn errors_never_echo_what_the_caller_sent() {
    let fx = fx().await;
    let m = "ECHO-MARKER-4471";
    let mut texts: Vec<(StatusCode, Value)> = vec![
        call(
            &fx,
            Method::POST,
            "/keys",
            Some(json!({"name": format!("{m}\n")})),
        )
        .await,
        import(&fx, &format!("{m}\n"), ED, None).await,
        import(&fx, "x", &format!("{m} garbage"), Some(m)).await,
        import(&fx, "x", RSA, Some(m)).await,
        import(&fx, "x", ED_ENC, Some(m)).await,
        import(
            &fx,
            &"k".repeat(70),
            &format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{m}\n"),
            None,
        )
        .await,
        call(&fx, Method::GET, &format!("/keys/{m}"), None).await,
        call(&fx, Method::DELETE, &format!("/keys/{m}"), None).await,
    ];
    let (s, v, _) = {
        // A body that is not JSON at all, with the marker in it.
        let uri = format!("{BASE}/keys/import");
        let b = format!("{{\"name\": \"{m}\", oops");
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(&uri)
            .header(header::HOST, HOST);
        for (n, val) in fx.admin.headers("POST", &uri, b.as_bytes()) {
            req = req.header(n, val);
        }
        let res = router(fx.app.clone())
            .oneshot(
                req.header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(b))
                    .unwrap(),
            )
            .await
            .unwrap();
        let s = res.status();
        let t = String::from_utf8_lossy(&to_bytes(res.into_body(), 1 << 20).await.unwrap())
            .into_owned();
        (
            s,
            serde_json::from_str::<Value>(&t).unwrap_or(Value::Null),
            t,
        )
    };
    texts.push((s, v));
    for (s, v) in texts {
        assert!(s.is_client_error(), "{s} {v}");
        assert!(!v.to_string().contains(m), "echoed: {v}");
    }
}

#[tokio::test]
async fn scopes_step_up_and_the_contract_expose_public_data_only() {
    let fx = fx().await;
    let id = generate(&fx, "k").await["id"].as_str().unwrap().to_owned();
    let viewer = enroll(&fx.app, "viewer", "device", &["read"]).await;
    let uri = |p: &str| format!("{BASE}{p}");

    assert_eq!(
        send(&fx, &viewer, Method::GET, &uri("/keys"), None, true)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &fx,
            &viewer,
            Method::GET,
            &uri(&format!("/keys/{id}")),
            None,
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    for (m, p, b) in [
        (Method::POST, "/keys".to_owned(), Some(json!({"name": "v"}))),
        (
            Method::POST,
            "/keys/import".to_owned(),
            Some(json!({"name": "v", "private_key": ED})),
        ),
        (Method::DELETE, format!("/keys/{id}"), None),
    ] {
        let (s, _) = send(&fx, &viewer, m, &uri(&p), b, true).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{p}");
    }
    let spec: Value =
        serde_json::from_str(&ainkrad_core_server::api::v1::spec::json_for(&[Arc::new(
            Leyline,
        )]))
        .unwrap();
    let p = &spec["paths"];
    assert_eq!(
        p["/modules/leyline/v1/keys"]["get"]["x-ainkrad-scope"],
        "read"
    );
    assert_eq!(
        p["/modules/leyline/v1/keys"]["post"]["x-ainkrad-scope"],
        "admin"
    );
    assert_eq!(
        p["/modules/leyline/v1/keys/import"]["post"]["x-ainkrad-scope"],
        "admin"
    );
    assert_eq!(
        p["/modules/leyline/v1/keys/{key}"]["delete"]["x-ainkrad-destructive"],
        true
    );
    // No schema a key route answers with has a private or passphrase field.
    let view = spec["components"]["schemas"]["KeyView"]["properties"]
        .as_object()
        .unwrap();
    assert!(
        view.keys()
            .all(|k| !k.contains("private") && !k.contains("pass")),
        "{view:?}"
    );
}

/// `pem` (an encrypted key) with its bcrypt round count replaced.
fn with_rounds(pem: &str, rounds: u32) -> String {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let mut raw = STANDARD.decode(body).unwrap();
    let at = raw.windows(6).position(|w| w == b"bcrypt").unwrap();
    // "bcrypt", then the options string: its length, the salt string (length + 16), the rounds.
    let rounds_at = at + 6 + 4 + 4 + 16;
    raw[rounds_at..rounds_at + 4].copy_from_slice(&rounds.to_be_bytes());
    let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in STANDARD.encode(&raw).as_bytes().chunks(70) {
        out += std::str::from_utf8(chunk).unwrap();
        out.push('\n');
    }
    out + "-----END OPENSSH PRIVATE KEY-----\n"
}

#[tokio::test]
async fn a_hostile_bcrypt_cost_is_refused_at_once_and_junk_is_only_invalid() {
    let fx = fx().await;
    for rounds in [u32::MAX, 1025] {
        let started = std::time::Instant::now();
        let (s, v) = import(&fx, "slow", &with_rounds(ED_ENC, rounds), Some(PASS)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{rounds}");
        assert!(
            v["message"].as_str().unwrap().contains("hashing cost"),
            "{v}"
        );
        assert!(
            started.elapsed().as_secs() < 2,
            "{rounds} was not refused up front"
        );
    }
    // A key that does not parse is "not valid"; only a refused algorithm is "unsupported".
    let (s, v) = import(&fx, "junk", "not a key", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["message"], "the key is not valid");
    let (_, v) = import(&fx, "rsa", RSA, None).await;
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("RSA keys are not supported"),
        "{v}"
    );
}

#[tokio::test]
async fn importing_needs_the_step_up_and_generating_does_not() {
    let fx = fx().await;
    let laptop = enroll(&fx.app, "laptop", "device", &["admin"]).await; // admin, not elevated
    let uri = format!("{BASE}/keys/import");
    let body = json!({"name": "i", "private_key": ED});
    let (s, v) = send(&fx, &laptop, Method::POST, &uri, Some(body), true).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("step_up_required"))
    );
    assert_eq!(
        count(&fx, "leyline_keys").await + count(&fx, "core_secrets").await,
        0
    );
    let uri = format!("{BASE}/keys");
    let (s, _) = send(
        &fx,
        &laptop,
        Method::POST,
        &uri,
        Some(json!({"name": "g"})),
        true,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    import_ok(&fx, "i", ED, None).await; // the elevated admin
    let spec: Value =
        serde_json::from_str(&ainkrad_core_server::api::v1::spec::json_for(&[Arc::new(
            Leyline,
        )]))
        .unwrap();
    let p = &spec["paths"];
    assert_eq!(
        p["/modules/leyline/v1/keys/import"]["post"]["x-ainkrad-destructive"],
        true
    );
    assert!(p["/modules/leyline/v1/keys"]["post"]["x-ainkrad-destructive"].is_null());
}

#[tokio::test]
async fn each_key_is_leasable_only_to_the_runners_of_the_hosts_that_use_it() {
    let fx = fx().await;
    let r1 = &fx.runner;
    let r2 = enroll(&fx.app, "runner-2", "runner", &["runner"]).await;
    let mut ids = Vec::new();
    for name in ["a", "b", "c"] {
        ids.push(generate(&fx, name).await["id"].as_str().unwrap().to_owned());
    }
    let (a, b, c) = (&ids[0], &ids[1], &ids[2]);
    // A is used by a host on R2 only: R2 may be leased it, R1 may not. B has no host: no one.
    host_with(&fx, "on-r2", a, Some(&r2.id)).await;
    assert_eq!(key_runners(&fx, a).await, std::slice::from_ref(&r2.id));
    assert!(key_runners(&fx, b).await.is_empty());
    assert_eq!(
        lease_and_redeem_as(&fx, a, r1).await.err(),
        Some(StatusCode::BAD_REQUEST)
    );
    assert!(lease_and_redeem_as(&fx, a, &r2).await.is_ok());
    for r in [r1, &r2] {
        assert_eq!(
            lease_and_redeem_as(&fx, b, r).await.err(),
            Some(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            lease_and_redeem_as(&fx, c, r).await.err(),
            Some(StatusCode::BAD_REQUEST)
        );
    }
    // C is the key of a jump host on R1; a host on R2 jumps through it: both runners need C.
    let hop = host_with(&fx, "hop", c, Some(&r1.id)).await;
    let body = json!({"name": "behind", "address": "b.example.com", "username": "deploy",
                      "key_id": a, "via_runner": r2.id, "jump_chain": [hop]});
    let (s, v) = call(&fx, Method::POST, "/hosts", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let behind = v["id"].as_str().unwrap().to_owned();
    let mut both = vec![r1.id.clone(), r2.id.clone()];
    both.sort();
    assert_eq!(key_runners(&fx, c).await, both);
    assert_eq!(key_runners(&fx, a).await, std::slice::from_ref(&r2.id));
    assert!(lease_and_redeem_as(&fx, c, r1).await.is_ok());
    assert!(lease_and_redeem_as(&fx, c, &r2).await.is_ok());
    // The jumping host goes: C is back to its own host's runner. The audit rows say so.
    call(&fx, Method::DELETE, &format!("/hosts/{behind}"), None).await;
    assert_eq!(key_runners(&fx, c).await, std::slice::from_ref(&r1.id));
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'leyline.key.runners'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert!(n >= 3, "{n}");
}
