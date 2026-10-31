//! The composed Core (`ainkrad-core-citadel serve`), booted for real on a temp dir: Citadel is
//! mounted only on `--enable-module citadel`, behind the Core's gate (scope and step-up enforced
//! by the real server, not a router in the test), and a plain `serve` serves nothing for the module.

use std::sync::Arc;
use std::time::Duration;

use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::scheduler::SystemClock;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_ainkrad-core-citadel");

struct Server {
    dir: std::path::PathBuf,
    bind: String,
    http: reqwest::Client,
    _child: tokio::process::Child,
    /// All scopes, step-up key, not elevated.
    admin: TestDevice,
    /// `read` only.
    phone: TestDevice,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Enrols two devices, starts `serve` with `extra` flags, waits for it, logs both devices in.
async fn boot(name: &str, extra: &[&str]) -> Server {
    let dir = std::env::temp_dir().join(format!("core-citadel-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("core.db");
    let identity = Identity::load_or_create(&dir).unwrap();
    let pool = ainkrad_core_server::store::connect(&db).await.unwrap();
    let clock = Arc::new(SystemClock);
    let all = ["read", "approve", "terminal", "agent", "admin"];
    let admin = TestDevice::enroll(&pool, "mac", "device", &all, &identity.fp, clock.clone()).await;
    let phone = TestDevice::enroll(&pool, "phone", "device", &["read"], &identity.fp, clock).await;
    pool.close().await;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bind = format!("127.0.0.1:{port}");
    let child = tokio::process::Command::new(BIN)
        .args([
            "serve",
            db.to_str().unwrap(),
            "--listen",
            &format!("loopback:{port}"),
        ])
        .args(extra)
        .stderr(std::fs::File::create(dir.join("server.log")).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(&bind).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let s = Server {
        dir,
        bind,
        http: reqwest::Client::new(),
        _child: child,
        admin,
        phone,
    };
    for d in [&s.admin, &s.phone] {
        s.login(d).await;
    }
    s
}

impl Server {
    async fn login(&self, d: &TestDevice) {
        let url = |p: &str| format!("http://{}{p}", self.bind);
        let c: Value = self
            .http
            .post(url("/handshake/challenge"))
            .json(&json!({"device_id": d.id}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let body = json!({"challenge": c["challenge"]}).to_string();
        let mut r = self
            .http
            .post(url("/handshake/session"))
            .header("content-type", "application/json")
            .body(body.clone());
        for (k, v) in d.headers_session("POST", "/handshake/session", body.as_bytes(), None) {
            r = r.header(k, v);
        }
        let s: Value = r.send().await.unwrap().json().await.unwrap();
        d.set_session(s["session_id"].as_str().map(str::to_owned));
        assert!(d.session.lock().unwrap().is_some(), "{s}");
    }

    /// A signed request: the status and the JSON body.
    async fn call(
        &self,
        d: &TestDevice,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let bytes = body.map(|b| b.to_string()).unwrap_or_default();
        let mut r = self
            .http
            .request(
                method.parse().unwrap(),
                format!("http://{}{path}", self.bind),
            )
            .body(bytes.clone());
        if !bytes.is_empty() {
            r = r.header("content-type", "application/json");
        }
        for (k, v) in d.headers(method, path, bytes.as_bytes()) {
            r = r.header(k, v);
        }
        let res = r.send().await.unwrap();
        let status = res.status().as_u16();
        (status, res.json().await.unwrap_or(Value::Null))
    }
}

const COMPANIES: &str = "/modules/citadel/v1/companies";
const DEPARTMENT: &str = "/modules/citadel/v1/departments/1";

#[tokio::test]
async fn enabled_citadel_is_served_behind_scope_and_step_up() {
    let s = boot("on", &["--enable-module", "citadel"]).await;
    // A read route: a `read`-only device reads; the module's migrations ran before the mount.
    let (status, body) = s.call(&s.phone, "GET", COMPANIES, None).await;
    assert_eq!(status, 200, "{body}");
    // Scope: the same phone cannot write, the admin can (the real gate, not the handler).
    let new = json!({"name": "Acme"});
    let (status, body) = s.call(&s.phone, "POST", COMPANIES, Some(new.clone())).await;
    assert_eq!(
        (status, &body["code"]),
        (403, &json!("forbidden_scope")),
        "{body}"
    );
    let (status, body) = s.call(&s.admin, "POST", COMPANIES, Some(new)).await;
    assert_eq!(status, 200, "{body}");
    // Step-up: an unelevated admin is refused the destructive route before it looks at the id.
    let (status, body) = s.call(&s.admin, "DELETE", DEPARTMENT, None).await;
    assert_eq!(
        (status, &body["code"]),
        (403, &json!("step_up_required")),
        "{body}"
    );
    // Elevate through the real challenge, then the route is reached (no such department: 404).
    let (status, c) = s
        .call(
            &s.admin,
            "POST",
            "/api/v1/auth/step-up/challenge",
            Some(json!({})),
        )
        .await;
    assert_eq!(status, 200, "{c}");
    let proof = s.admin.stepup_body(c["challenge"].as_str().unwrap());
    let (status, body) = s
        .call(&s.admin, "POST", "/api/v1/auth/step-up", Some(proof))
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = s.call(&s.admin, "DELETE", DEPARTMENT, None).await;
    assert_eq!(
        (status, &body["code"]),
        (404, &json!("not_found")),
        "{body}"
    );
    // The phone is not elevated by the admin's elevation.
    let (status, _) = s.call(&s.phone, "DELETE", DEPARTMENT, None).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn a_plain_serve_mounts_nothing() {
    let s = boot("off", &[]).await;
    // Not mounted: the gate denies a route nothing declares (deny by default), so even a full
    // admin is refused before any handler (the same call is a 200 with `--enable-module citadel`).
    let (status, body) = s.call(&s.admin, "GET", COMPANIES, None).await;
    assert_eq!(
        (status, &body["code"]),
        (403, &json!("forbidden_scope")),
        "{body}"
    );
}

#[tokio::test]
async fn an_unknown_module_stops_the_start() {
    let out = tokio::process::Command::new(BIN)
        .args(["serve", "/nonexistent/core.db", "--enable-module", "nope"])
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--enable-module nope"));
}

#[tokio::test]
async fn an_unknown_module_in_the_config_stops_the_start() {
    let dir = std::env::temp_dir().join(format!("core-citadel-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "home = {:?}\nmodules = [\"nope\"]\n",
            dir.display().to_string()
        ),
    )
    .unwrap();
    let out = tokio::process::Command::new(BIN)
        .args(["serve", "--config", cfg.to_str().unwrap()])
        .output()
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--enable-module nope"));
}
