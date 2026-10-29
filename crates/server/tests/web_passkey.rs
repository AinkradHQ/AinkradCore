//! E1-08.4: a real browser with a virtual authenticator against the real Core, end to end. Not
//! part of `make test` (a browser is heavy): `make test-web` runs it. Chromium comes from
//! `CHROME`, else Playwright's cached `chrome-headless-shell`; it is driven over the Chrome
//! DevTools Protocol directly (`WebAuthn.addVirtualAuthenticator`, `Runtime.evaluate`).
//!
//! The browser registers a passkey through the real pairing flow (an elevated admin device
//! creates the pairing and approves the SAS), signs in with a non-extractable WebCrypto session
//! key, makes a signed request, steps up with a user-verified assertion, opens the event socket
//! with a one-time ticket, and is revoked: the socket closes with 4001 and the session is dead.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::auth::web::Passkeys;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use axum::body::{Body, to_bytes};
use axum::http::Request;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::AsyncBufReadExt;
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A CDP connection to the browser, with one page session attached (flat mode).
struct Cdp {
    ws: Socket,
    next: u64,
    session: Option<String>,
}

impl Cdp {
    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = &self.session {
            msg["sessionId"] = json!(s);
        }
        self.ws.send(Message::text(msg.to_string())).await.unwrap();
        loop {
            let m = self.ws.next().await.expect("the browser answers").unwrap();
            let Message::Text(t) = m else { continue };
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["id"] == json!(id) {
                assert!(v.get("error").is_none(), "{method}: {v}");
                return v["result"].clone();
            }
        }
    }

    /// Evaluates `expr` in the page and awaits it: its JSON value.
    async fn eval(&mut self, expr: &str) -> Value {
        let r = self
            .call(
                "Runtime.evaluate",
                json!({"expression": expr, "awaitPromise": true, "returnByValue": true}),
            )
            .await;
        assert!(r.get("exceptionDetails").is_none(), "{expr}: {r}");
        r["result"]["value"].clone()
    }
}

/// `CHROME`, else Playwright's cached headless shell.
fn chrome() -> String {
    if let Ok(c) = std::env::var("CHROME") {
        return c;
    }
    let cache = std::path::PathBuf::from(std::env::var("HOME").unwrap())
        .join("Library/Caches/ms-playwright");
    let mut found: Vec<_> = std::fs::read_dir(&cache)
        .expect("Playwright's browser cache (or set CHROME)")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("chromium_headless_shell-"))
        })
        .collect();
    found.sort();
    let dir = found
        .pop()
        .expect("a chromium_headless_shell in the cache (or set CHROME)");
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    let bin = dir.join(format!(
        "chrome-headless-shell-mac-{arch}/chrome-headless-shell"
    ));
    bin.to_string_lossy().into_owned()
}

/// An admin-side signed request, in process.
async fn admin(app: &App, dev: &TestDevice, method: &str, uri: &str, body: Value) -> Value {
    let bytes = if body.is_null() {
        String::new()
    } else {
        body.to_string()
    };
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", &app.host)
        .header("content-type", "application/json");
    for (n, v) in dev.headers(method, uri, bytes.as_bytes()) {
        b = b.header(n, v);
    }
    let res = router(app.clone())
        .oneshot(b.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let v: Value = serde_json::from_slice(&to_bytes(res.into_body(), 1 << 20).await.unwrap())
        .unwrap_or(Value::Null);
    assert!(status.is_success(), "{method} {uri}: {status} {v}");
    v
}

#[tokio::test]
#[ignore = "drives a real browser: `make test-web`"]
async fn a_browser_pairs_signs_in_steps_up_streams_and_is_revoked() {
    tokio::time::timeout(Duration::from_secs(120), run())
        .await
        .expect("the browser test finished within 2 minutes");
}

async fn run() {
    let dir = std::env::temp_dir().join(format!("core-web-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = ainkrad_core_server::store::connect(&dir.join("core.db"))
        .await
        .unwrap();
    let identity = Arc::new(Identity::load_or_create(&dir).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = format!("localhost:{}", listener.local_addr().unwrap().port());
    let clock = Arc::new(SystemClock);
    let mut app = App::new(pool.clone(), clock.clone(), host.clone(), identity.clone());
    app.passkeys = Some(Arc::new(Passkeys::new(&host, true).unwrap()));
    let service = router(app.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await });

    // The admin's Mac, with a session and a real step-up.
    let mac = TestDevice::enroll(
        &pool,
        "mac",
        "device",
        &ainkrad_core_server::store::gov::SCOPES,
        &identity.fp,
        clock.clone(),
    )
    .await;
    let s = app.auth.issue_session(&mac.id, clock.unix());
    mac.set_session(Some(s.id));
    let c = admin(
        &app,
        &mac,
        "POST",
        "/api/v1/auth/step-up/challenge",
        Value::Null,
    )
    .await;
    let body = mac.stepup_body(c["challenge"].as_str().unwrap());
    admin(&app, &mac, "POST", "/api/v1/auth/step-up", body).await;

    // The browser.
    let profile = dir.join("profile");
    let mut child = tokio::process::Command::new(chrome())
        .args([
            "--headless",
            "--remote-debugging-port=0",
            "--no-first-run",
            "--no-default-browser-check",
            &format!("--user-data-dir={}", profile.display()),
            "about:blank",
        ])
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("chromium starts");
    let mut lines = tokio::io::BufReader::new(child.stderr.take().unwrap()).lines();
    let url = loop {
        let line = lines
            .next_line()
            .await
            .unwrap()
            .expect("chromium prints its DevTools URL");
        if let Some(u) = line.strip_prefix("DevTools listening on ") {
            break u.trim().to_owned();
        }
    };
    let (ws, _) = tokio_tungstenite::connect_async(url.as_str())
        .await
        .unwrap();
    let mut cdp = Cdp {
        ws,
        next: 0,
        session: None,
    };
    let page = format!("http://{host}/healthz");
    let t = cdp.call("Target.createTarget", json!({"url": page})).await;
    let a = cdp
        .call(
            "Target.attachToTarget",
            json!({"targetId": t["targetId"], "flatten": true}),
        )
        .await;
    cdp.session = a["sessionId"].as_str().map(str::to_owned);
    tokio::time::sleep(Duration::from_millis(500)).await;
    cdp.call("WebAuthn.enable", json!({})).await;
    cdp.call(
        "WebAuthn.addVirtualAuthenticator",
        json!({"options": {"protocol": "ctap2", "transport": "internal", "hasResidentKey": true,
            "hasUserVerification": true, "isUserVerified": true,
            "automaticPresenceSimulation": true}}),
    )
    .await;
    cdp.eval(include_str!("web_passkey.js")).await;

    // Pairing: created and approved by the elevated Mac, never by the browser.
    let body = json!({"name": "Chromium", "kind": "passkey", "scopes": ["read", "admin"]});
    let p = admin(&app, &mac, "POST", "/api/v1/pairings", body).await;
    let claim = cdp.eval(&format!("ak.pair({})", p["code"])).await;
    assert_eq!(claim["status"], 202, "{claim}");
    let pid = p["pairing_id"].as_str().unwrap();
    let view = admin(
        &app,
        &mac,
        "GET",
        &format!("/api/v1/pairings/{pid}"),
        Value::Null,
    )
    .await;
    assert_eq!(
        view["sas"], claim["body"]["sas"],
        "both screens show the same SAS"
    );
    let uri = format!("/api/v1/pairings/{pid}/approve");
    admin(&app, &mac, "POST", &uri, json!({"sas": view["sas"]})).await;

    // Sign-in, a signed request, a step-up, the ticketed socket.
    let g = cdp.eval("ak.signIn()").await;
    assert_eq!(g["status"], 200, "{g}");
    assert_eq!(
        g["extractable"], false,
        "the session key never leaves WebCrypto"
    );
    let me = cdp.eval(r#"ak.signed("GET", "/api/v1/me")"#).await;
    assert_eq!(me["status"], 200, "{me}");
    let device = g["body"]["device_id"].as_str().unwrap().to_owned();
    assert_eq!(me["body"]["device"]["id"], json!(device));
    let rename =
        format!(r#"ak.signed("PATCH", "/api/v1/devices/{device}", {{"name": "Chromium web"}})"#);
    let before = cdp.eval(&rename).await;
    assert_eq!(before["body"]["code"], "step_up_required", "{before}");
    let up = cdp.eval("ak.stepUp()").await;
    assert_eq!(up["status"], 200, "{up}");
    let after = cdp.eval(&rename).await;
    assert_eq!(after["status"], 200, "{after}");
    let sock = cdp.eval("ak.socket()").await;
    assert_eq!(sock["protocol"], "ainkrad.v1", "{sock}");

    // Revoked from the Mac: the socket closes with 4001 within 5 s, the session is dead.
    admin(
        &app,
        &mac,
        "DELETE",
        &format!("/api/v1/devices/{device}"),
        Value::Null,
    )
    .await;
    let code = cdp
        .eval("Promise.race([ak.closed(), new Promise(r => setTimeout(() => r(0), 5000))])")
        .await;
    assert_eq!(code, 4001, "closed as revoked within 5 s");
    let me = cdp.eval(r#"ak.signed("GET", "/api/v1/me")"#).await;
    assert_eq!(me["status"], 401, "{me}");
    assert_eq!(me["body"]["code"], "auth_failed");

    let _ = child.kill().await;
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}
