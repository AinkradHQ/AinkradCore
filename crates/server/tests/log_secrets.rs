//! Signatures, nonces, challenges (session and step-up), public keys (the step-up key too),
//! pairing codes, QR secrets and SAS strings never
//! reach the server log, whatever succeeds or fails. Its own test binary, so the global log subscriber sees every line.

use std::io::Write;
use std::sync::{Arc, Mutex};

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::crypto::b64;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use axum::body::{Body, to_bytes};
use axum::http::Request;
use tower::ServiceExt;

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn send(
    app: &App,
    method: &str,
    uri: &str,
    h: &[(&'static str, String)],
    body: &str,
) -> String {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "core.test")
        .header("content-type", "application/json");
    for (n, v) in h {
        b = b.header(*n, v);
    }
    let res = router(app.clone())
        .oneshot(b.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    String::from_utf8(to_bytes(res.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap()
}

#[tokio::test]
async fn no_signature_nonce_challenge_or_key_is_logged() {
    let buf = Buf::default();
    let w = buf.clone();
    // The server's own filter (`ops::logging::quiet`), everything else at TRACE.
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || w.clone())
        .finish()
        .with(ainkrad_core_server::ops::logging::quiet())
        .init();

    let dir = std::env::temp_dir().join(format!("core-logs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = ainkrad_core_server::store::connect(&dir.join("core.db"))
        .await
        .unwrap();
    let identity = Arc::new(Identity::load_or_create(&dir).unwrap());
    let clock = Arc::new(SystemClock);
    let mut app = App::new(
        pool.clone(),
        clock.clone(),
        "core.test".to_owned(),
        identity.clone(),
    );
    app.passkeys = Some(Arc::new(
        ainkrad_core_server::auth::web::Passkeys::new("core.test", false).unwrap(),
    ));
    let mac = TestDevice::enroll(
        &pool,
        "mac",
        "device",
        &ainkrad_core_server::store::gov::SCOPES,
        &identity.fp,
        clock.clone(),
    )
    .await;
    let stranger = TestDevice::new(&identity.fp, clock.clone());

    let mut planted = vec![b64(&mac.spki), b64(&stranger.spki)];
    // A challenge, a session from it, then good, replayed and stranger requests.
    let got = send(
        &app,
        "POST",
        "/handshake/challenge",
        &[],
        &format!(r#"{{"device_id":"{}"}}"#, mac.id),
    )
    .await;
    let challenge: serde_json::Value = serde_json::from_str(&got).unwrap();
    let challenge = challenge["challenge"].as_str().unwrap().to_owned();
    let body = format!(r#"{{"challenge":"{challenge}"}}"#);
    let h = mac.headers_session("POST", "/handshake/session", body.as_bytes(), None);
    planted.extend([challenge, h[3].1.clone(), h[4].1.clone()]);
    let session: serde_json::Value =
        serde_json::from_str(&send(&app, "POST", "/handshake/session", &h, &body).await).unwrap();
    mac.set_session(session["session_id"].as_str().map(str::to_owned));
    stranger.set_session(Some(ainkrad_core_server::auth::crypto::random_id("s_")));
    for dev in [&mac, &stranger] {
        let h = dev.headers("GET", "/api/v1/me", b"");
        planted.extend([h[3].1.clone(), h[4].1.clone()]);
        send(&app, "GET", "/api/v1/me", &h, "").await;
        send(&app, "GET", "/api/v1/me", &h, "").await;
    }
    // A skewed one.
    let session = mac.session.lock().unwrap().clone();
    let h = mac.headers_at(
        "GET",
        "/api/v1/me",
        b"",
        session.as_deref(),
        clock.unix() - 600,
        "AAAAAAAAAAAAAAAAAAAAAA",
    );
    planted.push(h[4].1.clone());
    send(&app, "GET", "/api/v1/me", &h, "").await;

    // A step-up: a failed proof, then a good one; neither the challenges, the step-up key nor
    // its signatures are logged.
    planted.push(b64(&mac.stepup_spki));
    for good in [false, true] {
        let h = mac.headers("POST", "/api/v1/auth/step-up/challenge", b"{}");
        let got = send(&app, "POST", "/api/v1/auth/step-up/challenge", &h, "{}").await;
        let got: serde_json::Value = serde_json::from_str(&got).unwrap();
        let c = got["challenge"].as_str().unwrap().to_owned();
        let mut body = mac.stepup_body(&c);
        if !good {
            body["stepup_sig"] = serde_json::json!(b64(&[7u8; 64]));
        }
        let sig = body["stepup_sig"].as_str().unwrap().to_owned();
        let body = body.to_string();
        let h = mac.headers("POST", "/api/v1/auth/step-up", body.as_bytes());
        send(&app, "POST", "/api/v1/auth/step-up", &h, &body).await;
        planted.extend([c, sig]);
    }

    // A pairing: its code and QR secret, a wrong claim, a right one and its SAS.
    let body = r#"{"name":"Phone","kind":"device","scopes":["read"]}"#;
    let h = mac.headers("POST", "/api/v1/pairings", body.as_bytes());
    let created: serde_json::Value =
        serde_json::from_str(&send(&app, "POST", "/api/v1/pairings", &h, body).await).unwrap();
    let code = created["code"].as_str().unwrap().to_owned();
    let qr = created["qr"].as_str().unwrap().to_owned();
    let secret = qr
        .split("&s=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_owned();
    let phone = TestDevice::new(&identity.fp, clock.clone());
    let wrong = phone.claim_body(Some("ZZZZZ-ZZZZZ"), None).to_string();
    send(&app, "POST", "/pair/claim", &[], &wrong).await;
    let right = phone.claim_body(Some(&code), None);
    let claimed: serde_json::Value =
        serde_json::from_str(&send(&app, "POST", "/pair/claim", &[], &right.to_string()).await)
            .unwrap();
    let sas = claimed["sas"].as_str().unwrap().to_owned();
    planted.extend([
        code.clone(),
        code.replace('-', ""),
        secret,
        sas,
        right["pop"].as_str().unwrap().to_owned(),
    ]);

    // A passkey (E1-08): its registration options and credential, a sign-in's options, session
    // key and assertion (a wrong one too), a step-up assertion, and a WebSocket ticket.
    planted.extend(passkey_flow(&app, &mac, &identity.fp, clock.clone()).await);

    let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        log.contains("pairing claimed") && log.contains("pairing claim refused"),
        "{log}"
    );
    assert!(
        log.contains("signed request refused"),
        "the log was captured: {log}"
    );
    assert!(log.contains("session issued"), "{log}");
    assert!(log.contains("web session issued"), "{log}");
    assert!(
        log.contains("step-up refused") && log.contains("session elevated"),
        "{log}"
    );
    for secret in planted {
        assert!(
            !log.contains(&secret),
            "{secret} leaked into the log:\n{log}"
        );
    }
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

/// Every value of `v` that is a string of 16 characters or more: the base64url fields of a
/// WebAuthn exchange.
fn strings(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) if s.len() >= 16 => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|v| strings(v, out)),
        serde_json::Value::Object(o) => o.values().for_each(|v| strings(v, out)),
        _ => {}
    }
}

/// A passkey paired, signed in (once wrongly), stepped up, and given a ticket: what was sent.
async fn passkey_flow(
    app: &App,
    mac: &TestDevice,
    core_fp: &str,
    clock: Arc<SystemClock>,
) -> Vec<String> {
    use ainkrad_core_server::auth::testing::authenticator::SoftAuthenticator;
    let mut sent = Vec::new();
    let body = r#"{"name":"Safari","kind":"passkey","scopes":["read"]}"#;
    let h = mac.headers("POST", "/api/v1/pairings", body.as_bytes());
    let p = json(&send(app, "POST", "/api/v1/pairings", &h, body).await);
    let code = p["code"].as_str().unwrap().to_owned();
    let pid = p["pairing_id"].as_str().unwrap().to_owned();
    let body = format!(r#"{{"code":"{code}"}}"#);
    let o = json(&send(app, "POST", "/pair/passkey/options", &[], &body).await);
    let mut a = SoftAuthenticator::new("core.test", "https://core.test");
    let cred = a.register(&o["options"]);
    strings(&o, &mut sent);
    strings(&cred, &mut sent);
    let body = serde_json::json!({"code": code, "credential": cred}).to_string();
    let c = json(&send(app, "POST", "/pair/passkey/claim", &[], &body).await);
    let device = c["device_id"].as_str().unwrap().to_owned();
    let body = serde_json::json!({"sas": c["sas"]}).to_string();
    let uri = format!("/api/v1/pairings/{pid}/approve");
    let h = mac.headers("POST", &uri, body.as_bytes());
    send(app, "POST", &uri, &h, &body).await;

    let key = TestDevice::new(core_fp, clock.clone());
    let web = TestDevice::from_pkcs8(&device, &key.pkcs8, core_fp, clock);
    sent.push(b64(&web.spki));
    for good in [false, true] {
        let body = serde_json::json!({"session_spki": b64(&web.spki)}).to_string();
        let o = json(&send(app, "POST", "/handshake/passkey/options", &[], &body).await);
        a.flags = if good { 0x05 } else { 0x01 };
        let assertion = a.assert(&o["options"]);
        strings(&o, &mut sent);
        strings(&assertion, &mut sent);
        let body = serde_json::json!({"credential": assertion}).to_string();
        let g = json(&send(app, "POST", "/handshake/passkey/session", &[], &body).await);
        if good {
            web.set_session(g["session_id"].as_str().map(str::to_owned));
        }
    }
    let h = web.headers("POST", "/api/v1/auth/step-up/challenge", b"");
    let c = json(&send(app, "POST", "/api/v1/auth/step-up/challenge", &h, "").await);
    let assertion = a.assert(&c["options"]);
    strings(&c, &mut sent);
    strings(&assertion, &mut sent);
    let body = serde_json::json!({"challenge": c["challenge"], "assertion": assertion}).to_string();
    let h = web.headers("POST", "/api/v1/auth/step-up", body.as_bytes());
    let e = json(&send(app, "POST", "/api/v1/auth/step-up", &h, &body).await);
    assert!(e["elevated_until"].is_string(), "{e}");
    let h = web.headers("POST", "/api/v1/ws-ticket", b"");
    let t = json(&send(app, "POST", "/api/v1/ws-ticket", &h, "").await);
    sent.push(t["ticket"].as_str().unwrap().to_owned());
    // The user handle and the RP's own name are not secrets.
    sent.retain(|s| s != "Ainkrad Core" && s != "core.test" && s != "https://core.test");
    sent
}
