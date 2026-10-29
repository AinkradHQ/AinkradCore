//! Signatures, nonces, challenges, public keys, pairing codes, QR secrets and SAS strings never
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
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || w.clone())
        .init();

    let dir = std::env::temp_dir().join(format!("core-logs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = ainkrad_core_server::store::connect(&dir.join("core.db"))
        .await
        .unwrap();
    let identity = Arc::new(Identity::load_or_create(&dir).unwrap());
    let clock = Arc::new(SystemClock);
    let app = App::new(
        pool.clone(),
        clock.clone(),
        "core.test".to_owned(),
        identity.clone(),
    );
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
    for secret in planted {
        assert!(
            !log.contains(&secret),
            "{secret} leaked into the log:\n{log}"
        );
    }
    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}
