//! Signatures, nonces, challenges (session and step-up), public keys (the step-up key too),
//! pairing codes, QR secrets, SAS strings, and the secrets broker's values and leases never
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
    let identity = Arc::new(
        Identity::load_or_create(
            &dir,
            &ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32]),
        )
        .unwrap(),
    );
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
    // A legacy plaintext identity key is sealed on load: the log says so and carries no key bytes.
    {
        let legacy = dir.join("legacy-home");
        std::fs::create_dir_all(&legacy).unwrap();
        let der = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        let file = legacy.join("core-identity.p8");
        std::fs::write(&file, der.as_ref()).unwrap();
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        Identity::load_or_create(
            &legacy,
            &ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32]),
        )
        .unwrap();
        let hex: String = der.as_ref().iter().map(|x| format!("{x:02x}")).collect();
        planted.extend([hex, b64(der.as_ref())]);
    }
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

    // The secrets broker (E2-07): a value stored, a malformed body around another, a rotation,
    // a lease and its redemption (then a spent one), and a real-shaped value refused.
    planted.extend(secrets_flow(&mut app, &mac, clock.clone()).await);

    // Master-key rotation (E2-07.1): the old and the new key, loaded and rotated, in every
    // encoding the code could print, and the audit row it wrote.
    planted.extend(rotation_flow(&dir, &pool, &mac, &clock).await);

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
    // Finding 4: the stranger's `auth_failed` names the peer and the device it claimed.
    assert!(
        log.lines().any(|l| l.contains("api refusal")
            && l.contains("auth_failed")
            && l.contains("peer")
            && l.contains("\"local\"")
            && l.contains(&stranger.id)),
        "an unattributed auth_failed: {log}"
    );
    assert!(log.contains("web session issued"), "{log}");
    assert!(log.contains("secrets broker: master key loaded"), "{log}");
    assert!(
        log.contains("key file sealed under the master key"),
        "{log}"
    );
    // The broker's refusals ran, so their lines are scanned too.
    assert!(
        log.contains("real_secret_refused") && log.contains("lease_expired"),
        "{log}"
    );
    // The passkey failure paths ran, so the scan below covers their lines too.
    assert!(log.contains("passkey registration refused"), "{log}");
    assert!(log.contains("assertion refused"), "{log}");
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

/// Stores, rotates, leases and redeems secrets; returns the values and the lease ids sent.
async fn secrets_flow(app: &mut App, mac: &TestDevice, clock: Arc<SystemClock>) -> Vec<String> {
    use ainkrad_core::settings::{Key, Scope};
    let pool = app.pool.clone();
    app.secrets = Some(Arc::new(
        ainkrad_core_server::ops::secretbox::SecretBox::new(&[9; 32]),
    ));
    let by = ainkrad_core_server::api::v1::BY;
    let now = clock.now();
    ainkrad_core_server::store::settings::set(
        &pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        by,
        &now,
    )
    .await
    .unwrap();
    let runner = TestDevice::enroll(
        &pool,
        "vm",
        "runner",
        &["runner"],
        &app.auth.identity.fp,
        clock.clone(),
    )
    .await;
    let s = app.auth.issue_session(&runner.id, clock.unix());
    runner.set_session(Some(s.id));
    let (v1, v2, v3) = (
        "log-planted-one-5d1e",
        "log-planted-two-a4c2",
        "log-planted-bad-93f0",
    );
    let real = ainkrad_proto::redact::PLANTED[0].1.to_owned();
    let call = |dev: &TestDevice, m: &str, uri: &str, body: serde_json::Value| {
        let body = body.to_string();
        let h = dev.headers(m, uri, body.as_bytes());
        (m.to_owned(), uri.to_owned(), h, body)
    };
    let mut sent = vec![v1.to_owned(), v2.to_owned(), v3.to_owned(), real.clone()];
    for (m, uri, h, body) in [
        call(
            mac,
            "POST",
            "/api/v1/secrets",
            serde_json::json!({"name": "git.token", "value": v1, "runners": [runner.id]}),
        ),
        call(
            mac,
            "POST",
            "/api/v1/secrets",
            serde_json::json!({"name": 7, "value": v3}),
        ),
        call(
            mac,
            "POST",
            "/api/v1/secrets",
            serde_json::json!({"name": "real", "value": real}),
        ),
        call(
            mac,
            "PUT",
            "/api/v1/secrets/git.token",
            serde_json::json!({"value": v2}),
        ),
    ] {
        send(app, &m, &uri, &h, &body).await;
    }
    let (_, uri, h, body) = call(
        mac,
        "POST",
        "/api/v1/secrets/git.token/leases",
        serde_json::json!({"runner": runner.id}),
    );
    let lease = json(&send(app, "POST", &uri, &h, &body).await)["lease"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut answers = Vec::new();
    for _ in 0..2 {
        let (_, uri, h, body) = call(
            &runner,
            "POST",
            "/api/v1/secret-leases/redeem",
            serde_json::json!({"lease": lease}),
        );
        answers.push(json(&send(app, "POST", &uri, &h, &body).await));
    }
    assert_eq!(answers[0]["value"], v2, "{answers:?}");
    assert_eq!(answers[1]["code"], "lease_expired", "{answers:?}");
    sent.push(lease);
    sent
}

/// Loads a master key, seals a secret, rotates the key and loads the new one; returns the
/// key bytes (hex and base64url) and the value. Also asserts the audit row holds none of them.
async fn rotation_flow(
    dir: &std::path::Path,
    pool: &sqlx::SqlitePool,
    mac: &TestDevice,
    clock: &SystemClock,
) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;

    use ainkrad_core::audit::AuditActor;
    use ainkrad_core_server::ops::master_rotate::{Stop, rotate};
    use ainkrad_core_server::ops::secretbox::SecretBox;
    use ainkrad_core_server::store::secrets::{self, NewValue};
    const VALUE: &str = "log-planted-rot-c81d";
    // The broker flow above sealed under its own test key: start this one clean.
    sqlx::query("DELETE FROM core_secrets")
        .execute(pool)
        .await
        .unwrap();
    let keys = dir.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let master = keys.join("master.key");
    // The key the Core identity in `dir` is sealed under: the rotation re-seals it too.
    let old = [7u8; 32];
    std::fs::write(&master, old).unwrap();
    std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
    let sealer = SecretBox::for_serve(&master).expect("a 0600 key");
    let new = NewValue {
        value: VALUE,
        runners: None,
        delivery: None,
    };
    secrets::create(
        pool,
        &sealer,
        "rot.token",
        &new,
        &mac.id,
        AuditActor::System,
        &clock.now(),
    )
    .await
    .unwrap();
    let report = rotate(&dir.join("core.db"), &keys, Stop::Never)
        .await
        .unwrap();
    assert_eq!(report.moved, 1);
    SecretBox::for_serve(&master).expect("the new key loads");
    let fresh = std::fs::read(&master).unwrap();
    assert_ne!(fresh, old);
    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'secret.master_rotated'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let mut planted = vec![VALUE.to_owned()];
    for key in [old.to_vec(), fresh] {
        planted.extend([hex(&key), b64(&key)]);
    }
    for p in &planted {
        assert!(
            !details.contains(p),
            "{p} in the rotation audit row: {details}"
        );
    }
    planted
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

/// A passkey paired (once wrongly), signed in (once wrongly), stepped up (once wrongly), and
/// given a ticket: what was sent.
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
    let mut a = SoftAuthenticator::new("core.test", "https://core.test");
    // A registration that does not verify (another origin) first: its failure line logs nothing sent.
    let o = json(&send(app, "POST", "/pair/passkey/options", &[], &body).await);
    a.origin = "https://evil.test".into();
    let bad = a.register(&o["options"]);
    a.origin = "https://core.test".into();
    strings(&o, &mut sent);
    strings(&bad, &mut sent);
    let claim = serde_json::json!({"code": code, "credential": bad}).to_string();
    send(app, "POST", "/pair/passkey/claim", &[], &claim).await;
    let o = json(&send(app, "POST", "/pair/passkey/options", &[], &body).await);
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
    // A step-up without user verification, then a good one.
    let mut e = serde_json::Value::Null;
    for good in [false, true] {
        let h = web.headers("POST", "/api/v1/auth/step-up/challenge", b"");
        let c = json(&send(app, "POST", "/api/v1/auth/step-up/challenge", &h, "").await);
        a.flags = if good { 0x05 } else { 0x01 };
        let assertion = a.assert(&c["options"]);
        strings(&c, &mut sent);
        strings(&assertion, &mut sent);
        let body =
            serde_json::json!({"challenge": c["challenge"], "assertion": assertion}).to_string();
        let h = web.headers("POST", "/api/v1/auth/step-up", body.as_bytes());
        e = json(&send(app, "POST", "/api/v1/auth/step-up", &h, &body).await);
    }
    assert!(e["elevated_until"].is_string(), "{e}");
    let h = web.headers("POST", "/api/v1/ws-ticket", b"");
    let t = json(&send(app, "POST", "/api/v1/ws-ticket", &h, "").await);
    sent.push(t["ticket"].as_str().unwrap().to_owned());
    // The user handle and the RP's own name are not secrets.
    sent.retain(|s| s != "Ainkrad Core" && s != "core.test" && s != "https://core.test");
    sent
}
