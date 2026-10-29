//! Pairing (handshake spec §7, §17 cases 16 to 21 and 32): two simulated devices pair end to
//! end by code and by QR; a code works once and for 5 minutes; the SAS must match; scopes only
//! narrow; wrong claims lock the address and, past the global budget, burn every live pairing;
//! a runner pairs the same way.

use super::signed::raw;
use super::*;
use crate::auth::crypto::{fingerprint, unb64};

async fn audited(fx: &Fx, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

/// `POST /api/v1/pairings` as `by`.
async fn create(fx: &Fx, by: &TestDevice, kind: &str, scopes: &[&str]) -> (StatusCode, Value) {
    let body = json!({"name": "New", "kind": kind, "scopes": scopes});
    send(
        &fx.app,
        req(Method::POST, "/api/v1/pairings", Some(by), Some(body)),
    )
    .await
}

/// A new device's key, not enrolled yet.
fn newcomer(fx: &Fx) -> TestDevice {
    TestDevice::new(&fx.app.auth.identity.fp, fx.clock.clone())
}

async fn claim(
    fx: &Fx,
    dev: &TestDevice,
    code: Option<&str>,
    secret: Option<&str>,
    peer: &str,
) -> (StatusCode, Value) {
    let body = dev.claim_body(code, secret);
    let r = from(peer, req(Method::POST, "/pair/claim", None, Some(body)));
    send(&fx.app, r).await
}

async fn status(fx: &Fx, dev: &TestDevice) -> (StatusCode, Value) {
    let h = dev.headers_session("POST", "/pair/status", b"", None);
    send(&fx.app, raw(Method::POST, "/pair/status", &h, b"")).await
}

async fn approve(fx: &Fx, id: &str, body: Value) -> (StatusCode, Value) {
    let uri = format!("/api/v1/pairings/{id}/approve");
    send(&fx.app, req(Method::POST, &uri, Some(&fx.dev), Some(body))).await
}

/// §17.16: create, claim by code, compare the SAS, approve; the device then takes a session.
#[tokio::test]
async fn two_devices_pair_end_to_end_by_code_and_by_qr() {
    let fx = fx().await;
    let (status_code, created) = create(&fx, &fx.dev, "device", &["read", "approve"]).await;
    assert_eq!(status_code, StatusCode::OK, "{created}");
    let code = created["code"].as_str().unwrap();
    assert_eq!((code.len(), &code[5..6]), (11, "-"));
    assert_eq!(created["expires_at"], "2026-10-22T10:05:00.000Z");
    let id = created["pairing_id"].as_str().unwrap();

    let mut phone = newcomer(&fx);
    let (s, got) = claim(&fx, &phone, Some(&code.to_lowercase()), None, "10.1.1.1").await;
    assert_eq!(s, StatusCode::ACCEPTED, "{got}");
    let core_spki = unb64(got["core_spki"].as_str().unwrap(), 122).unwrap();
    assert_eq!(
        fingerprint(&core_spki),
        fx.app.auth.identity.fp,
        "the Core it reached"
    );
    phone.id = got["device_id"].as_str().unwrap().to_owned();
    let phone_sas = got["sas"].as_str().unwrap().to_owned();

    // Pending: only /pair/status answers it.
    assert_eq!(status(&fx, &phone).await.1["status"], "pending");
    phone.set_session(Some(crate::auth::crypto::random_id("s_")));
    let (s, body) = send(&fx.app, req(Method::GET, "/api/v1/me", Some(&phone), None)).await;
    assert_eq!(
        (s, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("auth_failed"))
    );
    let challenge = json!({"device_id": phone.id});
    let (_, ch) = send(
        &fx.app,
        req(Method::POST, "/handshake/challenge", None, Some(challenge)),
    )
    .await;
    let body = json!({"challenge": ch["challenge"]}).to_string();
    let h = phone.headers_session("POST", "/handshake/session", body.as_bytes(), None);
    let (s, _) = send(
        &fx.app,
        raw(Method::POST, "/handshake/session", &h, body.as_bytes()),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "no session while pending");

    // The approver sees the claimant and the same SAS, and approves with it.
    let uri = format!("/api/v1/pairings/{id}");
    let seen = fx.ok(&uri).await;
    assert_eq!(seen["status"], "claimed");
    assert_eq!(seen["sas"], phone_sas.as_str(), "both screens show one SAS");
    assert_eq!(seen["fingerprint"], fingerprint(&phone.spki).as_str());
    assert_eq!(seen["key_storage"], "software");
    let (s, done) = approve(&fx, id, json!({"sas": phone_sas.to_lowercase()})).await;
    assert_eq!(s, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "approved");
    assert_eq!(status(&fx, &phone).await.1["status"], "active");
    let (_, ch) = send(
        &fx.app,
        req(
            Method::POST,
            "/handshake/challenge",
            None,
            Some(json!({"device_id": phone.id})),
        ),
    )
    .await;
    let body = json!({"challenge": ch["challenge"]}).to_string();
    let h = phone.headers_session("POST", "/handshake/session", body.as_bytes(), None);
    let (s, grant) = send(
        &fx.app,
        raw(Method::POST, "/handshake/session", &h, body.as_bytes()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{grant}");
    assert_eq!(grant["scopes"], json!(["approve", "read"]));
    phone.set_session(grant["session_id"].as_str().map(str::to_owned));
    let (s, me) = send(&fx.app, req(Method::GET, "/api/v1/me", Some(&phone), None)).await;
    assert_eq!((s, &me["device"]["name"]), (StatusCode::OK, &json!("New")));
    for (action, n) in [
        ("pairing.created", 1),
        ("pairing.claimed", 1),
        ("pairing.approved", 1),
    ] {
        assert_eq!(audited(&fx, action).await, n, "{action}");
    }

    // The QR path: the secret, and the Core fingerprint to check.
    let (_, created) = create(&fx, &fx.dev, "device", &["read"]).await;
    let qr = created["qr"].as_str().unwrap();
    assert!(
        qr.starts_with("ainkrad-pair:v1?h=core.test&p=443&c="),
        "{qr}"
    );
    let field = |k: &str| {
        qr.split(['?', '&'])
            .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
            .unwrap()
            .to_owned()
    };
    assert_eq!(field("c"), fx.app.auth.identity.fp);
    let pad = newcomer(&fx);
    let (s, got) = claim(&fx, &pad, None, Some(&field("s")), "10.1.1.2").await;
    assert_eq!(s, StatusCode::ACCEPTED, "{got}");
}

/// §17.17, §17.18: a code works once; a claim past 5 minutes fails; an approval past them
/// fails and the device never becomes usable.
#[tokio::test]
async fn a_code_works_once_and_for_five_minutes() {
    let fx = fx().await;
    let (_, created) = create(&fx, &fx.dev, "device", &["read"]).await;
    let code = created["code"].as_str().unwrap().to_owned();
    assert_eq!(
        claim(&fx, &newcomer(&fx), Some(&code), None, "10.2.0.1")
            .await
            .0,
        StatusCode::ACCEPTED
    );
    let (s, body) = claim(&fx, &newcomer(&fx), Some(&code), None, "10.2.0.2").await;
    assert_eq!(
        (s, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("pairing_failed"))
    );

    let (_, late) = create(&fx, &fx.dev, "device", &["read"]).await;
    fx.clock.advance(301);
    let (s, _) = claim(&fx, &newcomer(&fx), late["code"].as_str(), None, "10.2.0.3").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "claimed at 5 min + 1 s");

    fx.clock.set(NOW);
    let (_, slow) = create(&fx, &fx.dev, "device", &["read"]).await;
    let mut dev = newcomer(&fx);
    let (_, got) = claim(&fx, &dev, slow["code"].as_str(), None, "10.2.0.4").await;
    dev.id = got["device_id"].as_str().unwrap().to_owned();
    fx.clock.advance(301);
    let (s, body) = approve(
        &fx,
        slow["pairing_id"].as_str().unwrap(),
        json!({"sas": got["sas"]}),
    )
    .await;
    assert_eq!(
        (s, &body["code"]),
        (StatusCode::CONFLICT, &json!("pairing_expired"))
    );
    assert_eq!(
        status(&fx, &dev).await.1["status"],
        "expired",
        "never usable"
    );
    assert_eq!(audited(&fx, "pairing.expired").await, 1);
}

/// §17.19, §17.20: a wrong SAS is refused and leaves the device pending; scopes never widen,
/// at creation or at approval; only `admin` creates.
#[tokio::test]
async fn the_sas_must_match_and_scopes_only_narrow() {
    let fx = fx().await;
    let (_, created) = create(&fx, &fx.dev, "device", &["read", "approve"]).await;
    let id = created["pairing_id"].as_str().unwrap();
    let mut dev = newcomer(&fx);
    let (_, got) = claim(&fx, &dev, created["code"].as_str(), None, "10.3.0.1").await;
    dev.id = got["device_id"].as_str().unwrap().to_owned();
    let (s, body) = approve(&fx, id, json!({"sas": "AAAA-BBBB-CCCC-DDDD"})).await;
    assert_eq!(
        (s, &body["code"]),
        (StatusCode::CONFLICT, &json!("sas_mismatch"))
    );
    assert_eq!(status(&fx, &dev).await.1["status"], "pending");
    assert_eq!(audited(&fx, "pairing.refused").await, 1);
    let (s, body) = approve(&fx, id, json!({"sas": ""})).await;
    assert_eq!(
        (s, &body["code"]),
        (StatusCode::CONFLICT, &json!("sas_mismatch")),
        "empty SAS"
    );
    let (s, _) = approve(
        &fx,
        id,
        json!({"sas": got["sas"], "scopes": ["read", "admin"]}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "wider than bound");
    let (s, done) = approve(&fx, id, json!({"sas": got["sas"], "scopes": ["read"]})).await;
    assert_eq!(s, StatusCode::OK, "{done}");
    let row = crate::store::gov::get_device(&fx.app.pool, &dev.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.status.as_str(), row.scopes.clone()),
        ("active", vec!["read".to_owned()])
    );

    // A narrow approver cannot create wider than itself; a non-admin cannot create at all.
    let narrow = fx.enroll("narrow", &["read", "admin"]).await;
    assert_eq!(
        create(&fx, &narrow, "device", &["terminal"]).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        create(&fx, &narrow, "device", &["read"]).await.0,
        StatusCode::OK
    );
    let reader = fx.enroll("reader", &["read"]).await;
    assert_eq!(
        create(&fx, &reader, "device", &["read"]).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        create(&fx, &fx.dev, "passkey", &["read"]).await.0,
        StatusCode::BAD_REQUEST
    );
    // At most three live.
    assert_eq!(
        create(&fx, &fx.dev, "device", &["read"]).await.0,
        StatusCode::OK
    );
    assert_eq!(
        create(&fx, &fx.dev, "device", &["read"]).await.0,
        StatusCode::OK
    );
    assert_eq!(
        create(&fx, &fx.dev, "device", &["read"]).await.0,
        StatusCode::CONFLICT
    );
}

/// §17.21: 20 wrong claims from 20 addresses burn every live pairing (one audit row, and none
/// per claim); 20 from one address lock it.
#[tokio::test]
async fn wrong_claims_burn_live_pairings_and_lock_the_address() {
    let fx = fx().await;
    let (_, live) = create(&fx, &fx.dev, "device", &["read"]).await;
    for i in 0..20 {
        let (s, _) = claim(
            &fx,
            &newcomer(&fx),
            Some("ZZZZZ-ZZZZZ"),
            None,
            &format!("10.4.0.{i}"),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    let id = live["pairing_id"].as_str().unwrap();
    assert_eq!(
        fx.ok(&format!("/api/v1/pairings/{id}")).await["status"],
        "burned"
    );
    assert_eq!(audited(&fx, "pairing.burned").await, 1);
    assert_eq!(
        audited(&fx, "pairing.refused").await,
        0,
        "no row per wrong claim (M4)"
    );
    let (s, _) = claim(&fx, &newcomer(&fx), live["code"].as_str(), None, "10.4.1.1").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a burned code is dead");

    for _ in 0..20 {
        claim(&fx, &newcomer(&fx), Some("YYYYY-YYYYY"), None, "10.4.2.1").await;
    }
    let (s, _) = claim(&fx, &newcomer(&fx), Some("YYYYY-YYYYY"), None, "10.4.2.1").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "the address is locked");
}

/// E1-07.7: a runner pairs the same way, as kind `runner` with exactly the `runner` scope.
#[tokio::test]
async fn a_runner_pairs_like_any_device() {
    let fx = fx().await;
    assert_eq!(
        create(&fx, &fx.dev, "runner", &["read"]).await.0,
        StatusCode::BAD_REQUEST
    );
    let (_, created) = create(&fx, &fx.dev, "runner", &["runner"]).await;
    let mut runner = newcomer(&fx);
    let (_, got) = claim(&fx, &runner, created["code"].as_str(), None, "10.5.0.1").await;
    runner.id = got["device_id"].as_str().unwrap().to_owned();
    let (s, _) = approve(
        &fx,
        created["pairing_id"].as_str().unwrap(),
        json!({"sas": got["sas"]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let row = crate::store::gov::get_device(&fx.app.pool, &runner.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.kind.as_str(), row.scopes.clone()),
        ("runner", vec!["runner".to_owned()])
    );
    assert_eq!(status(&fx, &runner).await.1["status"], "active");
}

/// T-PAIR-7: the claim is one transaction. A claim that fails inside it (a key enrolled
/// already) leaves the pairing live, no device and no audit row; a bad proof spends nothing.
#[tokio::test]
async fn a_claim_is_all_or_nothing() {
    let fx = fx().await;
    let (_, created) = create(&fx, &fx.dev, "device", &["read"]).await;
    let code = created["code"].as_str().unwrap();
    let id = created["pairing_id"].as_str().unwrap();
    let (s, _) = claim(&fx, &fx.dev, Some(code), None, "10.6.0.1").await;
    assert_eq!(s, StatusCode::CONFLICT, "the fixture's key is enrolled");
    let mut bad = newcomer(&fx).claim_body(Some(code), None);
    bad["pop"] = json!(crate::auth::crypto::b64(&[0; 64]));
    let r = from(
        "10.6.0.2",
        req(Method::POST, "/pair/claim", None, Some(bad)),
    );
    assert_eq!(send(&fx.app, r).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        fx.ok(&format!("/api/v1/pairings/{id}")).await["status"],
        "live"
    );
    assert_eq!(audited(&fx, "pairing.claimed").await, 0);
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM core_devices")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(devices, 1, "only the fixture's");
    assert_eq!(
        claim(&fx, &newcomer(&fx), Some(code), None, "10.6.0.3")
            .await
            .0,
        StatusCode::ACCEPTED
    );
}

/// §17.24 (the network half), §17.25: a bootstrap pairing is refused over TCP and from a socket
/// peer of another user; only this user's socket peer may claim it.
#[tokio::test]
async fn a_bootstrap_pairing_is_claimable_only_from_the_hosts_socket() {
    use crate::gateway::Local;
    use crate::store::gov::{NewPairing, create_pairing};
    let fx = fx().await;
    let scopes = vec!["read".to_owned()];
    let p = NewPairing {
        kind: "device",
        name: "first",
        scopes: &scopes,
        created_by: None,
        bootstrap: true,
        recovery: false,
    };
    let refused = create_pairing(
        &fx.app.pool,
        &p,
        ainkrad_core::audit::AuditActor::System,
        fx.clock.unix(),
    )
    .await;
    assert!(refused.is_err(), "a device exists already");
    sqlx::query("DELETE FROM core_devices")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let created = create_pairing(
        &fx.app.pool,
        &p,
        ainkrad_core::audit::AuditActor::System,
        fx.clock.unix(),
    )
    .await
    .unwrap();
    let dev = newcomer(&fx);
    let body = dev.claim_body(Some(&created.code), None);
    let (s, _) = claim(&fx, &dev, Some(&created.code), None, "127.0.0.1").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "over TCP");
    for same_user in [false, true] {
        let mut r = req(Method::POST, "/pair/claim", None, Some(body.clone()));
        r.extensions_mut().insert(Local { same_user });
        let want = if same_user {
            StatusCode::ACCEPTED
        } else {
            StatusCode::UNAUTHORIZED
        };
        assert_eq!(send(&fx.app, r).await.0, want, "same user: {same_user}");
    }
}
