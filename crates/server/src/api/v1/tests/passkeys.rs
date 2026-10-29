//! Passkeys (handshake spec §9, §17.30; E1-08.1/.2/.3) through the real routes with the software
//! authenticator: paired by an elevated admin device and never self-enrolled, signed in to a web
//! session signed with the browser's session key, stepped up by an assertion, revoked like any
//! device.

use std::sync::Arc;

use super::*;
use crate::auth::crypto::b64;
use crate::auth::testing::authenticator::SoftAuthenticator;
use crate::auth::web::Passkeys;
use crate::store::gov;

pub(super) const ORIGIN: &str = "https://core.test";

/// `fx` with passkeys on for `core.test`.
pub(super) async fn fx_pk() -> Fx {
    let mut fx = fx().await;
    fx.app.passkeys = Some(Arc::new(Passkeys::new(HOST, false).unwrap()));
    fx
}

/// Sets `auth.passkey_admin` (T-PK-3): 1 lets a passkey hold `admin`.
pub(super) async fn passkey_admin(fx: &Fx, on: bool) {
    crate::store::settings::set(
        &fx.app.pool,
        ainkrad_core::settings::Key::AuthPasskeyAdmin,
        ainkrad_core::settings::Scope::Server,
        if on { "1" } else { "0" },
        ainkrad_core::audit::AuditActor::System,
        &fx.app.clock.now(),
    )
    .await
    .unwrap();
}

/// An unsigned POST to a pre-auth route.
pub(super) async fn pre(fx: &Fx, path: &str, body: Value) -> (StatusCode, Value) {
    send(&fx.app, req(Method::POST, path, None, Some(body))).await
}

/// `by` creates a passkey pairing with `scopes`: its body (`code`, `pairing_id`, …).
pub(super) async fn pairing(fx: &Fx, by: &TestDevice, scopes: &[&str]) -> (StatusCode, Value) {
    let body = json!({"name": "Safari", "kind": "passkey", "scopes": scopes});
    send(
        &fx.app,
        req(Method::POST, "/api/v1/pairings", Some(by), Some(body)),
    )
    .await
}

/// A passkey paired end to end by `fx.dev`: the authenticator and the device id.
pub(super) async fn pair_passkey(fx: &Fx, scopes: &[&str]) -> (SoftAuthenticator, String) {
    let (status, p) = pairing(fx, &fx.dev, scopes).await;
    assert_eq!(status, StatusCode::OK, "{p}");
    let code = p["code"].as_str().unwrap();
    let (status, o) = pre(fx, "/pair/passkey/options", json!({"code": code})).await;
    assert_eq!(status, StatusCode::OK, "{o}");
    let mut a = SoftAuthenticator::new(HOST, ORIGIN);
    let body = json!({"code": code, "credential": a.register(&o["options"]), "platform": "web"});
    let (status, c) = pre(fx, "/pair/passkey/claim", body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{c}");
    let pid = p["pairing_id"].as_str().unwrap();
    let ours = crate::auth::pairing::sas(&fx.app.auth.identity.spki, &a.spki(), pid);
    assert_eq!(
        c["sas"],
        json!(ours),
        "the SAS is over the credential's own key"
    );
    let uri = format!("/api/v1/pairings/{pid}/approve");
    let body = json!({"sas": c["sas"]});
    let (status, v) = send(&fx.app, req(Method::POST, &uri, Some(&fx.dev), Some(body))).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    (a, c["device_id"].as_str().unwrap().to_owned())
}

/// A browser: a fresh P-256 session key, signing as the passkey device `device`.
pub(super) fn browser(fx: &Fx, device: &str) -> TestDevice {
    let k = TestDevice::new(&fx.app.auth.identity.fp, fx.clock.clone());
    TestDevice::from_pkcs8(device, &k.pkcs8, &fx.app.auth.identity.fp, fx.clock.clone())
}

/// Signs `web` in with `a`: the grant, or the refusal.
pub(super) async fn sign_in(
    fx: &Fx,
    a: &mut SoftAuthenticator,
    web: &TestDevice,
) -> (StatusCode, Value) {
    let (status, o) = pre(
        fx,
        "/handshake/passkey/options",
        json!({"session_spki": b64(&web.spki)}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{o}");
    let cred = a.assert(&o["options"]);
    let (status, g) = pre(
        fx,
        "/handshake/passkey/session",
        json!({"credential": cred}),
    )
    .await;
    if status == StatusCode::OK {
        web.set_session(g["session_id"].as_str().map(str::to_owned));
    }
    (status, g)
}

/// A step-up challenge for `web`'s session: its challenge and options.
pub(super) async fn stepup_options(fx: &Fx, web: &TestDevice) -> Value {
    let uri = "/api/v1/auth/step-up/challenge";
    let (status, c) = send(&fx.app, req(Method::POST, uri, Some(web), None)).await;
    assert_eq!(status, StatusCode::OK, "{c}");
    c
}

pub(super) async fn step_up(fx: &Fx, web: &TestDevice, body: Value) -> (StatusCode, Value) {
    send(
        &fx.app,
        req(Method::POST, "/api/v1/auth/step-up", Some(web), Some(body)),
    )
    .await
}

pub(super) fn code_of(v: &Value) -> &str {
    v["code"].as_str().unwrap_or_default()
}

#[tokio::test]
async fn a_passkey_pairs_signs_in_steps_up_and_is_revoked_like_any_device() {
    let fx = fx_pk().await;
    passkey_admin(&fx, true).await;
    let (mut a, id) = pair_passkey(&fx, &["read", "admin"]).await;
    let row = gov::get_device(&fx.app.pool, &id).await.unwrap().unwrap();
    assert_eq!(
        (row.kind.as_str(), row.status.as_str()),
        ("passkey", "active")
    );
    assert_eq!(row.routine_spki, a.spki());

    let web = browser(&fx, &id);
    let (status, g) = sign_in(&fx, &mut a, &web).await;
    assert_eq!(status, StatusCode::OK, "{g}");
    assert_eq!(g["scopes"], json!(["admin", "read"]));
    let secs = 8 * 3600;
    let expires = crate::scheduler::iso_of_unix(fx.clock.unix() + secs);
    assert_eq!(g["expires_at"], json!(expires), "8 h by default, absolute");
    let (status, me) = send(&fx.app, req(Method::GET, "/api/v1/me", Some(&web), None)).await;
    assert_eq!(status, StatusCode::OK, "{me}");

    // A destructive route needs a step-up, and the passkey's assertion is one.
    let rename = format!("/api/v1/devices/{id}");
    let body = || Some(json!({"name": "Safari on the Mac"}));
    let (status, v) = send(&fx.app, req(Method::PATCH, &rename, Some(&web), body())).await;
    assert_eq!(
        (status, code_of(&v)),
        (StatusCode::FORBIDDEN, "step_up_required")
    );
    let c = stepup_options(&fx, &web).await;
    assert_eq!(c["options"]["publicKey"]["userVerification"], "required");
    let assertion = a.assert(&c["options"]);
    let (status, v) = step_up(
        &fx,
        &web,
        json!({"challenge": c["challenge"], "assertion": assertion}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["elevated_until"].is_string());
    let (status, v) = send(&fx.app, req(Method::PATCH, &rename, Some(&web), body())).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let granted: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'auth.step_up' \
         AND json_extract(details, '$.device') = ?",
    )
    .bind(&id)
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(granted, 1, "the grant is audited once");

    // Revoked like any device: its session and any new sign-in are refused.
    let (status, v) = send(&fx.app, req(Method::DELETE, &rename, Some(&fx.dev), None)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, v) = send(&fx.app, req(Method::GET, "/api/v1/me", Some(&web), None)).await;
    assert_eq!(
        (status, code_of(&v)),
        (StatusCode::UNAUTHORIZED, "auth_failed")
    );
    let (status, v) = sign_in(&fx, &mut a, &browser(&fx, &id)).await;
    assert_eq!(
        (status, code_of(&v)),
        (StatusCode::UNAUTHORIZED, "auth_failed")
    );
}

#[tokio::test]
async fn a_passkey_gets_admin_only_when_the_setting_allows_it() {
    let fx = fx_pk().await;
    let refused = |(s, v): (StatusCode, Value)| {
        assert_eq!(
            (s, code_of(&v)),
            (StatusCode::FORBIDDEN, "forbidden_scope"),
            "{v}"
        );
    };
    // Off by default: no admin passkey pairing; a native device still gets one.
    refused(pairing(&fx, &fx.dev, &["read", "admin"]).await);
    let body = json!({"name": "Mac", "kind": "device", "scopes": ["read", "admin"]});
    let (s, v) = send(
        &fx.app,
        req(Method::POST, "/api/v1/pairings", Some(&fx.dev), Some(body)),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // Allowed at creation, then turned off before the approval: refused there too, but a
    // narrower approval without admin goes through.
    passkey_admin(&fx, true).await;
    let (s, p) = pairing(&fx, &fx.dev, &["read", "admin"]).await;
    assert_eq!(s, StatusCode::OK, "{p}");
    let code = p["code"].as_str().unwrap();
    let (_, o) = pre(&fx, "/pair/passkey/options", json!({"code": code})).await;
    let mut a = SoftAuthenticator::new(HOST, ORIGIN);
    let body = json!({"code": code, "credential": a.register(&o["options"])});
    let (s, c) = pre(&fx, "/pair/passkey/claim", body).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{c}");
    passkey_admin(&fx, false).await;
    let uri = format!(
        "/api/v1/pairings/{}/approve",
        p["pairing_id"].as_str().unwrap()
    );
    let approve = |scopes: Value| {
        let body = json!({"sas": c["sas"], "scopes": scopes});
        send(&fx.app, req(Method::POST, &uri, Some(&fx.dev), Some(body)))
    };
    refused(approve(Value::Null).await);
    let (s, v) = approve(json!(["read"])).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let reader = c["device_id"].as_str().unwrap().to_owned();
    // Nor is admin added to it later.
    let uri = format!("/api/v1/devices/{reader}/scopes");
    let body = json!({"scopes": ["read", "admin"]});
    refused(send(&fx.app, req(Method::PUT, &uri, Some(&fx.dev), Some(body))).await);

    // With the setting on it pairs with admin; turned off again, that device keeps admin.
    passkey_admin(&fx, true).await;
    let (mut a, id) = pair_passkey(&fx, &["read", "admin"]).await;
    passkey_admin(&fx, false).await;
    let (s, g) = sign_in(&fx, &mut a, &browser(&fx, &id)).await;
    assert_eq!(s, StatusCode::OK, "{g}");
    assert!(
        g["scopes"].as_array().unwrap().contains(&json!("admin")),
        "{g}"
    );
    let uri = format!("/api/v1/devices/{id}/scopes");
    let (s, v) = send(
        &fx.app,
        req(
            Method::PUT,
            &uri,
            Some(&fx.dev),
            Some(json!({"scopes": ["read", "admin"]})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "an admin passkey keeps admin: {v}");
}

#[tokio::test]
async fn a_passkey_is_never_self_enrolled() {
    let fx = fx_pk().await;
    let mut a = SoftAuthenticator::new(HOST, ORIGIN);
    let failed = |(s, v): (StatusCode, Value)| (s, code_of(&v).to_owned());
    let pf = (StatusCode::UNAUTHORIZED, "pairing_failed".to_owned());
    // No pairing at all: no code, a made-up code, a made-up secret.
    let (s, v) = pre(&fx, "/pair/passkey/options", json!({})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let made_up = json!({"code": "ABCDE-FGHJK"});
    assert_eq!(failed(pre(&fx, "/pair/passkey/options", made_up).await), pf);
    let made_up = json!({"secret": b64(&[7; 16])});
    assert_eq!(failed(pre(&fx, "/pair/passkey/options", made_up).await), pf);
    let body = json!({"code": "ABCDE-FGHJK", "credential": a.register(&json!({"publicKey":
        {"challenge": "AAAA", "user": {"id": "AAAA"}}}))});
    assert_eq!(failed(pre(&fx, "/pair/passkey/claim", body).await), pf);

    // The approver: admin, elevated, scopes within its own.
    let reader = fx.enroll("phone", &["read", "approve"]).await;
    assert_eq!(
        failed(pairing(&fx, &reader, &["read"]).await).1,
        "forbidden_scope"
    );
    let admin = fx.enroll("mac", &["read", "admin"]).await;
    let s = admin.session.lock().unwrap().clone().unwrap();
    fx.app.auth.elevate(&s, &admin.id, fx.clock.unix() - 1);
    assert_eq!(
        failed(pairing(&fx, &admin, &["read"]).await).1,
        "step_up_required"
    );
    let (s, v) = pairing(&fx, &fx.dev, &["read", "runner"]).await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "a passkey never holds runner: {v}"
    );
    let narrow = fx.enroll("narrow", &["read", "admin"]).await;
    assert_eq!(
        failed(pairing(&fx, &narrow, &["terminal"]).await).1,
        "forbidden_scope"
    );

    // A device pairing's code on the passkey path, and a passkey pairing's on the device path.
    let body = json!({"name": "cli", "kind": "device", "scopes": ["read"]});
    let (_, dp) = send(
        &fx.app,
        req(Method::POST, "/api/v1/pairings", Some(&fx.dev), Some(body)),
    )
    .await;
    let dcode = json!({"code": dp["code"]});
    assert_eq!(failed(pre(&fx, "/pair/passkey/options", dcode).await), pf);
    let (_, p) = pairing(&fx, &fx.dev, &["read"]).await;
    let stranger = TestDevice::new(&fx.app.auth.identity.fp, fx.clock.clone());
    let claim = stranger.claim_body(p["code"].as_str(), None);
    assert_eq!(failed(pre(&fx, "/pair/claim", claim).await), pf);

    // Claimed without asking for options: refused, and nothing spent.
    let code = p["code"].as_str().unwrap();
    let body = json!({"code": code, "credential": a.register(&json!({"publicKey":
        {"challenge": "AAAA", "user": {"id": "AAAA"}}}))});
    let (s, v) = pre(&fx, "/pair/passkey/claim", body).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // A credential answering other options does not verify.
    let (_, o) = pre(&fx, "/pair/passkey/options", json!({"code": code})).await;
    let mut other = o.clone();
    other["options"]["publicKey"]["challenge"] = json!(b64(&[1; 32]));
    let body = json!({"code": code, "credential": a.register(&other["options"])});
    assert_eq!(
        pre(&fx, "/pair/passkey/claim", body).await.0,
        StatusCode::BAD_REQUEST
    );
    // Then the real claim, once; the code is spent.
    let (_, o) = pre(&fx, "/pair/passkey/options", json!({"code": code})).await;
    let cred = a.register(&o["options"]);
    let body = json!({"code": code, "credential": cred.clone()});
    assert_eq!(
        pre(&fx, "/pair/passkey/claim", body.clone()).await.0,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        failed(pre(&fx, "/pair/passkey/claim", body).await),
        pf,
        "reused"
    );
    assert_eq!(
        failed(pre(&fx, "/pair/passkey/options", json!({"code": code})).await),
        pf
    );

    // Expired: past the pairing's 5 minutes.
    let (_, p) = pairing(&fx, &fx.dev, &["read"]).await;
    fx.clock.advance(301);
    let late = json!({"code": p["code"]});
    assert_eq!(failed(pre(&fx, "/pair/passkey/options", late).await), pf);

    // Pending until approved: it cannot sign in.
    let claimed = sqlx::query_scalar::<_, String>("SELECT device_id FROM core_passkeys LIMIT 1")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    let (s, v) = sign_in(&fx, &mut a, &browser(&fx, &claimed)).await;
    assert_eq!((s, code_of(&v)), (StatusCode::UNAUTHORIZED, "auth_failed"));
}

#[tokio::test]
async fn without_passkeys_there_is_no_passkey_pairing() {
    let fx = fx().await;
    let (s, v) = pairing(&fx, &fx.dev, &["read"]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, v) = pre(
        &fx,
        "/handshake/passkey/options",
        json!({"session_spki": "x"}),
    )
    .await;
    assert_eq!(
        (s, code_of(&v)),
        (StatusCode::BAD_REQUEST, "passkeys_disabled")
    );
}
