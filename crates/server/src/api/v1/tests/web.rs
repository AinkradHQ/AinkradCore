//! The web session and the passkey's own refusals (handshake spec §9, §8, §14; E1-08.1/.3):
//! every sign-in failure is the one `auth_failed`, a clone locks the passkey once, a web session
//! is signed only with its own key, and a passkey step-up needs a user-verified assertion over
//! this session's own live challenge, from this origin and RP, once.

use super::passkeys::{
    browser, code_of, fx_pk, pair_passkey, pre, sign_in, step_up, stepup_options,
};
use super::*;
use crate::auth::crypto::b64;
use crate::auth::testing::authenticator::{SoftAuthenticator, UP, UV};
use crate::store::gov;

async fn audit_rows(fx: &Fx) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

/// Sends a sign-in assertion as is.
async fn session_with(fx: &Fx, cred: Value) -> (StatusCode, Value) {
    pre(
        fx,
        "/handshake/passkey/session",
        json!({"credential": cred}),
    )
    .await
}

/// Fresh options for `web`'s key.
async fn options(fx: &Fx, web: &TestDevice) -> Value {
    let (s, o) = pre(
        fx,
        "/handshake/passkey/options",
        json!({"session_spki": b64(&web.spki)}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{o}");
    o["options"].clone()
}

#[tokio::test]
async fn every_sign_in_failure_is_one_answer_and_writes_no_audit_row() {
    let fx = fx_pk().await;
    let (mut a, id) = pair_passkey(&fx, &["read"]).await;
    let web = browser(&fx, &id);
    let before = audit_rows(&fx).await;
    let mut answers = Vec::new();
    let started = std::time::Instant::now();

    // Options the Core never issued.
    answers.push(session_with(&fx, a.assert_challenge(&b64(&[9; 32]))).await);
    // An unknown credential.
    let mut stranger = SoftAuthenticator::new(HOST, super::passkeys::ORIGIN);
    stranger.user.clone_from(&a.user);
    let o = options(&fx, &web).await;
    answers.push(session_with(&fx, stranger.assert(&o)).await);
    // Another origin, another RP, no user verification.
    for case in 0..3 {
        let o = options(&fx, &web).await;
        match case {
            0 => a.origin = "https://evil.test".into(),
            1 => a.rp_id = "evil.test".into(),
            _ => a.flags = UP,
        }
        answers.push(session_with(&fx, a.assert(&o)).await);
        (a.origin, a.rp_id, a.flags) = (super::passkeys::ORIGIN.into(), HOST.into(), UP | UV);
    }
    // A good one, then the same assertion again.
    let o = options(&fx, &web).await;
    let cred = a.assert(&o);
    assert_eq!(session_with(&fx, cred.clone()).await.0, StatusCode::OK);
    answers.push(session_with(&fx, cred).await);
    // An expired ceremony.
    let o = options(&fx, &web).await;
    fx.clock.advance(61);
    answers.push(session_with(&fx, a.assert(&o)).await);

    let n = answers.len() as u32;
    assert!(
        started.elapsed() >= crate::api::v1::gate::FAIL_FLOOR * n,
        "each at the floor"
    );
    let shape = |v: &Value| (v["code"].clone(), v["message"].clone());
    for (status, body) in &answers {
        assert_eq!(*status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(shape(body), shape(&answers[0].1), "one body");
    }
    assert_eq!(answers[0].1["code"], "auth_failed");
    assert_eq!(
        audit_rows(&fx).await,
        before,
        "refusals are counted, never audited"
    );
    let d = gov::get_device(&fx.app.pool, &id).await.unwrap().unwrap();
    assert_eq!(d.status, "active", "failures never lock the passkey");
}

#[tokio::test]
async fn a_sign_count_that_does_not_grow_locks_the_passkey_once() {
    let fx = fx_pk().await;
    let (mut a, id) = pair_passkey(&fx, &["read"]).await;
    let web = browser(&fx, &id);
    assert_eq!(sign_in(&fx, &mut a, &web).await.0, StatusCode::OK);
    let before = audit_rows(&fx).await;
    a.counter = Some(1);
    let (s, v) = sign_in(&fx, &mut a, &browser(&fx, &id)).await;
    assert_eq!((s, code_of(&v)), (StatusCode::UNAUTHORIZED, "auth_failed"));
    let d = gov::get_device(&fx.app.pool, &id).await.unwrap().unwrap();
    assert_eq!(d.status, "locked");
    let revoked: Option<String> =
        sqlx::query_scalar("SELECT revoked_at FROM core_passkeys WHERE device_id = ?")
            .bind(&id)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert!(revoked.is_some(), "the credential is revoked");
    assert_eq!(audit_rows(&fx).await, before + 1, "one passkey.locked row");
    // Its live session went with it; trying again writes nothing more.
    let (s, _) = send(&fx.app, req(Method::GET, "/api/v1/me", Some(&web), None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    a.counter = Some(1);
    assert_eq!(
        sign_in(&fx, &mut a, &browser(&fx, &id)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(audit_rows(&fx).await, before + 1);
    let action: String =
        sqlx::query_scalar("SELECT action FROM audit_events ORDER BY seq DESC LIMIT 1")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(action, "passkey.locked");
}

#[tokio::test]
async fn a_web_session_is_signed_only_with_its_own_key_and_ends_on_time() {
    let fx = fx_pk().await;
    let (mut a, id) = pair_passkey(&fx, &["read"]).await;
    let web = browser(&fx, &id);
    assert_eq!(sign_in(&fx, &mut a, &web).await.0, StatusCode::OK);
    let refused = |(s, v): (StatusCode, Value)| (s, code_of(&v).to_owned());
    let af = (StatusCode::UNAUTHORIZED, "auth_failed".to_owned());

    // Another key on the same session: the credential's own, or another browser's.
    let other = browser(&fx, &id);
    other.set_session(web.session.lock().unwrap().clone());
    assert_eq!(
        refused(send(&fx.app, req(Method::GET, "/api/v1/me", Some(&other), None)).await),
        af
    );
    // A passkey device never takes the native session-less calls.
    let body = json!({"challenge": "x"}).to_string();
    let mut r = Request::builder()
        .method("POST")
        .uri("/handshake/session")
        .header(header::HOST, HOST);
    for (k, v) in web.headers_session("POST", "/handshake/session", body.as_bytes(), None) {
        r = r.header(k, v);
    }
    assert_eq!(
        refused(send(&fx.app, r.body(Body::from(body)).unwrap()).await),
        af
    );
    // A session of another passkey device.
    let (mut b, id_b) = pair_passkey(&fx, &["read"]).await;
    let web_b = browser(&fx, &id_b);
    assert_eq!(sign_in(&fx, &mut b, &web_b).await.0, StatusCode::OK);
    let mixed = TestDevice::from_pkcs8(
        &id,
        &web_b.pkcs8,
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    );
    mixed.set_session(web_b.session.lock().unwrap().clone());
    assert_eq!(
        refused(send(&fx.app, req(Method::GET, "/api/v1/me", Some(&mixed), None)).await),
        af
    );

    // The lifetime is the setting, absolute.
    let uri = "/api/v1/settings/server/auth.web_session_secs";
    let (s, v) = send(
        &fx.app,
        req(
            Method::PUT,
            uri,
            Some(&fx.dev),
            Some(json!({"value": 3600})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = send(
        &fx.app,
        req(Method::PUT, uri, Some(&fx.dev), Some(json!({"value": 60}))),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "below the 1 h floor");
    let short = browser(&fx, &id);
    assert_eq!(sign_in(&fx, &mut a, &short).await.0, StatusCode::OK);
    fx.clock.advance(3599);
    assert_eq!(
        send(&fx.app, req(Method::GET, "/api/v1/me", Some(&short), None))
            .await
            .0,
        StatusCode::OK
    );
    fx.clock.advance(1);
    assert_eq!(
        refused(send(&fx.app, req(Method::GET, "/api/v1/me", Some(&short), None)).await),
        af
    );
}

/// Forgets the passkey's step-up failures, so one test can try every refusal.
async fn reset(fx: &Fx, id: &str) {
    fx.app.auth.stepup_failures.clear(id);
    sqlx::query("DELETE FROM core_auth_limits WHERE key = ?")
        .bind(format!("stepup:{id}"))
        .execute(&fx.app.pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_passkey_step_up_needs_a_verified_assertion_over_its_own_live_challenge() {
    let fx = fx_pk().await;
    let (mut a, id) = pair_passkey(&fx, &["read", "admin"]).await;
    let web = browser(&fx, &id);
    assert_eq!(sign_in(&fx, &mut a, &web).await.0, StatusCode::OK);
    let failed = |(s, v): (StatusCode, Value)| {
        assert_eq!(
            (s, code_of(&v)),
            (StatusCode::FORBIDDEN, "step_up_failed"),
            "{v}"
        );
    };
    let try_with = |a: &mut SoftAuthenticator, c: &Value| json!({"challenge": c["challenge"], "assertion": a.assert(&c["options"])});

    let c = stepup_options(&fx, &web).await;
    a.flags = UP;
    failed(step_up(&fx, &web, try_with(&mut a, &c)).await);
    a.flags = UP | UV;
    let c = stepup_options(&fx, &web).await;
    a.origin = "https://evil.test".into();
    failed(step_up(&fx, &web, try_with(&mut a, &c)).await);
    a.origin = super::passkeys::ORIGIN.into();
    let c = stepup_options(&fx, &web).await;
    a.rp_id = "evil.test".into();
    failed(step_up(&fx, &web, try_with(&mut a, &c)).await);
    a.rp_id = HOST.into();
    reset(&fx, &id).await;

    // Another session's challenge, an expired one, a replayed assertion.
    let other = browser(&fx, &id);
    assert_eq!(sign_in(&fx, &mut a, &other).await.0, StatusCode::OK);
    let theirs = stepup_options(&fx, &other).await;
    stepup_options(&fx, &web).await;
    failed(step_up(&fx, &web, try_with(&mut a, &theirs)).await);
    let c = stepup_options(&fx, &web).await;
    fx.clock.advance(61);
    failed(step_up(&fx, &web, try_with(&mut a, &c)).await);
    let c = stepup_options(&fx, &web).await;
    let good = try_with(&mut a, &c);
    assert_eq!(step_up(&fx, &web, good.clone()).await.0, StatusCode::OK);
    failed(step_up(&fx, &web, good).await);
    reset(&fx, &id).await;

    // The wrong kind of proof for each kind of device.
    let c = stepup_options(&fx, &web).await;
    let sig = json!({"challenge": c["challenge"], "stepup_sig": b64(&[0; 64])});
    failed(step_up(&fx, &web, sig).await);
    let native = fx.enroll("mac", &["read", "admin"]).await;
    let c = stepup_options(&fx, &native).await;
    assert!(
        c.get("options").is_none(),
        "a native challenge has no WebAuthn options"
    );
    let body = json!({"challenge": c["challenge"], "assertion": a.assert_challenge(c["challenge"].as_str().unwrap())});
    failed(step_up(&fx, &native, body).await);
}
