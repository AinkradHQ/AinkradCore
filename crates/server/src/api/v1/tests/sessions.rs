//! Sessions and lockouts, the handshake spec's §17 cases 9, 10, 22, 23 and 32 (for
//! lockouts): challenge-response through the router, and persisted lockouts that never lock a
//! device out from its own address.

use super::signed::{PATH, raw};
use super::*;
use crate::auth::crypto::unb64;
use crate::scheduler::iso_of_unix;

/// The challenge and session calls as a client makes them.
async fn login(fx: &Fx, dev: &TestDevice, challenge: Option<&str>) -> (StatusCode, Value) {
    let challenge = match challenge {
        Some(c) => c.to_owned(),
        None => {
            let ask = req(
                Method::POST,
                "/handshake/challenge",
                None,
                Some(json!({"device_id": dev.id})),
            );
            let (status, got) = send(&fx.app, ask).await;
            assert_eq!(status, StatusCode::OK, "{got}");
            assert_eq!(got["expires_in"], 60);
            got["challenge"].as_str().unwrap().to_owned()
        }
    };
    let body = json!({"challenge": challenge}).to_string();
    let h = dev.headers_session("POST", "/handshake/session", body.as_bytes(), None);
    send(
        &fx.app,
        raw(Method::POST, "/handshake/session", &h, body.as_bytes()),
    )
    .await
}

/// §17.9: a valid signature on an expired session is `session_expired`; the challenge-response
/// restores access.
#[tokio::test]
async fn an_expired_session_is_renewed_by_challenge_response() {
    let fx = fx().await;
    fx.clock.advance(15 * 60);
    let (status, body) = fx.get(PATH).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("session_expired"))
    );
    let (status, got) = login(&fx, &fx.dev, None).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let id = got["session_id"].as_str().unwrap();
    assert!(crate::auth::crypto::is_id(id, "s_"));
    assert_eq!(got["scopes"], json!(ALL));
    assert!(got["elevated_until"].is_null());
    assert_eq!(got["expires_at"], iso_of_unix(fx.clock.unix() + 900));
    fx.dev.set_session(Some(id.to_owned()));
    assert_eq!(fx.get(PATH).await.0, StatusCode::OK);
}

/// §17.10: a challenge works once, only for its own device, and only for 60 s; an unknown
/// device id still gets one.
#[tokio::test]
async fn challenges_are_single_use_bound_to_their_device_and_short_lived() {
    let fx = fx().await;
    let other = fx.enroll("other", &["read"]).await;
    let ask = |id: &str| {
        req(
            Method::POST,
            "/handshake/challenge",
            None,
            Some(json!({"device_id": id})),
        )
    };
    let (_, got) = send(&fx.app, ask(&fx.dev.id)).await;
    let c = got["challenge"].as_str().unwrap().to_owned();
    assert_eq!(unb64(&c, 43).unwrap().len(), 32);
    let refused = |r: (StatusCode, Value)| {
        assert_eq!(
            (r.0, r.1["code"].clone()),
            (StatusCode::UNAUTHORIZED, json!("auth_failed"))
        )
    };
    refused(login(&fx, &other, Some(&c)).await);
    assert_eq!(login(&fx, &fx.dev, Some(&c)).await.0, StatusCode::OK);
    refused(login(&fx, &fx.dev, Some(&c)).await);
    let (_, got) = send(&fx.app, ask(&fx.dev.id)).await;
    fx.clock.advance(61);
    refused(login(&fx, &fx.dev, got["challenge"].as_str()).await);
    let (status, got) = send(&fx.app, ask(&fx.stranger().id)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unknown device gets one too: {got}"
    );
    let (status, _) = send(&fx.app, ask("d_NOT-AN-ID")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The session call takes no session header.
    let body = json!({"challenge": "x"}).to_string();
    let h = fx
        .dev
        .headers("POST", "/handshake/session", body.as_bytes());
    let r = raw(Method::POST, "/handshake/session", &h, body.as_bytes());
    assert_eq!(send(&fx.app, r).await.0, StatusCode::BAD_REQUEST);
    // Challenges are limited per address: 30 a minute.
    for _ in 0..40 {
        send(&fx.app, from("10.5.5.5", ask(&fx.dev.id))).await;
    }
    assert_eq!(
        send(&fx.app, from("10.5.5.5", ask(&fx.dev.id))).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// §17.22, §17.23, §17.32: an address that fails 20 times is locked across a restart, with
/// one audit row; failures naming a device from other addresses never lock that device out.
#[tokio::test]
async fn lockouts_persist_and_never_lock_a_device_out_from_its_own_address() {
    let mut fx = fx().await;
    // 20 strangers, so the per-(address, device) lock (5) never comes first.
    for _ in 0..20 {
        let r = from(
            "10.7.0.1",
            req(Method::GET, PATH, Some(&fx.stranger()), None),
        );
        assert_eq!(send(&fx.app, r).await.0, StatusCode::UNAUTHORIZED);
    }
    let locked = |fx: &Fx| from("10.7.0.1", req(Method::GET, PATH, Some(&fx.dev), None));
    assert_eq!(
        send(&fx.app, locked(&fx)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    fx.restart();
    let s = fx.app.auth.issue_session(&fx.dev.id, fx.clock.unix());
    fx.dev.set_session(Some(s.id));
    assert_eq!(
        send(&fx.app, locked(&fx)).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "after a restart"
    );
    let lockouts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'auth.lockout'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(lockouts, 1, "one row for the one lock");

    // 1,000 failures naming the device, from 1,000 other addresses: forged signatures.
    let forger = TestDevice::new(&fx.app.auth.identity.fp, fx.clock.clone());
    let forged =
        TestDevice::from_pkcs8(&fx.dev.id, &forger.pkcs8, &forger.core_fp, fx.clock.clone());
    forged.set_session(fx.dev.session.lock().unwrap().clone());
    // Concurrently: each refusal takes `FAIL_FLOOR`.
    for chunk in 0..10 {
        let sent = (0..100).map(|j| {
            let i = chunk * 100 + j;
            let r = from(
                &format!("10.8.{}.{}", i / 250, i % 250),
                req(Method::GET, PATH, Some(&forged), None),
            );
            send(&fx.app, r)
        });
        for (status, _) in futures_util::future::join_all(sent).await {
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }
    let own = from("10.6.0.1", req(Method::GET, PATH, Some(&fx.dev), None));
    assert_eq!(
        send(&fx.app, own).await.0,
        StatusCode::OK,
        "still works from its own address"
    );
}
