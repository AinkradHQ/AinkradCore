//! Renewing the token: rotation, single flight, no loop, the verdicts, a person's credential that
//! wins a race, and a client secret that changes.

use std::sync::atomic::Ordering;
use std::time::Duration;

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::{Value, json};

use super::ops::run;
use super::*;
use crate::connections::linear::{CallError, Cred, Limit, unpack};
use crate::store::connections::health::{self, Signal};
use crate::store::connections::{get, secret};

async fn get_issue(f: &Fx, c: &Connection) -> Result<Value, CallError> {
    let args = json!({"id": "ENG-1"});
    run(f, c, &Limit::any(), "linear.get_issue", args).await
}

#[tokio::test]
async fn concurrent_renewals_spend_the_refresh_token_once() {
    let f = fx(true).await;
    let served = f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 30))
        .await;
    let cx = f.cx(NOW);
    let (a, b, d) = tokio::join!(
        f.linear.fresh(&cx, c.id),
        f.linear.fresh(&cx, c.id),
        f.linear.fresh(&cx, c.id)
    );
    for m in [a.unwrap(), b.unwrap(), d.unwrap()] {
        assert_eq!(m.access(), "acc2-7f3a9d41e0b2");
        assert_eq!(m.refresh(), Some("ref2-91c4d2b7a6e1"));
    }
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "single-flight: one refresh, not three"
    );
    let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(
        stored.refresh(),
        Some("ref2-91c4d2b7a6e1"),
        "the rotated token is sealed"
    );
    assert_eq!(stored.expires_at.as_deref(), Some(at(3600).as_str()));
    // Not due any more: nothing is spent. Due again later: the NEW refresh token is used.
    f.linear.fresh(&cx, c.id).await.unwrap();
    assert_eq!(f.fake.count("POST /oauth/token"), 1);
    let later = at(7200);
    let m = f.linear.fresh(&f.cx(&later), c.id).await.unwrap();
    assert_eq!(m.refresh(), Some("ref3-91c4d2b7a6e1"));
    let sent = f.fake.last("POST /oauth/token").unwrap();
    assert_eq!(f.fake.bad(), 0, "the refresh is a form, as Linear takes it");
    assert_eq!(sent.body["grant_type"], "refresh_token");
    assert_eq!(sent.body["refresh_token"], "ref2-91c4d2b7a6e1");
    assert_eq!(sent.body["client_id"], "client-id-8c41");
    assert_eq!(sent.body["client_secret"], CLIENT_SECRET);
}

#[tokio::test]
async fn an_answer_without_a_new_refresh_token_keeps_the_old_one() {
    let f = fx(true).await;
    f.fake.reply(
        "POST /oauth/token",
        200,
        json!({"access_token": "acc9-0a1b2c3d4e5f", "expires_in": 3600}),
    );
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let m = f.linear.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(m.refresh(), Some(REFRESH));
    assert!(matches!(unpack(&m), Some(Cred::Oauth(_))));
}

#[tokio::test]
async fn only_invalid_grant_condemns_a_refresh_token() {
    let f = fx(true).await;
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let fresh = |f: &Fx| {
        let (l, pool, sealer, id) = (f.linear.clone(), f.pool.clone(), f.sealer.clone(), c.id);
        async move {
            let who = Who {
                workspace: 1,
                by_device: "d_test",
                actor: AuditActor::System,
                now: NOW,
            };
            let cx = Ctx {
                pool: &pool,
                sealer: &sealer,
                who,
            };
            l.fresh(&cx, id).await.map(|_| ())
        }
    };
    let cases = [
        (
            400u16,
            json!({"error": "invalid_grant"}),
            CallError::AuthFailed,
        ),
        (
            401,
            json!({"error": "invalid_grant"}),
            CallError::AuthFailed,
        ),
        (
            401,
            json!({"error": "invalid_client"}),
            CallError::AppConfig,
        ),
        (
            400,
            json!({"error": "unauthorized_client"}),
            CallError::AppConfig,
        ),
        // An edge or a proxy answering 401 or 403 says nothing about THIS credential.
        (401, json!({}), CallError::Forbidden),
        (403, json!({"error": "access_denied"}), CallError::Forbidden),
        (
            400,
            json!({"error": "invalid_request"}),
            CallError::BadRequest(400),
        ),
        (429, json!({}), CallError::RateLimited { retry_after: None }),
        (503, json!({}), CallError::Upstream(503)),
    ];
    for (status, body, want) in cases {
        f.fake.reply("POST /oauth/token", status, body.clone());
        assert_eq!(fresh(&f).await, Err(want.clone()), "{status} {body}");
    }
    let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(
        stored.refresh(),
        Some(REFRESH),
        "a failed refresh leaves the credential as it was"
    );
    // And the health class of those that are not about the credential is none.
    for e in [
        CallError::AppConfig,
        CallError::Forbidden,
        CallError::BadRequest(400),
    ] {
        assert_eq!(e.health(), None, "{e:?}");
    }
}

#[tokio::test]
async fn a_401_renews_once_and_retries_once() {
    let f = fx(true).await;
    let served = f.fake.rotating();
    f.fake.on("GQL Issue", |s| {
        if s.auth.as_deref() == Some("Bearer acc2-7f3a9d41e0b2") {
            Reply::data(json!({"issue": issue("ENG-1", "ENG")}))
        } else {
            Reply::error(401, "AUTHENTICATION_ERROR")
        }
    });
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 3600))
        .await;
    assert_eq!(get_issue(&f, &c).await.unwrap()["identifier"], "ENG-1");
    assert_eq!(served.load(Ordering::SeqCst), 1);
    assert_eq!(f.fake.count("GQL Issue"), 2);
    // A service that keeps saying 401: one refresh, one retry, then the failure.
    let g = fx(true).await;
    let served = g.fake.rotating();
    g.fake
        .on("GQL Issue", |_| Reply::error(401, "AUTHENTICATION_ERROR"));
    let c = g
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 3600))
        .await;
    assert_eq!(get_issue(&g, &c).await.unwrap_err(), CallError::AuthFailed);
    assert_eq!(served.load(Ordering::SeqCst), 1);
    // It does not loop: a fresh token that is refused again is not a reason to spend another
    // refresh token (it was renewed less than the skew ago).
    assert_eq!(get_issue(&g, &c).await.unwrap_err(), CallError::AuthFailed);
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "no second refresh within the skew"
    );
    assert_eq!(g.fake.count("GQL Issue"), 3);
}

#[tokio::test]
async fn an_api_key_is_never_renewed() {
    let f = fx(true).await;
    f.fake.rotating();
    f.fake
        .on("GQL Issue", |_| Reply::error(401, "AUTHENTICATION_ERROR"));
    let c = f.key().await;
    assert_eq!(get_issue(&f, &c).await.unwrap_err(), CallError::AuthFailed);
    assert_eq!(f.fake.count("POST /oauth/token"), 0);
    let m = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(m.access(), API_KEY);
    assert_eq!(m.refresh(), None);
}

#[tokio::test]
async fn without_an_app_an_expired_token_cannot_be_renewed() {
    let f = fx(false).await;
    f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let e = f
        .linear
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e, CallError::OAuthNotConfigured);
    assert_eq!(f.fake.count("POST /oauth/token"), 0);
    // A token that is not due needs no app.
    let live = f
        .connect("live", "oauth", &oauth(ACCESS, REFRESH, 3600))
        .await;
    f.linear.fresh(&f.cx(NOW), live.id).await.unwrap();
}

async fn suspect(f: &Fx, id: i64) {
    let status = UpstreamStatus::AuthFailed;
    let signal = Signal::Upstream {
        status,
        retry_after: None,
        reset_at: None,
    };
    health::signal(&f.pool, 1, id, signal, NOW).await.unwrap();
}

#[tokio::test]
async fn a_renewal_does_not_clear_a_pending_auth_failure() {
    let f = fx(true).await;
    let served = f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    suspect(&f, c.id).await;
    let before = get(&f.pool, 1, c.id).await.unwrap();
    assert_eq!(before.state_reason.as_deref(), Some("auth_suspected"));
    f.linear.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(served.load(Ordering::SeqCst), 1);
    let after = get(&f.pool, 1, c.id).await.unwrap();
    assert_eq!(
        after.state_reason.as_deref(),
        Some("auth_suspected"),
        "only a test clears it"
    );
    assert_ne!(after.status, "active");
}

#[tokio::test]
async fn a_caller_that_is_dropped_mid_renewal_cannot_lose_the_rotated_token() {
    let f = fx(true).await;
    f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let cx = f.cx(NOW);
    let dropped = tokio::time::timeout(Duration::from_millis(40), f.linear.fresh(&cx, c.id)).await;
    assert!(
        dropped.is_err(),
        "the caller gave up while the token endpoint was answering"
    );
    tokio::time::sleep(Duration::from_millis(700)).await;
    let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(
        stored.refresh(),
        Some("ref2-91c4d2b7a6e1"),
        "the rotated refresh token was sealed"
    );
}

#[tokio::test]
async fn the_lock_map_does_not_grow_with_every_connection_renewed() {
    let f = fx(true).await;
    f.fake.reply(
        "POST /oauth/token",
        200,
        json!({"access_token": "acc9-0a1b2c3d4e5f", "refresh_token": "ref9-0a1b2c3d4e5f",
            "expires_in": 3600}),
    );
    for name in ["a1", "b1", "c1", "d1"] {
        let c = f.connect(name, "oauth", &oauth(ACCESS, REFRESH, 10)).await;
        f.linear.fresh(&f.cx(NOW), c.id).await.unwrap();
    }
    assert!(f.linear.locks.lock().unwrap().len() <= 1);
}

#[tokio::test]
async fn a_renewal_the_service_refuses_is_a_conclusive_rejection() {
    let f = fx(true).await;
    f.fake
        .reply("POST /oauth/token", 400, json!({"error": "invalid_grant"}));
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let t = f.linear.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(
        (t.status.as_str(), t.state_reason.as_deref()),
        ("disabled", Some("auth_failed"))
    );
}

#[tokio::test]
async fn a_renewal_that_only_failed_is_inconclusive_and_one_that_works_then_tests() {
    let f = fx(true).await;
    f.fake.reply("POST /oauth/token", 503, json!({}));
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let t = f.linear.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(
        t.status, "active",
        "a 5xx on the token endpoint disables nothing"
    );
    f.fake.rotating();
    let t = f.linear.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(t.identity, Some(format!("{ME} at {ORG}")));
    let sent = f.fake.last("GQL Viewer").unwrap();
    assert_eq!(
        sent.auth.as_deref(),
        Some("Bearer acc2-7f3a9d41e0b2"),
        "tested with the renewed token"
    );
}

#[tokio::test]
async fn a_changed_client_secret_disables_no_connection() {
    let f = fx(true).await;
    // Linear now only knows the NEW secret.
    f.fake.on("POST /oauth/token", |s| {
        if s.body["client_secret"] == "new-secret-5f3a" {
            let body = json!({"access_token": "acc7-1a2b3c4d5e6f", "refresh_token": "ref7-1a2b3c4d5e6f",
                "expires_in": 3600});
            Reply::json(200, body)
        } else {
            Reply::json(401, json!({"error": "invalid_client"}))
        }
    });
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    // The old secret is refused: that is Core's app registration, not the connection's credential.
    let t = f.linear.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(t.status, "active", "{:?}", t.state_reason);
    assert_ne!(t.state_reason.as_deref(), Some("auth_failed"));
    let e = f
        .linear
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e, CallError::AppConfig);
    assert_eq!(e.health(), None);
    // The admin enters the new secret: the same connection renews, with the refresh token it had.
    let new = OAuthApp::new("client-id-8c41", "new-secret-5f3a", &[REDIRECT]);
    assert!(f.linear.set_app(new));
    let m = f.linear.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(m.refresh(), Some("ref7-1a2b3c4d5e6f"));
    assert_eq!(
        f.fake.last("POST /oauth/token").unwrap().body["refresh_token"],
        REFRESH
    );
}

#[tokio::test]
async fn a_credential_a_person_stores_meanwhile_wins_over_a_renewal() {
    let f = fx(true).await;
    f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let (l, pool, sealer) = (f.linear.clone(), f.pool.clone(), f.sealer.clone());
    let renewing = tokio::spawn(async move {
        let who = Who {
            workspace: 1,
            by_device: "d_test",
            actor: AuditActor::System,
            now: NOW,
        };
        let cx = Ctx {
            pool: &pool,
            sealer: &sealer,
            who,
        };
        l.fresh(&cx, c.id).await
    });
    // While the token endpoint is still answering (it takes 150 ms), a person stores a key.
    tokio::time::sleep(Duration::from_millis(50)).await;
    secret::replace(&f.pool, &f.sealer, c.id, &key(), f.cx(NOW).who)
        .await
        .unwrap();
    let got = renewing.await.unwrap().unwrap();
    assert_eq!(
        got.access(),
        API_KEY,
        "the renewal hands back what is stored now"
    );
    let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(stored.access(), API_KEY);
    assert_eq!(
        stored.refresh(),
        None,
        "the rotated refresh token did not overwrite it"
    );
}

#[tokio::test]
async fn a_verdict_about_an_old_credential_cannot_settle_a_new_one() {
    let f = fx(true).await;
    // The old refresh token is refused, slowly.
    f.fake.on("POST /oauth/token", |_| {
        Reply::json(400, json!({"error": "invalid_grant"})).delayed(200)
    });
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let (l, pool, sealer) = (f.linear.clone(), f.pool.clone(), f.sealer.clone());
    let id = c.id;
    let testing = tokio::spawn(async move {
        let who = Who {
            workspace: 1,
            by_device: "d_test",
            actor: AuditActor::System,
            now: NOW,
        };
        let cx = Ctx {
            pool: &pool,
            sealer: &sealer,
            who,
        };
        l.test_connection(&cx, id).await
    });
    tokio::time::sleep(Duration::from_millis(60)).await;
    secret::replace(&f.pool, &f.sealer, c.id, &key(), f.cx(NOW).who)
        .await
        .unwrap();
    let t = testing.await.unwrap().unwrap();
    assert_ne!(
        t.status, "disabled",
        "the refusal was about the credential that was replaced"
    );
    let now = get(&f.pool, 1, c.id).await.unwrap();
    assert_ne!(now.state_reason.as_deref(), Some("auth_failed"));
}
