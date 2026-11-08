//! Renewing a rotating bot token: rotation, single flight, no loop, the verdicts, a person's
//! credential that wins a race, and a client secret that changes.

use std::sync::atomic::Ordering;
use std::time::Duration;

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::{Value, json};

use super::ops::run;
use super::*;
use crate::connections::slack::{CallError, Cred, Limit, unpack};
use crate::store::connections::health::{self, Signal};
use crate::store::connections::{get, secret};

const ACC2: &str = "xoxe.xoxb-test-111-222-acc2";
const REF2: &str = "xoxe-1-test-ref2-91c4d2";

async fn read(f: &Fx, c: &Connection) -> Result<Value, CallError> {
    run(
        f,
        c,
        &Limit::any(),
        "slack.read_channel",
        json!({"channel": CH}),
    )
    .await
}

#[tokio::test]
async fn concurrent_renewals_spend_the_refresh_token_once() {
    let f = fx_rotating(true).await;
    let served = f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 30))
        .await;
    let cx = f.cx(NOW);
    let (a, b, d) = tokio::join!(
        f.slack.fresh(&cx, c.id),
        f.slack.fresh(&cx, c.id),
        f.slack.fresh(&cx, c.id)
    );
    for m in [a.unwrap(), b.unwrap(), d.unwrap()] {
        assert_eq!((m.access(), m.refresh()), (ACC2, Some(REF2)));
    }
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "single-flight: one refresh, not three"
    );
    let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(stored.refresh(), Some(REF2), "the rotated token is sealed");
    assert_eq!(stored.expires_at.as_deref(), Some(at(43200).as_str()));
    // Not due any more: nothing is spent. Due again later: the NEW refresh token is used.
    f.slack.fresh(&cx, c.id).await.unwrap();
    assert_eq!(f.fake.count("oauth.v2.access"), 1);
    let later = at(50_000);
    let m = f.slack.fresh(&f.cx(&later), c.id).await.unwrap();
    assert_eq!(m.refresh(), Some("xoxe-1-test-ref3-91c4d2"));
    let sent = f.fake.last("oauth.v2.access").unwrap();
    assert_eq!(
        f.fake.bad(),
        0,
        "the refresh is a form with no Authorization header"
    );
    assert_eq!(
        sent.form,
        json!({"grant_type": "refresh_token", "refresh_token": REF2, "client_id": "1234.5678",
            "client_secret": CLIENT_SECRET})
    );
}

#[tokio::test]
async fn an_answer_without_a_new_refresh_token_keeps_the_old_one() {
    let f = fx_rotating(true).await;
    f.fake.reply(
        "oauth.v2.access",
        Reply::ok(json!({"access_token": "xoxe.xoxb-test-111-222-acc9", "expires_in": 43200})),
    );
    let c = f
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    let m = f.slack.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(m.refresh(), Some(REFRESH));
    assert!(matches!(unpack(&m), Some(Cred::Rotating(_))));
    // An answer with no expiry cannot be kept alive: nothing is stored.
    f.fake.reply(
        "oauth.v2.access",
        Reply::ok(json!({"access_token": "xoxe.xoxb-test-111-222-acc8"})),
    );
    let c2 = f
        .connect("two", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    let e = f
        .slack
        .fresh(&f.cx(NOW), c2.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(e, CallError::Internal(_)), "{e:?}");
    let stored = secret::open(&f.pool, &f.sealer, 1, c2.id).await.unwrap().0;
    assert_eq!(stored.access(), ROT_ACCESS);
}

#[tokio::test]
async fn only_invalid_refresh_token_condemns_a_refresh_token() {
    let f = fx_rotating(true).await;
    let c = f
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    let cases = [
        (Reply::err("invalid_refresh_token"), CallError::AuthFailed),
        (
            Reply::http(400, json!({"ok": false, "error": "invalid_refresh_token"})),
            CallError::AuthFailed,
        ),
        (Reply::err("bad_client_secret"), CallError::AppConfig),
        (Reply::err("invalid_client_id"), CallError::AppConfig),
        // The token being dead or the request being wrong in some other way is no verdict.
        (Reply::err("token_revoked"), CallError::BadRequest(200)),
        (Reply::err("invalid_code"), CallError::BadRequest(200)),
        // An edge or a proxy answering 401 or 403 says nothing about THIS credential.
        (Reply::http(401, json!({})), CallError::Forbidden),
        (
            Reply::http(403, json!({"ok": false, "error": "access_denied"})),
            CallError::Forbidden,
        ),
        (
            Reply::err("ratelimited"),
            CallError::RateLimited { retry_after: None },
        ),
        (
            Reply::http(429, json!({})),
            CallError::RateLimited { retry_after: None },
        ),
        (Reply::http(503, json!({})), CallError::Upstream(503)),
        (Reply::http(200, json!({})), CallError::Upstream(200)),
    ];
    for (reply, want) in cases {
        f.fake.reply("oauth.v2.access", reply.clone());
        let got = f.slack.fresh(&f.cx(NOW), c.id).await.map(|_| ());
        assert_eq!(got, Err(want.clone()), "{} {}", reply.status, reply.body);
    }
    let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(
        stored.refresh(),
        Some(REFRESH),
        "a failed refresh leaves the credential as it was"
    );
    for e in [
        CallError::AppConfig,
        CallError::Forbidden,
        CallError::BadRequest(200),
    ] {
        assert_eq!(e.health(), None, "{e:?}");
    }
}

#[tokio::test]
async fn a_refused_rotating_token_renews_once_and_retries_once() {
    let f = fx_rotating(true).await;
    let served = f.fake.rotating();
    f.fake.on("conversations.history", |s| {
        if s.auth.as_deref() == Some(format!("Bearer {ACC2}").as_str()) {
            history(vec![msg(TS, "a")])
        } else {
            Reply::err("invalid_auth")
        }
    });
    let c = f
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 3600))
        .await;
    assert!(read(&f, &c).await.is_ok());
    assert_eq!(served.load(Ordering::SeqCst), 1);
    assert_eq!(f.fake.count("conversations.history"), 2);
    // A service that keeps refusing: one refresh, one retry, then the failure.
    let g = fx_rotating(true).await;
    let served = g.fake.rotating();
    g.fake
        .reply("conversations.history", Reply::err("token_expired"));
    let c = g
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 3600))
        .await;
    assert_eq!(read(&g, &c).await.unwrap_err(), CallError::AuthFailed);
    assert_eq!(served.load(Ordering::SeqCst), 1);
    // It does not loop: a fresh token that is refused again is not a reason to spend another
    // refresh token (it was renewed less than the skew ago).
    assert_eq!(read(&g, &c).await.unwrap_err(), CallError::AuthFailed);
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "no second refresh within the skew"
    );
    assert_eq!(g.fake.count("conversations.history"), 3);
}

#[tokio::test]
async fn without_an_app_an_expired_token_cannot_be_renewed() {
    let f = fx(false).await;
    f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    let e = f
        .slack
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e, CallError::OAuthNotConfigured);
    // No app configured says nothing about the credential: no health signal, a plain code.
    assert_eq!((e.health(), e.code()), (None, "not_configured"));
    assert_eq!(f.fake.count("oauth.v2.access"), 0);
    // A token that is not due needs no app.
    let live = f
        .connect("live", "oauth", &rotating(ROT_ACCESS, REFRESH, 3600))
        .await;
    f.slack.fresh(&f.cx(NOW), live.id).await.unwrap();
}

async fn suspect(f: &Fx, id: i64) {
    let signal = Signal::Upstream {
        status: UpstreamStatus::AuthFailed,
        retry_after: None,
        reset_at: None,
    };
    health::signal(&f.pool, 1, id, signal, NOW).await.unwrap();
}

#[tokio::test]
async fn a_renewal_does_not_clear_a_pending_auth_failure() {
    let f = fx_rotating(true).await;
    let served = f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    suspect(&f, c.id).await;
    let before = get(&f.pool, 1, c.id).await.unwrap();
    assert_eq!(before.state_reason.as_deref(), Some("auth_suspected"));
    f.slack.fresh(&f.cx(NOW), c.id).await.unwrap();
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
    let f = fx_rotating(true).await;
    f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    let cx = f.cx(NOW);
    let dropped = tokio::time::timeout(Duration::from_millis(40), f.slack.fresh(&cx, c.id)).await;
    assert!(
        dropped.is_err(),
        "the caller gave up while the token endpoint was answering"
    );
    tokio::time::sleep(Duration::from_millis(700)).await;
    let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(
        stored.refresh(),
        Some(REF2),
        "the rotated refresh token was sealed"
    );
}

#[tokio::test]
async fn the_lock_map_does_not_grow_with_every_connection_renewed() {
    let f = fx_rotating(true).await;
    f.fake.reply(
        "oauth.v2.access",
        Reply::ok(json!({"access_token": "xoxe.xoxb-test-111-222-acc9",
            "refresh_token": "xoxe-1-test-ref9-0a1b2c", "expires_in": 43200})),
    );
    for name in ["a1", "b1", "c1", "d1"] {
        let c = f
            .connect(name, "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
            .await;
        f.slack.fresh(&f.cx(NOW), c.id).await.unwrap();
    }
    assert!(f.slack.locks.lock().unwrap().len() <= 1);
}

#[tokio::test]
async fn a_renewal_slack_refuses_is_a_conclusive_rejection_and_a_failure_is_not() {
    let f = fx_rotating(true).await;
    f.fake
        .reply("oauth.v2.access", Reply::err("invalid_refresh_token"));
    let c = f
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    let t = f.slack.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(
        (t.status.as_str(), t.state_reason.as_deref()),
        ("disabled", Some("auth_failed"))
    );
    let g = fx_rotating(true).await;
    g.fake.reply("oauth.v2.access", Reply::http(503, json!({})));
    let c = g
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    let t = g.slack.test_connection(&g.cx(NOW), c.id).await.unwrap();
    assert_eq!(
        t.status, "active",
        "a 5xx on the token endpoint disables nothing"
    );
    g.fake.rotating();
    let t = g.slack.test_connection(&g.cx(NOW), c.id).await.unwrap();
    assert_eq!(t.identity, Some(format!("{BOT_USER} in {TEAM}")));
    let sent = g.fake.last("auth.test").unwrap();
    assert_eq!(
        sent.auth,
        Some(format!("Bearer {ACC2}")),
        "tested with the renewed token"
    );
}

#[tokio::test]
async fn a_changed_client_secret_disables_no_connection() {
    let f = fx_rotating(true).await;
    // Slack now only knows the NEW secret.
    f.fake.on("oauth.v2.access", |s| {
        if s.form["client_secret"] == "new-secret-5f3a" {
            Reply::ok(json!({"access_token": "xoxe.xoxb-test-111-222-acc7",
                "refresh_token": "xoxe-1-test-ref7-1a2b3c", "expires_in": 43200}))
        } else {
            Reply::err("bad_client_secret")
        }
    });
    let c = f
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    // The old secret is refused: that is Core's app registration, not the connection's credential.
    let t = f.slack.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(t.status, "active", "{:?}", t.state_reason);
    assert_ne!(t.state_reason.as_deref(), Some("auth_failed"));
    let e = f
        .slack
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e, CallError::AppConfig);
    assert_eq!(e.health(), None);
    // The admin enters the new secret: the same connection renews, with the refresh token it had.
    let new = OAuthApp::new("1234.5678", "new-secret-5f3a", REDIRECT);
    assert!(f.slack.set_app(new));
    let m = f.slack.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(m.refresh(), Some("xoxe-1-test-ref7-1a2b3c"));
    assert_eq!(
        f.fake.last("oauth.v2.access").unwrap().form["refresh_token"],
        REFRESH
    );
}

#[tokio::test]
async fn a_credential_a_person_stores_meanwhile_wins_over_a_renewal() {
    let f = fx_rotating(true).await;
    f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    let (l, pool, sealer) = (f.slack.clone(), f.pool.clone(), f.sealer.clone());
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
    // While the token endpoint is still answering (it takes 150 ms), a person stores a token.
    tokio::time::sleep(Duration::from_millis(50)).await;
    secret::replace(&f.pool, &f.sealer, c.id, &bot(), f.cx(NOW).who)
        .await
        .unwrap();
    let got = renewing.await.unwrap().unwrap();
    assert_eq!(
        got.access(),
        ACCESS,
        "the renewal hands back what is stored now"
    );
    let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!((stored.access(), stored.refresh()), (ACCESS, None));
}

#[tokio::test]
async fn a_verdict_about_an_old_credential_cannot_settle_a_new_one() {
    let f = fx_rotating(true).await;
    // The old refresh token is refused, slowly.
    f.fake.on("oauth.v2.access", |_| {
        Reply::err("invalid_refresh_token").delayed(200)
    });
    let c = f
        .connect("acme", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    let (l, pool, sealer) = (f.slack.clone(), f.pool.clone(), f.sealer.clone());
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
    secret::replace(&f.pool, &f.sealer, c.id, &bot(), f.cx(NOW).who)
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
