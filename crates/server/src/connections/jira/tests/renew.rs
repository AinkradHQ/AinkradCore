//! Renewing the token: rotation, single flight, no loop, the verdicts.

use std::sync::atomic::Ordering;
use std::time::Duration;

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::json;

use super::*;
use crate::connections::jira::cred::unpack;
use crate::connections::jira::{CallError, FlowError, Limit};
use crate::store::connections::health::{self, Signal};
use crate::store::connections::{get, secret, verdict};

#[tokio::test]
async fn concurrent_renewals_spend_the_refresh_token_once() {
    let f = fx(true).await;
    let served = f.fake.rotating();
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 30))
        .await;
    let cx = f.cx(NOW);
    let (a, b, d) = tokio::join!(
        f.jira.fresh(&cx, c.id),
        f.jira.fresh(&cx, c.id),
        f.jira.fresh(&cx, c.id)
    );
    for m in [a.unwrap(), b.unwrap(), d.unwrap()] {
        assert_eq!(
            m.access(),
            format!("oauth|{CLOUD}|{SITE}|acc2-7f3a9d41e0b2")
        );
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
        "the rotated token is what is sealed"
    );
    assert_eq!(stored.expires_at.as_deref(), Some(at(3600).as_str()));
    // Not due any more: nothing is spent. Due again later: the NEW refresh token is used.
    f.jira.fresh(&cx, c.id).await.unwrap();
    assert_eq!(f.fake.count("POST /oauth/token"), 1);
    let later = at(7200);
    let m = f.jira.fresh(&f.cx(&later), c.id).await.unwrap();
    assert_eq!(m.refresh(), Some("ref3-91c4d2b7a6e1"));
    let body = f.fake.last("POST /oauth/token").unwrap().body;
    assert_eq!(body["grant_type"], "refresh_token");
    assert_eq!(body["refresh_token"], "ref2-91c4d2b7a6e1");
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
    let m = f.jira.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(m.refresh(), Some(REFRESH));
    assert!(matches!(unpack(&m), Some(cred::Cred::Oauth { .. })));
}

#[tokio::test]
async fn a_refused_refresh_is_an_auth_failure_and_a_slow_service_is_not() {
    let f = fx(true).await;
    f.fake
        .reply("POST /oauth/token", 400, json!({"error": "invalid_grant"}));
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let e = f
        .jira
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e, CallError::AuthFailed);
    f.fake.reply("POST /oauth/token", 503, json!({}));
    let e = f
        .jira
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e, CallError::Upstream(503));
    let stored = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(
        stored.refresh(),
        Some(REFRESH),
        "a failed refresh leaves the credential as it was"
    );
}

#[tokio::test]
async fn a_401_renews_once_and_retries_once() {
    let f = fx(true).await;
    let served = f.fake.rotating();
    f.fake
        .on(&format!("GET {}", oauth_path("/issue/ABC-1")), |s| {
            if s.auth.as_deref() == Some("Bearer acc2-7f3a9d41e0b2") {
                Reply::json(
                    200,
                    json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"}}}),
                )
            } else {
                Reply::json(401, json!({}))
            }
        });
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 3600))
        .await;
    let v = f
        .jira
        .call(
            &f.cx(NOW),
            &c,
            &Limit::any(),
            "jira.get_issue",
            &json!({"key": "ABC-1"}),
        )
        .await;
    assert_eq!(v.unwrap()["key"], "ABC-1");
    assert_eq!(served.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.fake.count(&format!("GET {}", oauth_path("/issue/ABC-1"))),
        2
    );
    // A service that keeps saying 401: one refresh, one retry, then the failure.
    let g = fx(true).await;
    let served = g.fake.rotating();
    g.fake.reply(
        &format!("GET {}", oauth_path("/issue/ABC-1")),
        401,
        json!({}),
    );
    let c = g
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 3600))
        .await;
    let e = g
        .jira
        .call(
            &g.cx(NOW),
            &c,
            &Limit::any(),
            "jira.get_issue",
            &json!({"key": "ABC-1"}),
        )
        .await;
    assert_eq!(e.unwrap_err(), CallError::AuthFailed);
    assert_eq!(served.load(Ordering::SeqCst), 1);
    // And it does not loop: a fresh token that is refused again is not a reason to spend another
    // refresh token (it was renewed less than the skew ago).
    let args = json!({"key": "ABC-1"});
    let e = g
        .jira
        .call(&g.cx(NOW), &c, &Limit::any(), "jira.get_issue", &args)
        .await;
    assert_eq!(e.unwrap_err(), CallError::AuthFailed);
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "no second refresh within the skew"
    );
    assert_eq!(
        g.fake.count(&format!("GET {}", oauth_path("/issue/ABC-1"))),
        3,
        "two calls for the first (401, renew, retry), one for the second (no renewal)"
    );
}

#[tokio::test]
async fn an_oauth_connection_tests_with_the_scopes_it_asked_for() {
    let f = fx(true).await;
    f.fake.reply(
        "GET /me",
        200,
        json!({"account_id": "5b10ac8d", "name": "Ann Lee"}),
    );
    let m = oauth(ACCESS, REFRESH, 3600);
    let c = f.connect("acme", "oauth", &m).await;
    let who = f.cx(NOW).who;
    let t = verdict::run_test(&f.pool, &f.sealer, &f.reg, c.id, who)
        .await
        .unwrap();
    assert_eq!(t.status, "active", "{:?}", t.state_reason);
    assert!(t.identity.is_some());
    assert_eq!(
        f.fake.count(&format!("GET {}", oauth_path("/myself"))),
        0,
        "/myself needs read:jira-user"
    );
    // The fake enforces scopes: without read:me even /me is refused, so the test would notice.
    f.fake.grant_scopes(&["read:jira-work"]);
    let far = oauth(ACCESS, REFRESH, 3600 * 24 * 365 * 30);
    let rejected = f.jira.test(&far).await.map(|_| ());
    assert_eq!(
        rejected,
        Err(crate::connections::adapter::TestError::Rejected)
    );
    // And the calls the operations make are covered by the requested scopes.
    f.fake.grant_scopes(&["read:jira-work", "write:jira-work"]);
    let ok = json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"}}});
    f.fake
        .reply(&format!("GET {}", oauth_path("/issue/ABC-1")), 200, ok);
    let args = json!({"key": "ABC-1"});
    f.jira
        .call(&f.cx(NOW), &c, &Limit::any(), "jira.get_issue", &args)
        .await
        .unwrap();
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
    f.jira.fresh(&f.cx(NOW), c.id).await.unwrap();
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
    let dropped = tokio::time::timeout(Duration::from_millis(40), f.jira.fresh(&cx, c.id)).await;
    assert!(
        dropped.is_err(),
        "the caller gave up while the token endpoint was still answering"
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
        json!({"access_token": "acc9-0a1b2c3d4e5f", "refresh_token": "ref9-0a1b2c3d4e5f", "expires_in": 3600}),
    );
    for name in ["a1", "b1", "c1", "d1"] {
        let c = f.connect(name, "oauth", &oauth(ACCESS, REFRESH, 10)).await;
        f.jira.fresh(&f.cx(NOW), c.id).await.unwrap();
    }
    assert!(f.jira.locks.lock().unwrap().len() <= 1);
}

#[tokio::test]
async fn one_user_cannot_fill_the_waiting_sign_ins() {
    let f = fx(true).await;
    for _ in 0..8 {
        f.jira.start(1, REDIRECT, None).unwrap();
    }
    assert_eq!(
        f.jira.start(1, REDIRECT, None),
        Err(FlowError::TooManyFlows)
    );
    assert!(
        f.jira.start(2, REDIRECT, None).is_ok(),
        "another user is not affected"
    );
}

#[tokio::test]
async fn a_renewal_the_service_refuses_is_a_conclusive_rejection() {
    let f = fx(true).await;
    f.fake
        .reply("POST /oauth/token", 400, json!({"error": "invalid_grant"}));
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let t = f.jira.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(
        (t.status.as_str(), t.state_reason.as_deref()),
        ("disabled", Some("auth_failed"))
    );
    // The generic test cannot renew: an expired token is inconclusive there, never a rejection.
    let g = fx(true).await;
    g.fake
        .reply("POST /oauth/token", 400, json!({"error": "invalid_grant"}));
    g.fake.reply("GET /me", 401, json!({}));
    let m = oauth(ACCESS, REFRESH, -3600 * 24 * 365 * 10);
    let c = g.connect("acme", "oauth", &m).await;
    let t = verdict::run_test(&g.pool, &g.sealer, &g.reg, c.id, g.cx(NOW).who)
        .await
        .unwrap();
    assert_eq!(t.status, "active");
}

#[tokio::test]
async fn a_renewal_that_only_failed_is_inconclusive_and_one_that_works_then_tests() {
    let f = fx(true).await;
    f.fake.reply("POST /oauth/token", 503, json!({}));
    let c = f
        .connect("acme", "oauth", &oauth(ACCESS, REFRESH, 10))
        .await;
    let t = f.jira.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(
        t.status, "active",
        "a 5xx on the token endpoint disables nothing"
    );
    f.fake.reply(
        "GET /me",
        200,
        json!({"account_id": "5b10ac8d", "name": "Ann Lee"}),
    );
    f.fake.rotating();
    let t = f.jira.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(
        t.identity.as_deref(),
        Some("5b10ac8d at https://acme.atlassian.net")
    );
    let sent = f.fake.last("GET /me").unwrap();
    assert_eq!(
        sent.auth.as_deref(),
        Some("Bearer acc2-7f3a9d41e0b2"),
        "tested with the renewed token"
    );
}
