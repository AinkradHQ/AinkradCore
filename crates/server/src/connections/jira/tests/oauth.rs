//! Sign in with Atlassian and the token's life: PKCE, state, exchange, discovery, rotation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::json;

use super::*;
use crate::connections::jira::cred::unpack;
use crate::connections::jira::oauth::s256;
use crate::connections::jira::{CallError, FlowError, Limit};
use crate::store::connections::health::{self, Signal};
use crate::store::connections::{get, secret, verdict};

fn param(url: &str, k: &str) -> Option<String> {
    let u = reqwest::Url::parse(url).unwrap();
    let found = u.query_pairs().find(|(name, _)| name == k);
    found.map(|(_, v)| v.into_owned())
}

fn issue_tokens(f: &Fake) {
    f.reply(
        "POST /oauth/token",
        200,
        json!({"access_token": ACCESS, "refresh_token": REFRESH, "expires_in": 3600,
            "scope": "read:jira-work offline_access"}),
    );
    f.reply(
        "GET /oauth/token/accessible-resources",
        200,
        json!([
            {"id": CLOUD, "url": SITE, "name": "Acme", "scopes": ["read:jira-work"]},
            {"id": "7d0c4b1e-0000-4000-8000-000000000001", "url": "https://wiki.atlassian.net",
             "name": "Wiki", "scopes": ["read:confluence-content.all"]},
            {"id": "../etc", "url": SITE, "name": "Bad", "scopes": ["read:jira-work"]},
        ]),
    );
}

#[tokio::test]
async fn the_authorize_url_carries_state_pkce_and_offline_access() {
    let f = fx(true).await;
    let s = f.jira.start(1, REDIRECT, None).unwrap();
    let u = &s.authorize_url;
    assert!(u.contains("/authorize?"), "{u}");
    assert_eq!(param(u, "state").as_deref(), Some(s.state.as_str()));
    assert_eq!(param(u, "client_id").as_deref(), Some("client-id-8c41"));
    assert_eq!(param(u, "redirect_uri").as_deref(), Some(REDIRECT));
    assert_eq!(param(u, "audience").as_deref(), Some("api.atlassian.com"));
    assert_eq!(param(u, "response_type").as_deref(), Some("code"));
    assert_eq!(param(u, "code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(param(u, "code_challenge").unwrap().len(), 43);
    assert!(param(u, "scope").unwrap().contains("offline_access"));
    assert!(
        !u.contains(CLIENT_SECRET),
        "the client secret is never in the URL"
    );
    let other = f.jira.start(1, REDIRECT, None).unwrap();
    assert_ne!(other.state, s.state);
}

#[tokio::test]
async fn without_an_app_registered_start_is_a_plain_refusal() {
    let f = fx(false).await;
    let e = f.jira.start(1, REDIRECT, None).unwrap_err();
    assert_eq!(e, FlowError::NotConfigured);
    assert!(e.to_string().contains("not set up"), "{e}");
    let one = [REDIRECT];
    assert!(OAuthApp::new("", "x", &one).is_none() && OAuthApp::new("x", " ", &one).is_none());
    assert!(
        !format!(
            "{:?}",
            OAuthApp::new("id-1", CLIENT_SECRET, &[REDIRECT]).unwrap()
        )
        .contains("clsec")
    );
}

#[tokio::test]
async fn only_the_registered_redirect_uris_are_accepted() {
    let f = fx(true).await;
    let userinfo = format!("http://u:p{}127.0.0.1:53682/callback", '@');
    let bad = [
        "http://evil.test:53682/callback",
        "http://127.0.0.1/callback",
        "http://127.0.0.1:53683/callback",
        "http://127.0.0.1:53682/callback/",
        "http://127.0.0.1:53682/callback?x=1",
        "http://127.0.0.1:53682/callback#frag",
        "http://localhost:53682/callback",
        "http://[::1]:53682/callback",
        "https://core.example.com/callback",
        "https://127.0.0.1:53682/callback",
        "http://127.0.0.1.evil.test:53682/callback",
        "ftp://127.0.0.1:53682/callback",
        "javascript:alert(1)",
        "not a url",
        userinfo.as_str(),
    ];
    for b in bad {
        assert_eq!(f.jira.start(1, b, None), Err(FlowError::BadRedirect), "{b}");
    }
    assert!(f.jira.start(1, REDIRECT, None).is_ok());
    assert_eq!(
        f.jira.start(1, REDIRECT, Some("short")),
        Err(FlowError::BadChallenge)
    );
    // What may be registered at all: fixed loopback http addresses, nothing else.
    let new = |r: &[&str]| OAuthApp::new("id-1", "secret-1", r);
    assert!(new(&["http://127.0.0.1:5/cb", "http://[::1]:5/cb"]).is_some());
    for r in [
        &[][..],
        &["http://localhost:5/cb"],
        &["https://core.example.com/cb"],
        &["http://127.0.0.1/cb"],
        &["http://127.0.0.1:5/cb", "http://evil.test:5/cb"],
        &["http://127.0.0.1:5/cb?a=1"],
    ] {
        assert!(new(r).is_none(), "{r:?}");
    }
}

#[tokio::test]
async fn the_code_is_exchanged_with_pkce_then_sealed_and_tested() {
    let f = fx(true).await;
    issue_tokens(&f.fake);
    f.fake.reply(
        "GET /me",
        200,
        json!({"account_id": "5b10ac8d", "name": "Ann Lee"}),
    );
    let s = f.jira.start(1, REDIRECT, None).unwrap();
    let done = f
        .jira
        .finish(1, &s.state, "code-xyz", None, NOW)
        .await
        .unwrap();
    let body = f.fake.last("POST /oauth/token").unwrap().body;
    assert_eq!(body["grant_type"], "authorization_code");
    assert_eq!(body["code"], "code-xyz");
    assert_eq!(body["redirect_uri"], REDIRECT);
    assert_eq!(body["client_secret"], CLIENT_SECRET);
    let challenge = param(&s.authorize_url, "code_challenge").unwrap();
    assert_eq!(s256(body["code_verifier"].as_str().unwrap()), challenge);
    let auth = f
        .fake
        .last("GET /oauth/token/accessible-resources")
        .unwrap()
        .auth;
    assert_eq!(auth.as_deref(), Some(format!("Bearer {ACCESS}").as_str()));
    // Only the Jira site with a valid id is offered.
    assert_eq!(done.sites.len(), 1);
    assert_eq!(
        (done.sites[0].cloud_id.as_str(), done.sites[0].name.as_str()),
        (CLOUD, "Acme")
    );
    assert!(!format!("{done:?}").contains("7f3a9d41"));

    let m = done.material_for(&done.sites[0]).unwrap();
    assert_eq!(m.expires_at.as_deref(), Some(at(3600).as_str()));
    let c = f.connect("acme", "oauth", &m).await;
    let who = f.cx(NOW).who;
    let tested = verdict::run_test(&f.pool, &f.sealer, &f.reg, c.id, who)
        .await
        .unwrap();
    assert_eq!(
        tested.identity.as_deref(),
        Some("5b10ac8d at https://acme.atlassian.net")
    );
    let sent = f.fake.last("GET /me").unwrap();
    assert_eq!(
        sent.auth.as_deref(),
        Some(format!("Bearer {ACCESS}").as_str())
    );
    let opened = secret::open(&f.pool, &f.sealer, 1, c.id).await.unwrap().0;
    assert_eq!(opened.refresh(), Some(REFRESH));
}

#[tokio::test]
async fn a_wrong_expired_reused_or_foreign_state_is_refused() {
    let f = fx(true).await;
    issue_tokens(&f.fake);
    let go = |user, state: &str| {
        let jira = f.jira.clone();
        let state = state.to_owned();
        async move {
            jira.finish(user, &state, "code", None, NOW)
                .await
                .map(|_| ())
        }
    };
    assert_eq!(go(1, "made-up").await, Err(FlowError::UnknownState));
    let s = f.jira.start(1, REDIRECT, None).unwrap();
    // Another user cannot spend it, and trying does not spend it either.
    assert_eq!(go(2, &s.state).await, Err(FlowError::UnknownState));
    assert_eq!(f.fake.count("POST /oauth/token"), 0);
    assert_eq!(go(1, &s.state).await, Ok(()));
    assert_eq!(
        go(1, &s.state).await,
        Err(FlowError::UnknownState),
        "single use"
    );
    let e = f.jira.start(1, REDIRECT, None).unwrap();
    f.jira
        .flows
        .lock()
        .unwrap()
        .get_mut(&e.state)
        .unwrap()
        .expires = Instant::now() - Duration::from_secs(1);
    assert_eq!(
        go(1, &e.state).await,
        Err(FlowError::UnknownState),
        "expired"
    );
    assert_eq!(
        f.fake.count("POST /oauth/token"),
        1,
        "nothing was exchanged for a refused state"
    );
}

#[tokio::test]
async fn an_app_made_verifier_must_match_its_challenge() {
    let f = fx(true).await;
    issue_tokens(&f.fake);
    let verifier = "v".repeat(64);
    let s = f.jira.start(1, REDIRECT, Some(&s256(&verifier))).unwrap();
    let wrong = f
        .jira
        .finish(1, &s.state, "c", Some("not-the-verifier"), NOW)
        .await;
    assert_eq!(wrong.map(|_| ()), Err(FlowError::BadVerifier));
    assert_eq!(f.fake.count("POST /oauth/token"), 0);
    let s = f.jira.start(1, REDIRECT, Some(&s256(&verifier))).unwrap();
    assert_eq!(
        f.jira.finish(1, &s.state, "c", None, NOW).await.map(|_| ()),
        Err(FlowError::BadVerifier)
    );
    let s = f.jira.start(1, REDIRECT, Some(&s256(&verifier))).unwrap();
    f.jira
        .finish(1, &s.state, "c", Some(&verifier), NOW)
        .await
        .unwrap();
    assert_eq!(
        f.fake.last("POST /oauth/token").unwrap().body["code_verifier"],
        verifier.as_str()
    );
}

#[tokio::test]
async fn a_refused_code_or_a_missing_refresh_token_fails_plainly() {
    let f = fx(true).await;
    f.fake
        .reply("POST /oauth/token", 403, json!({"error": "access_denied"}));
    let s = f.jira.start(1, REDIRECT, None).unwrap();
    let e = f
        .jira
        .finish(1, &s.state, "c", None, NOW)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e, FlowError::Exchange(CallError::AuthFailed));
    assert!(!e.to_string().contains("access_denied"));
    f.fake.reply(
        "POST /oauth/token",
        200,
        json!({"access_token": ACCESS, "expires_in": 3600}),
    );
    let s = f.jira.start(1, REDIRECT, None).unwrap();
    let e = f
        .jira
        .finish(1, &s.state, "c", None, NOW)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e, FlowError::NoRefreshToken);
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
