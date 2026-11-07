//! Sign in with Linear: authorize address, PKCE, state, the form-encoded exchange, who signed in,
//! and the credential test.

use serde_json::json;

use super::*;
use crate::connections::adapter::TestError;
use crate::connections::linear::oauth::s256;
use crate::connections::linear::{CallError, FlowError};
use crate::store::connections::verdict;

fn param(url: &str, k: &str) -> Option<String> {
    let u = reqwest::Url::parse(url).unwrap();
    let found = u.query_pairs().find(|(name, _)| name == k);
    found.map(|(_, v)| v.into_owned())
}

fn issue_tokens(f: &Fake) {
    f.reply(
        "POST /oauth/token",
        200,
        // `scope` is an array for apps made before Dec 2023; it must not matter.
        json!({"access_token": ACCESS, "token_type": "Bearer", "refresh_token": REFRESH,
            "expires_in": 86399, "scope": ["read", "issues:create"]}),
    );
}

#[tokio::test]
async fn the_authorize_url_carries_state_pkce_and_comma_separated_scopes() {
    let f = fx(true).await;
    let s = f.linear.start(1, REDIRECT, None).unwrap();
    let u = &s.authorize_url;
    assert!(u.contains("/oauth/authorize?"), "{u}");
    assert_eq!(param(u, "state").as_deref(), Some(s.state.as_str()));
    assert_eq!(param(u, "client_id").as_deref(), Some("client-id-8c41"));
    assert_eq!(param(u, "redirect_uri").as_deref(), Some(REDIRECT));
    assert_eq!(param(u, "response_type").as_deref(), Some("code"));
    assert_eq!(param(u, "code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(param(u, "code_challenge").unwrap().len(), 43);
    let scope = param(u, "scope").unwrap();
    assert_eq!(scope, "read,issues:create,comments:create");
    for broad in ["write", "admin"] {
        assert!(!scope.split(',').any(|x| x == broad), "{broad}");
    }
    assert!(
        !u.contains(CLIENT_SECRET),
        "the client secret is never in the URL"
    );
    let other = f.linear.start(1, REDIRECT, None).unwrap();
    assert_ne!(other.state, s.state);
    assert_ne!(
        param(&other.authorize_url, "code_challenge"),
        param(u, "code_challenge")
    );
}

#[tokio::test]
async fn without_an_app_registered_start_is_a_plain_refusal() {
    let f = fx(false).await;
    let e = f.linear.start(1, REDIRECT, None).unwrap_err();
    assert_eq!(e, FlowError::NotConfigured);
    assert!(e.to_string().contains("not set up"), "{e}");
    let one = [REDIRECT];
    assert!(OAuthApp::new("", "x", &one).is_none() && OAuthApp::new("x", " ", &one).is_none());
    let app = OAuthApp::new("id-1", CLIENT_SECRET, &[REDIRECT]).unwrap();
    assert!(!format!("{app:?}").contains("clsec"));
    assert_eq!(f.linear.pending(), 0);
}

#[tokio::test]
async fn only_the_registered_redirect_uris_are_accepted() {
    let f = fx(true).await;
    let userinfo = format!("http://u:p{}127.0.0.1:53682/callback", '@');
    let bad = [
        "http://127.0.0.1:53682/callback/",
        "http://127.0.0.1:53682/callbackx",
        "http://127.0.0.1:53683/callback",
        "http://localhost:53682/callback",
        "https://127.0.0.1:53682/callback",
        "http://127.0.0.1:53682/callback?x=1",
        "http://127.0.0.1/callback",
        "http://evil.test/callback",
        "",
        userinfo.as_str(),
    ];
    for r in bad {
        assert_eq!(
            f.linear.start(1, r, None),
            Err(FlowError::BadRedirect),
            "{r}"
        );
    }
    assert_eq!(f.linear.pending(), 0);
    // What may be REGISTERED is only a fixed loopback address.
    for r in [
        "https://app.example/cb",
        "http://localhost:8000/cb",
        "http://127.0.0.1/cb",
        "http://127.0.0.1:8000/cb?x=1",
        "http://127.0.0.1:8000/cb#f",
        "http://0.0.0.0:8000/cb",
        "custom-scheme://cb",
    ] {
        assert!(OAuthApp::new("id", "secret", &[r]).is_none(), "{r}");
    }
    assert!(OAuthApp::new("id", "secret", &["http://[::1]:8000/cb"]).is_some());
    assert!(OAuthApp::new("id", "secret", &[]).is_none());
}

#[tokio::test]
async fn a_finished_sign_in_exchanges_a_form_with_the_verifier_and_reads_who_signed_in() {
    let f = fx(true).await;
    issue_tokens(&f.fake);
    let s = f.linear.start(1, REDIRECT, None).unwrap();
    let challenge = param(&s.authorize_url, "code_challenge").unwrap();
    let fin = f
        .linear
        .finish(1, &s.state, "code-3b9f6e2d", None, NOW)
        .await
        .unwrap();
    assert_eq!(fin.workspace, ORG);
    let seen = f.fake.last("POST /oauth/token").unwrap();
    assert!(
        seen.content_type
            .as_deref()
            .is_some_and(|c| c.starts_with("application/x-www-form-urlencoded")),
        "Linear's token endpoint takes a form, not JSON: {:?}",
        seen.content_type
    );
    assert_eq!(f.fake.bad(), 0);
    let b = &seen.body;
    assert_eq!(b["grant_type"], "authorization_code");
    assert_eq!(b["client_id"], "client-id-8c41");
    assert_eq!(b["client_secret"], CLIENT_SECRET);
    assert_eq!(b["code"], "code-3b9f6e2d");
    assert_eq!(b["redirect_uri"], REDIRECT);
    // The verifier Core kept is the one the challenge in the authorize URL commits to.
    assert_eq!(s256(b["code_verifier"].as_str().unwrap()), challenge);
    // Who signed in was read with the new token as a Bearer.
    assert_eq!(
        f.fake.last("GQL Viewer").unwrap().auth,
        Some(format!("Bearer {ACCESS}"))
    );
    let text = format!("{fin:?}");
    for secret in [ACCESS, REFRESH] {
        assert!(!text.contains(secret), "{text}");
    }
    let m = fin.material().unwrap();
    assert_eq!(m.refresh(), Some(REFRESH));
    assert_eq!(m.expires_at.as_deref(), Some(at(86399).as_str()));
    // Stored and tested as a connection: the identity names the user and the workspace.
    let c = f.connect("acme", "oauth", &m).await;
    let tested = verdict::run_test(&f.pool, &f.sealer, &f.reg, c.id, f.cx(NOW).who)
        .await
        .unwrap();
    assert_eq!(tested.identity, Some(format!("{ME} at {ORG}")));
}

#[tokio::test]
async fn a_state_is_spent_once_by_its_own_user_and_a_code_must_be_text() {
    let f = fx(true).await;
    issue_tokens(&f.fake);
    let s = f.linear.start(1, REDIRECT, None).unwrap();
    // Another user cannot finish it, and does not spend it.
    let e = f.linear.finish(2, &s.state, "code-1", None, NOW).await;
    assert!(matches!(e, Err(FlowError::UnknownState)));
    // A made-up state.
    let e = f.linear.finish(1, "nope", "code-1", None, NOW).await;
    assert!(matches!(e, Err(FlowError::UnknownState)));
    assert_eq!(f.fake.count("POST /oauth/token"), 0);
    // A code that is no text is refused, and the attempt spends the state.
    let long = "x".repeat(2049);
    for code in ["", "a\nb", long.as_str()] {
        let s = f.linear.start(1, REDIRECT, None).unwrap();
        let e = f.linear.finish(1, &s.state, code, None, NOW).await;
        assert!(matches!(e, Err(FlowError::BadCode)), "{code:?}");
        let again = f.linear.finish(1, &s.state, "code-1", None, NOW).await;
        assert!(matches!(again, Err(FlowError::UnknownState)));
    }
    // The first good finish spends it: a replay finds nothing.
    let s = f.linear.start(1, REDIRECT, None).unwrap();
    f.linear
        .finish(1, &s.state, "code-1", None, NOW)
        .await
        .unwrap();
    let again = f.linear.finish(1, &s.state, "code-1", None, NOW).await;
    assert!(matches!(again, Err(FlowError::UnknownState)));
    assert_eq!(f.fake.count("POST /oauth/token"), 1);
    // A cancelled sign-in is gone; another user's cancel does nothing.
    let s = f.linear.start(1, REDIRECT, None).unwrap();
    let before = f.linear.pending();
    f.linear.cancel(2, &s.state);
    assert_eq!(f.linear.pending(), before);
    f.linear.cancel(1, &s.state);
    assert_eq!(f.linear.pending(), before - 1);
}

#[tokio::test]
async fn an_app_made_verifier_must_match_the_challenge_it_started_with() {
    let f = fx(true).await;
    issue_tokens(&f.fake);
    let verifier = "v".repeat(64);
    let s = f.linear.start(1, REDIRECT, Some(&s256(&verifier))).unwrap();
    let e = f.linear.finish(1, &s.state, "c1", None, NOW).await;
    assert!(matches!(e, Err(FlowError::BadVerifier)));
    let s = f.linear.start(1, REDIRECT, Some(&s256(&verifier))).unwrap();
    let e = f.linear.finish(1, &s.state, "c1", Some("w"), NOW).await;
    assert!(matches!(e, Err(FlowError::BadVerifier)));
    let s = f.linear.start(1, REDIRECT, Some(&s256(&verifier))).unwrap();
    f.linear
        .finish(1, &s.state, "c1", Some(&verifier), NOW)
        .await
        .unwrap();
    assert_eq!(
        f.fake.last("POST /oauth/token").unwrap().body["code_verifier"],
        verifier
    );
    let (bang, long) = ("!".repeat(43), "a".repeat(44));
    for bad in ["short", bang.as_str(), long.as_str()] {
        assert_eq!(
            f.linear.start(1, REDIRECT, Some(bad)),
            Err(FlowError::BadChallenge)
        );
    }
}

#[tokio::test]
async fn the_exchange_fails_into_plain_errors() {
    let f = fx(true).await;
    let finish = |f: &Fx| {
        let s = f.linear.start(1, REDIRECT, None).unwrap();
        let l = f.linear.clone();
        async move { l.finish(1, &s.state, "c1", None, NOW).await.map(|_| ()) }
    };
    f.fake
        .reply("POST /oauth/token", 400, json!({"error": "invalid_grant"}));
    let e = finish(&f).await.unwrap_err();
    assert_eq!(e, FlowError::Exchange(CallError::AuthFailed));
    f.fake
        .reply("POST /oauth/token", 401, json!({"error": "invalid_client"}));
    let e = finish(&f).await.unwrap_err();
    assert_eq!(e, FlowError::Exchange(CallError::AppConfig));
    f.fake.reply("POST /oauth/token", 503, json!({}));
    let e = finish(&f).await.unwrap_err();
    assert_eq!(e, FlowError::Exchange(CallError::Upstream(503)));
    f.fake.reply(
        "POST /oauth/token",
        200,
        json!({"access_token": ACCESS, "expires_in": 3600}),
    );
    assert_eq!(finish(&f).await.unwrap_err(), FlowError::NoRefreshToken);
    // Tokens issued, but who they belong to cannot be read: no connection is made.
    issue_tokens(&f.fake);
    f.fake
        .on("GQL Viewer", |_| Reply::error(401, "AUTHENTICATION_ERROR"));
    let e = finish(&f).await.unwrap_err();
    assert_eq!(e, FlowError::Exchange(CallError::AuthFailed));
    f.fake.data("Viewer", json!({"viewer": {"id": ME}}));
    let e = finish(&f).await.unwrap_err();
    assert!(
        matches!(e, FlowError::Exchange(CallError::Upstream(200))),
        "{e:?}"
    );
    // Not one error text carries a secret.
    let text = e.to_string();
    for secret in [ACCESS, REFRESH, CLIENT_SECRET] {
        assert!(!text.contains(secret));
    }
}

#[tokio::test]
async fn pending_sign_ins_are_capped_and_end_when_the_app_changes() {
    let f = fx(true).await;
    for _ in 0..8 {
        f.linear.start(1, REDIRECT, None).unwrap();
    }
    assert_eq!(
        f.linear.start(1, REDIRECT, None),
        Err(FlowError::TooManyFlows)
    );
    f.linear.start(2, REDIRECT, None).unwrap();
    assert_eq!(f.linear.pending(), 9);
    // The same app written again changes nothing; a different one ends every pending sign-in.
    let same = OAuthApp::new("client-id-8c41", CLIENT_SECRET, &[REDIRECT]);
    assert!(!f.linear.set_app(same));
    assert_eq!(f.linear.pending(), 9);
    let rotated = OAuthApp::new("client-id-8c41", "new-secret-5f3a", &[REDIRECT]);
    assert!(f.linear.set_app(rotated));
    assert_eq!(f.linear.pending(), 0);
    assert!(f.linear.set_app(None));
    assert!(!f.linear.app_configured() && f.linear.redirects().is_empty());
}

#[tokio::test]
async fn the_credential_test_is_the_viewer_and_a_refusal_is_only_conclusive_when_fresh() {
    let f = fx(true).await;
    let ok = f.linear.test(&key()).await.unwrap();
    assert_eq!(ok.subject, format!("{ME} at {ORG}"));
    // A token without the scope Linear needs is refused: a rejection for a live token ...
    f.fake.grant_scopes(&[]);
    assert_eq!(f.linear.test(&key()).await, Err(TestError::Rejected));
    // (live by the real clock, which `test` reads: far in the future)
    let live = oauth_material(ACCESS, REFRESH, Some("2999-01-01T00:00:00.000Z")).unwrap();
    assert_eq!(f.linear.test(&live).await, Err(TestError::Rejected));
    // ... but nothing is concluded about a token that is past its expiry.
    let past = oauth_material(ACCESS, REFRESH, Some("2020-01-01T00:00:00.000Z")).unwrap();
    assert_eq!(f.linear.test(&past).await, Err(TestError::Inconclusive));
    f.fake.grant_scopes(&["read"]);
    // Rate limits, outages and unreadable answers say nothing about the credential.
    for reply in [
        Reply::error(429, "RATELIMITED"),
        Reply::json(503, json!({})),
        Reply::error(200, "FORBIDDEN"),
        Reply::json(200, json!({"data": {"viewer": {"id": ME}}})),
        Reply::data(json!({"viewer": {"id": "", "organization": {"urlKey": ORG}}})),
    ] {
        f.fake.on("GQL Viewer", move |_| reply.clone());
        assert_eq!(f.linear.test(&key()).await, Err(TestError::Inconclusive));
    }
    // A material that is not a usable credential is no verdict either.
    let junk = crate::connections::material::Material::new("short", None, None).unwrap();
    assert_eq!(f.linear.test(&junk).await, Err(TestError::Inconclusive));
}
