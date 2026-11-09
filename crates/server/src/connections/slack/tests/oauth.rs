//! Add to Slack: authorize address, `state`, the form-encoded exchange, which workspace and which
//! kind of token signed in, and the credential test.

use serde_json::{Value, json};

use super::*;
use crate::connections::adapter::TestError;
use crate::connections::slack::{CallError, FlowError, SCOPES};
use crate::store::connections::verdict;

fn param(url: &str, k: &str) -> Option<String> {
    let u = reqwest::Url::parse(url).unwrap();
    let found = u.query_pairs().find(|(name, _)| name == k);
    found.map(|(_, v)| v.into_owned())
}

/// What `oauth.v2.access` answers for a bot install; `authed_user` carries a USER token that must
/// never be read.
fn install() -> Value {
    json!({"access_token": ACCESS, "token_type": "bot", "scope": "channels:read,chat:write",
        "bot_user_id": BOT_USER, "app_id": "A012AB3CD", "team": {"id": TEAM, "name": "Acme"},
        "enterprise": null, "is_enterprise_install": false,
        "authed_user": {"id": "U999AB3CD", "scope": "identify", "access_token": "xoxp-test-user-leak",
            "token_type": "user"}})
}

fn issue(f: &Fake, body: Value) {
    f.reply("oauth.v2.access", Reply::ok(body));
}

#[tokio::test]
async fn the_authorize_url_asks_for_bot_scopes_only_and_carries_state() {
    let f = fx(true).await;
    let s = f.slack.start(1, REDIRECT, None).unwrap();
    let u = &s.authorize_url;
    assert!(u.contains("/oauth/v2/authorize?"), "{u}");
    assert_eq!(param(u, "state").as_deref(), Some(s.state.as_str()));
    assert_eq!(param(u, "client_id").as_deref(), Some("1234.5678"));
    assert_eq!(param(u, "redirect_uri").as_deref(), Some(REDIRECT));
    let scope = param(u, "scope").unwrap();
    assert_eq!(scope, SCOPES);
    for never in [
        "im:",
        "mpim:",
        "chat:write.public",
        "chat:write.customize",
        "users:read.email",
        "files:",
        "admin",
        "manage",
        "identify",
    ] {
        assert!(!scope.contains(never), "{never}");
    }
    // A bot only: no user scope, and Slack has no PKCE to ask for.
    for never in [
        "user_scope",
        "code_challenge",
        "code_challenge_method",
        "response_type",
        "team",
    ] {
        assert!(param(u, never).is_none(), "{never}");
    }
    assert!(
        !u.contains(CLIENT_SECRET),
        "the client secret is never in the URL"
    );
    let other = f.slack.start(1, REDIRECT, None).unwrap();
    assert_ne!(other.state, s.state);
    // The workspace a re-sign-in must land in is only a hint, and only when it is a workspace id.
    let hinted = f.slack.start(1, REDIRECT, Some(TEAM)).unwrap();
    assert_eq!(param(&hinted.authorize_url, "team").as_deref(), Some(TEAM));
    for junk in ["Acme", "E012AB3CD", "T012&scope=admin", ""] {
        let s = f.slack.start(1, REDIRECT, Some(junk)).unwrap();
        assert!(param(&s.authorize_url, "team").is_none(), "{junk:?}");
        assert_eq!(param(&s.authorize_url, "scope").as_deref(), Some(SCOPES));
    }
}

#[tokio::test]
async fn without_an_app_registered_start_is_a_plain_refusal() {
    let f = fx(false).await;
    let e = f.slack.start(1, REDIRECT, None).unwrap_err();
    assert_eq!(e, FlowError::NotConfigured);
    assert!(e.to_string().contains("not set up"), "{e}");
    assert!(
        OAuthApp::new("", "x", REDIRECT).is_none() && OAuthApp::new("x", " ", REDIRECT).is_none()
    );
    let app = OAuthApp::new("id-1", CLIENT_SECRET, REDIRECT).unwrap();
    assert!(!format!("{app:?}").contains("clsec"));
    assert_eq!(f.slack.pending(), 0);
}

#[tokio::test]
async fn only_the_registered_https_redirect_is_accepted_and_a_loopback_one_never_registers() {
    let f = fx(true).await;
    let userinfo = format!(
        "https://u:p{}core.example.test/connections/slack/callback",
        '@'
    );
    let bad = [
        "https://core.example.test/connections/slack/callback/",
        "https://core.example.test/connections/slack/callbackx",
        "https://core.example.test/connections/slack",
        "https://other.example.test/connections/slack/callback",
        "http://core.example.test/connections/slack/callback",
        "https://core.example.test:8443/connections/slack/callback",
        "https://core.example.test/connections/slack/callback?x=1",
        "https://core.example.test/connections/slack/callback#f",
        "http://127.0.0.1:47613/callback",
        "https://127.0.0.1/connections/slack/callback",
        "",
        userinfo.as_str(),
    ];
    for r in bad {
        assert_eq!(
            f.slack.start(1, r, None),
            Err(FlowError::BadRedirect),
            "{r}"
        );
    }
    assert_eq!(f.slack.pending(), 0);
    // What may be REGISTERED is only a fixed https address of a host name: Slack refuses the
    // Mac app's loopback `http` catcher.
    for r in [
        "http://127.0.0.1:47613/callback",
        "http://localhost:8000/cb",
        "http://core.example.test/cb",
        "https://127.0.0.1/cb",
        "https://[::1]/cb",
        "https://core.example.test:8443/cb",
        "https://core.example.test/cb?x=1",
        "https://core.example.test/cb#f",
        "https://u:p@core.example.test/cb",
        "custom-scheme://cb",
        "",
    ] {
        assert!(OAuthApp::new("id", "secret", r).is_none(), "{r}");
    }
    assert!(OAuthApp::new("id", "secret", "https://core.example.test/cb").is_some());
    assert!(OAuthApp::new("id", "secret", "https://core.example.test:443/cb").is_some());
    assert!(crate::connections::slack::redirect_ok(
        "https://a.example.test/x"
    ));
}

#[tokio::test]
async fn a_finished_sign_in_exchanges_a_form_and_reads_who_was_installed() {
    let f = fx(true).await;
    issue(&f.fake, install());
    let s = f.slack.start(1, REDIRECT, None).unwrap();
    let fin = f
        .slack
        .finish(1, &s.state, "code-3b9f6e2d", NOW)
        .await
        .unwrap();
    assert_eq!(fin.workspace, TEAM);
    let seen = f.fake.last("oauth.v2.access").unwrap();
    assert!(
        seen.auth.is_none(),
        "the client authenticates in the form, not with a header"
    );
    let want = json!({"client_id": "1234.5678", "client_secret": CLIENT_SECRET,
        "code": "code-3b9f6e2d", "redirect_uri": REDIRECT});
    assert_eq!(
        seen.form, want,
        "no grant_type, no verifier: Slack documents neither here"
    );
    assert_eq!(f.fake.bad(), 0);
    // Who was installed was read with the new token as a Bearer, and with nothing in the form.
    let me = f.fake.last("auth.test").unwrap();
    assert_eq!(me.auth, Some(format!("Bearer {ACCESS}")));
    assert_eq!(me.form, json!({}));
    let text = format!("{fin:?}");
    for secret in [ACCESS, "xoxp-test-user-leak"] {
        assert!(!text.contains(secret), "{text}");
    }
    // A long-lived bot token: no refresh token, no expiry; the installer's own token is not kept.
    let m = fin.material().unwrap();
    assert_eq!(
        (m.access(), m.refresh(), m.expires_at.clone()),
        (ACCESS, None, None)
    );
    let c = f.connect("acme", "oauth", &m).await;
    let tested = verdict::run_test(&f.pool, &f.sealer, &f.reg, c.id, f.cx(NOW).who)
        .await
        .unwrap();
    assert_eq!(tested.identity, Some(format!("{BOT_USER} in {TEAM}")));
    let stored = crate::store::connections::secret::open(&f.pool, &f.sealer, 1, c.id)
        .await
        .unwrap()
        .0;
    assert!(!format!("{:?}", stored.access()).contains("xoxp"));
}

#[tokio::test]
async fn an_app_with_token_rotation_gives_a_rotating_token_with_its_refresh_token() {
    let f = fx(true).await;
    let mut body = install();
    body["access_token"] = json!(ROT_ACCESS);
    body["refresh_token"] = json!(REFRESH);
    body["expires_in"] = json!(43200);
    issue(&f.fake, body);
    let s = f.slack.start(1, REDIRECT, None).unwrap();
    let fin = f.slack.finish(1, &s.state, "code-1", NOW).await.unwrap();
    let m = fin.material().unwrap();
    assert_eq!((m.access(), m.refresh()), (ROT_ACCESS, Some(REFRESH)));
    assert_eq!(m.expires_at.as_deref(), Some(at(43200).as_str()));
    assert!(!format!("{fin:?}").contains(REFRESH));
}

/// A change to an install answer.
type Edit = Box<dyn Fn(&mut Value)>;

#[tokio::test]
async fn only_a_bot_of_one_workspace_is_ever_connected() {
    let f = fx(true).await;
    let edits: Vec<(&str, Edit)> = vec![
        (
            "a user token type",
            Box::new(|b| b["token_type"] = json!("user")),
        ),
        (
            "no token type",
            Box::new(|b| {
                b.as_object_mut().unwrap().remove("token_type");
            }),
        ),
        (
            "no bot user",
            Box::new(|b| {
                b.as_object_mut().unwrap().remove("bot_user_id");
            }),
        ),
        (
            "a bad bot user",
            Box::new(|b| b["bot_user_id"] = json!("bot")),
        ),
        ("no team", Box::new(|b| b["team"] = json!(null))),
        (
            "no team id",
            Box::new(|b| b["team"] = json!({"name": "Acme"})),
        ),
        (
            "an enterprise as the team",
            Box::new(|b| b["team"]["id"] = json!("E012AB3CD")),
        ),
        (
            "an enterprise install",
            Box::new(|b| b["is_enterprise_install"] = json!(true)),
        ),
        (
            "a user access token",
            Box::new(|b| b["access_token"] = json!("xoxp-test-111-222-acc1")),
        ),
        (
            "an app token",
            Box::new(|b| b["access_token"] = json!("xapp-1-test-111-222-acc1")),
        ),
        (
            "a rotating token with no refresh token",
            Box::new(|b| b["access_token"] = json!(ROT_ACCESS)),
        ),
        (
            "a refresh token beside a plain token",
            Box::new(|b| b["refresh_token"] = json!(REFRESH)),
        ),
        (
            "a rotating user token",
            Box::new(|b| {
                b["access_token"] = json!("xoxe.xoxp-test-111-222-acc1");
                b["refresh_token"] = json!(REFRESH);
            }),
        ),
    ];
    for (what, edit) in edits {
        let mut body = install();
        edit(&mut body);
        issue(&f.fake, body);
        let s = f.slack.start(1, REDIRECT, None).unwrap();
        let r = f.slack.finish(1, &s.state, "code-1", NOW).await;
        assert!(
            matches!(r, Err(FlowError::NotABotInstall)),
            "{what}: {:?}",
            r.map(|_| ())
        );
    }
    // The workspace the exchange named must be the one `auth.test` names.
    issue(&f.fake, install());
    f.fake.reply("auth.test", Reply::ok(auth_test("T999AB3CD")));
    let s = f.slack.start(1, REDIRECT, None).unwrap();
    let r = f.slack.finish(1, &s.state, "code-1", NOW).await;
    assert!(matches!(r, Err(FlowError::NotABotInstall)));
    // A token with no bot behind it (auth.test has no bot_id) is no bot, however it was issued.
    let mut no_bot = auth_test(TEAM);
    no_bot.as_object_mut().unwrap().remove("bot_id");
    f.fake.reply("auth.test", Reply::ok(no_bot));
    let s = f.slack.start(1, REDIRECT, None).unwrap();
    let r = f.slack.finish(1, &s.state, "code-1", NOW).await;
    assert!(
        matches!(r, Err(FlowError::Exchange(CallError::Refused(_)))),
        "{:?}",
        r.map(|_| ())
    );
    let mut ent = auth_test(TEAM);
    ent["is_enterprise_install"] = json!(true);
    f.fake.reply("auth.test", Reply::ok(ent));
    let s = f.slack.start(1, REDIRECT, None).unwrap();
    let r = f.slack.finish(1, &s.state, "code-1", NOW).await;
    assert!(matches!(r, Err(FlowError::Exchange(CallError::Refused(_)))));
}

#[tokio::test]
async fn a_state_is_spent_once_by_its_own_user_and_a_code_must_be_text() {
    let f = fx(true).await;
    issue(&f.fake, install());
    let s = f.slack.start(1, REDIRECT, None).unwrap();
    // Another user cannot finish it, and does not spend it.
    let e = f.slack.finish(2, &s.state, "code-1", NOW).await;
    assert!(matches!(e, Err(FlowError::UnknownState)));
    let e = f.slack.finish(1, "nope", "code-1", NOW).await;
    assert!(matches!(e, Err(FlowError::UnknownState)));
    assert_eq!(f.fake.count("oauth.v2.access"), 0);
    // A code that is no text is refused, and the attempt spends the state.
    let long = "x".repeat(2049);
    for code in ["", "a\nb", long.as_str()] {
        let s = f.slack.start(1, REDIRECT, None).unwrap();
        let e = f.slack.finish(1, &s.state, code, NOW).await;
        assert!(matches!(e, Err(FlowError::BadCode)), "{code:?}");
        let again = f.slack.finish(1, &s.state, "code-1", NOW).await;
        assert!(matches!(again, Err(FlowError::UnknownState)));
    }
    // The first good finish spends it: a replay finds nothing.
    let s = f.slack.start(1, REDIRECT, None).unwrap();
    f.slack.finish(1, &s.state, "code-1", NOW).await.unwrap();
    let again = f.slack.finish(1, &s.state, "code-1", NOW).await;
    assert!(matches!(again, Err(FlowError::UnknownState)));
    assert_eq!(f.fake.count("oauth.v2.access"), 1);
    // A cancelled sign-in is gone; another user's cancel does nothing.
    let s = f.slack.start(1, REDIRECT, None).unwrap();
    let before = f.slack.pending();
    f.slack.cancel(2, &s.state);
    assert_eq!(f.slack.pending(), before);
    f.slack.cancel(1, &s.state);
    assert_eq!(f.slack.pending(), before - 1);
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn the_exchange_fails_into_plain_errors() {
    let f = fx(true).await;
    let finish = |f: &Fx| {
        let s = f.slack.start(1, REDIRECT, None).unwrap();
        let l = f.slack.clone();
        async move { l.finish(1, &s.state, "c1", NOW).await.map(|_| ()) }
    };
    for (reply, want) in [
        (Reply::err("invalid_code"), CallError::BadRequest(200)),
        (Reply::err("bad_redirect_uri"), CallError::BadRequest(200)),
        (Reply::err("bad_client_secret"), CallError::AppConfig),
        (Reply::err("invalid_client_id"), CallError::AppConfig),
        (
            Reply::err("ratelimited"),
            CallError::RateLimited { retry_after: None },
        ),
        (Reply::http(503, json!({})), CallError::Upstream(503)),
        (Reply::http(401, json!({})), CallError::Forbidden),
        (Reply::http(200, json!({})), CallError::Upstream(200)),
    ] {
        f.fake.reply("oauth.v2.access", reply.clone());
        let e = finish(&f).await.unwrap_err();
        assert_eq!(e, FlowError::Exchange(want), "{:?}", reply.body);
    }
    // Tokens issued, but who they belong to cannot be read: no connection is made.
    issue(&f.fake, install());
    f.fake.reply("auth.test", Reply::err("invalid_auth"));
    let e = finish(&f).await.unwrap_err();
    assert_eq!(e, FlowError::Exchange(CallError::AuthFailed));
    f.fake
        .reply("auth.test", Reply::ok(json!({"user_id": BOT_USER})));
    let e = finish(&f).await.unwrap_err();
    assert!(
        matches!(e, FlowError::Exchange(CallError::Refused(_))),
        "{e:?}"
    );
    // Not one error text carries a secret.
    let text = format!("{e} {e:?}");
    for secret in [ACCESS, REFRESH, CLIENT_SECRET, "xoxp"] {
        assert!(!text.contains(secret));
    }
}

#[tokio::test]
async fn pending_sign_ins_are_capped_and_end_when_the_app_changes() {
    let f = fx(true).await;
    for _ in 0..8 {
        f.slack.start(1, REDIRECT, None).unwrap();
    }
    assert_eq!(
        f.slack.start(1, REDIRECT, None),
        Err(FlowError::TooManyFlows)
    );
    f.slack.start(2, REDIRECT, None).unwrap();
    assert_eq!(f.slack.pending(), 9);
    // The same app written again changes nothing; a different one ends every pending sign-in.
    let same = OAuthApp::new("1234.5678", CLIENT_SECRET, REDIRECT);
    assert!(!f.slack.set_app(same));
    assert_eq!(f.slack.pending(), 9);
    let rotated = OAuthApp::new("1234.5678", "new-secret-5f3a", REDIRECT);
    assert!(f.slack.set_app(rotated));
    assert_eq!(f.slack.pending(), 0);
    let moved = OAuthApp::new(
        "1234.5678",
        "new-secret-5f3a",
        "https://other.example.test/cb",
    );
    assert!(f.slack.set_app(moved));
    assert_eq!(f.slack.redirects(), ["https://other.example.test/cb"]);
    assert!(f.slack.set_app(None));
    assert!(!f.slack.app_configured() && f.slack.redirects().is_empty());
}

#[tokio::test]
async fn the_credential_test_is_auth_test_and_a_refusal_is_only_conclusive_when_fresh() {
    let f = fx(true).await;
    let ok = f.slack.test(&bot()).await.unwrap();
    assert_eq!(ok.subject, format!("{BOT_USER} in {TEAM}"));
    // A renamed workspace is the same identity: only the stable id is in it.
    let mut renamed = auth_test(TEAM);
    renamed["team"] = json!("Acme Renamed");
    f.fake.reply("auth.test", Reply::ok(renamed));
    assert_eq!(f.slack.test(&bot()).await.unwrap().subject, ok.subject);
    f.fake.reply("auth.test", Reply::ok(auth_test(TEAM)));
    // A token Slack refuses is a rejection for a live token ...
    f.fake.reply("auth.test", Reply::err("invalid_auth"));
    assert_eq!(f.slack.test(&bot()).await, Err(TestError::Rejected));
    let live = oauth_material(ROT_ACCESS, Some(REFRESH), Some("2999-01-01T00:00:00.000Z")).unwrap();
    assert_eq!(f.slack.test(&live).await, Err(TestError::Rejected));
    // ... but nothing is concluded about a rotating token that is past its expiry.
    let past = oauth_material(ROT_ACCESS, Some(REFRESH), Some("2020-01-01T00:00:00.000Z")).unwrap();
    assert_eq!(f.slack.test(&past).await, Err(TestError::Inconclusive));
    // A token that is no bot is a rejection.
    let mut no_bot = auth_test(TEAM);
    no_bot.as_object_mut().unwrap().remove("bot_id");
    f.fake.reply("auth.test", Reply::ok(no_bot));
    assert_eq!(f.slack.test(&bot()).await, Err(TestError::Rejected));
    // Rate limits, outages and unreadable answers say nothing about the credential.
    for reply in [
        Reply::err("ratelimited"),
        Reply::http(429, json!({})),
        Reply::http(503, json!({})),
        Reply::err("missing_scope"),
        Reply::err("internal_error"),
        Reply::ok(json!({"user_id": BOT_USER, "bot_id": "B012AB3CD"})),
        Reply::ok(json!({"user_id": "bot", "team_id": TEAM, "bot_id": "B012AB3CD"})),
        Reply::http(200, json!({"team_id": TEAM})),
    ] {
        f.fake.reply("auth.test", reply.clone());
        assert_eq!(
            f.slack.test(&bot()).await,
            Err(TestError::Inconclusive),
            "{:?}",
            reply.body
        );
    }
    // A material that is not a usable credential is no verdict either.
    let junk = crate::connections::material::Material::new("short", None, None).unwrap();
    assert_eq!(f.slack.test(&junk).await, Err(TestError::Inconclusive));
    assert_eq!(f.fake.bad(), 0);
}

#[test]
fn the_production_authorize_address_is_slack_com_and_carries_no_secret() {
    let app = OAuthApp::new("1234.5678", CLIENT_SECRET, REDIRECT).unwrap();
    let slack = Slack::new(Some(app));
    let s = slack.start(1, REDIRECT, None).unwrap();
    assert!(
        s.authorize_url
            .starts_with("https://slack.com/oauth/v2/authorize?")
    );
    assert!(!s.authorize_url.contains(CLIENT_SECRET));
}
