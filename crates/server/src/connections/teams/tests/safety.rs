//! Secrets never leave, hosts are exact, redirects are not followed, a message cannot ping a
//! channel, and a real Microsoft token is not refused by the secret gate.

use serde_json::json;

use super::*;
use crate::connections::adapter::{KindAdapter, TestError};
use crate::connections::teams::http::Http;
use crate::connections::teams::ops::plan;
use crate::connections::teams::{CallError, Limit, unpack};

#[test]
fn only_the_two_hosts_are_reachable_and_only_over_https() {
    let h = Http::production();
    for ok in [
        "https://graph.microsoft.com/v1.0/me",
        "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
    ] {
        assert!(h.allows(ok), "{ok}");
    }
    for bad in [
        "https://graph.microsoft.com.evil.test/v1.0/me",
        "https://evil.test/graph.microsoft.com/v1.0/me",
        "http://graph.microsoft.com/v1.0/me",
        "https://graph.microsoft.com:8443/v1.0/me",
        "https://login.microsoft.com/x",
        "https://microsoft.com/devicelogin",
        "https://login.live.com/x",
        "https://graph.microsoft.com@evil.test/v1.0/me",
        "https://evil.test#@graph.microsoft.com/",
        "ftp://graph.microsoft.com/",
        "https://127.0.0.1/v1.0/me",
        "https://localhost/v1.0/me",
        "https://169.254.169.254/latest",
    ] {
        assert!(!h.allows(bad), "{bad}");
    }
}

#[tokio::test]
async fn a_redirect_is_not_followed_and_no_token_goes_with_it() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let a = json!({"team": TEAM_A, "channel": CH_A1});
    for to in [
        format!("http://{}/v1.0/me", f.addr),
        "https://evil.test/steal".to_owned(),
    ] {
        f.fake.reply(
            "messages",
            Reply::http(302, json!({})).header("location", &to),
        );
        let before = f.fake.count("me");
        let e = run(&f, &c, &Limit::any(), "teams.list_messages", a.clone())
            .await
            .unwrap_err();
        assert_eq!(e, CallError::Upstream(302));
        assert_eq!(f.fake.count("me"), before, "the redirect was not followed");
    }
    // The token endpoint's redirect is not followed either.
    let g = fx(true).await;
    g.fake.reply(
        "token",
        Reply::http(307, json!({})).header("location", &format!("http://{}/v1.0/me", g.addr)),
    );
    let c = g.connect("acme", &material(ACCESS, REFRESH, 10)).await;
    let e = g
        .teams
        .fresh(&g.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e, CallError::Upstream(307));
    assert_eq!(g.fake.count("me"), 0);
}

#[tokio::test]
async fn no_secret_is_in_any_error_debug_or_audit_row() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let m = material(ACCESS, REFRESH, 3600);
    let b32_access = m.access().to_owned();
    let b32_refresh = m.refresh().unwrap().to_owned();
    // An upstream that echoes the bearer it was sent, in every kind of error.
    f.fake.on("messages", |s| {
        let echoed = s.auth.clone().unwrap_or_default();
        Reply::http(
            400,
            json!({"error": {"code": "BadRequest", "message": format!("bad {echoed} {ACCESS} {REFRESH}")}}),
        )
    });
    let a = json!({"team": TEAM_A, "channel": CH_A1});
    let mut texts = Vec::new();
    for reply in [
        None,
        Some(Reply::graph(401, "InvalidAuthenticationToken")),
        Some(Reply::graph(500, "x")),
    ] {
        if let Some(r) = reply {
            f.fake.reply("messages", r);
        }
        let e = run(&f, &c, &Limit::any(), "teams.list_messages", a.clone())
            .await
            .unwrap_err();
        texts.push(format!("{e} {e:?} {} {}", e.code(), e.health().is_some()));
    }
    let cred = unpack(&m).unwrap();
    texts.push(format!(
        "{m:?} {m} {cred:?} {:?}",
        cred.authorization().unwrap()
    ));
    texts.push(format!("{:?}", TeamsApp::new(CLIENT, TENANT)));
    texts.push(f.audit_text().await);
    for t in &texts {
        for secret in [
            ACCESS,
            REFRESH,
            ACC2,
            REF2,
            b32_access.as_str(),
            b32_refresh.as_str(),
        ] {
            assert!(!t.contains(secret), "{secret} in {t}");
        }
    }
    // The broker scrubs the raw tokens (and their Bearer forms) from an answer by value.
    let secrets = crate::connections::teams::secrets_of(&m);
    assert_eq!(secrets, vec![ACCESS.to_owned(), REFRESH.to_owned()]);
}

#[test]
fn a_message_cannot_ping_a_channel_a_team_or_a_person() {
    let l = Limit::any();
    let post = |t: &str| {
        plan(
            "teams.post_message",
            &json!({"team": TEAM_A, "channel": CH_A1, "text": t}),
            &l,
        )
    };
    for bad in [
        "<at id=\"0\">Jane</at> hi",
        "<AT>x</AT>",
        "x <at",
        "hi @channel",
        "hi @Channel!",
        "@TEAM look",
        "@everyone",
        "@here now",
        "line\n@channel",
        "ctrl\u{0}char",
        "esc\u{1b}[31m",
    ] {
        assert!(post(bad).is_err(), "{bad:?}");
    }
    for ok in [
        "mail me at a@b.test",
        "see #general",
        "<b>bold</b> & more",
        "line\nbreak\tand tab",
        "100% done",
    ] {
        assert!(post(ok).is_ok(), "{ok:?}");
    }
    let reply = plan(
        "teams.reply_message",
        &json!({"team": TEAM_A, "channel": CH_A1, "message": MSG, "text": "<at>x</at>"}),
        &l,
    );
    assert!(reply.is_err());
}

#[tokio::test]
async fn the_tests_verdicts_follow_the_status_and_the_expiry() {
    let f = fx(true).await;
    // `test` judges expiry by the real clock, so these expiries are real-clock ones.
    let real = |secs: i64| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = crate::scheduler::iso_of_unix(now + secs);
        crate::connections::teams::cred::oauth_material(TENANT, ACCESS, REFRESH, &exp).unwrap()
    };
    let live = real(3600);
    let dead = real(-10);
    let check = |m: Material| {
        let t = f.teams.clone();
        async move { t.test(&m).await }
    };
    f.fake
        .reply("me", Reply::graph(401, "InvalidAuthenticationToken"));
    assert_eq!(check(live).await.unwrap_err(), TestError::Rejected);
    assert_eq!(
        check(dead).await.unwrap_err(),
        TestError::Inconclusive,
        "an expired token proves nothing"
    );
    for reply in [
        Reply::graph(403, "Forbidden"),
        Reply::graph(429, "TooManyRequests"),
        Reply::graph(503, "serviceNotAvailable"),
        Reply::ok(json!({"id": "not-a-guid"})),
        Reply::ok(json!({})),
        Reply::ok(json!([])),
    ] {
        f.fake.reply("me", reply.clone());
        let got = check(real(3600)).await.unwrap_err();
        assert_eq!(
            got,
            TestError::Inconclusive,
            "{} {}",
            reply.status,
            reply.body
        );
    }
    f.fake
        .reply("me", Reply::ok(json!({"id": USER, "displayName": "Robin"})));
    let id = check(real(3600)).await.unwrap();
    assert_eq!(
        id.subject,
        format!("{USER} in {TENANT}"),
        "ids, never a name"
    );
    // Not a Teams credential at all.
    let odd = Material::new("plain-token-0123456789", None, None).unwrap();
    assert_eq!(check(odd).await.unwrap_err(), TestError::Inconclusive);
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn a_real_looking_microsoft_token_passes_the_secret_gate_only_sealed_as_base32() {
    use crate::store::connections::{NewConnection, Who, create};
    use crate::store::secrets::Error;
    let f = fx(true).await;
    let who = Who {
        workspace: 1,
        by_device: "d_test",
        actor: AuditActor::System,
        now: NOW,
    };
    // A JWT whose random bytes happen to hold a key shape (`_sk-` and 20 key bytes), as about one
    // in five thousand do: the redactor would call it a real OpenAI key.
    let unlucky_access = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJ4In0.AbC_sk-AbCdEfGhIjKlMnOpQrStUvWxYz0123";
    let unlucky_refresh =
        "0.ARoAv4j5cvGGr0GRqy180BHbR_ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789.AgABAAEAAAD";
    let new = |name| NewConnection {
        kind: "teams",
        name,
        label: "t",
        auth_method: "oauth",
    };
    let raw = Material::new(unlucky_access, Some(unlucky_refresh), Some(&at(3600))).unwrap();
    let refused = create(&f.pool, &f.sealer, &f.reg, &new("raw"), &raw, who).await;
    assert!(
        matches!(
            refused,
            Err(Error::Refused {
                code: "real_secret_refused",
                ..
            })
        ),
        "the hazard is real: {refused:?}"
    );
    let wrapped = crate::connections::teams::tests::oauth_wrapped(unlucky_access, unlucky_refresh);
    let made = create(&f.pool, &f.sealer, &f.reg, &new("sealed"), &wrapped, who).await;
    assert!(made.is_ok(), "{made:?}");
    // And a renewal's rotated token can always be stored (the same gate runs there).
    let c = made.unwrap();
    let (_, version) = crate::store::connections::secret::open(&f.pool, &f.sealer, 1, c.id)
        .await
        .unwrap();
    crate::store::connections::secret::renew(&f.pool, &f.sealer, c.id, &wrapped, who, version)
        .await
        .unwrap();
}
