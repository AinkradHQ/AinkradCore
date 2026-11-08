//! What each failure means for the caller and for health. Nothing an agent can provoke (a missing
//! or forbidden channel, a bad argument, a redirect, a huge answer, a cursor or a resource that
//! makes Graph fail, a 429 on one channel, an error that merely NAMES an auth code) is a signal
//! about the connection; a 401 that `/me` confirms is.

use std::time::Duration;

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::{Value, json};

use super::*;
use crate::connections::teams::{CallError, Limit};

async fn read(f: &Fx, c: &Connection) -> Result<Value, CallError> {
    let a = json!({"team": TEAM_A, "channel": CH_A1});
    run(f, c, &Limit::any(), "teams.list_messages", a).await
}

/// What reading the channel comes to when `messages` answers `reply` (a fresh service each time:
/// a cooling channel is remembered).
async fn answer_of(reply: &Reply) -> (Result<Value, CallError>, Fx) {
    let f = fx(true).await;
    let c = f.signed_in().await;
    f.fake.reply("messages", reply.clone());
    (read(&f, &c).await, f)
}

#[tokio::test]
async fn graph_error_codes_and_statuses_map_to_the_right_error() {
    let cases = [
        (Reply::graph(403, "Forbidden"), CallError::Forbidden),
        (Reply::graph(403, "accessDenied"), CallError::Forbidden),
        (
            Reply::graph(403, "Authorization_RequestDenied"),
            CallError::Forbidden,
        ),
        (Reply::graph(404, "ResourceNotFound"), CallError::NotFound),
        (Reply::graph(404, "ChannelNotFound"), CallError::NotFound),
        (
            Reply::graph(404, "Request_ResourceNotFound"),
            CallError::NotFound,
        ),
        (Reply::graph(404, "NotFound"), CallError::NotFound),
        (Reply::graph(400, "BadRequest"), CallError::BadRequest(400)),
        (
            Reply::graph(400, "SomethingNew"),
            CallError::BadRequest(400),
        ),
        (Reply::http(409, json!({})), CallError::BadRequest(409)),
        // A 5xx on a resource an agent named is not Microsoft's outage.
        (
            Reply::graph(503, "serviceNotAvailable"),
            CallError::BadRequest(503),
        ),
        (
            Reply::graph(500, "generalException"),
            CallError::BadRequest(500),
        ),
        (
            Reply::http(302, json!({})).header("location", "https://evil.test/x"),
            CallError::Upstream(302),
        ),
        (
            Reply::http(200, json!(null)).raw(b"<html>proxy</html>".to_vec()),
            CallError::Upstream(200),
        ),
    ];
    for (reply, want) in cases {
        let (got, f) = answer_of(&reply).await;
        assert_eq!(
            got.map(|_| ()),
            Err(want.clone()),
            "{} {}",
            reply.status,
            reply.body
        );
        assert_eq!(want.health(), None, "{want:?}");
        assert_eq!(f.fake.bad(), 0);
    }
}

#[tokio::test]
async fn an_error_that_merely_names_an_auth_code_is_not_an_auth_failure() {
    // Only HTTP 401 is a refused token. A 400, 403 or 404 can carry any code an agent provoked.
    for code in [
        "InvalidAuthenticationToken",
        "Unauthorized",
        "AuthenticationError",
    ] {
        for (status, want) in [
            (403, CallError::Forbidden),
            (404, CallError::NotFound),
            (400, CallError::BadRequest(400)),
        ] {
            let (got, f) = answer_of(&Reply::graph(status, code)).await;
            assert_eq!(got.map(|_| ()), Err(want), "{status} {code}");
            assert_eq!(
                f.fake.count("token"),
                0,
                "no refresh was spent: {status} {code}"
            );
            assert_eq!(f.fake.count("me"), 0, "{status} {code}");
        }
    }
}

#[tokio::test]
async fn a_429_cools_that_channel_for_a_bounded_time_and_is_no_health_signal() {
    for (retry, want) in [
        (Some("17"), 17),
        (Some("0"), 1),
        (Some("99999"), 600),
        (None, 60),
    ] {
        let mut reply = Reply::graph(429, "TooManyRequests");
        if let Some(r) = retry {
            reply = reply.header("Retry-After", r);
        }
        let (got, f) = answer_of(&reply).await;
        let e = got.unwrap_err();
        assert!(
            matches!(e, CallError::Cooling { wait_secs } if wait_secs <= want && wait_secs + 2 >= want),
            "{retry:?}: {e:?}"
        );
        assert_eq!(e.health(), None);
        assert_eq!(e.code(), "rate_limited");
        assert_eq!(f.fake.count("me"), 0);
    }
}

#[tokio::test]
async fn a_burst_to_one_channel_never_touches_another_channel_or_health() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    f.fake.reply(
        "post",
        Reply::graph(429, "TooManyRequests").header("Retry-After", "30"),
    );
    let any = Limit::any();
    let post = |ch: &'static str| {
        let a = json!({"team": TEAM_A, "channel": ch, "text": "x"});
        run(&f, &c, &any, "teams.post_message", a)
    };
    let first = post(CH_A1).await.unwrap_err();
    assert!(matches!(first, CallError::Cooling { wait_secs } if (29..=30).contains(&wait_secs)));
    // The next ones to that channel are refused here: Graph is not asked, nothing is signalled.
    for _ in 0..5 {
        let e = post(CH_A1).await.unwrap_err();
        assert!(matches!(e, CallError::Cooling { .. }), "{e:?}");
        assert_eq!(e.health(), None);
    }
    assert_eq!(f.fake.count("post"), 1);
    // Reading the same channel is cooling too (Microsoft limits the channel), another is not.
    assert!(matches!(
        read(&f, &c).await.unwrap_err(),
        CallError::Cooling { .. }
    ));
    f.fake.reply(
        "post",
        Reply::http(201, message(TEAM_A, CH_A2, "1616990099999", "x")),
    );
    assert!(post(CH_A2).await.is_ok(), "another channel goes on");
    let teams = run(&f, &c, &Limit::any(), "teams.list_teams", json!({})).await;
    assert!(teams.is_ok(), "lists go on");
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn list_calls_cool_per_list_and_the_cooling_is_per_connection() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let d = f.connect("other", &material(ACCESS, REFRESH, 3600)).await;
    f.fake.reply(
        "teams",
        Reply::graph(429, "TooManyRequests").header("Retry-After", "20"),
    );
    let l = Limit::any();
    let e = run(&f, &c, &l, "teams.list_teams", json!({}))
        .await
        .unwrap_err();
    assert!(matches!(e, CallError::Cooling { .. }));
    let again = run(&f, &c, &l, "teams.list_teams", json!({}))
        .await
        .unwrap_err();
    assert!(matches!(again, CallError::Cooling { .. }));
    assert_eq!(f.fake.count("teams"), 1);
    // Another list, a channel read, and the same list on ANOTHER connection are not held.
    let ch = run(&f, &c, &l, "teams.list_channels", json!({"team": TEAM_A})).await;
    assert!(ch.is_ok());
    assert!(read(&f, &c).await.is_ok());
    f.fake.reply("teams", Reply::ok(json!({"value": []})));
    assert!(run(&f, &d, &l, "teams.list_teams", json!({})).await.is_ok());
}

#[tokio::test]
async fn what_an_agent_can_provoke_is_no_health_signal() {
    for e in [
        CallError::Forbidden,
        CallError::NotFound,
        CallError::BadRequest(400),
        CallError::BadRequest(503),
        CallError::Upstream(302),
        CallError::Upstream(200),
        CallError::Upstream(404),
        CallError::TooLarge,
        CallError::TimedOut,
        CallError::Broken,
        CallError::Refused("x".into()),
        CallError::Internal("x"),
        CallError::AppConfig,
        CallError::InteractionRequired,
        CallError::OAuthNotConfigured,
        CallError::TenantNotAllowed,
        CallError::Cooling { wait_secs: 5 },
    ] {
        assert_eq!(e.health(), None, "{e:?}");
    }
    assert_eq!(
        CallError::AuthFailed.health(),
        Some((UpstreamStatus::AuthFailed, None))
    );
    assert_eq!(
        CallError::RateLimited {
            retry_after: Some(5)
        }
        .health(),
        Some((UpstreamStatus::RateLimited, Some(5)))
    );
    assert_eq!(
        CallError::Upstream(502).health(),
        Some((UpstreamStatus::ServerError, None))
    );
    assert_eq!(
        CallError::Network.health(),
        Some((UpstreamStatus::Unreachable, None))
    );
}

#[tokio::test]
async fn too_large_and_late_answers_are_no_signal() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let big = vec![b' '; 5 * 1024 * 1024];
    f.fake.reply("messages", Reply::ok(json!(null)).raw(big));
    assert_eq!(read(&f, &c).await.unwrap_err(), CallError::TooLarge);
    // A text body past the cap, too.
    let slow = format!("{{\"value\": \"{}\"}}", "x".repeat(5 * 1024 * 1024));
    f.fake
        .reply("messages", Reply::ok(json!(null)).raw(slow.into_bytes()));
    assert_eq!(read(&f, &c).await.unwrap_err(), CallError::TooLarge);
    // A late answer: the client's own timeout, shortened for the test.
    let g = fx(true).await;
    let t = std::sync::Arc::new(crate::connections::teams::Teams::with(
        crate::connections::teams::http::Http::loopback(g.addr)
            .with_timeout(Duration::from_millis(200)),
        None,
    ));
    let gc = g.signed_in().await;
    g.fake
        .reply("channel", Reply::ok(channel_info("", CH_A1)).delayed(1500));
    let a = json!({"team": TEAM_A, "channel": CH_A1});
    let e = t
        .call(&g.cx(NOW), &gc, &Limit::any(), "teams.list_messages", &a)
        .await
        .unwrap_err();
    assert_eq!(e, CallError::TimedOut);
    assert_eq!(e.health(), None);
}

#[tokio::test]
async fn a_refused_token_renews_once_and_retries_once_then_is_auth_failed_when_me_agrees() {
    let f = fx(true).await;
    let served = f.fake.rotating();
    f.fake.on("messages", |s| {
        if s.auth.as_deref() == Some(format!("Bearer {ACC2}").as_str()) {
            Reply::ok(json!({"value": []}))
        } else {
            Reply::graph(401, "InvalidAuthenticationToken")
        }
    });
    let c = f.signed_in().await;
    assert!(read(&f, &c).await.is_ok());
    assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(f.fake.count("messages"), 2);
    // A service that keeps refusing, `/me` included: one refresh, one retry, then the failure,
    // and no loop.
    let g = fx(true).await;
    let served = g.fake.rotating();
    g.fake
        .reply("messages", Reply::graph(401, "InvalidAuthenticationToken"));
    g.fake
        .reply("me", Reply::graph(401, "InvalidAuthenticationToken"));
    let c = g.signed_in().await;
    assert_eq!(read(&g, &c).await.unwrap_err(), CallError::AuthFailed);
    assert_eq!(read(&g, &c).await.unwrap_err(), CallError::AuthFailed);
    assert_eq!(
        served.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "no second refresh within the skew"
    );
    assert_eq!(g.fake.count("messages"), 3);
}

#[tokio::test]
async fn a_401_to_one_resource_while_me_works_is_no_verdict_on_the_credential() {
    let f = fx(true).await;
    f.fake.rotating();
    f.fake
        .reply("messages", Reply::graph(401, "InvalidAuthenticationToken"));
    let c = f.signed_in().await;
    let e = read(&f, &c).await.unwrap_err();
    assert_eq!(e, CallError::Forbidden);
    assert_eq!(e.health(), None);
    assert!(f.fake.count("me") >= 1, "confirmed against /me");
    // /me that cannot answer is not a verdict either.
    let g = fx(true).await;
    g.fake.rotating();
    g.fake
        .reply("messages", Reply::graph(401, "InvalidAuthenticationToken"));
    g.fake.reply("me", Reply::graph(503, "serviceNotAvailable"));
    let c = g.signed_in().await;
    let e = read(&g, &c).await.unwrap_err();
    assert_eq!(e.health(), None, "{e:?}");
}

#[tokio::test]
async fn a_missing_scope_is_forbidden_not_a_verdict() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    f.fake.grant_scopes(&[
        "openid",
        "offline_access",
        "User.Read",
        "Channel.ReadBasic.All",
        "ChannelMessage.Send",
    ]);
    let e = read(&f, &c).await.unwrap_err();
    assert_eq!(e, CallError::Forbidden);
    assert_eq!(e.health(), None);
    let a = json!({"team": TEAM_A, "channel": CH_A1, "text": "x"});
    run(&f, &c, &Limit::any(), "teams.post_message", a)
        .await
        .unwrap();
}
