//! What each failure means for the caller and for health. Nothing an agent can provoke (a missing
//! or forbidden channel, a bad argument, a redirect, a huge answer, a cursor that makes Graph
//! fail) is a signal about the connection; a 401, a 429 and a 5xx without caller input are.

use std::time::Duration;

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::{Value, json};

use super::*;
use crate::connections::teams::{CallError, Limit};

async fn read(f: &Fx, c: &Connection) -> Result<Value, CallError> {
    let a = json!({"team": TEAM_A, "channel": CH_A1});
    run(f, c, &Limit::any(), "teams.list_messages", a).await
}

#[tokio::test]
async fn graph_error_codes_and_statuses_map_to_the_right_error() {
    let f = fx(true).await;
    let c = f.signed_in().await;
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
        (
            Reply::graph(429, "TooManyRequests"),
            CallError::RateLimited { retry_after: None },
        ),
        (
            Reply::graph(429, "TooManyRequests").header("Retry-After", "17"),
            CallError::RateLimited {
                retry_after: Some(17),
            },
        ),
        (
            Reply::graph(429, "TooManyRequests").header("Retry-After", "99999"),
            CallError::RateLimited {
                retry_after: Some(3600),
            },
        ),
        (
            Reply::graph(503, "serviceNotAvailable"),
            CallError::Upstream(503),
        ),
        (
            Reply::graph(500, "generalException"),
            CallError::Upstream(500),
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
        f.fake.reply("messages", reply.clone());
        let got = read(&f, &c).await.map(|_| ());
        assert_eq!(got, Err(want.clone()), "{} {}", reply.status, reply.body);
    }
    assert_eq!(f.fake.bad(), 0);
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
async fn a_5xx_after_a_caller_cursor_is_not_microsofts_outage() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let f = fx(true).await;
    let c = f.signed_in().await;
    f.fake
        .reply("messages", Reply::graph(500, "generalException"));
    let a = json!({"team": TEAM_A, "channel": CH_A1, "cursor": URL_SAFE_NO_PAD.encode("garbage")});
    let e = run(&f, &c, &Limit::any(), "teams.list_messages", a)
        .await
        .unwrap_err();
    assert_eq!(e, CallError::BadRequest(500));
    assert_eq!(e.health(), None);
    // The same 5xx with no cursor from the caller IS a signal.
    assert_eq!(
        read(&f, &c).await.unwrap_err().health(),
        Some((UpstreamStatus::ServerError, None))
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
        .reply("messages", Reply::ok(json!({"value": []})).delayed(1500));
    let a = json!({"team": TEAM_A, "channel": CH_A1});
    let e = t
        .call(&g.cx(NOW), &gc, &Limit::any(), "teams.list_messages", &a)
        .await
        .unwrap_err();
    assert_eq!(e, CallError::TimedOut);
    assert_eq!(e.health(), None);
}

#[tokio::test]
async fn a_refused_token_renews_once_and_retries_once_then_is_auth_failed() {
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
    // A service that keeps refusing: one refresh, one retry, then the failure, and no loop.
    let g = fx(true).await;
    let served = g.fake.rotating();
    g.fake
        .reply("messages", Reply::graph(401, "InvalidAuthenticationToken"));
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
async fn a_missing_scope_is_forbidden_not_a_verdict() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    f.fake.grant_scopes(&[
        "openid",
        "offline_access",
        "User.Read",
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
