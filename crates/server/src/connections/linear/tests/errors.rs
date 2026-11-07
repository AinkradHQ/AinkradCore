//! What an answer that is not data means: the error each one maps to, and which of them reach
//! connection health. Only what is about the credential or the service may; everything an agent
//! can provoke by what it names (a missing issue, a forbidden one, a bad input, an oversized or
//! slow answer, a redirect) must not.

use std::time::Duration;

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::{Value, json};

use super::ops::run;
use super::*;
use crate::connections::linear::{CallError, Limit};

async fn get(f: &Fx, c: &Connection) -> Result<Value, CallError> {
    run(
        f,
        c,
        &Limit::any(),
        "linear.get_issue",
        json!({"id": "ENG-1"}),
    )
    .await
}

async fn with(reply: Reply) -> Result<Value, CallError> {
    let f = fx(false).await;
    let c = f.key().await;
    f.fake.on("GQL Issue", move |_| reply.clone());
    get(&f, &c).await
}

fn health(r: &Result<Value, CallError>) -> Option<(UpstreamStatus, Option<u64>)> {
    r.as_ref().err().and_then(CallError::health)
}

#[tokio::test]
async fn errors_are_told_by_code_first_and_status_second() {
    let auth = ("AUTHENTICATION_ERROR", UpstreamStatus::AuthFailed);
    // A 200, a 400 or a 401: the code decides.
    for status in [200u16, 400, 401, 403] {
        let r = with(Reply::error(status, auth.0)).await;
        assert_eq!(r, Err(CallError::AuthFailed), "{status}");
        assert_eq!(health(&r), Some((auth.1, None)));
    }
    // The error `type` names it too when the code does not.
    let by_type = Reply::json(
        200,
        json!({"errors": [{"message": "m", "extensions": {"type": "authentication error"}}]}),
    );
    assert_eq!(with(by_type).await, Err(CallError::AuthFailed));
    // A bare status with no body.
    for (status, want) in [
        (401u16, CallError::AuthFailed),
        (403, CallError::Forbidden),
        (404, CallError::NotFound),
        (422, CallError::BadRequest(422)),
    ] {
        assert_eq!(
            with(Reply::json(status, Value::Null)).await,
            Err(want),
            "{status}"
        );
    }
    // Several errors: the worst decides, whatever their order.
    let two = json!({"errors": [
        {"extensions": {"code": "FORBIDDEN"}}, {"extensions": {"code": "AUTHENTICATION_ERROR"}}]});
    assert_eq!(
        with(Reply::json(200, two)).await,
        Err(CallError::AuthFailed)
    );
}

#[tokio::test]
async fn a_200_with_errors_is_never_a_success_and_its_data_is_dropped() {
    let both = json!({"data": {"issue": issue("ENG-1", "ENG")},
        "errors": [{"message": "partial", "extensions": {"code": "INVALID_INPUT"}}]});
    let r = with(Reply::json(200, both)).await;
    assert_eq!(r, Err(CallError::BadRequest(200)));
    assert_eq!(health(&r), None);
    // An `errors` that is not even a list is still an error.
    let odd = json!({"data": {"issue": issue("ENG-1", "ENG")}, "errors": "boom"});
    assert_eq!(
        with(Reply::json(200, odd)).await,
        Err(CallError::BadRequest(200))
    );
    // No data object at all: unreadable, and no signal.
    for body in [
        json!({}),
        json!({"data": null}),
        json!({"data": []}),
        json!([]),
    ] {
        let r = with(Reply::json(200, body)).await;
        assert_eq!(r, Err(CallError::Upstream(200)));
        assert_eq!(health(&r), None);
    }
    let mut raw = Reply::json(200, Value::Null);
    raw.raw = Some(b"<html>not json</html>".to_vec());
    let r = with(raw).await;
    assert_eq!(r, Err(CallError::Upstream(200)));
    assert_eq!(health(&r), None);
}

#[tokio::test]
async fn a_rate_limit_cools_with_the_wait_the_service_gave() {
    let r = with(Reply::error(429, "RATELIMITED").header("retry-after", "42")).await;
    assert_eq!(
        r,
        Err(CallError::RateLimited {
            retry_after: Some(42)
        })
    );
    assert_eq!(health(&r), Some((UpstreamStatus::RateLimited, Some(42))));
    // The code alone is enough, at any status.
    let r = with(Reply::error(200, "ratelimited")).await;
    assert!(matches!(r, Err(CallError::RateLimited { .. })), "{r:?}");
    // The reset header is epoch MILLISECONDS: 90 s from now is about 90, never 90,000.
    let soon = (now_secs() + 90) * 1000;
    let h =
        Reply::error(429, "RATELIMITED").header("x-ratelimit-requests-reset", &soon.to_string());
    let Err(CallError::RateLimited {
        retry_after: Some(s),
    }) = with(h).await
    else {
        panic!("no wait")
    };
    assert!((80..=91).contains(&s), "{s}");
    // A wait is believed up to a day.
    let r = with(Reply::error(429, "RATELIMITED").header("retry-after", "99999999")).await;
    assert_eq!(
        r,
        Err(CallError::RateLimited {
            retry_after: Some(86_400)
        })
    );
    let r = with(Reply::json(429, Value::Null)).await;
    assert!(matches!(r, Err(CallError::RateLimited { .. })));
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn nothing_an_agent_can_provoke_is_a_health_signal() {
    let provoked = [
        // Forbidden, not found, bad input, an unknown code, a complexity refusal.
        Reply::error(200, "FORBIDDEN"),
        Reply::error(403, "FORBIDDEN"),
        Reply::error(200, "NOT_FOUND"),
        Reply::error(400, "INVALID_INPUT"),
        Reply::error(400, "GRAPHQL_VALIDATION_FAILED"),
        Reply::error(400, "COMPLEXITY_TOO_HIGH"),
        Reply::error(200, "SOMETHING_NEW"),
        Reply::json(404, Value::Null),
        Reply::json(400, Value::Null),
        Reply::json(422, json!({"errors": []})),
        // A redirect, which the client never follows.
        Reply::json(302, Value::Null).header("location", "http://127.0.0.1:1/x"),
        Reply::json(301, Value::Null),
    ];
    for reply in provoked {
        let r = with(reply.clone()).await;
        assert!(r.is_err(), "{:?}", reply.body);
        assert_eq!(health(&r), None, "{:?} {r:?}", reply.body);
    }
    // The ones that DO speak: a refused credential, a rate limit, Linear's own 5xx.
    for (reply, want) in [
        (
            Reply::error(401, "AUTHENTICATION_ERROR"),
            UpstreamStatus::AuthFailed,
        ),
        (
            Reply::error(429, "RATELIMITED"),
            UpstreamStatus::RateLimited,
        ),
        (Reply::json(500, Value::Null), UpstreamStatus::ServerError),
        (
            Reply::json(
                503,
                json!({"errors": [{"extensions": {"code": "FORBIDDEN"}}]}),
            ),
            UpstreamStatus::ServerError,
        ),
    ] {
        let r = with(reply).await;
        assert_eq!(health(&r).map(|h| h.0), Some(want), "{r:?}");
    }
}

#[tokio::test]
async fn a_huge_a_late_and_a_broken_answer_say_nothing_about_health() {
    // Larger than the cap: refused unread.
    let mut big = Reply::json(200, Value::Null);
    big.raw = Some(vec![b' '; super::super::http::MAX_ANSWER_BYTES + 10]);
    let r = with(big).await;
    assert_eq!(r, Err(CallError::TooLarge));
    assert_eq!(health(&r), None);
    // No answer in time.
    let f = fx(false).await;
    let slow = Linear::with(
        super::super::http::Http::loopback(f.addr).with_timeout(Duration::from_millis(100)),
        None,
    );
    let c = f.key().await;
    f.fake.on("GQL Issue", |_| {
        Reply::data(json!({"issue": null})).delayed(1500)
    });
    let args = json!({"id": "ENG-1"});
    let r = slow
        .call(&f.cx(NOW), &c, &Limit::any(), "linear.get_issue", &args)
        .await;
    assert_eq!(r, Err(CallError::TimedOut));
    assert_eq!(health(&r), None);
    // Nobody home: the one failure that says the service is unreachable.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let gone = Linear::loopback(None, dead);
    let r = gone
        .call(&f.cx(NOW), &c, &Limit::any(), "linear.get_issue", &args)
        .await;
    assert_eq!(r, Err(CallError::Network));
    assert_eq!(health(&r), Some((UpstreamStatus::Unreachable, None)));
}

#[tokio::test]
async fn a_redirect_is_not_followed_and_its_target_is_never_asked() {
    let target = Fake::default();
    let taddr = target.serve().await;
    let f = fx(false).await;
    let c = f.key().await;
    let to = format!("http://{taddr}/graphql");
    f.fake.on("GQL Issue", move |_| {
        Reply::json(307, Value::Null).header("location", &to)
    });
    let r = get(&f, &c).await;
    assert_eq!(r, Err(CallError::Upstream(307)));
    assert!(
        target.seen().is_empty(),
        "the redirect target was never asked"
    );
}

#[tokio::test]
async fn every_error_prints_fixed_text_and_names_a_plain_code() {
    let all = [
        CallError::AuthFailed,
        CallError::Forbidden,
        CallError::NotFound,
        CallError::RateLimited {
            retry_after: Some(3),
        },
        CallError::Upstream(502),
        CallError::BadRequest(400),
        CallError::Network,
        CallError::TooLarge,
        CallError::TimedOut,
        CallError::Broken,
        CallError::Refused("no".into()),
        CallError::Internal("fixed"),
        CallError::AppConfig,
        CallError::OAuthNotConfigured,
    ];
    for e in all {
        let text = format!("{e} {e:?}");
        for secret in [ACCESS, REFRESH, API_KEY, CLIENT_SECRET, "Bearer", "http"] {
            assert!(!text.contains(secret), "{e:?}: {text}");
        }
        assert!(e.code().chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}

#[tokio::test]
async fn a_message_an_upstream_wrote_is_never_what_decides_or_what_is_kept() {
    // The message says "rate limit" but the code is a bad input: no cooling. And the message text
    // appears nowhere in the error.
    let body = json!({"errors": [{"message": "RATELIMITED token lin_api_leak",
        "extensions": {"code": "INVALID_INPUT"}}]});
    let r = with(Reply::json(400, body)).await;
    let Err(e) = r else { panic!("not an error") };
    assert_eq!(e, CallError::BadRequest(400));
    assert!(!format!("{e} {e:?}").contains("lin_api_leak"));
}
