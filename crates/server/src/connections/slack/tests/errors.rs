//! What an answer that is not data means: the error each Slack `error` code and each status maps
//! to, and which of them reach connection health. Only what is about the credential or the
//! service may; everything an agent can provoke by what it names (a missing channel, a forbidden
//! one, a bad input, a flood of posts, an oversized or slow answer, a redirect) must not.

use std::time::Duration;

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::{Value, json};

use super::ops::run;
use super::*;
use crate::connections::slack::{CallError, Limit};

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

async fn with(reply: Reply) -> Result<Value, CallError> {
    let f = fx(false).await;
    let c = f.bot().await;
    f.fake.reply("conversations.history", reply);
    read(&f, &c).await
}

fn health(r: &Result<Value, CallError>) -> Option<(UpstreamStatus, Option<u64>)> {
    r.as_ref().err().and_then(CallError::health)
}

#[tokio::test]
async fn an_ok_false_is_told_by_its_error_code_at_any_status() {
    use CallError::*;
    let table: [(&str, CallError); 36] = [
        ("invalid_auth", AuthFailed),
        ("account_inactive", AuthFailed),
        ("token_revoked", AuthFailed),
        ("token_expired", AuthFailed),
        ("not_authed", AuthFailed),
        ("ratelimited", Cooling { wait_secs: 60 }),
        ("rate_limited", Throttled),
        ("message_limit_exceeded", Throttled),
        ("channel_not_found", NotFound),
        ("thread_not_found", NotFound),
        ("message_not_found", NotFound),
        ("user_not_found", NotFound),
        ("missing_scope", Forbidden),
        ("no_permission", Forbidden),
        ("access_denied", Forbidden),
        ("not_in_channel", Forbidden),
        ("is_archived", Forbidden),
        ("team_access_not_granted", Forbidden),
        ("not_allowed_token_type", Forbidden),
        ("restricted_action", Forbidden),
        ("restricted_action_read_only_channel", Forbidden),
        ("cannot_reply_to_message", Forbidden),
        ("channel_is_limited_access", Forbidden),
        ("internal_error", Upstream(200)),
        ("fatal_error", Upstream(200)),
        ("service_unavailable", Upstream(200)),
        ("request_timeout", Upstream(200)),
        ("msg_too_long", BadRequest(200)),
        ("invalid_arguments", BadRequest(200)),
        ("invalid_cursor", BadRequest(200)),
        ("no_text", BadRequest(200)),
        ("already_reacted", BadRequest(200)),
        ("invalid_name", BadRequest(200)),
        ("something_new", BadRequest(200)),
        ("", BadRequest(200)),
        ("INVALID_AUTH", BadRequest(200)),
    ];
    for (code, want) in table {
        let r = with(Reply::err(code)).await;
        assert_eq!(r, Err(want.clone()), "{code}");
        // The same code on a 4xx is the same word; it never turns into a stronger one.
        if !matches!(want, Upstream(_)) {
            let r = with(Reply::http(400, json!({"ok": false, "error": code}))).await;
            assert_eq!(
                r.as_ref().err().map(CallError::code),
                Some(want.code()),
                "{code} @400"
            );
        }
    }
}

#[tokio::test]
async fn nothing_an_agent_can_provoke_is_a_health_signal() {
    let provoked = [
        "channel_not_found",
        "thread_not_found",
        "message_not_found",
        "user_not_found",
        "missing_scope",
        "not_in_channel",
        "is_archived",
        "no_permission",
        "access_denied",
        "msg_too_long",
        "invalid_arguments",
        "invalid_cursor",
        "no_text",
        "already_reacted",
        "rate_limited",
        "ratelimited",
        "message_limit_exceeded",
        "restricted_action",
        "cannot_reply_to_message",
        "internal_error",
        "fatal_error",
        "service_unavailable",
        "something_new",
        "invalid_name",
        "invalid_ts_latest",
        "invalid_limit",
        "not_reactable",
        "thread_locked",
    ];
    for code in provoked {
        let r = with(Reply::err(code)).await;
        assert!(r.is_err(), "{code}");
        assert_eq!(health(&r), None, "{code}: {r:?}");
    }
    for reply in [
        Reply::http(400, Value::Null),
        Reply::http(404, Value::Null),
        Reply::http(403, json!({"ok": false, "error": "access_denied"})),
        Reply::http(422, json!({"ok": false})),
        // A redirect, which the client never follows, and a 200 that says nothing readable.
        Reply::http(302, Value::Null).header("location", "http://127.0.0.1:1/x"),
        Reply::http(301, Value::Null),
        Reply::http(200, json!({})),
        Reply::http(200, json!({"ok": "true"})),
        Reply::http(200, json!({"ok": null, "error": "invalid_auth"})),
        Reply::http(200, json!([])),
        Reply::http(200, Value::Null),
        Reply::http(200, json!({"ok": false, "error": ["invalid_auth"]})),
        Reply::http(200, json!({"ok": false, "error": 5})),
        Reply::http(200, json!({"ok": false})),
        // A 429 to a method an agent drives cools that kind of call here, not the connection.
        Reply::http(429, Value::Null),
        Reply::http(429, json!({"ok": false, "error": "ratelimited"})).header("retry-after", "30"),
    ] {
        let r = with(reply.clone()).await;
        assert!(r.is_err(), "{:?}", reply.body);
        assert_eq!(health(&r), None, "{:?} {r:?}", reply.body);
    }
    // The ones that DO speak: a refused credential, Slack's own 5xx. (A rate limit speaks only
    // for `auth.test` and `oauth.v2.access`, which no agent drives: see `pace.rs`.)
    for (reply, want) in [
        (Reply::err("invalid_auth"), UpstreamStatus::AuthFailed),
        (Reply::err("token_revoked"), UpstreamStatus::AuthFailed),
        (Reply::err("account_inactive"), UpstreamStatus::AuthFailed),
        (Reply::err("token_expired"), UpstreamStatus::AuthFailed),
        (Reply::http(401, Value::Null), UpstreamStatus::AuthFailed),
        (Reply::http(500, Value::Null), UpstreamStatus::ServerError),
        (
            Reply::http(503, json!({"ok": false, "error": "channel_not_found"})),
            UpstreamStatus::ServerError,
        ),
    ] {
        let r = with(reply).await;
        assert_eq!(health(&r).map(|h| h.0), Some(want), "{r:?}");
    }
}

#[tokio::test]
async fn a_200_with_ok_false_drops_whatever_data_it_carries() {
    let both = json!({"ok": false, "error": "channel_not_found",
        "messages": [msg(TS, "secret")], "has_more": true});
    let r = with(Reply::http(200, both)).await;
    assert_eq!(r, Err(CallError::NotFound));
    assert!(!format!("{r:?}").contains("secret"));
    // No `ok`, a non-boolean `ok`, or an answer that is not JSON at all: unreadable.
    for body in [
        json!({"messages": []}),
        json!({"ok": 1, "messages": []}),
        json!([]),
    ] {
        assert_eq!(
            with(Reply::http(200, body)).await,
            Err(CallError::Upstream(200))
        );
    }
    for raw in [
        b"<html>not json</html>".to_vec(),
        b"{\"ok\": ".to_vec(),
        vec![0xff, 0xfe],
    ] {
        let r = with(Reply::http(200, Value::Null).raw(raw)).await;
        assert_eq!(r, Err(CallError::Upstream(200)));
        assert_eq!(health(&r), None);
    }
    // `ok:true` is only believed at 2xx.
    let r = with(Reply::http(400, json!({"ok": true, "messages": []}))).await;
    assert_eq!(r, Err(CallError::BadRequest(400)));
}

#[tokio::test]
async fn a_rate_limit_cools_that_kind_of_call_for_the_wait_slack_gave_bounded() {
    let cool = |secs| CallError::Cooling { wait_secs: secs };
    let r = with(
        Reply::http(429, json!({"ok": false, "error": "ratelimited"})).header("retry-after", "42"),
    )
    .await;
    assert_eq!(r, Err(cool(42)));
    assert_eq!(
        health(&r),
        None,
        "an agent can provoke it: no health signal"
    );
    // The code alone is enough at 200, with or without a header.
    let r = with(Reply::err("ratelimited").header("retry-after", "7")).await;
    assert_eq!(r, Err(cool(7)));
    let r = with(Reply::err("ratelimited")).await;
    assert_eq!(r, Err(cool(60)));
    // A wait is believed up to ten minutes (the client reads at most an hour), at least a second;
    // a header that is not a number is no wait.
    for (header, want) in [("99999999", 600), ("3600", 600), ("601", 600), ("0", 1)] {
        let r = with(Reply::http(429, Value::Null).header("retry-after", header)).await;
        assert_eq!(r, Err(cool(want)), "{header}");
    }
    for junk in ["soon", "-5", "1.5", ""] {
        let r = with(Reply::http(429, Value::Null).header("retry-after", junk)).await;
        assert_eq!(r, Err(cool(60)), "{junk:?}");
    }
}

#[tokio::test]
async fn a_huge_a_late_and_a_broken_answer_say_nothing_about_health() {
    let big =
        Reply::http(200, Value::Null).raw(vec![b' '; super::super::http::MAX_ANSWER_BYTES + 10]);
    let r = with(big).await;
    assert_eq!(r, Err(CallError::TooLarge));
    assert_eq!(health(&r), None);
    // No answer in time.
    let f = fx(false).await;
    let slow = Slack::with(
        super::super::http::Http::loopback(f.addr).with_timeout(Duration::from_millis(100)),
        None,
    );
    let c = f.bot().await;
    f.fake
        .reply("conversations.history", history(vec![]).delayed(1500));
    let args = json!({"channel": CH});
    let r = slow
        .call(&f.cx(NOW), &c, &Limit::any(), "slack.read_channel", &args)
        .await;
    assert_eq!(r, Err(CallError::TimedOut));
    assert_eq!(health(&r), None);
    // Nobody home: the one failure that says the service is unreachable.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let gone = Slack::loopback(None, dead);
    let r = gone
        .call(&f.cx(NOW), &c, &Limit::any(), "slack.read_channel", &args)
        .await;
    assert_eq!(r, Err(CallError::Network));
    assert_eq!(health(&r), Some((UpstreamStatus::Unreachable, None)));
}

#[tokio::test]
async fn a_redirect_is_not_followed_and_its_target_is_never_asked() {
    let target = Fake::default();
    let taddr = target.serve().await;
    let f = fx(false).await;
    let c = f.bot().await;
    let to = format!("http://{taddr}/api/conversations.history");
    f.fake.on("conversations.history", move |_| {
        Reply::http(307, Value::Null).header("location", &to)
    });
    let r = read(&f, &c).await;
    assert_eq!(r, Err(CallError::Upstream(307)));
    assert!(
        target.seen().is_empty(),
        "the redirect target was never asked"
    );
}

#[tokio::test]
async fn a_token_the_install_lacks_the_scope_for_is_forbidden_and_costs_no_health() {
    let f = fx(false).await;
    let c = f.bot().await;
    f.fake
        .reply("conversations.history", history(vec![msg(TS, "a")]));
    f.fake.grant_scopes(&["channels:read", "chat:write"]);
    let r = read(&f, &c).await;
    assert_eq!(r, Err(CallError::Forbidden));
    assert_eq!(health(&r), None);
    f.fake.grant_scopes(&["channels:read", "channels:history"]);
    assert!(read(&f, &c).await.is_ok());
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn a_bot_token_that_slack_refuses_is_never_renewed() {
    let f = fx(true).await;
    f.fake.rotating();
    f.fake
        .reply("conversations.history", Reply::err("invalid_auth"));
    let c = f.bot().await;
    assert_eq!(read(&f, &c).await, Err(CallError::AuthFailed));
    assert_eq!(f.fake.count("oauth.v2.access"), 0);
    assert_eq!(f.fake.count("conversations.history"), 1);
}

#[test]
fn every_error_prints_fixed_text_and_names_a_plain_code() {
    let all = [
        CallError::AuthFailed,
        CallError::Forbidden,
        CallError::NotFound,
        CallError::RateLimited {
            retry_after: Some(3),
        },
        CallError::Throttled,
        CallError::Cooling { wait_secs: 7 },
        CallError::NeedsMode2,
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
        for secret in [
            ACCESS,
            ROT_ACCESS,
            REFRESH,
            CLIENT_SECRET,
            "Bearer",
            "http",
            "xox",
        ] {
            assert!(!text.contains(secret), "{e:?}: {text}");
        }
        assert!(
            e.code()
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        );
    }
}

#[tokio::test]
async fn a_message_slack_wrote_is_never_what_decides_or_what_is_kept() {
    // The text says "ratelimited" and carries a token, but the code is a bad input: no cooling,
    // and none of the text appears in the error.
    let body = json!({"ok": false, "error": "invalid_arguments",
        "error_description": "ratelimited token xoxb-leak", "warning": "xoxb-leak",
        "response_metadata": {"messages": ["ratelimited xoxb-leak"]}});
    let r = with(Reply::http(200, body)).await;
    let Err(e) = r else { panic!("not an error") };
    assert_eq!(e, CallError::BadRequest(200));
    assert!(!format!("{e} {e:?}").contains("leak"));
}
