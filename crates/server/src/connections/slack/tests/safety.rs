//! Odd answers, addresses, and secrets: nothing panics, nothing but `slack.com` is reachable, and
//! no credential appears in an error, an audit row or a printed value.

use serde_json::{Value, json};

use super::ops::run;
use super::*;
use crate::connections::slack::http::{Http, Method};
use crate::connections::slack::{CallError, Limit};

fn every_op() -> Vec<(&'static str, Value)> {
    vec![
        ("slack.list_channels", json!({})),
        ("slack.read_channel", json!({"channel": CH})),
        ("slack.read_thread", json!({"channel": CH, "ts": TS})),
        ("slack.get_user", json!({"user": "U0123456789"})),
        ("slack.post_message", json!({"channel": CH, "text": "t"})),
        (
            "slack.add_reaction",
            json!({"channel": CH, "ts": TS, "name": "x"}),
        ),
    ]
}

fn odd_bodies() -> Vec<Value> {
    let m = |v: Value| json!({"ok": true, "messages": v});
    vec![
        json!({"ok": true}),
        m(json!(5)),
        m(json!(null)),
        m(json!("x")),
        m(json!({"0": {}})),
        m(
            json!([null, 5, "x", [], {}, {"ts": 5}, {"ts": null}, {"ts": "x"}, {"ts": ["1700000000.000100"]}]),
        ),
        m(
            json!([{"ts": TS, "user": 5, "text": 5, "bot_id": [], "subtype": {}, "thread_ts": 7, "reply_count": "3"}]),
        ),
        m(json!([{"ts": TS, "text": "\u{0}\u{202e}\u{1F600}"}])),
        m(json!(
            (0..80).map(|_| json!({"ts": TS})).collect::<Vec<_>>()
        )),
        json!({"ok": true, "channels": 5}),
        json!({"ok": true, "channels": null}),
        json!({"ok": true, "channels": [null, 5, "x", [], {"id": 5}, {"id": null}, {"id": ["C012AB3CD"]},
            {"id": "C9990000000", "name": ["x"]}, {"id": CH, "name": 5, "is_private": "yes", "num_members": -1}]}),
        json!({"ok": true, "channels": {"0": {"id": CH}}, "response_metadata": 5}),
        json!({"ok": true, "channels": [], "response_metadata": {"next_cursor": ["x"]}}),
        json!({"ok": true, "channels": [], "response_metadata": {"next_cursor": "has space"}}),
        json!({"ok": true, "user": 5}),
        json!({"ok": true, "user": []}),
        json!({"ok": true, "user": {"id": "U0123456789", "profile": 5, "name": ["x"], "team_id": 5}}),
        json!({"ok": true, "user": {"id": 5}}),
        json!({"ok": true, "channel": 5}),
        json!({"ok": true, "channel": []}),
        json!({"ok": true, "channel": CH, "ts": 5}),
        json!({"ok": true, "channel": {"id": PRIV, "is_private": "true", "is_mpim": 0}}),
        json!({"ok": true, "a": {"b": {"c": {"d": {"e": [[[[[[[[[[1]]]]]]]]]]}}}}}),
        json!({"ok": true, "ts": 1e308, "channel": "\u{1F600}"}),
    ]
}

#[tokio::test]
async fn no_operation_panics_on_odd_json_and_a_limited_one_never_passes_what_it_cannot_check() {
    let f = fx(false).await;
    let c = f.bot().await;
    let limited = Limit::only(&[CH.to_owned(), PRIV.to_owned()]);
    for body in odd_bodies() {
        for m in Method::ALL {
            if !matches!(
                m,
                Method::OauthV2Access | Method::AuthTest | Method::ConversationsInfo
            ) {
                f.fake.reply(m.name(), Reply::http(200, body.clone()));
            }
        }
        for (op, args) in every_op() {
            for l in [&limited, &Limit::any()] {
                let r = run(&f, &c, l, op, args.clone()).await;
                // What a limited list returns holds only channels the limit names.
                if let (Ok(v), true, "slack.list_channels") = (&r, l.limited(), op) {
                    for ch in v["channels"].as_array().unwrap() {
                        assert!(ch["id"] == CH || ch["id"] == PRIV, "{body}: {v}");
                    }
                }
                // A post whose answer is not for the channel asked is never a success.
                if let (Ok(v), "slack.post_message") = (&r, op) {
                    assert_eq!(v["channel"], CH, "{body}");
                }
            }
        }
    }
    // Bodies that are not even JSON values the parser accepts: deep nesting, a lone bracket.
    for raw in [
        "[".repeat(5000).into_bytes(),
        b"{\"ok\": ".to_vec(),
        vec![0xff, 0xfe, 0x00],
        b"null".to_vec(),
        b"\"just a string\"".to_vec(),
    ] {
        for m in Method::ALL {
            if !matches!(
                m,
                Method::OauthV2Access | Method::AuthTest | Method::ConversationsInfo
            ) {
                f.fake
                    .reply(m.name(), Reply::http(200, Value::Null).raw(raw.clone()));
            }
        }
        for (op, args) in every_op() {
            let r = run(&f, &c, &Limit::any(), op, args).await;
            assert!(r.is_err(), "{op}: {r:?}");
        }
    }
    assert_eq!(f.fake.bad(), 0);
}

#[test]
fn only_https_slack_com_can_be_called() {
    let h = Http::production();
    for m in Method::ALL {
        assert!(
            h.allows(&format!("https://slack.com/api/{}", m.name())),
            "{}",
            m.name()
        );
    }
    let at = '@';
    let userinfo = format!("https://user:pw{at}slack.com/api/auth.test");
    let userinfo2 = format!("https://slack.com{at}evil.test/api/auth.test");
    for url in [
        "https://api.slack.com/api/auth.test",
        "https://files.slack.com/api/auth.test",
        "https://hooks.slack.com/services/T0/B0/x",
        "https://acme.slack.com/api/auth.test",
        "https://slack.com.evil.test/api/auth.test",
        "https://evil.test/slack.com",
        "https://evil.test/?h=slack.com",
        "https://eviltest-slack.com.evil.test/api/auth.test",
        "https://xslack.com/api/auth.test",
        "https://sub.slack.com/api/auth.test",
        "http://slack.com/api/auth.test",
        "https://slack.com:8443/api/auth.test",
        "https://127.0.0.1/api/auth.test",
        "https://[::1]/api/auth.test",
        "ftp://slack.com/api/auth.test",
        "//slack.com/api/auth.test",
        "slack.com/api/auth.test",
        "",
        userinfo.as_str(),
        userinfo2.as_str(),
    ] {
        assert!(!h.allows(url), "{url}");
    }
    assert_eq!(h.api, "https://slack.com");
}

/// The Web API methods this adapter can ever call: nine, fixed.
#[test]
fn the_method_set_is_fixed() {
    let names: Vec<_> = Method::ALL.iter().map(|m| m.name()).collect();
    assert_eq!(
        names,
        [
            "auth.test",
            "conversations.info",
            "conversations.history",
            "conversations.replies",
            "conversations.list",
            "users.info",
            "chat.postMessage",
            "reactions.add",
            "oauth.v2.access"
        ]
    );
    // None of Slack's file, admin, user-list, DM or impersonating methods is in it.
    for n in names {
        for never in [
            "files",
            "admin",
            "users.list",
            "im.",
            "mpim",
            "chat.update",
            "chat.delete",
            "search",
            "usergroups",
        ] {
            assert!(!n.contains(never), "{n}");
        }
    }
}

#[tokio::test]
async fn no_credential_appears_in_an_error_an_audit_row_or_a_printed_value() {
    let f = fx(true).await;
    // Slack echoes secrets in what it says; none may reach an error.
    let echo = format!("bad token {ACCESS} {ROT_ACCESS} {REFRESH} {CLIENT_SECRET} Bearer {ACCESS}");
    let loud = json!({"ok": false, "error": "invalid_arguments", "message": echo,
        "error_description": echo, "warning": echo});
    for m in Method::ALL {
        if m != Method::AuthTest {
            f.fake.reply(m.name(), Reply::http(200, loud.clone()));
        }
    }
    let rot = f
        .connect("o", "oauth", &rotating(ROT_ACCESS, REFRESH, 10))
        .await;
    let key = f.bot().await;
    let mut printed = Vec::new();
    for c in [&rot, &key] {
        for (op, args) in every_op() {
            if let Err(e) = run(&f, c, &Limit::any(), op, args).await {
                printed.push(format!("{e} {e:?}"));
            }
        }
        let t = f.slack.test_connection(&f.cx(NOW), c.id).await.unwrap();
        printed.push(format!("{t:?}"));
    }
    let started = f.slack.start(1, REDIRECT, None).unwrap();
    let e = f
        .slack
        .finish(1, &started.state, "code", NOW)
        .await
        .unwrap_err();
    printed.push(format!("{e} {e:?}"));
    printed.push(f.audit_text().await);
    let m = rotating(ROT_ACCESS, REFRESH, 10);
    printed.push(format!(
        "{m:?} {m} {:?}",
        crate::connections::slack::unpack(&m)
    ));
    printed.push(format!(
        "{:?}",
        OAuthApp::new("id", CLIENT_SECRET, REDIRECT)
    ));
    printed.push(format!("{:?}", crate::connections::slack::unpack(&bot())));
    let all = printed.join("\n");
    for secret in [ACCESS, ROT_ACCESS, REFRESH, CLIENT_SECRET] {
        assert!(!all.contains(secret), "{secret} leaked into: {all}");
    }
    // And the errors that were returned are the fixed ones.
    let r = run(
        &f,
        &key,
        &Limit::any(),
        "slack.read_channel",
        json!({"channel": CH}),
    )
    .await;
    assert_eq!(r, Err(CallError::BadRequest(200)));
}
