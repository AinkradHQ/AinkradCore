//! Local pacing: a rate limit on a method an agent drives cools THAT kind of call on THAT
//! connection and never the connection's health, and every channel is confirmed once.

use std::time::Duration;

use serde_json::{Value, json};

use super::ops::run;
use super::*;
use crate::connections::slack::http::Method;
use crate::connections::slack::pace::{Family, Pace};
use crate::connections::slack::{CallError, Limit};

const SECOND_TOKEN: &str = "xoxb-test-111-222-acc3";

async fn any(f: &Fx, c: &Connection, op: &str, args: Value) -> Result<Value, CallError> {
    run(f, c, &Limit::any(), op, args).await
}

async fn read(f: &Fx, c: &Connection) -> Result<Value, CallError> {
    any(f, c, "slack.read_channel", json!({"channel": CH})).await
}

fn slow(secs: &'static str) -> Reply {
    Reply::http(429, json!({"ok": false, "error": "ratelimited"})).header("retry-after", secs)
}

fn posting(f: &Fx) {
    f.fake.on("chat.postMessage", |s| {
        Reply::ok(json!({"channel": s.form["channel"], "ts": TS}))
    });
}

#[tokio::test]
async fn a_hammered_method_is_refused_here_after_the_first_429_and_slack_is_not_asked_again() {
    let f = fx(false).await;
    let c = f.bot().await;
    f.fake.reply("conversations.history", slow("30"));
    let first = read(&f, &c).await;
    assert_eq!(first, Err(CallError::Cooling { wait_secs: 30 }));
    assert_eq!(first.as_ref().unwrap_err().health(), None);
    for _ in 0..5 {
        let r = read(&f, &c).await;
        let Err(CallError::Cooling { wait_secs }) = r else {
            panic!("{r:?}")
        };
        assert!((1..=30).contains(&wait_secs), "{wait_secs}");
        assert_eq!(r.unwrap_err().health(), None);
    }
    assert_eq!(
        f.fake.count("conversations.history"),
        1,
        "one request, then local refusals"
    );
    // The sentence says when to come back, and the code is the plain one.
    let e = read(&f, &c).await.unwrap_err();
    assert_eq!(e.code(), "rate_limited");
    assert!(e.to_string().contains("seconds"), "{e}");
    // Replies are the same Tier 1 pair as history.
    let args = json!({"channel": CH, "ts": TS});
    let r = any(&f, &c, "slack.read_thread", args).await;
    assert!(matches!(r, Err(CallError::Cooling { .. })), "{r:?}");
    assert_eq!(f.fake.count("conversations.replies"), 0);
}

#[tokio::test]
async fn the_other_kinds_of_call_keep_working_while_history_cools() {
    let f = fx(false).await;
    let c = f.bot().await;
    f.fake.reply("conversations.history", slow("120"));
    posting(&f);
    f.fake.reply("reactions.add", Reply::ok(json!({})));
    f.fake
        .reply("conversations.list", Reply::ok(json!({"channels": []})));
    f.fake.reply(
        "users.info",
        Reply::ok(json!({"user": {"id": "U0123456789"}})),
    );
    assert!(matches!(read(&f, &c).await, Err(CallError::Cooling { .. })));
    let post = json!({"channel": CH, "text": "still here"});
    any(&f, &c, "slack.post_message", post).await.unwrap();
    let react = json!({"channel": CH, "ts": TS, "name": "x"});
    any(&f, &c, "slack.add_reaction", react).await.unwrap();
    any(&f, &c, "slack.list_channels", json!({})).await.unwrap();
    any(&f, &c, "slack.get_user", json!({"user": "U0123456789"}))
        .await
        .unwrap();
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn a_cooling_post_leaves_reading_alone() {
    let f = fx(false).await;
    let c = f.bot().await;
    f.fake.reply("chat.postMessage", slow("45"));
    f.fake
        .reply("conversations.history", history(vec![msg(TS, "a")]));
    let post = json!({"channel": CH, "text": "x"});
    let r = any(&f, &c, "slack.post_message", post.clone()).await;
    assert_eq!(r, Err(CallError::Cooling { wait_secs: 45 }));
    let again = any(&f, &c, "slack.post_message", post).await;
    assert!(matches!(again, Err(CallError::Cooling { .. })));
    assert_eq!(f.fake.count("chat.postMessage"), 1);
    read(&f, &c).await.unwrap();
}

#[tokio::test]
async fn cooling_is_per_connection_and_not_global() {
    let f = fx(false).await;
    let a = f.bot().await;
    let other = token_material(SECOND_TOKEN).unwrap();
    let b = f.connect("other", "token", &other).await;
    f.fake.on("conversations.history", |s| {
        match s.auth.as_deref() == Some(format!("Bearer {ACCESS}").as_str()) {
            true => slow("90"),
            false => history(vec![msg(TS, "b")]),
        }
    });
    assert!(matches!(read(&f, &a).await, Err(CallError::Cooling { .. })));
    assert!(matches!(read(&f, &a).await, Err(CallError::Cooling { .. })));
    // The other connection of the same adapter is not cooling.
    read(&f, &b).await.unwrap();
    assert_eq!(f.fake.count("conversations.history"), 2);
}

#[tokio::test]
async fn cooling_ends_with_its_window() {
    let f = fx(false).await;
    let c = f.bot().await;
    let n = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = n.clone();
    f.fake.on("conversations.history", move |_| {
        match seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
            0 => slow("1"),
            _ => history(vec![msg(TS, "back")]),
        }
    });
    assert_eq!(read(&f, &c).await, Err(CallError::Cooling { wait_secs: 1 }));
    assert!(matches!(read(&f, &c).await, Err(CallError::Cooling { .. })));
    tokio::time::sleep(Duration::from_millis(1_150)).await;
    let r = read(&f, &c).await.unwrap();
    assert_eq!(r["messages"][0]["text"], "back");
    assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn the_pace_is_bounded_per_family_and_keeps_the_longer_wait() {
    let p = Pace::default();
    assert_eq!(p.wait(1, Family::History), None);
    assert_eq!(p.cool(1, Family::History, Some(5)), 5);
    // A shorter wait does not shorten a running one; a longer one extends it.
    assert_eq!(p.cool(1, Family::History, Some(2)), 5);
    assert_eq!(p.cool(1, Family::History, Some(50)), 50);
    assert_eq!(p.cool(1, Family::List, Some(1_000_000)), 600);
    assert_eq!(p.cool(1, Family::Post, Some(0)), 1);
    assert_eq!(p.wait(2, Family::History), None, "another connection");
    assert_eq!(p.wait(1, Family::Users), None, "another family");
    assert!(
        p.wait(1, Family::History)
            .is_some_and(|s| (1..=50).contains(&s))
    );
    // Only the methods an agent drives have a family.
    assert_eq!(Family::of(Method::AuthTest), None);
    assert_eq!(Family::of(Method::OauthV2Access), None);
    for m in Method::ALL {
        let drives = !matches!(m, Method::AuthTest | Method::OauthV2Access);
        assert_eq!(Family::of(m).is_some(), drives, "{}", m.name());
    }
}

#[tokio::test]
async fn a_list_stops_paging_at_the_first_rate_limit_and_says_it_is_cut() {
    let f = fx(false).await;
    let c = f.bot().await;
    let only = Limit::only(&["C9990000099".to_owned()]);
    let n = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = n.clone();
    f.fake.on("conversations.list", move |_| {
        match seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
            0 => Reply::ok(json!({"channels": [{"id": CH}],
                "response_metadata": {"next_cursor": "cGFnZTI="}})),
            _ => slow("20"),
        }
    });
    let v = run(&f, &c, &only, "slack.list_channels", json!({}))
        .await
        .unwrap();
    assert_eq!(
        f.fake.count("conversations.list"),
        2,
        "the second page was the last asked"
    );
    assert_eq!(
        (v["truncated"].clone(), v["next_cursor"].clone()),
        (json!(true), json!("cGFnZTI="))
    );
    assert_eq!(v["channels"], json!([]));
    // And the list is cooling: the next call asks nobody.
    let r = run(&f, &c, &only, "slack.list_channels", json!({})).await;
    assert!(matches!(r, Err(CallError::Cooling { .. })), "{r:?}");
    assert_eq!(f.fake.count("conversations.list"), 2);
    // A first page that is refused is the error, not an empty list.
    let g = fx(false).await;
    let c = g.bot().await;
    g.fake.reply("conversations.list", slow("20"));
    let r = run(&g, &c, &only, "slack.list_channels", json!({})).await;
    assert_eq!(r, Err(CallError::Cooling { wait_secs: 20 }));
    assert_eq!(g.fake.count("conversations.list"), 1);
}

#[tokio::test]
async fn a_rate_limit_on_auth_test_is_still_a_connection_signal() {
    let f = fx(false).await;
    f.fake.reply("auth.test", slow("30"));
    let cred = crate::connections::slack::unpack(&bot()).unwrap();
    let e = f.slack.viewer(&cred).await.unwrap_err();
    assert_eq!(
        e,
        CallError::RateLimited {
            retry_after: Some(30)
        }
    );
    assert!(e.health().is_some());
}

fn info(fields: Value) -> Reply {
    let mut ch = json!({"id": CH, "is_private": false, "is_mpim": false, "is_im": false});
    ch.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    Reply::ok(json!({"channel": ch}))
}

const WITH_CHANNEL: [(&str, &str); 4] = [
    ("slack.read_channel", "conversations.history"),
    ("slack.read_thread", "conversations.replies"),
    ("slack.post_message", "chat.postMessage"),
    ("slack.add_reaction", "reactions.add"),
];

fn args_of(op: &str) -> Value {
    match op {
        "slack.read_channel" => json!({"channel": CH}),
        "slack.read_thread" => json!({"channel": CH, "ts": TS}),
        "slack.post_message" => json!({"channel": CH, "text": "t"}),
        _ => json!({"channel": CH, "ts": TS, "name": "x"}),
    }
}

#[tokio::test]
async fn every_channel_id_is_confirmed_even_a_c_id_that_answers_as_a_group_dm() {
    let f = fx(false).await;
    let c = f.bot().await;
    for r in [
        info(json!({"is_mpim": true})),
        info(json!({"is_im": true})),
        info(json!({"is_mpim": true, "is_private": true})),
        info(json!({"id": "C9990000099"})),
        info(json!({"is_mpim": null})),
        info(json!({"is_private": null})),
        Reply::ok(json!({"channel": {"id": CH, "is_private": false}})),
        Reply::ok(json!({"channel": {"id": CH, "is_mpim": false}})),
        Reply::ok(json!({"channel": null})),
        Reply::ok(json!({})),
        Reply::err("channel_not_found"),
        Reply::err("internal_error"),
        Reply::http(500, Value::Null),
    ] {
        f.fake.reply("conversations.info", r.clone());
        for (op, _) in WITH_CHANNEL {
            let out = any(&f, &c, op, args_of(op)).await;
            assert!(out.is_err(), "{op} {:?}", r.body);
        }
    }
    // Nothing but the confirmation was ever asked: no history, no post, no reaction.
    for (_, method) in WITH_CHANNEL {
        assert_eq!(f.fake.count(method), 0, "{method}");
    }
    assert_eq!(f.fake.bad(), 0);
    // An answer that is a plain public channel lets all four through.
    f.fake.reply("conversations.info", info(json!({})));
    f.fake.reply("conversations.history", history(vec![]));
    f.fake.reply("conversations.replies", history(vec![]));
    f.fake.reply("reactions.add", Reply::ok(json!({})));
    posting(&f);
    for (op, _) in WITH_CHANNEL {
        any(&f, &c, op, args_of(op)).await.unwrap();
    }
}

async fn ask(f: &Fx, slack: &Slack, c: &Connection) -> Result<Value, CallError> {
    let args = json!({"channel": CH});
    let cx = f.cx(NOW);
    slack
        .call(&cx, c, &Limit::any(), "slack.read_channel", &args)
        .await
}

#[tokio::test]
async fn a_confirmation_is_remembered_per_connection_for_a_short_while() {
    let f = fx(false).await;
    let ttl = Duration::from_millis(300);
    let slack = Slack::loopback(None, f.addr).with_pace(Pace::with_ttl(ttl));
    let c = f.bot().await;
    let other = token_material(SECOND_TOKEN).unwrap();
    let other = f.connect("other", "token", &other).await;
    f.fake.reply("conversations.history", history(vec![]));
    ask(&f, &slack, &c).await.unwrap();
    ask(&f, &slack, &c).await.unwrap();
    assert_eq!(
        f.fake.count("conversations.info"),
        1,
        "the second call used the memory"
    );
    ask(&f, &slack, &other).await.unwrap();
    assert_eq!(
        f.fake.count("conversations.info"),
        2,
        "another connection confirms for itself"
    );
    tokio::time::sleep(Duration::from_millis(350)).await;
    ask(&f, &slack, &c).await.unwrap();
    assert_eq!(f.fake.count("conversations.info"), 3, "and it lapses");
    // A refusal is never remembered.
    f.fake
        .reply("conversations.info", info(json!({"is_mpim": true})));
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(ask(&f, &slack, &c).await.is_err());
    assert!(ask(&f, &slack, &c).await.is_err());
    assert_eq!(f.fake.count("conversations.info"), 5);
}

#[tokio::test]
async fn the_confirmation_is_its_own_kind_of_call_and_a_cooling_one_stops_unconfirmed_channels_only()
 {
    let f = fx(false).await;
    let c = f.bot().await;
    f.fake.reply("conversations.history", history(vec![]));
    read(&f, &c).await.unwrap();
    f.fake.reply("conversations.info", slow("60"));
    // A confirmed channel needs no new answer; one not confirmed yet is refused locally.
    read(&f, &c).await.unwrap();
    let r = any(&f, &c, "slack.read_channel", json!({"channel": CH2})).await;
    assert!(matches!(r, Err(CallError::Cooling { .. })), "{r:?}");
    let r = any(
        &f,
        &c,
        "slack.read_channel",
        json!({"channel": "C0000000001"}),
    )
    .await;
    assert!(matches!(r, Err(CallError::Cooling { .. })));
    assert_eq!(f.fake.count("conversations.info"), 2);
}
