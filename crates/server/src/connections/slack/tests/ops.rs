//! Every operation: the request the adapter builds (exactly the parameters it intends), the typed
//! answer it returns (nothing else Slack sent), and what message text is allowed to be.

use serde_json::{Value, json};

use super::*;
use crate::connections::slack::{CallError, Limit};

pub async fn run(
    f: &Fx,
    c: &Connection,
    limit: &Limit,
    op: &str,
    args: Value,
) -> Result<Value, CallError> {
    f.slack.call(&f.cx(NOW), c, limit, op, &args).await
}

async fn any(f: &Fx, c: &Connection, op: &str, args: Value) -> Result<Value, CallError> {
    run(f, c, &Limit::any(), op, args).await
}

#[tokio::test]
async fn list_channels_returns_a_typed_set_and_never_a_direct_message() {
    let f = fx(false).await;
    let c = f.bot().await;
    f.fake.reply(
        "conversations.list",
        Reply::ok(json!({"channels": [
            {"id": CH, "name": "general", "is_channel": true, "is_private": false,
             "is_member": true, "num_members": 12, "topic": {"value": "secret topic"},
             "purpose": {"value": "secret purpose"}, "creator": "U1"},
            {"id": PRIV, "name": "ops", "is_private": true, "is_member": false},
            {"id": "D012AB3CD", "is_im": true, "user": "U012AB3CD"},
            {"id": "G999AB3CD", "is_mpim": true, "name": "mpdm-a--b-1"},
            {"id": "not an id", "name": "x"}, {"name": "no id"}, 5, null],
            "response_metadata": {"next_cursor": "dXNlcjpVMDYx"}})),
    );
    let v = any(&f, &c, "slack.list_channels", json!({})).await.unwrap();
    let ids: Vec<_> = v["channels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].clone())
        .collect();
    assert_eq!(ids, [json!(CH), json!(PRIV)]);
    let first = &v["channels"][0];
    assert_eq!(first["name"], "general");
    assert_eq!(first["num_members"], 12);
    let text = v.to_string();
    for leak in ["secret", "creator", "topic", "purpose", "mpdm"] {
        assert!(!text.contains(leak), "{leak}: {text}");
    }
    // The list is cut by Slack's cursor, and says so.
    assert_eq!(
        (v["truncated"].clone(), v["next_cursor"].clone()),
        (json!(true), json!("dXNlcjpVMDYx"))
    );
    let sent = f.fake.last("conversations.list").unwrap().form;
    assert_eq!(sent["types"], "public_channel,private_channel");
    assert_eq!(sent["exclude_archived"], "true");
    assert_eq!(sent["limit"], "100");
    assert!(sent.get("cursor").is_none());
    // The cursor of a previous page goes back, and a short list is not truncated.
    f.fake
        .reply("conversations.list", Reply::ok(json!({"channels": []})));
    let v = any(
        &f,
        &c,
        "slack.list_channels",
        json!({"limit": 5, "cursor": "dXNlcjpVMDYx"}),
    )
    .await
    .unwrap();
    assert_eq!(v["truncated"], false);
    assert!(v.get("next_cursor").is_none());
    let sent = f.fake.last("conversations.list").unwrap().form;
    assert_eq!(
        (sent["limit"].clone(), sent["cursor"].clone()),
        (json!("5"), json!("dXNlcjpVMDYx"))
    );
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn read_channel_and_read_thread_return_typed_messages_only() {
    let f = fx(false).await;
    let c = f.bot().await;
    let mut m = msg(TS, "hello\tthere\nline two\u{7}");
    m["files"] = json!([{"id": "F1", "url_private": "https://files.example.test/x"}]);
    m["blocks"] = json!([{"type": "section"}]);
    m["attachments"] = json!([{"text": "att"}]);
    m["reactions"] = json!([{"name": "x"}]);
    m["bot_profile"] = json!({"app_id": "A1"});
    m["thread_ts"] = json!(TS);
    m["reply_count"] = json!(3);
    m["subtype"] = json!("bot_message");
    m["bot_id"] = json!("B012AB3CD");
    f.fake.reply(
        "conversations.history",
        Reply::ok(json!({"messages": [m.clone()], "has_more": true,
            "response_metadata": {"next_cursor": "bmV4dA=="}})),
    );
    let args = json!({"channel": CH, "oldest": "1699999999.000000", "latest": "1700000001.000000"});
    let v = any(&f, &c, "slack.read_channel", args).await.unwrap();
    let first = &v["messages"][0];
    assert_eq!(first["text"], "hello\tthere\nline two");
    assert_eq!(first["ts"], TS);
    assert_eq!(
        (first["reply_count"].clone(), first["subtype"].clone()),
        (json!(3), json!("bot_message"))
    );
    let text = v.to_string();
    for leak in [
        "url_private",
        "files",
        "blocks",
        "attachments",
        "reactions",
        "bot_profile",
        "A1",
    ] {
        assert!(!text.contains(leak), "{leak}: {text}");
    }
    assert_eq!(
        (v["has_more"].clone(), v["next_cursor"].clone()),
        (json!(true), json!("bmV4dA=="))
    );
    let sent = f.fake.last("conversations.history").unwrap();
    assert_eq!(
        sent.auth.as_deref(),
        Some(format!("Bearer {ACCESS}").as_str())
    );
    let want = json!({"channel": CH, "limit": "15", "oldest": "1699999999.000000",
        "latest": "1700000001.000000"});
    assert_eq!(sent.form, want);
    // A long text is cut and marked.
    let long = "x".repeat(5000);
    f.fake
        .reply("conversations.replies", history(vec![msg(TS, &long)]));
    let v = any(
        &f,
        &c,
        "slack.read_thread",
        json!({"channel": CH, "ts": TS, "limit": 3, "cursor": "bmV4dA=="}),
    )
    .await
    .unwrap();
    assert_eq!(
        v["messages"][0]["text"].as_str().unwrap().chars().count(),
        4000
    );
    assert_eq!(v["messages"][0]["text_truncated"], true);
    let sent = f.fake.last("conversations.replies").unwrap().form;
    assert_eq!(
        sent,
        json!({"channel": CH, "ts": TS, "limit": "3", "cursor": "bmV4dA=="})
    );
    // The page is never larger than Slack gives these apps.
    for bad in [0, 16, 1000] {
        let r = any(
            &f,
            &c,
            "slack.read_channel",
            json!({"channel": CH, "limit": bad}),
        )
        .await;
        assert!(matches!(r, Err(CallError::Refused(_))), "{bad}");
    }
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn get_user_returns_names_and_never_an_email_or_a_phone() {
    let f = fx(false).await;
    let c = f.bot().await;
    f.fake.reply(
        "users.info",
        Reply::ok(
            json!({"user": {"id": "U0123456789", "team_id": TEAM, "name": "ann",
            "real_name": "Ann A", "deleted": false, "is_bot": false, "tz": "Europe/Paris",
            "is_admin": true, "profile": {"display_name": "annie", "email": "ann@example.test",
            "phone": "+1 555 0100", "title": "CEO"}}}),
        ),
    );
    let v = any(&f, &c, "slack.get_user", json!({"user": "U0123456789"}))
        .await
        .unwrap();
    assert_eq!(
        v,
        json!({"id": "U0123456789", "name": "ann", "real_name": "Ann A", "display_name": "annie",
            "is_bot": false, "deleted": false, "team_id": TEAM})
    );
    assert_eq!(
        f.fake.last("users.info").unwrap().form,
        json!({"user": "U0123456789"})
    );
    // An answer about someone else is not the answer.
    f.fake.reply(
        "users.info",
        Reply::ok(json!({"user": {"id": "U9999999999"}})),
    );
    let r = any(&f, &c, "slack.get_user", json!({"user": "U0123456789"})).await;
    assert_eq!(r, Err(CallError::Upstream(200)));
    for bad in [
        "ann",
        "U0123456789,U0123456788",
        "C0123456789",
        "u0123456789",
        "",
    ] {
        let r = any(&f, &c, "slack.get_user", json!({"user": bad})).await;
        assert!(matches!(r, Err(CallError::Refused(_))), "{bad:?}");
    }
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn post_message_sends_plain_escaped_text_and_nothing_else() {
    let f = fx(false).await;
    let c = f.bot().await;
    f.fake.on("chat.postMessage", |s| {
        Reply::ok(
            json!({"channel": s.form["channel"], "ts": TS, "message": {"text": "echo",
            "bot_profile": {"x": 1}}}),
        )
    });
    let text = "a & b <!channel> <!here> <!everyone> <!subteam^S123> <@U012AB3CD> <#C012AB3CD> \
                <https://evil.example.test|click> >";
    let v = any(
        &f,
        &c,
        "slack.post_message",
        json!({"channel": CH, "text": text}),
    )
    .await
    .unwrap();
    assert_eq!(v, json!({"channel": CH, "ts": TS}));
    let sent = f.fake.last("chat.postMessage").unwrap().form;
    let want = "a &amp; b &lt;!channel&gt; &lt;!here&gt; &lt;!everyone&gt; &lt;!subteam^S123&gt; \
                &lt;@U012AB3CD&gt; &lt;#C012AB3CD&gt; &lt;https://evil.example.test|click&gt; &gt;";
    assert_eq!(sent["text"], want);
    let t = sent["text"].as_str().unwrap();
    assert!(!t.contains('<') && !t.contains('>'));
    assert_eq!(
        (
            sent["parse"].clone(),
            sent["unfurl_links"].clone(),
            sent["unfurl_media"].clone()
        ),
        (json!("none"), json!("false"), json!("false"))
    );
    for never in [
        "link_names",
        "blocks",
        "attachments",
        "username",
        "icon_emoji",
        "as_user",
        "reply_broadcast",
        "metadata",
    ] {
        assert!(sent.get(never).is_none(), "{never}");
    }
    // A reply goes into the thread of a message of the same channel.
    any(
        &f,
        &c,
        "slack.post_message",
        json!({"channel": CH, "text": "re", "thread_ts": TS}),
    )
    .await
    .unwrap();
    assert_eq!(
        f.fake.last("chat.postMessage").unwrap().form["thread_ts"],
        TS
    );
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn text_that_addresses_everyone_or_is_not_plain_is_refused_before_slack_is_asked() {
    let f = fx(false).await;
    let c = f.bot().await;
    let long = "x".repeat(4001);
    for text in [
        "hi @here",
        "@channel now",
        "ping @everyone",
        "@HERE",
        "x @Channel y",
        "a\u{0}b",
        "bell\u{7}",
        "",
        long.as_str(),
    ] {
        let r = any(
            &f,
            &c,
            "slack.post_message",
            json!({"channel": CH, "text": text}),
        )
        .await;
        assert!(matches!(r, Err(CallError::Refused(_))), "{text:?}");
    }
    for bad in [json!(5), json!(["a"]), json!({"a": 1}), Value::Null] {
        let r = any(
            &f,
            &c,
            "slack.post_message",
            json!({"channel": CH, "text": bad}),
        )
        .await;
        assert!(matches!(r, Err(CallError::Refused(_))), "{bad}");
    }
    assert!(f.fake.seen().is_empty());
    // The limit of the length is inclusive, and newlines and tabs are fine.
    let ok = format!("{}\n\t", "x".repeat(3998));
    f.fake.on("chat.postMessage", |s| {
        Reply::ok(json!({"channel": s.form["channel"], "ts": TS}))
    });
    any(
        &f,
        &c,
        "slack.post_message",
        json!({"channel": CH, "text": ok}),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn add_reaction_sends_three_fields_and_validates_the_name() {
    let f = fx(false).await;
    let c = f.bot().await;
    f.fake.reply("reactions.add", Reply::ok(json!({})));
    let v = any(
        &f,
        &c,
        "slack.add_reaction",
        json!({"channel": CH, "ts": TS, "name": "thumbsup"}),
    )
    .await
    .unwrap();
    assert_eq!(v, json!({"ok": true}));
    let want = json!({"channel": CH, "timestamp": TS, "name": "thumbsup"});
    assert_eq!(f.fake.last("reactions.add").unwrap().form, want);
    for bad in [":x:", "A", "a b", "wave::skin-tone-3", "", "a/../b"] {
        let r = any(
            &f,
            &c,
            "slack.add_reaction",
            json!({"channel": CH, "ts": TS, "name": bad}),
        )
        .await;
        assert!(matches!(r, Err(CallError::Refused(_))), "{bad:?}");
    }
    assert_eq!(f.fake.count("reactions.add"), 1);
    assert_eq!(f.fake.bad(), 0);
}

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

#[tokio::test]
async fn every_operation_is_a_closed_argument_set() {
    let f = fx(false).await;
    let c = f.bot().await;
    let smuggled = [
        "blocks",
        "attachments",
        "metadata",
        "username",
        "icon_emoji",
        "icon_url",
        "as_user",
        "reply_broadcast",
        "link_names",
        "parse",
        "unfurl_links",
        "markdown_text",
        "token",
        "channels",
        "channel_id",
        "user_id",
        "types",
        "team_id",
        "file",
        "thread",
    ];
    for (op, ok) in every_op() {
        for name in smuggled {
            let mut args = ok.clone();
            if name == "channel_id" || name == "channels" {
                args[name] = json!(CH2);
            } else {
                args[name] = json!("x");
            }
            let r = run(&f, &c, &Limit::any(), op, args).await;
            let Err(CallError::Refused(why)) = r else {
                panic!("{op} {name}: {r:?}")
            };
            assert!(why.contains("no argument named"), "{op} {name}: {why}");
        }
        // Not an object.
        for bad in [json!([1]), json!("x"), json!(5)] {
            let r = run(&f, &c, &Limit::any(), op, bad).await;
            assert!(matches!(r, Err(CallError::Refused(_))), "{op}");
        }
    }
    let r = run(&f, &c, &Limit::any(), "slack.files_upload", json!({})).await;
    assert!(matches!(r, Err(CallError::Refused(_))));
    assert!(f.fake.seen().is_empty(), "nothing smuggled was ever sent");
}
