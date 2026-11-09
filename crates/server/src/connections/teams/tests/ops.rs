//! Every operation, end to end against the fake: the request it makes (path, query, body), the
//! typed answer, and an odd answer that must be an error and never a panic.

use serde_json::{Value, json};

use super::*;
use crate::connections::teams::{CallError, Limit};

async fn go(f: &Fx, c: &Connection, op: &str, args: Value) -> Result<Value, CallError> {
    run(f, c, &Limit::any(), op, args).await
}

fn pair() -> Value {
    json!({"team": TEAM_A, "channel": CH_A1})
}

fn with(extra: Value) -> Value {
    let mut v = pair();
    v.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    v
}

#[tokio::test]
async fn list_teams_and_channels_are_typed_and_carry_their_keys() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let v = go(&f, &c, "teams.list_teams", json!({})).await.unwrap();
    assert_eq!(
        v["teams"][0],
        json!({"id": TEAM_A, "name": "Alpha", "description": "first"})
    );
    assert_eq!(v["teams"][1]["description"], "");
    assert_eq!(v["truncated"], false);
    let sent = f.fake.last("teams").unwrap();
    assert_eq!(sent.path, "/v1.0/me/joinedTeams");
    assert_eq!(
        sent.auth.as_deref(),
        Some(format!("Bearer {ACCESS}").as_str())
    );
    let v = go(&f, &c, "teams.list_channels", json!({"team": TEAM_A}))
        .await
        .unwrap();
    assert_eq!(v["channels"][0]["id"], CH_A1);
    assert_eq!(v["channels"][0]["key"], KEY_A1);
    assert_eq!(v["channels"][1]["membership_type"], "private");
    assert_eq!(
        f.fake.last("channels").unwrap().path,
        format!("/v1.0/teams/{TEAM_A}/channels")
    );
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn list_messages_pages_with_top_and_a_skip_token_cursor_only() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let link = format!(
        "https://graph.microsoft.com/v1.0/teams/{TEAM_A}/channels/{CH_A1}/messages?%24top=3&%24skiptoken=%5B%7B%22token%22%3A%22%2BRID%3A~x%22%7D%5D&%24expand=replies"
    );
    f.fake.on("messages", move |s| {
        let mut b = json!({"value": [message(TEAM_A, CH_A1, MSG, "hello")]});
        if s.params.get("$skiptoken").is_none() {
            b["@odata.nextLink"] = json!(link);
        }
        Reply::ok(b)
    });
    let v = go(&f, &c, "teams.list_messages", with(json!({"top": 3})))
        .await
        .unwrap();
    assert_eq!(
        f.fake.last("messages").unwrap().params,
        json!({"$top": "3"})
    );
    let m = &v["messages"][0];
    assert_eq!(m["id"], MSG);
    assert_eq!(m["from"], json!({"id": USER, "name": "Robin Kline"}));
    assert_eq!(
        (m["content"].as_str(), m["content_type"].as_str()),
        (Some("hello"), Some("text"))
    );
    // The cursor is the skip token alone: not Microsoft's URL, not its $expand.
    let cursor = v["next_cursor"].as_str().unwrap().to_owned();
    assert!(!cursor.contains("graph.microsoft.com") && !cursor.contains("expand"));
    let again = go(
        &f,
        &c,
        "teams.list_messages",
        with(json!({"top": 3, "cursor": cursor})),
    )
    .await
    .unwrap();
    assert!(again.get("next_cursor").is_none());
    let sent = f.fake.last("messages").unwrap();
    assert_eq!(sent.params["$skiptoken"], "[{\"token\":\"+RID:~x\"}]");
    assert_eq!(
        sent.params.as_object().unwrap().len(),
        2,
        "$top and $skiptoken only"
    );
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn get_message_and_replies_use_fixed_paths() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let v = go(&f, &c, "teams.get_message", with(json!({"message": MSG})))
        .await
        .unwrap();
    assert_eq!(v["id"], MSG);
    assert_eq!(
        f.fake.last("message").unwrap().path,
        format!("/v1.0/teams/{TEAM_A}/channels/{CH_A1}/messages/{MSG}")
    );
    let v = go(&f, &c, "teams.list_replies", with(json!({"message": MSG})))
        .await
        .unwrap();
    assert_eq!(v["messages"][0]["content"], "re");
    assert_eq!(
        f.fake.last("replies").unwrap().path,
        format!("/v1.0/teams/{TEAM_A}/channels/{CH_A1}/messages/{MSG}/replies")
    );
    // An answer for another message than the one asked for is unreadable.
    f.fake.on("message", |s| {
        let (team, channel) = ids(&s.path);
        Reply::ok(message(&team, &channel, "1616990000000", "x"))
    });
    let e = go(&f, &c, "teams.get_message", with(json!({"message": MSG})))
        .await
        .unwrap_err();
    assert_eq!(e, CallError::Upstream(200));
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn post_and_reply_send_exactly_a_plain_text_body() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let text = "Deploy <b>done</b> & <script>x</script> https://example.test/a?b=1";
    let v = go(&f, &c, "teams.post_message", with(json!({"text": text})))
        .await
        .unwrap();
    assert_eq!(v["id"], "1616990099999");
    let sent = f.fake.last("post").unwrap();
    assert_eq!(
        sent.body,
        json!({"body": {"contentType": "text", "content": text}})
    );
    assert_eq!(
        sent.path,
        format!("/v1.0/teams/{TEAM_A}/channels/{CH_A1}/messages")
    );
    let args = with(json!({"message": MSG, "text": "ok"}));
    let v = go(&f, &c, "teams.reply_message", args).await.unwrap();
    assert!(v["id"].is_string());
    let sent = f.fake.last("reply").unwrap();
    assert_eq!(
        sent.body,
        json!({"body": {"contentType": "text", "content": "ok"}})
    );
    assert_eq!(
        f.fake.bad(),
        0,
        "no mentions, attachments, importance or html ever"
    );
}

#[tokio::test]
async fn a_write_whose_answer_cannot_be_checked_is_a_success_with_a_warning() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    // The message is live once Microsoft answered 2xx: whatever the answer looks like, the agent
    // is told it was sent (and not to send it again), never that it failed.
    for body in [
        message(TEAM_B, CH_B1, "1616990099999", "x"),
        message(TEAM_A, CH_A2, "1616990099999", "x"),
        json!({"id": "1616990099999"}),
        json!({"id": "1616990099999", "channelIdentity": {"teamId": TEAM_A}}),
        json!({"id": "not-an-id", "channelIdentity": {"teamId": TEAM_A, "channelId": CH_A1}}),
        json!(null),
        json!("text"),
    ] {
        f.fake.reply("post", Reply::http(201, body));
        let args = with(json!({"text": "x"}));
        let v = go(&f, &c, "teams.post_message", args).await.unwrap();
        assert_eq!(v["unverified"], true, "{v}");
        assert!(v.get("id").is_none() && !v.to_string().contains(CH_B1));
    }
    // A 2xx whose body is not JSON at all, and an empty one.
    for raw in [b"<html>ok</html>".to_vec(), Vec::new()] {
        f.fake
            .reply("reply", Reply::http(201, json!(null)).raw(raw));
        let args = with(json!({"message": MSG, "text": "x"}));
        let v = go(&f, &c, "teams.reply_message", args).await.unwrap();
        assert_eq!(v["unverified"], true);
    }
    // A failure BEFORE the message exists is still an error.
    f.fake.reply("post", Reply::graph(403, "Forbidden"));
    let args = with(json!({"text": "x"}));
    let e = go(&f, &c, "teams.post_message", args).await.unwrap_err();
    assert_eq!(e, CallError::Forbidden);
}

#[tokio::test]
async fn an_odd_answer_is_an_error_and_never_a_panic() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let odd = [
        json!(null),
        json!([]),
        json!("text"),
        json!(42),
        json!({}),
        json!({"value": null}),
        json!({"value": "x"}),
        json!({"value": [null]}),
        json!({"value": [1, "a", []]}),
        json!({"value": [{"id": 5}]}),
        json!({"value": [{"id": "1616990032035", "channelIdentity": 7}]}),
        json!({"value": [{"id": "1616990032035", "channelIdentity": {"teamId": 1, "channelId": []}}]}),
        json!({"value": {"id": MSG}}),
        json!({"@odata.nextLink": 5, "value": []}),
    ];
    for body in odd {
        for (route, op, args) in [
            ("teams", "teams.list_teams", json!({})),
            ("channels", "teams.list_channels", json!({"team": TEAM_A})),
            ("messages", "teams.list_messages", pair()),
            (
                "message",
                "teams.get_message",
                with(json!({"message": MSG})),
            ),
            (
                "replies",
                "teams.list_replies",
                with(json!({"message": MSG})),
            ),
            ("post", "teams.post_message", with(json!({"text": "x"}))),
            (
                "reply",
                "teams.reply_message",
                with(json!({"message": MSG, "text": "x"})),
            ),
        ] {
            let status = if matches!(route, "post" | "reply") {
                201
            } else {
                200
            };
            f.fake.reply(route, Reply::http(status, body.clone()));
            let r = go(&f, &c, op, args).await;
            // A body that is an empty list is a valid empty answer; anything else that is not
            // what the route says is an error.
            // (A team or channel list skips an entry it cannot read, by design.)
            let write = matches!(route, "post" | "reply");
            if let (Ok(v), false) = (&r, matches!(route, "teams" | "channels")) {
                // A write that Microsoft answered is live: odd answers are a warning, not an error.
                if write {
                    assert_eq!(v["unverified"], true, "{route} {body} -> {v}");
                    continue;
                }
                let empty = body
                    .get("value")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty);
                assert!(empty, "{route} {body} -> {v}");
            }
        }
    }
    // A giant list is refused, not read.
    let many: Vec<Value> = (0..60)
        .map(|i| message(TEAM_A, CH_A1, &format!("16169900{i:05}"), "x"))
        .collect();
    f.fake.reply("messages", Reply::ok(json!({"value": many})));
    let e = go(&f, &c, "teams.list_messages", pair()).await.unwrap_err();
    assert_eq!(e, CallError::Upstream(200));
    // Control characters and a long content are cleaned and cut, with a marker.
    let long = format!("a\u{0}b\u{7}c\nd{}", "x".repeat(5000));
    f.fake
        .reply("message", Reply::ok(message(TEAM_A, CH_A1, MSG, &long)));
    let v = go(&f, &c, "teams.get_message", with(json!({"message": MSG})))
        .await
        .unwrap();
    let content = v["content"].as_str().unwrap();
    assert!(content.starts_with("abc\nd") && content.chars().count() == 4000);
    assert_eq!(v["content_truncated"], true);
}

#[tokio::test]
async fn lists_are_cut_with_a_truncated_marker() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let teams: Vec<Value> = (0..130)
        .map(|i| json!({"id": format!("00000000-0000-4000-8000-{i:012x}"), "displayName": "t"}))
        .collect();
    f.fake.reply("teams", Reply::ok(json!({"value": teams})));
    let v = go(&f, &c, "teams.list_teams", json!({})).await.unwrap();
    assert_eq!(v["teams"].as_array().unwrap().len(), 100);
    assert_eq!(v["truncated"], true);
}

#[tokio::test]
async fn bad_arguments_are_refused_before_microsoft_is_asked() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let long = "x".repeat(4001);
    for (op, args) in [
        ("teams.list_teams", json!({"x": 1})),
        ("teams.list_channels", json!({})),
        ("teams.list_channels", json!({"team": "Alpha"})),
        ("teams.list_messages", json!([1])),
        ("teams.list_messages", with(json!({"top": 0}))),
        ("teams.list_messages", with(json!({"top": 51}))),
        ("teams.list_messages", with(json!({"top": "5"}))),
        ("teams.list_messages", with(json!({"cursor": "a b"}))),
        ("teams.list_messages", with(json!({"$expand": "replies"}))),
        ("teams.list_messages", with(json!({"filter": "x"}))),
        ("teams.get_message", pair()),
        ("teams.get_message", with(json!({"message": "../x"}))),
        (
            "teams.get_message",
            with(json!({"message": 1616990032035u64})),
        ),
        ("teams.post_message", pair()),
        ("teams.post_message", with(json!({"text": ""}))),
        ("teams.post_message", with(json!({"text": long}))),
        (
            "teams.post_message",
            with(json!({"text": "x", "mentions": []})),
        ),
        (
            "teams.post_message",
            with(json!({"text": "x", "importance": "urgent"})),
        ),
        (
            "teams.post_message",
            with(json!({"text": "x", "contentType": "html"})),
        ),
        ("teams.post_message", with(json!({"text": "x\u{0}"}))),
        ("teams.reply_message", with(json!({"text": "x"}))),
        ("teams.delete_message", pair()),
        ("teams.list_chats", json!({})),
    ] {
        let e = go(&f, &c, op, args.clone()).await.unwrap_err();
        assert!(matches!(e, CallError::Refused(_)), "{op} {args}: {e:?}");
    }
    assert!(f.fake.seen().is_empty(), "nothing reached Microsoft");
}
