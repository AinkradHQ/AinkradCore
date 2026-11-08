//! The channel limit: every attempt to reach a channel the grant does not name, on the request
//! and on the answer. A channel is its ID, compared exactly: never a name, never another case.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::ops::run;
use super::*;
use crate::connections::slack::{CallError, Limit, resource_of};

fn only(ids: &[&str]) -> Limit {
    Limit::only(&ids.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
}

fn with_channel(op: &str, channel: Value) -> Value {
    match op {
        "slack.read_channel" => json!({"channel": channel}),
        "slack.read_thread" => json!({"channel": channel, "ts": TS}),
        "slack.post_message" => json!({"channel": channel, "text": "t"}),
        _ => json!({"channel": channel, "ts": TS, "name": "x"}),
    }
}

const WITH_CHANNEL: [&str; 4] = [
    "slack.read_channel",
    "slack.read_thread",
    "slack.post_message",
    "slack.add_reaction",
];

#[tokio::test]
async fn a_channel_outside_the_limit_is_refused_before_slack_is_asked() {
    let f = fx(false).await;
    let c = f.bot().await;
    let limit = only(&[CH]);
    let at = '@';
    let tricks = [
        json!(CH2),
        json!("general"),
        json!("#general"),
        json!("c012ab3cd"),
        json!(format!("{CH} ")),
        json!(format!(" {CH}")),
        json!(format!("{CH}\n")),
        json!(format!("{CH}\u{0}")),
        json!("C012AB3C\u{FF24}"),
        json!("C012AB\u{0417}CD"),
        json!(format!("{CH}/../{CH2}")),
        json!(format!("{CH}/{CH2}")),
        json!("%43012AB3CD"),
        json!(format!("{CH},{CH2}")),
        json!(format!("{CH} {CH2}")),
        json!([CH, CH2]),
        json!([CH]),
        json!({"id": CH}),
        json!("D012AB3CD"),
        json!("U012AB3CD"),
        json!("W012AB3CD"),
        json!(format!("{at}ainkrad")),
        json!("G999AB3CD"),
        json!(""),
        json!(null),
        json!(5),
        json!(true),
    ];
    for op in WITH_CHANNEL {
        for t in &tricks {
            let r = run(&f, &c, &limit, op, with_channel(op, t.clone())).await;
            assert!(matches!(r, Err(CallError::Refused(_))), "{op} {t}: {r:?}");
        }
    }
    assert!(f.fake.seen().is_empty(), "{:?}", f.fake.names());
    // The refusal does not say which channel is allowed or what exists.
    let r = run(
        &f,
        &c,
        &limit,
        "slack.read_channel",
        json!({"channel": CH2}),
    )
    .await;
    let Err(CallError::Refused(why)) = r else {
        panic!()
    };
    assert!(
        why.starts_with("outside_limit") && !why.contains(CH) && !why.contains(CH2),
        "{why}"
    );
}

#[tokio::test]
async fn a_channel_inside_the_limit_reaches_slack_as_exactly_that_id() {
    let f = fx(false).await;
    let c = f.bot().await;
    let limit = only(&[CH, CH2]);
    f.fake
        .reply("conversations.history", history(vec![msg(TS, "a")]));
    f.fake
        .reply("conversations.replies", history(vec![msg(TS, "a")]));
    f.fake.reply("reactions.add", Reply::ok(json!({})));
    f.fake.on("chat.postMessage", |s| {
        Reply::ok(json!({"channel": s.form["channel"], "ts": TS}))
    });
    for op in WITH_CHANNEL {
        for ch in [CH, CH2] {
            run(&f, &c, &limit, op, with_channel(op, json!(ch)))
                .await
                .unwrap();
            let name = match op {
                "slack.read_channel" => "conversations.history",
                "slack.read_thread" => "conversations.replies",
                "slack.post_message" => "chat.postMessage",
                _ => "reactions.add",
            };
            assert_eq!(f.fake.last(name).unwrap().form["channel"], ch);
        }
    }
    // A reply's thread timestamp is only ever sent with the permitted channel: a timestamp belongs
    // to one channel, so another channel's thread is Slack's `thread_not_found`, not a leak.
    let args = json!({"channel": CH, "ts": "1600000000.000200"});
    run(&f, &c, &limit, "slack.read_thread", args)
        .await
        .unwrap();
    let sent = f.fake.last("conversations.replies").unwrap().form;
    assert_eq!(
        (sent["channel"].clone(), sent["ts"].clone()),
        (json!(CH), json!("1600000000.000200"))
    );
    assert_eq!(f.fake.bad(), 0);
}

#[test]
fn a_limit_keeps_only_well_formed_channel_ids_and_a_grant_without_channels_is_any() {
    let l = only(&[
        "general",
        "c012ab3cd",
        "D012AB3CD",
        "U012AB3CD",
        "*",
        "C012AB3CD/*",
        CH,
    ]);
    assert_eq!(l, only(&[CH]));
    assert!(l.permits(CH) && !l.permits(CH2) && !l.permits("D012AB3CD") && !l.permits("*"));
    assert!(Limit::any().permits(CH2) && !Limit::any().limited());
    let mut grant = BTreeMap::new();
    assert_eq!(Limit::from_grant(&grant), Limit::any());
    grant.insert("channels".to_owned(), vec![CH.to_owned(), "*".to_owned()]);
    assert_eq!(Limit::from_grant(&grant), only(&[CH]));
    // Some other key is not this limit.
    let mut other = BTreeMap::new();
    other.insert("repos".to_owned(), vec![CH.to_owned()]);
    assert_eq!(Limit::from_grant(&other), Limit::any());
    // An empty list (every entry malformed) reaches nothing.
    grant.insert("channels".to_owned(), vec!["general".to_owned()]);
    let none = Limit::from_grant(&grant);
    assert!(none.limited() && !none.permits(CH));
    // The resource the broker decides on is the channel; none for the self-limited ones.
    assert_eq!(
        resource_of("slack.read_channel", &json!({"channel": CH})),
        Ok(Some(CH.to_owned()))
    );
    assert_eq!(resource_of("slack.list_channels", &json!({})), Ok(None));
    assert_eq!(
        resource_of("slack.get_user", &json!({"user": "U0123456789"})),
        Ok(None)
    );
    assert!(resource_of("slack.read_channel", &json!({"channel": "general"})).is_err());
}

#[tokio::test]
async fn a_grant_that_names_no_valid_channel_reaches_none_and_lists_none() {
    let f = fx(false).await;
    let c = f.bot().await;
    let none = only(&["general"]);
    for (op, args) in [
        ("slack.list_channels", json!({})),
        ("slack.read_channel", json!({"channel": CH})),
        ("slack.post_message", json!({"channel": CH, "text": "t"})),
    ] {
        let r = run(&f, &c, &none, op, args).await;
        assert!(matches!(r, Err(CallError::Refused(_))), "{op}");
    }
    assert!(f.fake.seen().is_empty());
}

#[tokio::test]
async fn a_g_id_is_a_private_channel_only_when_slack_says_so() {
    let f = fx(false).await;
    let c = f.bot().await;
    f.fake
        .reply("conversations.history", history(vec![msg(TS, "a")]));
    let info = |fields: Value| {
        let mut ch = json!({"id": PRIV, "is_private": true, "is_mpim": false, "is_im": false});
        ch.as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        Reply::ok(json!({"channel": ch}))
    };
    let args = json!({"channel": PRIV});
    // A private channel: info first, then the history.
    f.fake.reply("conversations.info", info(json!({})));
    run(&f, &c, &Limit::any(), "slack.read_channel", args.clone())
        .await
        .unwrap();
    assert_eq!(
        f.fake.names(),
        ["conversations.info", "conversations.history"]
    );
    assert_eq!(
        f.fake.last("conversations.info").unwrap().form,
        json!({"channel": PRIV})
    );
    // A second connection for the refusals: a confirmation is remembered per connection, and the
    // first connection's is.
    let c2 = f
        .connect(
            "two",
            "token",
            &token_material("xoxb-test-111-222-acc4").unwrap(),
        )
        .await;
    // Anything else, or anything unsaid, is refused and the history is never asked.
    let refusals = [
        info(json!({"is_mpim": true})),
        info(json!({"is_im": true})),
        info(json!({"is_private": false})),
        info(json!({"id": "G999AB3CD"})),
        Reply::ok(json!({"channel": {"id": PRIV, "is_private": true}})),
        Reply::ok(json!({"channel": {"id": PRIV, "is_mpim": false}})),
        Reply::ok(json!({"channel": null})),
        Reply::ok(json!({})),
        Reply::ok(json!({"channel": 5})),
    ];
    for r in refusals {
        let before = f.fake.count("conversations.history");
        f.fake.reply("conversations.info", r.clone());
        for op in [
            "slack.read_channel",
            "slack.read_thread",
            "slack.post_message",
            "slack.add_reaction",
        ] {
            let a = match op {
                "slack.read_channel" => json!({"channel": PRIV}),
                "slack.read_thread" => json!({"channel": PRIV, "ts": TS}),
                "slack.post_message" => json!({"channel": PRIV, "text": "t"}),
                _ => json!({"channel": PRIV, "ts": TS, "name": "x"}),
            };
            let out = run(&f, &c2, &Limit::any(), op, a).await;
            assert!(
                matches!(out, Err(CallError::Refused(_))),
                "{op} {:?}",
                r.body
            );
        }
        assert_eq!(f.fake.count("conversations.history"), before);
        assert_eq!(f.fake.count("chat.postMessage"), 0);
        assert_eq!(f.fake.count("reactions.add"), 0);
    }
    // A DM or a group DM whose id Slack hides behind `channel_not_found` is not a channel either.
    f.fake
        .reply("conversations.info", Reply::err("channel_not_found"));
    let r = run(&f, &c2, &Limit::any(), "slack.read_channel", args).await;
    assert_eq!(r, Err(CallError::NotFound));
    // A C id is confirmed the same way (see `every_channel_id_is_confirmed...`).
    f.fake.default_info();
    let infos = f.fake.count("conversations.info");
    let ch = json!({"channel": CH});
    run(&f, &c, &Limit::any(), "slack.read_channel", ch)
        .await
        .unwrap();
    assert_eq!(f.fake.count("conversations.info"), infos + 1);
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn a_post_answered_with_another_channel_is_refused_loudly() {
    let f = fx(false).await;
    let c = f.bot().await;
    let limit = only(&[CH]);
    for body in [
        json!({"channel": CH2, "ts": TS}),
        json!({"channel": "D012AB3CD", "ts": TS}),
        json!({"channel": CH}),
        json!({"channel": CH, "ts": "nope"}),
        json!({"ts": TS}),
        json!({"channel": [CH], "ts": TS}),
    ] {
        f.fake.reply("chat.postMessage", Reply::ok(body.clone()));
        let r = run(
            &f,
            &c,
            &limit,
            "slack.post_message",
            json!({"channel": CH, "text": "t"}),
        )
        .await;
        let Err(CallError::Refused(why)) = r else {
            panic!("{body}: {r:?}")
        };
        assert!(why.starts_with("outside_limit"), "{why}");
    }
}

#[tokio::test]
async fn a_list_is_cut_to_the_limit_even_when_slack_returns_more() {
    let f = fx(false).await;
    let c = f.bot().await;
    let all = json!({"channels": [
        {"id": CH, "name": "a"}, {"id": CH2, "name": "b"}, {"id": PRIV, "name": "c", "is_private": true}]});
    f.fake.reply("conversations.list", Reply::ok(all));
    let v = run(&f, &c, &only(&[CH2]), "slack.list_channels", json!({}))
        .await
        .unwrap();
    let ids: Vec<_> = v["channels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].clone())
        .collect();
    assert_eq!(ids, [json!(CH2)]);
    assert!(!v.to_string().contains(CH) || v.to_string().matches(CH).count() == 0);
    // A limited list asks for 200 at a time, so the limit is found in few requests.
    assert_eq!(
        f.fake.last("conversations.list").unwrap().form["limit"],
        "200"
    );
}

fn paged(f: &Fx, pages: usize, hit_on: Option<usize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let n = std::sync::Arc::new(AtomicUsize::new(0));
    f.fake.on("conversations.list", move |s| {
        let i = n.fetch_add(1, Ordering::SeqCst);
        let channels = if Some(i) == hit_on {
            json!([{"id": CH2, "name": "b"}])
        } else {
            json!([{"id": "C9990000000", "name": "other"}])
        };
        let cursor = if i + 1 < pages {
            format!("cGFnZQ{}", i + 1)
        } else {
            String::new()
        };
        let _ = s;
        Reply::ok(json!({"channels": channels, "response_metadata": {"next_cursor": cursor}}))
    });
}

#[tokio::test]
async fn a_limited_list_pages_to_find_its_channels_and_says_when_it_stopped_early() {
    let f = fx(false).await;
    let c = f.bot().await;
    // Found on the third page: three requests, and nothing is left unread that matters.
    paged(&f, 9, Some(2));
    let v = run(&f, &c, &only(&[CH2]), "slack.list_channels", json!({}))
        .await
        .unwrap();
    assert_eq!(f.fake.count("conversations.list"), 3);
    assert_eq!(
        (
            v["channels"].as_array().unwrap().len(),
            v["truncated"].clone()
        ),
        (1, json!(false))
    );
    assert!(v.get("next_cursor").is_none());
    assert_eq!(
        f.fake.last("conversations.list").unwrap().form["cursor"],
        "cGFnZQ2"
    );
    // Never found: five pages at most (the descriptor's budget counts on it), then a marker and
    // the cursor to go on from.
    let g = fx(false).await;
    let c = g.bot().await;
    paged(&g, 50, None);
    let v = run(&g, &c, &only(&[CH2]), "slack.list_channels", json!({}))
        .await
        .unwrap();
    assert_eq!(g.fake.count("conversations.list"), 5);
    assert_eq!(v["channels"], json!([]));
    assert_eq!(
        (v["truncated"].clone(), v["next_cursor"].clone()),
        (json!(true), json!("cGFnZQ5"))
    );
    // And it goes on from there.
    let v = run(
        &g,
        &c,
        &only(&[CH2]),
        "slack.list_channels",
        json!({"cursor": "cGFnZQ5"}),
    )
    .await
    .unwrap();
    let lists: Vec<_> = g
        .fake
        .seen()
        .into_iter()
        .filter(|s| s.name == "conversations.list")
        .collect();
    assert_eq!(lists.len(), 10);
    assert_eq!(
        lists[5].form["cursor"], "cGFnZQ5",
        "the second call starts where the first stopped"
    );
    assert_eq!(v["truncated"], true);
    // The last page is a clean end.
    let h = fx(false).await;
    let c = h.bot().await;
    paged(&h, 2, None);
    let v = run(&h, &c, &only(&[CH2]), "slack.list_channels", json!({}))
        .await
        .unwrap();
    assert_eq!(
        (h.fake.count("conversations.list"), v["truncated"].clone()),
        (2, json!(false))
    );
    assert_eq!(f.fake.bad() + g.fake.bad() + h.fake.bad(), 0);
}
