//! The channel limit: it holds on the request (exact team GUID and channel id, no variant gets
//! through) and on the answer, and the adapter and the store decide the same way.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;
use crate::connections::teams::{CallError, Limit, resource_of};
use crate::store::connections::grants::value_matches;

fn only_a1() -> Limit {
    Limit::only(&[KEY_A1.to_owned()])
}

fn args(team: &str, channel: &str) -> Value {
    json!({"team": team, "channel": channel})
}

/// Every operation that names a channel, with `team` and `channel` swapped in.
fn ops_for(team: &str, channel: &str) -> Vec<(&'static str, Value)> {
    let with = |extra: Value| {
        let mut v = args(team, channel);
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        v
    };
    vec![
        ("teams.list_messages", with(json!({}))),
        ("teams.get_message", with(json!({"message": MSG}))),
        ("teams.list_replies", with(json!({"message": MSG}))),
        ("teams.post_message", with(json!({"text": "x"}))),
        (
            "teams.reply_message",
            with(json!({"message": MSG, "text": "x"})),
        ),
    ]
}

#[tokio::test]
async fn only_the_named_channel_is_reachable_on_every_operation() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let limit = only_a1();
    for (op, a) in ops_for(TEAM_A, CH_A1) {
        run(&f, &c, &limit, op, a)
            .await
            .unwrap_or_else(|e| panic!("{op}: {e:?}"));
    }
    let reached = f.fake.graph_count();
    // Five operations, and the channel confirmed once for all of them.
    assert_eq!(reached, 6);
    assert_eq!(f.fake.count("channel"), 1);
    let upper_team = TEAM_A.to_uppercase();
    let upper_channel = CH_A1.to_uppercase();
    let skype = "19:4a95f7d8db4c4e7fae857bcebe0623e6\u{40}thread.skype";
    let encoded = "19%3A4a95f7d8db4c4e7fae857bcebe0623e6%40thread.tacv2";
    let traversal = format!("{CH_A1}/../{CH_A2}");
    let nested = format!("{CH_A1}/messages/{MSG}");
    let query = format!("{CH_A1}?$expand=replies");
    let team_path = format!("{TEAM_A}/channels/{CH_A2}");
    let both = KEY_A1.to_owned();
    let cases: Vec<(&str, &str)> = vec![
        (TEAM_A, CH_A2),              // the same team's other channel
        (TEAM_B, CH_B1),              // another team, a valid channel of it
        (TEAM_B, CH_A1),              // the allowed channel under another team
        (TEAM_A, CH_B1),              // another team's channel under this team
        (CH_A1, TEAM_A),              // swapped
        (upper_team.as_str(), CH_A1), // case variants
        (TEAM_A, upper_channel.as_str()),
        (TEAM_A, skype),   // the other suffix kind of the same middle
        (TEAM_A, encoded), // percent-encoded
        (TEAM_A, traversal.as_str()),
        (TEAM_A, nested.as_str()),
        (TEAM_A, query.as_str()),
        (team_path.as_str(), CH_A1), // a path in the team slot
        (TEAM_A, both.as_str()),     // the key in the channel slot
        (TEAM_A, ""),
        ("", CH_A1),
        ("*", "*"),
    ];
    for (team, channel) in cases {
        for (op, a) in ops_for(team, channel) {
            let e = run(&f, &c, &limit, op, a).await.unwrap_err();
            assert!(
                matches!(e, CallError::Refused(_)),
                "{op} {team} {channel}: {e:?}"
            );
        }
    }
    assert_eq!(
        f.fake.graph_count(),
        reached,
        "not one of them reached Microsoft"
    );
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn the_refusal_does_not_say_which_channel() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let e = run(
        &f,
        &c,
        &only_a1(),
        "teams.list_messages",
        args(TEAM_B, CH_B1),
    )
    .await
    .unwrap_err();
    let text = e.to_string();
    assert!(text.starts_with("refused: outside_limit"), "{text}");
    assert!(
        !text.contains(TEAM_B) && !text.contains("b6bed8d2"),
        "{text}"
    );
}

#[tokio::test]
async fn a_team_wildcard_means_that_teams_channels_and_nothing_else() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let limit = Limit::only(&[format!("{TEAM_A}/*")]);
    for ch in [CH_A1, CH_A2] {
        run(&f, &c, &limit, "teams.list_messages", args(TEAM_A, ch))
            .await
            .unwrap();
    }
    let e = run(&f, &c, &limit, "teams.list_messages", args(TEAM_B, CH_B1))
        .await
        .unwrap_err();
    assert!(matches!(e, CallError::Refused(_)));
    // Another team that merely starts the same, and an upper-case team, match nothing.
    let like = Limit::only(&[
        format!("{}/*", &TEAM_A[..35]),
        format!("{}/*", TEAM_A.to_uppercase()),
    ]);
    let e = run(&f, &c, &like, "teams.list_messages", args(TEAM_A, CH_A1))
        .await
        .unwrap_err();
    assert!(matches!(e, CallError::Refused(_)));
}

#[tokio::test]
async fn malformed_limit_entries_only_shrink_what_is_allowed() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let upper_key = KEY_A1.to_uppercase();
    let junk: Vec<String> = [
        "*",
        "teams/*",
        "/*",
        "",
        TEAM_A,
        "x/y",
        upper_key.as_str(),
        "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b/*/x",
        "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b/4a95f7d8db4c4e7fae857bcebe0623e6/",
        "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b/../4a95f7d8db4c4e7fae857bcebe0623e6",
        CH_A1,
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    let limit = Limit::only(&junk);
    for (op, a) in ops_for(TEAM_A, CH_A1) {
        let e = run(&f, &c, &limit, op, a).await.unwrap_err();
        assert!(matches!(e, CallError::Refused(_)), "{op}");
    }
    let e = run(&f, &c, &limit, "teams.list_teams", json!({}))
        .await
        .unwrap_err();
    assert!(matches!(e, CallError::Refused(w) if w.contains("no channel")));
    assert_eq!(f.fake.graph_count(), 0);
    // No limit key at all is "any"; the grant's own `channels` values are the limit.
    let mut grant = BTreeMap::new();
    assert_eq!(Limit::from_grant(&grant), Limit::any());
    grant.insert(
        "channels".to_owned(),
        vec![KEY_A1.to_owned(), "*".to_owned()],
    );
    assert_eq!(Limit::from_grant(&grant), only_a1());
}

#[tokio::test]
async fn the_adapter_and_the_store_decide_alike() {
    let upper_team = TEAM_A.to_uppercase();
    let skype = format!("{TEAM_A}/4a95f7d8db4c4e7fae857bcebe0623e6.skype");
    let entries = [
        vec![KEY_A1.to_owned()],
        vec![format!("{TEAM_A}/*")],
        vec![format!("{upper_team}/*")],
        vec![KEY_B1.to_owned(), format!("{TEAM_B}/*")],
        vec![String::new()],
    ];
    let probes = [
        (TEAM_A, CH_A1),
        (TEAM_A, CH_A2),
        (TEAM_B, CH_B1),
        (
            TEAM_A,
            "19:4a95f7d8db4c4e7fae857bcebe0623e6\u{40}thread.skype",
        ),
    ];
    for allowed in &entries {
        let limit = Limit::only(allowed);
        for (team, channel) in probes {
            let key = resource_of("teams.list_messages", &args(team, channel))
                .unwrap()
                .unwrap();
            let by_store = value_matches(allowed, &key);
            let by_adapter = limit_permits(&limit, team, &key);
            assert_eq!(by_store, by_adapter, "{allowed:?} vs {key}");
        }
    }
    let one = std::slice::from_ref(&skype);
    assert!(value_matches(one, &skype) && !value_matches(one, KEY_A1));
}

/// The adapter's decision for a key, through the public path: the operation is allowed or refused.
fn limit_permits(limit: &Limit, team: &str, key: &str) -> bool {
    let (_, mid) = key.split_once('/').unwrap();
    let channel = match mid.strip_suffix(".skype") {
        Some(m) => format!("19:{m}@thread.skype"),
        None => format!("19:{mid}@thread.tacv2"),
    };
    crate::connections::teams::Plan::from_test(limit, team, &channel)
}

#[tokio::test]
async fn lists_are_cut_to_the_limit_on_the_request_and_the_answer() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let limit = only_a1();
    let v = run(&f, &c, &limit, "teams.list_teams", json!({}))
        .await
        .unwrap();
    let ids: Vec<&str> = v["teams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [TEAM_A], "Beta is not in the limit");
    let v = run(
        &f,
        &c,
        &limit,
        "teams.list_channels",
        json!({"team": TEAM_A}),
    )
    .await
    .unwrap();
    let ids: Vec<&str> = v["channels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [CH_A1], "the private channel is not in the limit");
    let before = f.fake.graph_count();
    let e = run(
        &f,
        &c,
        &limit,
        "teams.list_channels",
        json!({"team": TEAM_B}),
    )
    .await
    .unwrap_err();
    assert!(matches!(e, CallError::Refused(_)));
    assert_eq!(
        f.fake.graph_count(),
        before,
        "another team's channels are not even asked for"
    );
    // A team wildcard sees every channel of that team and no other team.
    let wild = Limit::only(&[format!("{TEAM_A}/*")]);
    let v = run(
        &f,
        &c,
        &wild,
        "teams.list_channels",
        json!({"team": TEAM_A}),
    )
    .await
    .unwrap();
    assert_eq!(v["channels"].as_array().unwrap().len(), 2);
    let v = run(&f, &c, &wild, "teams.list_teams", json!({}))
        .await
        .unwrap();
    assert_eq!(v["teams"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn an_answer_outside_the_limit_is_refused_and_names_nothing() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    let limit = only_a1();
    let wrong = [
        message(TEAM_A, CH_A2, MSG, "secret-other-channel"),
        message(TEAM_B, CH_B1, MSG, "secret-other-team"),
        json!({"id": MSG, "chatId": "19:x_y\u{40}unq.gbl.spaces", "channelIdentity": null,
            "body": {"contentType": "text", "content": "secret-dm"}}),
        json!({"id": MSG, "body": {"contentType": "text", "content": "secret-no-identity"}}),
    ];
    for m in wrong {
        f.fake.reply(
            "messages",
            Reply::ok(json!({"value": [message(TEAM_A, CH_A1, MSG, "fine"), m]})),
        );
        let e = run(&f, &c, &limit, "teams.list_messages", args(TEAM_A, CH_A1))
            .await
            .unwrap_err();
        let text = format!("{e:?} {e}");
        assert!(
            matches!(e, CallError::Refused(_)) && !text.contains("secret"),
            "{text}"
        );
    }
}

#[tokio::test]
async fn a_cursor_cannot_add_a_parameter() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let f = fx(true).await;
    let c = f.signed_in().await;
    for token in [
        "abc&$expand=replies",
        "abc&$filter=from/user/id eq 'x'",
        "a=b&$select=body",
        "\u{1F600}%26$top=1000",
        "x\" ; drop",
    ] {
        let cursor = URL_SAFE_NO_PAD.encode(token);
        let a = json!({"team": TEAM_A, "channel": CH_A1, "cursor": cursor});
        run(&f, &c, &Limit::any(), "teams.list_messages", a)
            .await
            .unwrap();
        let sent = f.fake.last("messages").unwrap();
        assert_eq!(
            sent.params["$skiptoken"], token,
            "one value, however it looks"
        );
        assert_eq!(sent.params.as_object().unwrap().len(), 2);
    }
    assert_eq!(f.fake.bad(), 0);
    // A cursor that is not one Core made (raw text, control characters, too long) is refused.
    let (long, newline) = ("A".repeat(4097), URL_SAFE_NO_PAD.encode("a\nb"));
    for cursor in [
        "a b",
        "a&$expand=x",
        "%24expand",
        long.as_str(),
        newline.as_str(),
    ] {
        let a = json!({"team": TEAM_A, "channel": CH_A1, "cursor": cursor});
        let e = run(&f, &c, &Limit::any(), "teams.list_messages", a)
            .await
            .unwrap_err();
        assert!(matches!(e, CallError::Refused(_)), "{cursor:.20}");
    }
}
