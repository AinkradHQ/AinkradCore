//! Every channel is confirmed before it is read or posted to, because Graph does NOT refuse a
//! channel id asked under another team of the same tenant: under a `<team>/*` limit that would
//! reach any channel by its id. The fake here answers like Graph does, and the adapter must catch
//! it.

use serde_json::{Value, json};

use super::*;
use crate::connections::teams::{CallError, Limit};

fn wildcard(team: &str) -> Limit {
    Limit::only(&[format!("{team}/*")])
}

async fn ask(
    f: &Fx,
    c: &Connection,
    l: &Limit,
    op: &str,
    team: &str,
    ch: &str,
) -> Result<Value, CallError> {
    let mut a = json!({"team": team, "channel": ch});
    match op {
        "teams.post_message" => a["text"] = json!("x"),
        "teams.get_message" => a["message"] = json!(MSG),
        "teams.list_replies" => a["message"] = json!(MSG),
        "teams.reply_message" => {
            a["message"] = json!(MSG);
            a["text"] = json!("x");
        }
        _ => {}
    }
    run(f, c, l, op, a).await
}

const CHANNEL_OPS: [&str; 5] = [
    "teams.list_messages",
    "teams.get_message",
    "teams.list_replies",
    "teams.post_message",
    "teams.reply_message",
];

#[tokio::test]
async fn a_channel_of_another_team_is_refused_under_a_team_wildcard_before_anything_is_sent() {
    let f = fx(true).await;
    let c = f.signed_in().await;
    // The grant is TEAM_B's whole team; CH_A1 is a valid channel id of TEAM_A, and Graph answers
    // its lookup under TEAM_B with the channel as it is (it does not refuse the pair).
    let l = wildcard(TEAM_B);
    for op in CHANNEL_OPS {
        let e = ask(&f, &c, &l, op, TEAM_B, CH_A1).await.unwrap_err();
        assert!(
            matches!(&e, CallError::Refused(w) if w.starts_with("outside_limit")),
            "{op}: {e:?}"
        );
    }
    for route in ["messages", "message", "replies", "post", "reply"] {
        assert_eq!(f.fake.count(route), 0, "{route} was not asked");
    }
    assert!(f.fake.count("channel") >= 1);
    // The team's own channel is fine under the same grant.
    for op in CHANNEL_OPS {
        ask(&f, &c, &l, op, TEAM_B, CH_B1)
            .await
            .unwrap_or_else(|e| panic!("{op}: {e:?}"));
    }
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn a_channel_that_does_not_say_it_is_plain_and_in_this_tenant_and_team_is_refused() {
    let tenant_other = json!({"tenantId": OTHER_TENANT});
    let shared = json!({"membershipType": "shared"});
    let odd_kind = json!({"membershipType": "somethingNew"});
    let no_kind = json!({"membershipType": null});
    let no_tenant = json!({"tenantId": null});
    let wrong_id = json!({"id": CH_A2});
    let no_url = json!({"webUrl": null});
    let other_group =
        json!({"webUrl": format!("https://teams.microsoft.com/l/channel/x/y?groupId={TEAM_B}")});
    let no_group = json!({"webUrl": "https://teams.microsoft.com/l/channel/x/y"});
    let bad_url = json!({"webUrl": "not a url"});
    for (patch, shared_reason) in [
        (&tenant_other, true),
        (&shared, true),
        (&odd_kind, false),
        (&no_kind, false),
        (&no_tenant, true),
        (&wrong_id, false),
        (&no_url, false),
        (&other_group, false),
        (&no_group, false),
        (&bad_url, false),
    ] {
        let f = fx(true).await;
        let c = f.signed_in().await;
        let mut info = channel_info("", CH_A1);
        info.as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        f.fake.reply("channel", Reply::ok(info));
        for op in CHANNEL_OPS {
            let e = ask(&f, &c, &Limit::any(), op, TEAM_A, CH_A1)
                .await
                .unwrap_err();
            let CallError::Refused(why) = &e else {
                panic!("{op} {patch}: {e:?}")
            };
            assert_eq!(
                why.starts_with("shared_channel_unsupported"),
                shared_reason,
                "{patch}: {why}"
            );
        }
        assert_eq!(
            f.fake.graph_count(),
            f.fake.count("channel"),
            "{patch}: only the lookup was sent"
        );
    }
}

#[tokio::test]
async fn confirmation_fails_closed_on_an_error_or_cooling_and_remembers_only_a_yes() {
    for (reply, want) in [
        (Reply::graph(404, "ChannelNotFound"), CallError::NotFound),
        (Reply::graph(403, "Forbidden"), CallError::Forbidden),
        (
            Reply::graph(500, "generalException"),
            CallError::BadRequest(500),
        ),
        (
            Reply::http(200, json!(null)).raw(b"nope".to_vec()),
            CallError::Upstream(200),
        ),
    ] {
        let f = fx(true).await;
        let c = f.signed_in().await;
        f.fake.reply("channel", reply);
        let e = ask(&f, &c, &Limit::any(), "teams.post_message", TEAM_A, CH_A1)
            .await
            .unwrap_err();
        assert_eq!(e, want);
        assert_eq!(f.fake.count("post"), 0, "nothing was posted");
    }
    // A 429 on the lookup cools the channel: no post, and no second lookup.
    let f = fx(true).await;
    let c = f.signed_in().await;
    f.fake.reply(
        "channel",
        Reply::graph(429, "TooManyRequests").header("Retry-After", "9"),
    );
    for _ in 0..3 {
        let e = ask(&f, &c, &Limit::any(), "teams.post_message", TEAM_A, CH_A1)
            .await
            .unwrap_err();
        assert!(matches!(e, CallError::Cooling { .. }), "{e:?}");
    }
    assert_eq!((f.fake.count("channel"), f.fake.count("post")), (1, 0));
    // A yes is remembered for the connection, a no never is.
    let g = fx(true).await;
    let c = g.signed_in().await;
    let d = g.connect("two", &material(ACCESS, REFRESH, 3600)).await;
    for _ in 0..3 {
        ask(&g, &c, &Limit::any(), "teams.list_messages", TEAM_A, CH_A1)
            .await
            .unwrap();
    }
    assert_eq!(g.fake.count("channel"), 1);
    ask(&g, &d, &Limit::any(), "teams.list_messages", TEAM_A, CH_A1)
        .await
        .unwrap();
    assert_eq!(g.fake.count("channel"), 2, "per connection");
}
