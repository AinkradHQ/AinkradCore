//! Slack through the broker: the channel limit holds end to end (grant, request, answer), no
//! credential leaves, a message goes out as plain text, and what an agent can provoke gives no
//! health signal.

use ainkrad_proto::v2::MAX_SCHEMA_BYTES;

use super::*;
use crate::connections::slack::tests::{self as st, Reply};

/// A Broker whose Slack is the loopback one, a bot-token connection granted `read_messages` and
/// `post_messages` with `limits`, and an agent session allowed both.
async fn ready(limits: &[(&str, &[&str])]) -> (Fx, st::Fx, Connection, String) {
    let mut f = fx().await;
    let l = st::fx(false).await;
    f.reg.register(l.slack.clone()).unwrap();
    f.b = Broker::with(
        f.reg.clone(),
        Github::strict(),
        f.j.jira.clone(),
        Limits::default(),
    )
    .with_slack(l.slack.clone());
    let new = NewConnection {
        kind: "slack",
        name: "main",
        label: "A Slack workspace",
        auth_method: "token",
    };
    let c = create(&f.j.pool, &f.j.sealer, &f.reg, &new, &st::bot(), who())
        .await
        .unwrap();
    let caps = ["read_messages", "post_messages"];
    f.member(c.id, &caps, limits).await;
    f.grant(c.id, ("agent", "bot"), &caps, limits).await;
    let s = f.session(&caps).await;
    (f, l, c, s)
}

fn read(ch: &str) -> Value {
    json!({"channel": ch})
}

#[tokio::test]
async fn a_call_in_the_channel_limit_works_and_the_credential_never_leaves() {
    let (f, l, _c, s) = ready(&[("channels", &[st::CH])]).await;
    let echo = format!("token {} and Bearer {}", st::ACCESS, st::ACCESS);
    l.fake.reply(
        "conversations.history",
        st::history(vec![st::msg(st::TS, &echo)]),
    );
    let r = f.ask(&s, "slack.read_channel", read(st::CH)).await;
    assert!(r.ok, "{r:?}");
    let text = format!("{r:?}");
    assert!(!text.contains(st::ACCESS), "{text}");
    assert_eq!(r.result.as_ref().unwrap()["messages"][0]["ts"], st::TS);
    // The credential went upstream as a Bearer, and only in the header.
    let sent = l.fake.last("conversations.history").unwrap();
    assert_eq!(sent.auth, Some(format!("Bearer {}", st::ACCESS)));
    assert!(!sent.form.to_string().contains(st::ACCESS));
    assert!(!f.audit_text().await.contains(st::ACCESS));
    assert_eq!(l.fake.bad(), 0);
}

#[tokio::test]
async fn a_channel_outside_the_grant_is_refused_before_slack_is_asked() {
    let (f, l, _c, s) = ready(&[("channels", &[st::CH])]).await;
    for (tool, args) in [
        ("slack.read_channel", read(st::CH2)),
        (
            "slack.read_thread",
            json!({"channel": st::CH2, "ts": st::TS}),
        ),
        (
            "slack.post_message",
            json!({"channel": st::CH2, "text": "x"}),
        ),
        (
            "slack.add_reaction",
            json!({"channel": st::CH2, "ts": st::TS, "name": "x"}),
        ),
    ] {
        let r = f.ask(&s, tool, args).await;
        assert_eq!((r.ok, code(&r)), (false, "resource_denied"), "{tool}");
    }
    // Names, DMs, users and lists of channels are not channels at all.
    for bad in [
        json!("general"),
        json!("D012AB3CD"),
        json!("U012AB3CD"),
        json!([st::CH]),
        json!(null),
    ] {
        let r = f
            .ask(
                &s,
                "slack.post_message",
                json!({"channel": bad, "text": "x"}),
            )
            .await;
        assert!(!r.ok);
        assert!(
            matches!(code(&r), "bad_args" | "resource_denied"),
            "{bad}: {}",
            code(&r)
        );
    }
    // An operation with no channel that does not limit itself cannot run under a limit; the two
    // that do (a list cut to the limit, a user lookup) run.
    assert!(l.fake.seen().is_empty(), "{:?}", l.fake.names());
    l.fake.reply(
        "conversations.list",
        Reply::ok(json!({"channels": [{"id": st::CH, "name": "a"}, {"id": st::CH2, "name": "b"}]})),
    );
    let r = f.ask(&s, "slack.list_channels", json!({})).await;
    assert!(r.ok, "{r:?}");
    let ids: Vec<_> = r.result.unwrap()["channels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].clone())
        .collect();
    assert_eq!(ids, [json!(st::CH)]);
}

#[tokio::test]
async fn a_post_is_plain_text_audited_without_its_words_and_a_read_only_grant_cannot_post() {
    let (f, l, c, s) = ready(&[("channels", &[st::CH])]).await;
    l.fake.on("chat.postMessage", |q| {
        Reply::ok(json!({"channel": q.form["channel"], "ts": st::TS}))
    });
    let words = "launch codes are swordfish <!channel>";
    let r = f
        .ask(
            &s,
            "slack.post_message",
            json!({"channel": st::CH, "text": words}),
        )
        .await;
    assert!(r.ok, "{r:?}");
    let sent = l.fake.last("chat.postMessage").unwrap().form;
    assert_eq!(sent["text"], "launch codes are swordfish &lt;!channel&gt;");
    let audit = f.audit_text().await;
    assert!(!audit.contains("swordfish"), "{audit}");
    // A grant that names only the read capability does not carry a post.
    f.member(c.id, &["read_messages"], &[("channels", &[st::CH])])
        .await;
    f.grant(
        c.id,
        ("agent", "bot"),
        &["read_messages"],
        &[("channels", &[st::CH])],
    )
    .await;
    let before = l.fake.count("chat.postMessage");
    let r = f
        .ask(
            &s,
            "slack.post_message",
            json!({"channel": st::CH, "text": "x"}),
        )
        .await;
    assert!(!r.ok);
    assert_eq!(l.fake.count("chat.postMessage"), before);
}

#[tokio::test]
async fn a_post_answered_for_another_channel_is_refused_and_costs_no_health() {
    let (f, l, c, s) = ready(&[("channels", &[st::CH])]).await;
    l.fake.reply(
        "chat.postMessage",
        Reply::ok(json!({"channel": st::CH2, "ts": st::TS})),
    );
    let r = f
        .ask(
            &s,
            "slack.post_message",
            json!({"channel": st::CH, "text": "x"}),
        )
        .await;
    assert_eq!((r.ok, code(&r)), (false, "refused"));
    assert!(!format!("{r:?}").contains(st::CH2));
    assert_eq!(f.status(c.id).await, ("active".to_owned(), None));
}

#[tokio::test]
async fn what_an_agent_can_provoke_gives_no_health_signal_and_a_refused_token_is_pending_only() {
    let (f, l, c, s) = ready(&[]).await;
    for reply in [
        Reply::err("channel_not_found"),
        Reply::err("not_in_channel"),
        Reply::err("is_archived"),
        Reply::err("missing_scope"),
        Reply::err("invalid_arguments"),
        Reply::err("msg_too_long"),
        Reply::err("rate_limited"),
        Reply::err("internal_error"),
        Reply::http(404, Value::Null),
        Reply::http(302, Value::Null).header("location", "https://evil.example/x"),
        Reply::ok(json!({"messages": "not a list"})),
    ] {
        let body = reply.clone();
        l.fake.on("conversations.history", move |_| body.clone());
        let r = f.ask(&s, "slack.read_channel", read(st::CH)).await;
        assert!(!r.ok, "{:?}", reply.body);
        assert_eq!(
            f.status(c.id).await,
            ("active".to_owned(), None),
            "{:?}",
            reply.body
        );
    }
    // A credential Slack refuses is a pending signal: out of use until a test decides.
    l.fake
        .on("conversations.history", |_| Reply::err("invalid_auth"));
    let r = f.ask(&s, "slack.read_channel", read(st::CH)).await;
    assert_eq!((r.ok, code(&r)), (false, "auth_failed"));
    assert_eq!(
        f.status(c.id).await,
        ("unhealthy".to_owned(), Some("auth_suspected".to_owned()))
    );
    let again = f.ask(&s, "slack.read_channel", read(st::CH)).await;
    assert_eq!(code(&again), "auth_pending");
}

#[tokio::test]
async fn the_session_sees_slack_tools_with_schemas_and_write_marks() {
    let (f, _l, _c, s) = ready(&[]).await;
    let tools = f.b.tools(&f.env(), &s).await.unwrap();
    let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
    for want in [
        "slack.list_channels",
        "slack.read_channel",
        "slack.read_thread",
        "slack.get_user",
        "slack.post_message",
        "slack.add_reaction",
    ] {
        assert!(names.contains(&want), "{want} in {names:?}");
    }
    for t in tools.iter().filter(|t| t.name.starts_with("slack.")) {
        let schema = t.input_schema.as_ref().expect("a schema");
        assert!(schema.to_string().len() <= MAX_SCHEMA_BYTES);
        assert_eq!(
            t.write,
            matches!(t.name.as_str(), "slack.post_message" | "slack.add_reaction")
        );
    }
}

#[tokio::test]
async fn an_agent_hammering_history_never_changes_the_connections_health_and_posting_goes_on() {
    let (f, l, c, s) = ready(&[]).await;
    l.fake.on("conversations.history", |_| {
        Reply::http(429, json!({"ok": false, "error": "ratelimited"})).header("retry-after", "30")
    });
    l.fake.on("chat.postMessage", |q| {
        Reply::ok(json!({"channel": q.form["channel"], "ts": st::TS}))
    });
    for _ in 0..6 {
        let r = f.ask(&s, "slack.read_channel", read(st::CH)).await;
        assert_eq!((r.ok, code(&r)), (false, "rate_limited"));
        assert_eq!(f.status(c.id).await, ("active".to_owned(), None));
    }
    assert_eq!(
        l.fake.count("conversations.history"),
        1,
        "Slack was asked once"
    );
    // The connection is not cooling for anyone: a post goes through, and so does a second session.
    let r = f
        .ask(
            &s,
            "slack.post_message",
            json!({"channel": st::CH, "text": "hi"}),
        )
        .await;
    assert!(r.ok, "{r:?}");
    let t = f.session(&["read_messages", "post_messages"]).await;
    let r = f
        .ask(
            &t,
            "slack.post_message",
            json!({"channel": st::CH, "text": "too"}),
        )
        .await;
    assert!(r.ok, "{r:?}");
    assert_eq!(f.status(c.id).await, ("active".to_owned(), None));
    // The refusal says when to come back and never names a channel or a token.
    let r = f.ask(&s, "slack.read_channel", read(st::CH)).await;
    let text = format!("{r:?}");
    assert!(
        text.contains("seconds") && !text.contains(st::ACCESS),
        "{text}"
    );
    // Only a refused credential speaks for the connection.
    l.fake
        .on("chat.postMessage", |_| Reply::err("invalid_auth"));
    let r = f
        .ask(
            &s,
            "slack.post_message",
            json!({"channel": st::CH, "text": "x"}),
        )
        .await;
    assert_eq!((r.ok, code(&r)), (false, "auth_failed"));
    assert_eq!(
        f.status(c.id).await,
        ("unhealthy".to_owned(), Some("auth_suspected".to_owned()))
    );
}

#[tokio::test]
async fn a_connection_suspended_for_a_rotation_it_could_not_store_refuses_locally() {
    let (f, l, c, s) = ready(&[]).await;
    assert!(
        crate::store::connections::suspend::needs_mode_2(&f.j.pool, 1, c.id, NOW)
            .await
            .unwrap()
    );
    let r = f.ask(&s, "slack.read_channel", read(st::CH)).await;
    assert_eq!((r.ok, code(&r)), (false, "needs_mode_2"));
    let r = f
        .ask(
            &s,
            "slack.post_message",
            json!({"channel": st::CH, "text": "x"}),
        )
        .await;
    assert_eq!((r.ok, code(&r)), (false, "needs_mode_2"));
    assert!(l.fake.seen().is_empty());
    assert_eq!(
        f.status(c.id).await,
        ("unhealthy".to_owned(), Some("needs_mode_2".to_owned()))
    );
}
