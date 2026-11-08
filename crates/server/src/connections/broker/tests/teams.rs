//! Teams through the broker: the channel limit holds end to end (grant, request, answer), no
//! credential leaves, and what an agent can provoke gives no health signal.

use ainkrad_proto::v2::MAX_SCHEMA_BYTES;

use super::*;
use crate::connections::teams::tests as tt;

/// A Broker whose Teams is the loopback one, a signed-in connection granted `read_messages` and
/// `post_messages` with `limits`, and an agent session allowed both.
async fn ready_with(app: bool, limits: &[(&str, &[&str])]) -> (Fx, tt::Fx, Connection, String) {
    let mut f = fx().await;
    let t = tt::fx(app).await;
    f.reg.register(t.teams.clone()).unwrap();
    f.b = Broker::with(
        f.reg.clone(),
        Github::strict(),
        f.j.jira.clone(),
        Limits::default(),
    )
    .with_teams(t.teams.clone());
    let new = NewConnection {
        kind: "teams",
        name: "main",
        label: "A Microsoft tenant",
        auth_method: "oauth",
    };
    let m = tt::material(tt::ACCESS, tt::REFRESH, if app { 3600 } else { 10 });
    let c = create(&f.j.pool, &f.j.sealer, &f.reg, &new, &m, who())
        .await
        .unwrap();
    let caps = ["read_messages", "post_messages"];
    f.member(c.id, &caps, limits).await;
    f.grant(c.id, ("agent", "bot"), &caps, limits).await;
    if !app {
        f.default(c.id).await;
    }
    let s = f.session(&caps).await;
    (f, t, c, s)
}

async fn ready(limits: &[(&str, &[&str])]) -> (Fx, tt::Fx, Connection, String) {
    ready_with(true, limits).await
}

fn read(team: &str, channel: &str) -> Value {
    json!({"team": team, "channel": channel})
}

fn post(team: &str, channel: &str) -> Value {
    json!({"team": team, "channel": channel, "text": "hello"})
}

#[tokio::test]
async fn a_call_in_the_channel_limit_works_and_the_credential_never_leaves() {
    let (f, t, _c, s) = ready(&[("channels", &[tt::KEY_A1])]).await;
    let leaky = format!(
        "token {} and Bearer {} and {}",
        tt::ACCESS,
        tt::ACCESS,
        tt::REFRESH
    );
    t.fake.reply(
        "messages",
        tt::Reply::ok(json!({"value": [tt::message(tt::TEAM_A, tt::CH_A1, tt::MSG, &leaky)]})),
    );
    let r = f
        .ask(&s, "teams.list_messages", read(tt::TEAM_A, tt::CH_A1))
        .await;
    assert!(r.ok, "{r:?}");
    let text = format!("{r:?}");
    assert!(
        !text.contains(tt::ACCESS) && !text.contains(tt::REFRESH),
        "{text}"
    );
    assert_eq!(r.result.as_ref().unwrap()["messages"][0]["id"], tt::MSG);
    let r = f
        .ask(&s, "teams.post_message", post(tt::TEAM_A, tt::CH_A1))
        .await;
    assert!(r.ok, "{r:?}");
    assert!(!f.audit_text().await.contains(tt::ACCESS));
    assert_eq!(t.fake.bad(), 0);
}

#[tokio::test]
async fn a_channel_outside_the_grant_is_refused_before_microsoft_is_asked() {
    let (f, t, _c, s) = ready(&[("channels", &[tt::KEY_A1])]).await;
    for (tool, args) in [
        ("teams.list_messages", read(tt::TEAM_A, tt::CH_A2)),
        ("teams.list_messages", read(tt::TEAM_B, tt::CH_B1)),
        (
            "teams.get_message",
            json!({"team": tt::TEAM_B, "channel": tt::CH_A1, "message": tt::MSG}),
        ),
        (
            "teams.list_replies",
            json!({"team": tt::TEAM_A, "channel": tt::CH_A2, "message": tt::MSG}),
        ),
        ("teams.post_message", post(tt::TEAM_A, tt::CH_A2)),
        (
            "teams.reply_message",
            json!({"team": tt::TEAM_B, "channel": tt::CH_B1, "message": tt::MSG, "text": "x"}),
        ),
    ] {
        let r = f.ask(&s, tool, args).await;
        assert_eq!((r.ok, code(&r)), (false, "resource_denied"), "{tool}");
    }
    // Swapped, upper-case or encoded ids are not even arguments.
    for args in [
        read(tt::CH_A1, tt::TEAM_A),
        read(&tt::TEAM_A.to_uppercase(), tt::CH_A1),
        read(
            tt::TEAM_A,
            "19%3A4a95f7d8db4c4e7fae857bcebe0623e6%40thread.tacv2",
        ),
        read(tt::TEAM_A, &format!("{}/../{}", tt::CH_A1, tt::CH_A2)),
    ] {
        let r = f.ask(&s, "teams.list_messages", args).await;
        assert!(!r.ok);
    }
    // An operation with no channel that does not limit itself is not allowed under a limit.
    let r = f.ask(&s, "teams.get_message", json!({})).await;
    assert!(!r.ok);
    assert_eq!(t.fake.graph_count(), 0);
    // The two that limit themselves run, and are cut to the limit.
    let r = f.ask(&s, "teams.list_teams", json!({})).await;
    assert!(r.ok, "{r:?}");
    assert_eq!(
        r.result.as_ref().unwrap()["teams"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let r = f
        .ask(&s, "teams.list_channels", json!({"team": tt::TEAM_A}))
        .await;
    assert_eq!(
        r.result.as_ref().unwrap()["channels"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let r = f
        .ask(&s, "teams.list_channels", json!({"team": tt::TEAM_B}))
        .await;
    assert!(!r.ok);
}

#[tokio::test]
async fn an_answer_from_another_channel_is_not_shown_and_costs_no_health() {
    let (f, t, c, s) = ready(&[("channels", &[tt::KEY_A1])]).await;
    t.fake.reply(
        "messages",
        tt::Reply::ok(
            json!({"value": [tt::message(tt::TEAM_A, tt::CH_A2, tt::MSG, "secret-text")]}),
        ),
    );
    let r = f
        .ask(&s, "teams.list_messages", read(tt::TEAM_A, tt::CH_A1))
        .await;
    assert_eq!((r.ok, code(&r)), (false, "refused"));
    assert!(!format!("{r:?}").contains("secret-text"));
    assert_eq!(f.status(c.id).await, ("active".to_owned(), None));
}

#[tokio::test]
async fn what_an_agent_can_provoke_gives_no_health_signal_and_a_401_is_pending_only() {
    let (f, t, c, s) = ready(&[]).await;
    for reply in [
        tt::Reply::graph(403, "Forbidden"),
        tt::Reply::graph(404, "ResourceNotFound"),
        tt::Reply::graph(404, "ChannelNotFound"),
        tt::Reply::graph(400, "BadRequest"),
        tt::Reply::graph(403, "accessDenied"),
        tt::Reply::http(302, Value::Null).header("location", "https://evil.example/x"),
        tt::Reply::http(200, Value::Null).raw(b"<html>".to_vec()),
        tt::Reply::ok(json!({"value": "not a list"})),
    ] {
        let body = reply.clone();
        t.fake.on("messages", move |_| body.clone());
        let r = f
            .ask(&s, "teams.list_messages", read(tt::TEAM_A, tt::CH_A1))
            .await;
        assert!(!r.ok, "{:?}", reply.body);
        assert_eq!(
            f.status(c.id).await,
            ("active".to_owned(), None),
            "{:?}",
            reply.body
        );
    }
    // A cursor that makes Graph fail is the agent's doing, not Microsoft's outage.
    t.fake
        .reply("messages", tt::Reply::graph(500, "generalException"));
    let args = json!({"team": tt::TEAM_A, "channel": tt::CH_A1, "cursor": "Z2FyYmFnZQ"});
    let r = f.ask(&s, "teams.list_messages", args).await;
    assert!(!r.ok);
    assert_eq!(f.status(c.id).await, ("active".to_owned(), None));
    // A credential Microsoft refuses (after one renewal) is a pending signal.
    t.fake.rotating();
    t.fake.reply(
        "messages",
        tt::Reply::graph(401, "InvalidAuthenticationToken"),
    );
    let r = f
        .ask(&s, "teams.list_messages", read(tt::TEAM_A, tt::CH_A1))
        .await;
    assert_eq!((r.ok, code(&r)), (false, "auth_failed"));
    assert_eq!(
        f.status(c.id).await,
        ("unhealthy".to_owned(), Some("auth_suspected".to_owned()))
    );
    let again = f
        .ask(&s, "teams.list_messages", read(tt::TEAM_A, tt::CH_A1))
        .await;
    assert_eq!(code(&again), "auth_pending");
}

#[tokio::test]
async fn a_rate_limit_cools_the_connection_and_its_wait_refuses_the_next_call_locally() {
    let (f, t, c, s) = ready(&[]).await;
    let tools = f.b.tools(&f.env(), &s).await.unwrap();
    let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
    for want in [
        "teams.list_teams",
        "teams.list_messages",
        "teams.post_message",
        "teams.reply_message",
    ] {
        assert!(names.contains(&want), "{want} in {names:?}");
    }
    for tool in tools.iter().filter(|t| t.name.starts_with("teams.")) {
        let schema = tool.input_schema.as_ref().expect("a schema");
        assert!(schema.to_string().len() <= MAX_SCHEMA_BYTES);
        assert_eq!(
            tool.write,
            tool.name.ends_with("_message") && !tool.name.contains("get_")
        );
    }
    t.fake.reply(
        "messages",
        tt::Reply::graph(429, "TooManyRequests").header("Retry-After", "30"),
    );
    let r = f
        .ask(&s, "teams.list_messages", read(tt::TEAM_A, tt::CH_A1))
        .await;
    assert_eq!((r.ok, code(&r)), (false, "rate_limited"));
    assert_eq!(
        f.status(c.id).await,
        ("cooling".to_owned(), Some("rate_limited".to_owned()))
    );
    let again = f
        .ask(&s, "teams.list_messages", read(tt::TEAM_A, tt::CH_A1))
        .await;
    assert!(!again.ok);
    assert_eq!(
        t.fake.count("messages"),
        1,
        "refused locally, Microsoft was not asked again"
    );
}

#[tokio::test]
async fn a_missing_app_is_a_plain_refusal_and_no_verdict_on_the_connection() {
    let (f, _t, c, s) = ready_with(false, &[]).await;
    let r = f
        .ask(&s, "teams.list_messages", read(tt::TEAM_A, tt::CH_A1))
        .await;
    assert_eq!((r.ok, code(&r)), (false, "not_configured"), "{r:?}");
    assert_eq!(f.status(c.id).await, ("active".to_owned(), None));
}
