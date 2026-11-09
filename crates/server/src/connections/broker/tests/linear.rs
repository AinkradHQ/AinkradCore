//! Linear through the broker: the team limit holds end to end (grant, request, answer), no
//! credential leaves, and what an agent can provoke gives no health signal.

use ainkrad_proto::v2::MAX_SCHEMA_BYTES;

use super::*;
use crate::connections::linear::tests as lt;

/// A Broker whose Linear is the loopback one, a key connection granted `read_issues` and
/// `write_issues` with `limits`, and an agent session allowed both.
async fn ready(limits: &[(&str, &[&str])]) -> (Fx, lt::Fx, Connection, String) {
    let mut f = fx().await;
    let l = lt::fx(false).await;
    f.reg.register(l.linear.clone()).unwrap();
    f.b = Broker::with(
        f.reg.clone(),
        Github::strict(),
        f.j.jira.clone(),
        Limits::default(),
    )
    .with_linear(l.linear.clone());
    let new = NewConnection {
        kind: "linear",
        name: "main",
        label: "A Linear workspace",
        auth_method: "token",
    };
    let c = create(&f.j.pool, &f.j.sealer, &f.reg, &new, &lt::key(), who())
        .await
        .unwrap();
    let caps = ["read_issues", "write_issues"];
    f.member(c.id, &caps, limits).await;
    f.grant(c.id, ("agent", "bot"), &caps, limits).await;
    let s = f.session(&caps).await;
    (f, l, c, s)
}

fn get(id: &str) -> Value {
    json!({"id": id})
}

#[tokio::test]
async fn a_call_in_the_team_limit_works_and_the_credential_never_leaves() {
    let (f, l, _c, s) = ready(&[("teams", &["ENG"])]).await;
    let mut shown = lt::issue("ENG-1", "ENG");
    shown["description"] = json!(format!("token {} and Bearer {}", lt::API_KEY, lt::API_KEY));
    shown["title"] = json!(lt::API_KEY);
    l.fake.data("Issue", json!({"issue": shown}));
    let r = f.ask(&s, "linear.get_issue", get("ENG-1")).await;
    assert!(r.ok, "{r:?}");
    let text = format!("{r:?}");
    assert!(!text.contains(lt::API_KEY), "{text}");
    assert_eq!(r.result.as_ref().unwrap()["identifier"], "ENG-1");
    // The credential went upstream as the bare key (a personal API key takes no Bearer).
    assert_eq!(
        l.fake.last("GQL Issue").unwrap().auth.as_deref(),
        Some(lt::API_KEY)
    );
    assert!(!f.audit_text().await.contains(lt::API_KEY));
    assert_eq!(l.fake.bad(), 0);
}

#[tokio::test]
async fn a_team_outside_the_grant_is_refused_before_linear_is_asked() {
    let (f, l, _c, s) = ready(&[("teams", &["ENG"])]).await;
    for (tool, args) in [
        ("linear.get_issue", get("OPS-1")),
        ("linear.add_comment", json!({"id": "OPS-1", "body": "x"})),
        ("linear.update_issue", json!({"id": "OPS-1", "title": "x"})),
        ("linear.create_issue", json!({"team": "OPS", "title": "x"})),
        ("linear.list_workflow_states", json!({"team": "OPS"})),
    ] {
        let r = f.ask(&s, tool, args).await;
        assert_eq!((r.ok, code(&r)), (false, "resource_denied"), "{tool}");
    }
    // An operation with no team that does not limit itself is not allowed under a limit at all.
    let r = f.ask(&s, "linear.get_issue", json!({})).await;
    assert!(!r.ok);
    assert!(l.fake.seen().is_empty());
    // The ones that limit themselves run, and carry the limit to Linear.
    l.fake.data(
        "Issues",
        json!({"issues": {"nodes": [lt::issue("ENG-2", "ENG")], "pageInfo": {}}}),
    );
    let r = f.ask(&s, "linear.search_issues", json!({})).await;
    assert!(r.ok, "{r:?}");
    let vars = l.fake.last("GQL Issues").unwrap().body;
    assert_eq!(
        vars["filter"]["and"][0],
        json!({"team": {"key": {"in": ["ENG"]}}})
    );
}

#[tokio::test]
async fn an_issue_that_moved_out_of_the_limit_is_not_shown_and_costs_no_health() {
    let (f, l, c, s) = ready(&[("teams", &["ENG"])]).await;
    l.fake
        .data("Issue", json!({"issue": lt::issue("OPS-9", "OPS")}));
    let r = f.ask(&s, "linear.get_issue", get("ENG-1")).await;
    assert_eq!((r.ok, code(&r)), (false, "refused"));
    assert!(!format!("{r:?}").contains("OPS"));
    assert_eq!(f.status(c.id).await, ("active".to_owned(), None));
}

#[tokio::test]
async fn what_an_agent_can_provoke_gives_no_health_signal_and_a_401_is_pending_only() {
    let (f, l, c, s) = ready(&[]).await;
    for reply in [
        lt::Reply::error(200, "FORBIDDEN"),
        lt::Reply::error(400, "INVALID_INPUT"),
        lt::Reply::error(400, "COMPLEXITY_TOO_HIGH"),
        lt::Reply::json(404, Value::Null),
        lt::Reply::json(302, Value::Null).header("location", "https://evil.example/x"),
        lt::Reply::data(json!({"issue": null})),
    ] {
        let body = reply.clone();
        l.fake.on("GQL Issue", move |_| body.clone());
        let r = f.ask(&s, "linear.get_issue", get("ENG-1")).await;
        assert!(!r.ok, "{:?}", reply.body);
        assert_eq!(
            f.status(c.id).await,
            ("active".to_owned(), None),
            "{:?}",
            reply.body
        );
    }
    // A credential Linear refuses is a pending signal: out of use until a test decides.
    l.fake.on("GQL Issue", |_| {
        lt::Reply::error(401, "AUTHENTICATION_ERROR")
    });
    let r = f.ask(&s, "linear.get_issue", get("ENG-1")).await;
    assert_eq!((r.ok, code(&r)), (false, "auth_failed"));
    assert_eq!(
        f.status(c.id).await,
        ("unhealthy".to_owned(), Some("auth_suspected".to_owned()))
    );
    let again = f.ask(&s, "linear.get_issue", get("ENG-1")).await;
    assert_eq!(code(&again), "auth_pending");
}

#[tokio::test]
async fn a_rate_limit_cools_the_connection_and_the_session_sees_linear_tools() {
    let (f, l, c, s) = ready(&[]).await;
    let tools = f.b.tools(&f.env(), &s).await.unwrap();
    let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
    for want in [
        "linear.get_issue",
        "linear.create_issue",
        "linear.list_teams",
    ] {
        assert!(names.contains(&want), "{want} in {names:?}");
    }
    for t in tools.iter().filter(|t| t.name.starts_with("linear.")) {
        let schema = t.input_schema.as_ref().expect("a schema");
        assert!(schema.to_string().len() <= MAX_SCHEMA_BYTES);
        assert_eq!(
            t.write,
            !t.name.contains("get_") && !t.name.contains("list_") && !t.name.contains("search_")
        );
    }
    l.fake.on("GQL Issue", |_| {
        lt::Reply::error(429, "RATELIMITED").header("retry-after", "30")
    });
    let r = f.ask(&s, "linear.get_issue", get("ENG-1")).await;
    assert_eq!((r.ok, code(&r)), (false, "rate_limited"));
    assert_eq!(
        f.status(c.id).await,
        ("cooling".to_owned(), Some("rate_limited".to_owned()))
    );
}

#[tokio::test]
async fn linears_reported_budget_refuses_the_next_call_locally_before_it_cools_the_connection() {
    let (f, l, c, s) = ready(&[]).await;
    let reset_ms = (crate::scheduler::unix_secs(NOW).unwrap() + 100_000_000) * 1000;
    let low = lt::Reply::data(json!({"issue": lt::issue("ENG-1", "ENG")}))
        .header("x-ratelimit-requests-remaining", "3")
        .header("x-ratelimit-requests-reset", &reset_ms.to_string());
    l.fake.on("GQL Issue", move |_| low.clone());
    let r = f.ask(&s, "linear.get_issue", get("ENG-1")).await;
    assert!(r.ok, "{r:?}");
    // Three left, at or under the reserve: the broker refuses, and Linear is not asked again.
    let r = f.ask(&s, "linear.get_issue", get("ENG-1")).await;
    assert_eq!((r.ok, code(&r)), (false, "connection_busy"), "{r:?}");
    assert_eq!(l.fake.count("GQL Issue"), 1);
    assert_eq!(
        f.status(c.id).await,
        ("active".to_owned(), None),
        "refused, not cooled"
    );
}

#[tokio::test]
async fn a_missing_app_is_a_plain_refusal_and_no_verdict_on_the_connection() {
    let (f, _l, _c, s) = ready(&[]).await;
    let new = NewConnection {
        kind: "linear",
        name: "signed",
        label: "Signed in",
        auth_method: "oauth",
    };
    let due = lt::oauth(lt::ACCESS, lt::REFRESH, 10);
    let c = create(&f.j.pool, &f.j.sealer, &f.reg, &new, &due, who())
        .await
        .unwrap();
    let caps = ["read_issues", "write_issues"];
    f.member(c.id, &caps, &[]).await;
    f.grant(c.id, ("agent", "bot"), &caps, &[]).await;
    f.default(c.id).await;
    let r = f.ask(&s, "linear.get_issue", get("ENG-1")).await;
    assert_eq!((r.ok, code(&r)), (false, "not_configured"), "{r:?}");
    assert_eq!(f.status(c.id).await, ("active".to_owned(), None));
}
