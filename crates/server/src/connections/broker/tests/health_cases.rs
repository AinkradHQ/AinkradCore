//! What a call's end tells health, and what it never does.

use std::sync::atomic::Ordering;

use ainkrad_proto::v2::UpstreamStatus;

use super::*;
use crate::connections::broker::health::{Feed, forward};

fn get(n: u64) -> Value {
    json!({"repo": "acme/app", "number": n})
}

async fn ready() -> (Fx, Connection, String) {
    let f = fx().await;
    let c = f.github("main", GH_TOKEN).await;
    f.member(c.id, &["read_repo"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_repo"], &[]).await;
    let s = f.session(&["read_repo"]).await;
    (f, c, s)
}

async fn streak(f: &Fx, id: i64) -> i64 {
    sqlx::query_scalar("SELECT fail_streak FROM core_connections WHERE id = ?")
        .bind(id)
        .fetch_one(&f.j.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_401_is_a_pending_signal_only_and_never_disables() {
    let (f, c, s) = ready().await;
    f.gh.push(401, &[], r#"{"message":"Bad credentials"}"#);
    let r = f.ask(&s, "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "auth_failed"));
    assert_eq!(
        f.status(c.id).await,
        ("unhealthy".to_owned(), Some("auth_suspected".to_owned()))
    );
    let row: (i64, String) =
        sqlx::query_as("SELECT auth_pending, status FROM core_connections WHERE id = ?")
            .bind(c.id)
            .fetch_one(&f.j.pool)
            .await
            .unwrap();
    assert_eq!(row, (1, "unhealthy".to_owned()), "pending, not disabled");
    // Out of use until a test decides.
    let r = f.ask(&s, "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "auth_pending"));
    assert_eq!(f.gh.seen().len(), 1);
}

#[tokio::test]
async fn a_rate_limit_cools_the_connection_as_an_agent_signal() {
    let (f, c, s) = ready().await;
    f.gh.push(429, &[("retry-after", "30")], "{}");
    let r = f.ask(&s, "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "rate_limited"));
    assert_eq!(
        f.status(c.id).await,
        ("cooling".to_owned(), Some("rate_limited".to_owned()))
    );
    let source: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'connection.state_set' ORDER BY rowid DESC LIMIT 1",
    )
    .fetch_one(&f.j.pool)
    .await
    .unwrap();
    assert!(source.contains(r#""source":"agent""#), "{source}");
    let r = f.ask(&s, "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "unhealthy"));
}

#[tokio::test]
async fn an_agent_without_a_grant_cannot_cool_a_connection() {
    let (f, c, _s) = ready().await;
    let rate = Feed::of(UpstreamStatus::RateLimited);
    forward(&f.j.pool, 1, c.id, Some("ghost"), Some(&rate), NOW)
        .await
        .unwrap();
    assert_eq!(
        f.status(c.id).await.0,
        "active",
        "an agent with no grant is not heard"
    );
    let quota = Feed::of(UpstreamStatus::Quota);
    forward(&f.j.pool, 1, c.id, Some("ghost"), Some(&quota), NOW)
        .await
        .unwrap();
    assert_eq!(f.status(c.id).await.0, "active");
    forward(&f.j.pool, 1, c.id, Some("bot"), Some(&rate), NOW)
        .await
        .unwrap();
    assert_eq!(f.status(c.id).await.0, "cooling", "the granted agent is");
}

#[tokio::test]
async fn what_an_agent_can_provoke_gives_no_health_signal() {
    let (f, c, s) = ready().await;
    for (status, want) in [
        (404, "not_found"),
        (301, "upstream"),
        (302, "upstream"),
        (451, "upstream"),
        (422, "invalid"),
        (403, "forbidden"),
        (413, "upstream"),
    ] {
        f.gh.push(status, &[("location", "https://evil.example/x")], "{}");
        let r = f.ask(&s, "github.get_issue", get(1)).await;
        assert_eq!((r.ok, code(&r)), (false, want), "{status}");
    }
    // A result too large for the harness.
    let huge = format!(
        r#"{{"b":"{}"}}"#,
        "z".repeat(ainkrad_proto::v2::MAX_RESULT_BYTES + 1)
    );
    f.gh.push(200, &[], &huge);
    assert_eq!(
        code(&f.ask(&s, "github.get_issue", get(1)).await),
        "too_large"
    );
    assert_eq!(f.status(c.id).await, ("active".to_owned(), None));
    assert_eq!(streak(&f, c.id).await, 0, "nothing counted");
}

#[tokio::test]
async fn a_server_error_counts_and_a_success_starts_over() {
    let (f, c, s) = ready().await;
    f.gh.push(502, &[], "{}");
    assert_eq!(
        code(&f.ask(&s, "github.get_issue", get(1)).await),
        "upstream"
    );
    assert_eq!(streak(&f, c.id).await, 1);
    f.gh.push(200, &[], ISSUE);
    assert!(f.ask(&s, "github.get_issue", get(1)).await.ok);
    assert_eq!(streak(&f, c.id).await, 0);
    assert_eq!(f.status(c.id).await.0, "active", "never disabled by errors");
}

#[tokio::test]
async fn a_refusal_of_ours_tells_health_nothing() {
    let (f, c, s) = ready().await;
    f.gh.push(502, &[], "{}");
    f.ask(&s, "github.get_issue", get(1)).await;
    assert_eq!(streak(&f, c.id).await, 1);
    // A refused argument is not a success: the streak stays.
    let r = f.ask(&s, "github.get_issue", json!({"repo": "nope"})).await;
    assert_eq!(code(&r), "bad_args");
    assert_eq!(streak(&f, c.id).await, 1);
}

async fn oauth(f: &Fx, expires_in: i64) -> Connection {
    let new = NewConnection {
        kind: "jira",
        name: "acme",
        label: "A Jira site",
        auth_method: "oauth",
    };
    let m = jt::oauth("acc1-7f3a9d41e0b2", jt::REFRESH, expires_in);
    create(&f.j.pool, &f.j.sealer, &f.reg, &new, &m, who())
        .await
        .unwrap()
}

async fn jira_session(f: &Fx, c: &Connection) -> String {
    f.member(c.id, &["read_issues"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_issues"], &[]).await;
    f.session(&["read_issues"]).await
}

fn issue_path() -> String {
    format!("GET {}", jt::oauth_path("/issue/ABC-1"))
}

#[tokio::test]
async fn concurrent_calls_with_a_refresh_in_flight_renew_once() {
    let f = fx_app(Limits::default(), true).await;
    let c = oauth(&f, 10).await; // due: inside the renewal skew
    let served = f.j.fake.rotating();
    f.j.fake.reply(
        &issue_path(),
        200,
        json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"}}}),
    );
    let _ = jira_session(&f, &c).await;
    let mut sessions = Vec::new();
    for _ in 0..4 {
        sessions.push(f.session(&["read_issues"]).await);
    }
    let calls = sessions
        .iter()
        .map(|s| f.ask(s, "jira.get_issue", json!({"key": "ABC-1"})));
    let results = futures_util::future::join_all(calls).await;
    assert!(results.iter().all(|r| r.ok), "{results:?}");
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "single flight: one refresh token spent"
    );
    assert_eq!(f.status(c.id).await.0, "active");
}

#[tokio::test]
async fn a_refresh_failure_maps_to_a_plain_code_and_a_pending_signal() {
    // The service refuses the refresh token: pending, a test decides.
    let f = fx_app(Limits::default(), true).await;
    let c = oauth(&f, -100).await;
    f.j.fake
        .reply("POST /oauth/token", 400, json!({"error": "invalid_grant"}));
    let s = jira_session(&f, &c).await;
    let r = f.ask(&s, "jira.get_issue", json!({"key": "ABC-1"})).await;
    assert_eq!((r.ok, code(&r)), (false, "auth_failed"));
    assert_eq!(
        f.status(c.id).await,
        ("unhealthy".to_owned(), Some("auth_suspected".to_owned()))
    );
    // Core has no Atlassian app: cannot renew, plain code, same pending signal.
    let f = fx().await;
    let c = oauth(&f, -100).await;
    let s = jira_session(&f, &c).await;
    let r = f.ask(&s, "jira.get_issue", json!({"key": "ABC-1"})).await;
    assert_eq!((r.ok, code(&r)), (false, "oauth_not_configured"));
    assert_eq!(f.status(c.id).await.1.as_deref(), Some("auth_suspected"));
    assert!(
        f.j.fake.seen().is_empty(),
        "no request carried the stale token"
    );
    // A network failure of the token endpoint is not an auth verdict: no signal on health.
    let f = fx_app(Limits::default(), true).await;
    let c = oauth(&f, -100).await;
    f.j.fake
        .on("POST /oauth/token", |_| jt::Reply::json(500, json!({})));
    let s = jira_session(&f, &c).await;
    let r = f.ask(&s, "jira.get_issue", json!({"key": "ABC-1"})).await;
    assert!(!r.ok);
    assert_ne!(f.status(c.id).await.1.as_deref(), Some("auth_suspected"));
    assert_ne!(f.status(c.id).await.0, "disabled");
}

#[tokio::test]
async fn an_expired_github_token_is_refused_and_never_sent() {
    let f = fx().await;
    let m = Material::new(GH_TOKEN, None, Some("2026-11-06T09:00:00Z")).unwrap();
    let new = NewConnection {
        kind: "github",
        name: "app",
        label: "App install",
        auth_method: "app_install",
    };
    let c = create(&f.j.pool, &f.j.sealer, &f.reg, &new, &m, who())
        .await
        .unwrap();
    f.member(c.id, &["read_repo"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_repo"], &[]).await;
    let s = f.session(&["read_repo"]).await;
    let r = f.ask(&s, "github.get_issue", get(1)).await;
    assert_eq!((r.ok, code(&r)), (false, "credential_expired"));
    assert!(f.gh.seen().is_empty());
    assert_eq!(
        f.status(c.id).await.0,
        "active",
        "an expiry is not an agent's doing"
    );
}
