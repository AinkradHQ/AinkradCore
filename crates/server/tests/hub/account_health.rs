//! Account health through the hub (KAN-438 S3): an upstream 429 in a gateway report, answered by a
//! runner played by hand, cools the account exactly once; the session that reported it runs on;
//! and a new session on the cooled account is refused at start, not at its first request.

use ainkrad_core_server::store::accounts;
use ainkrad_proto::v2::*;

use super::gateway::{command, events, started, until, usage, world};

fn rate_limited(seq: u64) -> GatewayReport {
    GatewayReport {
        kind: GatewayReportKind::Upstream,
        status: UpstreamStatus::RateLimited,
        model: None,
        retry_after: Some(120),
        ..usage(seq, 0, 0)
    }
}

#[tokio::test]
async fn a_gateway_429_cools_the_account_once_and_a_new_session_on_it_is_refused() {
    let mut w = world("health-429", None).await;
    started(&mut w, u64::MAX).await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)));
    // The report, and its resend with the next read: one change of state.
    let ev = events(&w.session, AgentState::Running, vec![rate_limited(1)]);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(r) if r.gw_after == 1));
    let ev = events(&w.session, AgentState::Running, vec![rate_limited(1)]);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    let a = accounts::get(&w.core.app.pool, w.account.id).await.unwrap();
    assert_eq!(
        (a.state.as_str(), a.state_reason.as_deref()),
        ("cooling", Some("rate_limited"))
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'account.state_set'")
            .fetch_one(&w.core.app.pool)
            .await
            .unwrap();
    assert_eq!(rows, 1);
    let class: Option<String> =
        sqlx::query_scalar("SELECT upstream_class FROM core_agent_sessions WHERE id = ?")
            .bind(&w.session)
            .fetch_one(&w.core.app.pool)
            .await
            .unwrap();
    assert_eq!(class.as_deref(), Some("rate_limited"));
    // The reporting session runs on (a cooldown does not kill it).
    let s = ainkrad_core_server::store::agents::get(&w.core.app.pool, &w.session)
        .await
        .unwrap()
        .unwrap();
    assert!(s.live());
    // A fresh session on the same account is refused at its start.
    let second = super::gateway::start(&w.core, &w.runner, &w.account).await;
    until("the refusal", &w.core, &second, |s| !s.live()).await;
    let s = ainkrad_core_server::store::agents::get(&w.core.app.pool, &second)
        .await
        .unwrap()
        .unwrap();
    assert!(
        s.outcome.unwrap().to_string().contains("cooling"),
        "the outcome says why"
    );
}
