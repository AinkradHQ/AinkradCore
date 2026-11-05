//! An upstream `auth_failed` through the hub (KAN-435 G5): one report never disables an account. A
//! one-shot `gateway.test` through the session's runner decides: a provider that refuses the key again
//! disables it (audited, no new session is granted it), one that accepts it clears the signal.

use std::time::Duration;

use ainkrad_core_server::store::accounts;
use ainkrad_core_server::store::agents as sessions;
use ainkrad_proto::v2::*;

use super::gateway::{W, command, count, events, start, started, until, usage, world};

/// Answers every read with nothing new until a `gateway.test` arrives, which gets `result`.
async fn test_answered(w: &mut W, result: UpstreamStatus) {
    loop {
        let (stream, cmd) = command(&mut w.fake).await;
        match cmd {
            Command::AgentRead(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let ev = events(&w.session, AgentState::Running, vec![]);
                w.fake
                    .send(stream, Body::Result(Reply::AgentRead(ev)))
                    .await;
            }
            Command::GatewayTest(t) => {
                assert_eq!(t.provider, "anthropic");
                assert_eq!(t.upstream.host, "api.anthropic.com");
                assert!(t.lease.starts_with("l_"));
                let tested = GatewayTested {
                    result,
                    latency_ms: 5,
                };
                w.fake
                    .send(stream, Body::Result(Reply::GatewayTest(tested)))
                    .await;
                return;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

fn auth_failed(seq: u64) -> GatewayReport {
    GatewayReport {
        kind: GatewayReportKind::Upstream,
        status: UpstreamStatus::AuthFailed,
        model: None,
        ..usage(seq, 0, 0)
    }
}

async fn account_state(w: &W) -> String {
    accounts::get(&w.core.app.pool, w.account.id)
        .await
        .unwrap()
        .state
}

async fn settled(w: &W, state: &str) {
    for _ in 0..250 {
        let n = count(
            &w.core,
            &format!("SELECT count(*) FROM core_account_auth_signals WHERE state = '{state}'"),
        )
        .await;
        if n > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    panic!("the auth signal never became {state}");
}

#[tokio::test]
async fn one_auth_failed_disables_the_account_only_when_a_one_shot_test_confirms_it() {
    let mut w = world("gw-auth-confirmed", None).await;
    started(&mut w, u64::MAX).await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)));
    let ev = events(&w.session, AgentState::Running, vec![auth_failed(1)]);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    // The report alone changed nothing; the test is what the Core asks next.
    test_answered(&mut w, UpstreamStatus::AuthFailed).await;
    settled(&w, "confirmed").await;
    assert_eq!(account_state(&w).await, "disabled");
    let audit = count(
        &w.core,
        "SELECT count(*) FROM audit_events WHERE action = 'account.state_set'",
    )
    .await;
    assert_eq!(audit, 1);
    // A disabled account gets no new grant.
    let again = start(&w.core, &w.runner, &w.account).await;
    until("the new session to fail", &w.core, &again, |s| !s.live()).await;
    let row = sessions::get(&w.core.app.pool, &again)
        .await
        .unwrap()
        .unwrap();
    assert!(row.outcome.unwrap().to_string().contains("disabled"));
}

#[tokio::test]
async fn an_auth_failed_the_test_does_not_repeat_is_cleared_and_the_account_stays_usable() {
    let mut w = world("gw-auth-cleared", None).await;
    started(&mut w, u64::MAX).await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)));
    let ev = events(&w.session, AgentState::Running, vec![auth_failed(1)]);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    test_answered(&mut w, UpstreamStatus::Ok).await;
    settled(&w, "cleared").await;
    assert_eq!(account_state(&w).await, "active");
    assert_eq!(
        count(
            &w.core,
            "SELECT count(*) FROM audit_events WHERE action = 'account.state_set'"
        )
        .await,
        0
    );
}
