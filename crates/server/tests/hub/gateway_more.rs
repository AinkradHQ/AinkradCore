//! The rest of the gateway's wiring through the hub (KAN-435 G5 review): a gateway at its ceiling is
//! raised while the budgets have room and stopped with the reason when they have none, a cancel goes
//! out even when the limit could not be sent, the last answer of an ended session is stored with its
//! final reports, and a module's session may not name an API-key account yet.

use std::time::Duration;

use ainkrad_core_server::agents as service;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use ainkrad_proto::runner::Outcome;
use ainkrad_proto::v2::*;

use super::gateway::{
    command, count, events, key_secret, policy, started, until, up, usage, world,
};

#[tokio::test]
async fn a_gateway_nearly_at_its_ceiling_is_raised_while_the_budgets_have_room() {
    // The hold is 20M of a 25M budget. 19.9M spent leaves the gateway too little for a turn, but the
    // budget still has 5.1M: the Core sends a positive limit, absolute for this gateway instance.
    let mut w = world("gw-topup", Some(25_000_000)).await;
    started(&mut w, 20_000_000).await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)));
    let ev = events(
        &w.session,
        AgentState::Running,
        vec![usage(1, 19_900_000, 0)],
    );
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::AgentLimit(limit) = cmd else {
        panic!("expected a raise, got {cmd:?}")
    };
    assert_eq!(
        limit.ceiling.tokens, 25_000_000,
        "spent 19.9M plus the 5.1M left"
    );
    assert_eq!(limit.ceiling.usd_micros, u64::MAX);
    let ev = events(&w.session, AgentState::Running, vec![]);
    w.fake
        .send(stream, Body::Result(Reply::AgentLimit(ev)))
        .await;
    let (_, cmd) = command(&mut w.fake).await;
    assert!(
        matches!(cmd, Command::AgentRead(_)),
        "the session goes on: {cmd:?}"
    );
    let row = sessions::get(&w.core.app.pool, &w.session)
        .await
        .unwrap()
        .unwrap();
    assert!(row.live() && row.gw_stop.is_none());
}

#[tokio::test]
async fn a_gateway_at_its_ceiling_with_no_budget_room_ends_the_session_with_the_reason() {
    let mut w = world("gw-topup-none", Some(20_000_000)).await;
    started(&mut w, 20_000_000).await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)));
    let ev = events(
        &w.session,
        AgentState::Running,
        vec![usage(1, 19_900_000, 0)],
    );
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    // 100000 are left, less than a turn needs: nothing to raise it with, so the session is stopped.
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::AgentLimit(limit) = cmd else {
        panic!("expected agent.limit, got {cmd:?}")
    };
    assert_eq!((limit.ceiling.tokens, limit.ceiling.usd_micros), (0, 0));
    let ev = events(&w.session, AgentState::Running, vec![]);
    w.fake
        .send(stream, Body::Result(Reply::AgentLimit(ev)))
        .await;
    let (_, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentStop(_)), "{cmd:?}");
    let row = sessions::get(&w.core.app.pool, &w.session)
        .await
        .unwrap()
        .unwrap();
    assert!(row.gw_stop.unwrap().contains("ceiling is used up"));
}

#[tokio::test]
async fn a_cancel_is_sent_even_when_the_limit_could_not_be() {
    let mut w = world("gw-limit-fails", Some(700_000)).await;
    started(&mut w, 700_000).await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)));
    let ev = events(&w.session, AgentState::Running, vec![usage(1, 800_000, 0)]);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    // The runner fails the limit with something that is not "no such session".
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentLimit(_)));
    let busy = StreamError::new(ErrorCode::Busy, "busy");
    w.fake.send(stream, Body::Error(busy)).await;
    let (_, cmd) = command(&mut w.fake).await;
    assert!(
        matches!(cmd, Command::AgentStop(_)),
        "the cancel still goes out: {cmd:?}"
    );
}

#[tokio::test]
async fn the_last_answer_of_an_ended_session_is_stored_with_its_final_reports() {
    let mut w = world("gw-final", None).await;
    started(&mut w, u64::MAX).await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)));
    let mut ended = events(&w.session, AgentState::Ended, vec![]);
    ended.outcome = Some(Outcome::Cancelled {
        reason: "stopped".to_owned(),
    });
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ended.clone())))
        .await;
    // The Core ends the session and asks once more; what that answer carries (the approximate
    // charge of a request the stop aborted) is stored, not thrown away.
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)));
    ended.gateway = vec![GatewayReport {
        approximate: true,
        status: UpstreamStatus::Unreachable,
        ..usage(1, 500, 0)
    }];
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ended)))
        .await;
    until("the session to end", &w.core, &w.session, |s| !s.live()).await;
    for _ in 0..100 {
        if count(
            &w.core,
            "SELECT count(*) FROM core_cost_events WHERE approximate = 1",
        )
        .await
            == 1
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    panic!("the final report never reached the ledger");
}

#[tokio::test]
async fn a_module_session_may_not_name_an_api_key_account_yet() {
    let (core, _fake, runner, account) = up("gw-module", true, None).await;
    let policy = policy();
    let secrets = key_secret(&account);
    let new = NewSession {
        runner: &runner,
        harness: "claude",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &secrets,
        created_by: &runner,
    };
    let refused = service::ModuleAgents::named("citadel")
        .create(&core.app, &new)
        .await;
    let Err(service::Refusal::Runner(e)) = refused else {
        panic!("a module's gateway session was created")
    };
    assert!(e.message.contains("API-key account"), "{}", e.message);
    assert_eq!(
        count(&core, "SELECT count(*) FROM core_agent_sessions").await,
        0
    );
}
