//! Failover through the hub (KAN-438 S6), with a runner played by hand: an attempt that ends
//! `rate_limited` moves the run to the next account in a NEW session (the old row is untouched),
//! the successor's own grant names the new account, and a run that is cancelled while it moves
//! leaves nothing live. Usage, holds and ledger rows stay on their own attempt.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents as service;
use ainkrad_core_server::store::agents as sessions;
use ainkrad_core_server::store::{accounts, failover};
use ainkrad_proto::runner::Outcome;
use ainkrad_proto::v2::*;

use super::allocator::{chain_session, pool_of};
use super::gateway::{W, command, count, events, started, until, up, usage};

async fn second(core: &super::Core, runner: &str) -> accounts::Account {
    let now = core.app.clock.now();
    let sealer = core.app.secrets.as_deref().unwrap();
    let runners = [runner.to_owned()];
    let new = accounts::NewAccount {
        provider: "anthropic",
        label: "second",
        value: "throwaway-account-value-two-77d0be",
        runners: &runners,
        cap: None,
    };
    accounts::create(
        &core.app.pool,
        sealer,
        &new,
        runner,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap()
}

/// Answers the reads that see `session` end with `outcome`, until the next `agent.start`.
async fn end_then_start(w: &mut W, outcome: Outcome) -> (u64, AgentStart) {
    loop {
        let (stream, cmd) = command(&mut w.fake).await;
        match cmd {
            Command::AgentRead(_) => {
                let mut ev = events(&w.session, AgentState::Ended, vec![]);
                ev.outcome = Some(outcome.clone());
                w.fake
                    .send(stream, Body::Result(Reply::AgentRead(ev)))
                    .await;
            }
            Command::AgentStart(s) => return (stream, s),
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn an_attempt_that_ends_rate_limited_moves_the_run_to_the_next_account_in_a_new_session() {
    let (core, fake, runner, a) = up("fo-move", true, None).await;
    let b = second(&core, &runner).await;
    let chain = [pool_of(&core, &runner, &[a.id, b.id]).await];
    let session = chain_session(&core, &runner, &chain).await;
    let mut w = W {
        core,
        fake,
        runner,
        account: a.clone(),
        session: session.clone(),
    };
    started(&mut w, u64::MAX).await;
    until("running", &w.core, &session, |s| s.state == "running").await;
    let out = Outcome::Failed {
        reason: "429".to_owned(),
        fingerprint: Some("rate_limited".to_owned()),
    };
    let (stream, start) = end_then_start(&mut w, out).await;
    // A new session, on the other account, with its own grant: the old one is never reused.
    assert_ne!(start.session, session);
    assert_eq!(start.gateway.as_ref().map(|g| g.account), Some(b.id));
    assert!(
        start.secrets.is_empty(),
        "an API key is never an env secret"
    );
    assert_eq!(
        start
            .prompt
            .as_deref()
            .map(|p| p.starts_with(failover::NOTE)),
        Some(true)
    );
    let ev = events(&start.session, AgentState::Running, vec![]);
    w.fake
        .send(stream, Body::Result(Reply::AgentStart(ev)))
        .await;
    until("the successor runs", &w.core, &start.session, |s| {
        s.state == "running"
    })
    .await;
    // The old attempt: ended, on its own account, settled; the successor names the run.
    let old = sessions::get(&w.core.app.pool, &session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (old.state.as_str(), old.gateway_account_id),
        ("ended", Some(a.id))
    );
    let (run, of, account): (Option<String>, String, i64) = sqlx::query_as(
        "SELECT run_id, failover_of, account_id FROM core_agent_sessions WHERE id = ?",
    )
    .bind(&start.session)
    .fetch_one(&w.core.app.pool)
    .await
    .unwrap();
    assert_eq!(
        (run, of, account),
        (Some(session.clone()), session.clone(), b.id)
    );
    assert_eq!(
        count(&w.core, "SELECT count(*) FROM core_agent_sessions").await,
        2
    );
    // The old account is cooling from the end's own signal? Not for a harness class on an API key:
    // the gateway is the authority, and it reported nothing, so it stays active.
    let first = accounts::get(&w.core.app.pool, a.id).await.unwrap();
    assert_eq!(first.state, "active");
}

#[tokio::test]
async fn a_run_whose_chain_is_used_up_ends_and_starts_nothing() {
    let (core, fake, runner, a) = up("fo-exhaust", true, None).await;
    let chain = [pool_of(&core, &runner, &[a.id]).await];
    let session = chain_session(&core, &runner, &chain).await;
    let mut w = W {
        core,
        fake,
        runner,
        account: a,
        session: session.clone(),
    };
    started(&mut w, u64::MAX).await;
    let out = Outcome::Failed {
        reason: "429".to_owned(),
        fingerprint: Some("rate_limited".to_owned()),
    };
    // Two reads see it end; after them the Core would start the next attempt, and there is none.
    for _ in 0..2 {
        let (stream, cmd) = command(&mut w.fake).await;
        assert!(matches!(cmd, Command::AgentRead(_)), "{cmd:?}");
        let mut ev = events(&session, AgentState::Ended, vec![]);
        ev.outcome = Some(out.clone());
        w.fake
            .send(stream, Body::Result(Reply::AgentRead(ev)))
            .await;
    }
    until("the end", &w.core, &session, |s| !s.live()).await;
    for _ in 0..50 {
        if count(
            &w.core,
            "SELECT count(*) FROM core_agent_sessions WHERE failover_done = 1",
        )
        .await
            == 1
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
    let outcome = sessions::get(&w.core.app.pool, &session)
        .await
        .unwrap()
        .unwrap()
        .outcome
        .unwrap()
        .to_string();
    assert!(outcome.contains("no account is available"), "{outcome}");
    assert_eq!(
        count(&w.core, "SELECT count(*) FROM core_agent_sessions").await,
        1
    );
    assert_eq!(
        count(&w.core, "SELECT count(*) FROM core_budget_holds").await,
        0
    );
    let none =
        tokio::time::timeout(std::time::Duration::from_millis(500), command(&mut w.fake)).await;
    assert!(none.is_err(), "nothing is started: {:?}", none.map(|c| c.1));
}

#[tokio::test]
async fn a_quota_report_stops_the_attempt_for_a_move_and_no_raise_undoes_the_refusal() {
    // A budget big enough to top up from: a raise after the refusal would be granted if nothing gated it.
    let (core, fake, runner, a) = up("fo-quota", true, Some(40_000_000)).await;
    let b = second(&core, &runner).await;
    let chain = [pool_of(&core, &runner, &[a.id, b.id]).await];
    let session = chain_session(&core, &runner, &chain).await;
    let mut w = W {
        core,
        fake,
        runner,
        account: a.clone(),
        session: session.clone(),
    };
    started(&mut w, 20_000_000).await;
    // The gateway reports the provider's quota error: the Core decides the move, then refuses and stops.
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)), "{cmd:?}");
    let mut report = usage(1, 19_800_000, 0);
    report.status = UpstreamStatus::Quota;
    let ev = events(&session, AgentState::Running, vec![report]);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    let (mut limits, mut stopped) = (0, false);
    let (stream, start) = loop {
        let (stream, cmd) = command(&mut w.fake).await;
        match cmd {
            Command::AgentLimit(l) => {
                limits += 1;
                assert_eq!(
                    (l.ceiling.tokens, l.ceiling.usd_micros),
                    (0, 0),
                    "a raise must not undo the refusal"
                );
                let ev = events(&session, AgentState::Running, vec![]);
                w.fake
                    .send(stream, Body::Result(Reply::AgentLimit(ev)))
                    .await;
            }
            Command::AgentStop(st) => {
                assert!(!st.kill && !stopped);
                stopped = true;
                let mut ev = events(&session, AgentState::Ended, vec![]);
                ev.outcome = Some(Outcome::Cancelled {
                    reason: "stopped".to_owned(),
                });
                w.fake
                    .send(stream, Body::Result(Reply::AgentStop(ev)))
                    .await;
            }
            Command::AgentRead(_) => {
                let mut ev = events(
                    &session,
                    if stopped {
                        AgentState::Ended
                    } else {
                        AgentState::Running
                    },
                    vec![],
                );
                ev.outcome = stopped.then(|| Outcome::Cancelled {
                    reason: "stopped".to_owned(),
                });
                w.fake
                    .send(stream, Body::Result(Reply::AgentRead(ev)))
                    .await;
            }
            Command::AgentStart(s) => break (stream, s),
            other => panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(limits, 1, "one refusal and no raise");
    // The runner's cancel was a move, not a person's: a successor on the other account.
    assert_ne!(start.session, session);
    assert_eq!(start.gateway.as_ref().map(|g| g.account), Some(b.id));
    let ev = events(&start.session, AgentState::Running, vec![]);
    w.fake
        .send(stream, Body::Result(Reply::AgentStart(ev)))
        .await;
    until("the successor runs", &w.core, &start.session, |s| {
        s.state == "running"
    })
    .await;
    let audit = count(&w.core, "SELECT count(*) FROM audit_events WHERE action = 'agent.cancelled' AND details LIKE '%\"class\":\"quota\"%' AND details LIKE '%\"reason\":\"failover\"%'").await;
    assert_eq!(audit, 1);
    assert_eq!(
        count(
            &w.core,
            "SELECT count(*) FROM audit_events WHERE action = 'agent.cancelled'"
        )
        .await,
        1
    );
    // The gateway's own report limited the first account.
    assert_eq!(
        accounts::get(&w.core.app.pool, a.id).await.unwrap().state,
        "limited"
    );
}

#[tokio::test]
async fn a_core_that_went_down_between_the_end_and_the_move_finishes_the_move_once() {
    use ainkrad_core_server::store::agents::NewSession;
    let (core, mut fake, runner, a) = up("fo-restart", true, None).await;
    let b = second(&core, &runner).await;
    let chain = [pool_of(&core, &runner, &[a.id, b.id]).await];
    // The row as the Core left it: an attempt on `a`, over (rate limited), its failover never settled.
    let policy = super::gateway::policy();
    let new = NewSession {
        runner: &runner,
        harness: "claude",
        model: Some("claude-x"),
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &runner,
    };
    let now = core.app.clock.now();
    let old = sessions::create(&core.app.pool, &new, AuditActor::System, &now)
        .await
        .unwrap();
    let secret = serde_json::json!([{"name": a.secret_name, "var": "ANTHROPIC_API_KEY"}]);
    let outcome =
        serde_json::json!({"kind": "failed", "reason": "429", "fingerprint": "rate_limited"});
    sqlx::query(
        "UPDATE core_agent_sessions SET chain = ?, chain_pos = 0, account_id = ?, gateway_account_id = ?, \
         secrets = ?, state = 'ended', outcome = ?, ended_at = ?, start_sent = 1 WHERE id = ?",
    )
    .bind(serde_json::json!(chain).to_string())
    .bind(a.id)
    .bind(a.id)
    .bind(secret.to_string())
    .bind(outcome.to_string())
    .bind(&now)
    .bind(&old.id)
    .execute(&core.app.pool)
    .await
    .unwrap();
    assert_eq!(
        failover::unfinished(&core.app.pool).await.unwrap(),
        std::slice::from_ref(&old.id)
    );
    // The Core starts: it finds the attempt and moves the run, to the other account, in a new session.
    service::resume_all(&core.app).await.unwrap();
    let (stream, cmd) = command(&mut fake).await;
    let Command::AgentStart(start) = cmd else {
        panic!("expected agent.start, got {cmd:?}")
    };
    assert_ne!(start.session, old.id);
    assert_eq!(start.gateway.as_ref().map(|g| g.account), Some(b.id));
    let ev = events(&start.session, AgentState::Running, vec![]);
    fake.send(stream, Body::Result(Reply::AgentStart(ev))).await;
    until("the successor runs", &core, &start.session, |s| {
        s.state == "running"
    })
    .await;
    // A second start-up scan finds nothing to do: still one successor.
    service::resume_all(&core.app).await.unwrap();
    assert!(
        failover::unfinished(&core.app.pool)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        count(&core, "SELECT count(*) FROM core_agent_sessions").await,
        2
    );
}
