//! B-M1b: a client session does not outlive the device that created it. The supervisor kills its
//! harness once and lets the normal read loop carry on until the runner reports the end (its
//! draining gateway reports arrive after the kill and are stored, the hold is settled once), and
//! never moves its run. A runner that is away or revoked cannot
//! hold the session open: it ends `lost`. Revoked through the store alone, as the CLI does.

use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents::{self as service, AgentsConfig};
use ainkrad_core_server::gateway::Listen;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use ainkrad_core_server::store::gov;
use ainkrad_proto::runner::Outcome;
use ainkrad_proto::v2::{AgentState, Body, Command, Reply};

use super::agents::{Runner, quick as agents_quick, run_runner, script, state_of};
use super::allocator::{chain_session, pool_of};
use super::gateway::{W, command, count, events, started, until, up, usage};
use super::runner::{paired, state};
use super::{Core, quick as hub_quick};

fn short_lost() -> AgentsConfig {
    AgentsConfig {
        lost_after: Duration::from_secs(2),
        ..agents_quick()
    }
}

async fn revoke(core: &Core, id: &str) {
    let now = core.app.clock.now();
    let done = gov::revoke_device(&core.app.pool, id, AuditActor::System, None, &now);
    assert!(done.await.unwrap());
}

async fn session_by(core: &Core, runner: &str, creator: &str) -> String {
    let policy = serde_json::json!({"mode": "ask"});
    let new = NewSession {
        runner,
        harness: "fake",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: creator,
    };
    let now = core.app.clock.now();
    let s = sessions::create(&core.app.pool, &new, AuditActor::System, &now)
        .await
        .unwrap();
    service::authorize_for_tests(&core.app, &s.id);
    service::start(&core.app, &s)
        .await
        .unwrap_or_else(|e| panic!("{}", service::describe(&e)));
    s.id
}

/// Like [`session_by`], again while the runner is `busy` (a killed harness frees its slot in a
/// task of its own, a moment after the kill is answered).
async fn session_when_free(core: &Core, runner: &str, creator: &str) -> String {
    let policy = serde_json::json!({"mode": "ask"});
    for _ in 0..100 {
        let new = NewSession {
            runner,
            harness: "fake",
            model: None,
            prompt: Some("go"),
            workspace: None,
            policy: &policy,
            secrets: &[],
            created_by: creator,
        };
        let now = core.app.clock.now();
        let s = sessions::create(&core.app.pool, &new, AuditActor::System, &now)
            .await
            .unwrap();
        service::authorize_for_tests(&core.app, &s.id);
        if service::start(&core.app, &s).await.is_ok() {
            return s.id;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the runner's slot was never freed");
}

async fn running(core: &Core, id: &str) {
    for _ in 0..500 {
        if state_of(core, id).await.state == "running" {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{id} never ran");
}

/// Waits (bounded) for `id` to be over and returns it.
async fn over(core: &Core, id: &str, secs: u64) -> sessions::Session {
    let started = std::time::Instant::now();
    loop {
        let s = state_of(core, id).await;
        if !s.live() {
            return s;
        }
        assert!(
            started.elapsed() < Duration::from_secs(secs),
            "still {} after {secs} s",
            s.state
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn lines(core: &Core, id: &str) -> impl Future<Output = usize> {
    let (pool, id) = (core.app.pool.clone(), id.to_owned());
    async move {
        let t = sessions::transcript(&pool, &id, 0, 10_000).await.unwrap();
        t.iter().filter(|e| e.body["type"] == "line").count()
    }
}

const TICK: &str = "while :; do echo tick; sleep 0.05; done";

#[tokio::test]
async fn a_session_ends_and_its_harness_is_killed_when_its_creator_is_revoked() {
    let core = Core::start("creator-revoked", hub_quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("creator-revoked");
    paired(&core, &base, None, &st).await;
    let r = run_runner(&core, &base, &st, script(TICK)).await;
    let gone = core.device("device", &["agent"]).await;
    let kept = core.device("device", &["agent"]).await;
    let mine = session_by(&core, &r.id, &gone.id).await;
    let other = session_by(&core, &r.id, &kept.id).await;
    running(&core, &mine).await;
    running(&core, &other).await;
    // Revoked through the store only: no broadcast, as `device revoke` on the CLI.
    revoke(&core, &gone.id).await;
    let s = over(&core, &mine, 10).await;
    assert_eq!(s.state, "ended");
    // The bystander is untouched, on the Core and on the runner: it still ticks.
    assert!(state_of(&core, &other).await.live());
    let before = lines(&core, &other).await;
    // The kill freed the revoked creator's slot: a third session runs on the two-slot runner.
    let third = session_when_free(&core, &r.id, &kept.id).await;
    running(&core, &third).await;
    for _ in 0..100 {
        if lines(&core, &other).await > before + 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        lines(&core, &other).await > before + 3,
        "the bystander stalled"
    );
    r.halt().await;
    let _ = std::fs::remove_dir_all(&st.0);
}

/// A runner that is away cannot be told to kill: the session is lost once `lost_after` passes
/// (here 2 s), not retried for ever.
#[tokio::test]
async fn a_revoked_creators_session_on_an_away_runner_is_lost_after_lost_after() {
    let core = Core::start_agents("creator-away", hub_quick(), short_lost()).await;
    let base = format!("http://{}", core.host);
    let st = state("creator-away");
    paired(&core, &base, None, &st).await;
    let r = run_runner(&core, &base, &st, script(TICK)).await;
    let a = core.device("device", &["agent"]).await;
    let sa = session_by(&core, &r.id, &a.id).await;
    running(&core, &sa).await;
    r.halt().await;
    revoke(&core, &a.id).await;
    let s = over(&core, &sa, 10).await;
    assert_eq!(s.state, "lost");
    assert_eq!(s.outcome.unwrap()["reason"], "the runner never came back");
    let _ = std::fs::remove_dir_all(&st.0);
}

/// A runner that is revoked as well is lost at once, with the reason said.
#[tokio::test]
async fn a_revoked_creators_session_on_a_revoked_runner_is_lost_at_once() {
    let core = Core::start("creator-gone", hub_quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("creator-gone");
    paired(&core, &base, None, &st).await;
    let r = run_runner(&core, &base, &st, script(TICK)).await;
    let b = core.device("device", &["agent"]).await;
    let sb = session_by(&core, &r.id, &b.id).await;
    running(&core, &sb).await;
    let runner = r.id.clone();
    r.halt().await;
    revoke(&core, &b.id).await;
    revoke(&core, &runner).await;
    // `lost_after` is 60 s here: only the revoked runner can end it within seconds.
    let s = over(&core, &sb, 10).await;
    assert_eq!(s.state, "lost");
    assert_eq!(s.outcome.unwrap()["reason"], "the runner was revoked");
    let _ = std::fs::remove_dir_all(&st.0);
}

/// The Core goes away while the loop is retrying; the new one supervises the session again and it
/// still terminates.
#[tokio::test]
async fn a_core_restart_mid_retry_still_ends_the_session() {
    let dir = std::env::temp_dir().join(format!("core-hub-creator-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let listen = || Listen::Tcp("127.0.0.1:0".to_owned());
    let first = Core::start_with(
        "c-restart",
        hub_quick(),
        listen(),
        Some(&dir),
        None,
        short_lost(),
    )
    .await;
    let base = format!("http://{}", first.host);
    let st = state("creator-restart");
    paired(&first, &base, None, &st).await;
    let r: Runner = run_runner(&first, &base, &st, script(TICK)).await;
    let gone = first.device("device", &["agent"]).await;
    let id = session_by(&first, &r.id, &gone.id).await;
    running(&first, &id).await;
    r.halt().await;
    revoke(&first, &gone.id).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(state_of(&first, &id).await.live());
    first.app.closing.send_replace(true);
    // Nobody supervises it now: it stays live while the first Core is stopped.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(state_of(&first, &id).await.live());
    let restarted = first.app.clock.now();
    let second = Core::start_with(
        "c-restart",
        hub_quick(),
        listen(),
        Some(&dir),
        None,
        short_lost(),
    )
    .await;
    assert_eq!(service::resume_all(&second.app).await.unwrap(), 1);
    let s = over(&second, &id, 10).await;
    assert_eq!(s.state, "lost");
    // The second Core ended it: after it started, with the restart's own lost_after wait.
    assert!(s.ended_at.unwrap() > restarted, "ended before the restart");
    let _ = std::fs::remove_dir_all(&st.0);
    drop(second);
    drop(first);
}

/// The runner drains the gateway's in-flight requests after a kill, still `running`, and their
/// final reports arrive with later reads. The Core must not end the session at the kill: every
/// report is stored, the hold is held until the runner's `ended`, and released once.
#[tokio::test]
async fn the_drained_reports_after_a_kill_are_stored_and_the_hold_is_released_once() {
    let (core, fake, runner, account) = up("creator-gw", true, Some(700_000)).await;
    let session = super::gateway::start(&core, &runner, &account).await;
    let mut w = W {
        core,
        fake,
        runner,
        account,
        session: session.clone(),
    };
    started(&mut w, 700_000).await;
    let gone = w.core.device("device", &["admin"]).await;
    let holds = "SELECT count(*) FROM core_budget_holds";
    let costs = "SELECT count(*) FROM core_cost_events";
    assert_eq!(count(&w.core, holds).await, 1);
    // The first long poll is pending at the runner; the creator is revoked meanwhile.
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)));
    sqlx::query("UPDATE core_agent_sessions SET created_by = ? WHERE id = ?")
        .bind(&gone.id)
        .bind(&session)
        .execute(&w.core.app.pool)
        .await
        .unwrap();
    revoke(&w.core, &gone.id).await;
    let ev = events(&session, AgentState::Running, vec![]);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    // The runner is told to kill (once), and is still draining: `running`, with a report.
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::AgentStop(stop) = cmd else {
        panic!("expected agent.stop, got {cmd:?}")
    };
    assert_eq!((stop.session.as_str(), stop.kill), (session.as_str(), true));
    let draining = events(
        &session,
        AgentState::Running,
        vec![usage(1, 100_000, 20_000)],
    );
    w.fake
        .send(stream, Body::Result(Reply::AgentStop(draining)))
        .await;
    // The Core reads on (no second kill, no end): it acknowledges the stored report; a late one comes.
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::AgentRead(read) = cmd else {
        panic!("expected agent.read, got {cmd:?}")
    };
    assert_eq!(read.gw_after, 1, "the stop answer's report was stored");
    let late = events(&session, AgentState::Running, vec![usage(2, 5_000, 0)]);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(late)))
        .await;
    let (stream, cmd) = command(&mut w.fake).await;
    let Command::AgentRead(read) = cmd else {
        panic!("expected agent.read, got {cmd:?}")
    };
    assert_eq!(read.gw_after, 2, "the late report was stored");
    assert!(
        state_of(&w.core, &session).await.live(),
        "not ended while draining"
    );
    assert_eq!(count(&w.core, holds).await, 1, "the hold waits for the end");
    assert_eq!(count(&w.core, costs).await, 2);
    // The drain is over: the runner reports the end with the last report.
    let mut ended = events(&session, AgentState::Ended, vec![usage(3, 1_000, 0)]);
    ended.outcome = Some(Outcome::Cancelled {
        reason: "killed".to_owned(),
    });
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ended.clone())))
        .await;
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(
        matches!(cmd, Command::AgentRead(_)),
        "the acknowledgement read"
    );
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ended)))
        .await;
    until("the end", &w.core, &session, |s| !s.live()).await;
    assert_eq!(count(&w.core, costs).await, 3);
    assert_eq!(count(&w.core, holds).await, 0);
    assert_eq!(state_of(&w.core, &session).await.state, "ended");
}

/// A chain session still waiting for an account has nothing on a runner: it ends `cancelled`
/// with the true reason, and no `agent.start` is ever sent.
#[tokio::test]
async fn a_waiting_chain_session_of_a_revoked_creator_ends_saying_why() {
    let (core, mut fake, runner, account) = up("creator-wait", true, None).await;
    let chain = [pool_of(&core, &runner, &[account.id]).await];
    sqlx::query(
        "UPDATE core_accounts SET state = 'cooling', state_reason = 'rate_limited', \
         state_until = ? WHERE id = ?",
    )
    .bind(ainkrad_core_server::scheduler::iso_of_unix(
        core.app.clock.unix() + 600,
    ))
    .bind(account.id)
    .execute(&core.app.pool)
    .await
    .unwrap();
    let session = chain_session(&core, &runner, &chain).await;
    let gone = core.device("device", &["admin"]).await;
    sqlx::query("UPDATE core_agent_sessions SET created_by = ? WHERE id = ?")
        .bind(&gone.id)
        .bind(&session)
        .execute(&core.app.pool)
        .await
        .unwrap();
    revoke(&core, &gone.id).await;
    let s = over(&core, &session, 10).await;
    let outcome = s.outcome.unwrap();
    assert_eq!(outcome["kind"], "cancelled");
    assert_eq!(outcome["reason"], "its creator was revoked");
    let sent = tokio::time::timeout(Duration::from_millis(600), command(&mut fake)).await;
    assert!(
        sent.is_err(),
        "nothing is sent for it: {:?}",
        sent.map(|c| c.1)
    );
}

/// An attempt that ends on its own (rate limited) while its creator is revoked does not move the
/// run: no successor, no pick, no hold.
#[tokio::test]
async fn a_run_whose_creator_is_revoked_gets_no_successor() {
    let (core, fake, runner, a) = up("creator-fo", true, None).await;
    let b = super::failover::second(&core, &runner).await;
    let chain = [pool_of(&core, &runner, &[a.id, b.id]).await];
    let session = chain_session(&core, &runner, &chain).await;
    let mut w = W {
        core,
        fake,
        runner,
        account: a,
        session: session.clone(),
    };
    started(&mut w, u64::MAX).await;
    until("running", &w.core, &session, |s| s.state == "running").await;
    let gone = w.core.device("device", &["admin"]).await;
    // The long poll is pending; the creator is revoked just before the attempt ends by itself.
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)));
    sqlx::query("UPDATE core_agent_sessions SET created_by = ? WHERE id = ?")
        .bind(&gone.id)
        .bind(&session)
        .execute(&w.core.app.pool)
        .await
        .unwrap();
    revoke(&w.core, &gone.id).await;
    let mut ended = events(&session, AgentState::Ended, vec![]);
    ended.outcome = Some(Outcome::Failed {
        reason: "429".to_owned(),
        fingerprint: Some("rate_limited".to_owned()),
    });
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ended.clone())))
        .await;
    // The acknowledgement read of the end; then nothing is started.
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)));
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ended)))
        .await;
    until("settled", &w.core, &session, |s| !s.live()).await;
    let settled = "SELECT count(*) FROM core_agent_sessions WHERE failover_done = 1";
    for _ in 0..100 {
        if count(&w.core, settled).await == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_eq!(count(&w.core, settled).await, 1, "the attempt is settled");
    let sent = tokio::time::timeout(Duration::from_millis(900), command(&mut w.fake)).await;
    assert!(sent.is_err(), "nothing is started: {:?}", sent.map(|c| c.1));
    assert_eq!(
        count(&w.core, "SELECT count(*) FROM core_agent_sessions").await,
        1
    );
    assert_eq!(
        count(&w.core, "SELECT count(*) FROM core_budget_holds").await,
        0
    );
}
