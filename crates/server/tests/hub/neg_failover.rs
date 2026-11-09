//! S8, through the hub: a person's cancel that lands while the Core's own quota stop is on its way to
//! the runner. The runner then reports the stop as `Cancelled`, which the Core wrote as a move; the
//! person's cancel settled the run first, so no successor starts and nothing is held.

use ainkrad_core_server::store::agents as sessions;
use ainkrad_core_server::store::failover;
use ainkrad_proto::runner::Outcome;
use ainkrad_proto::v2::*;

use super::allocator::{chain_session, pool_of};
use super::gateway::{W, command, count, events, started, until, up, usage};

#[tokio::test]
async fn neg_a_cancel_during_the_quota_stop_leaves_no_successor_and_no_hold() {
    let (core, fake, runner, a) = up("neg-fo-cancel", true, Some(40_000_000)).await;
    let b = super::failover::second(&core, &runner).await;
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
    let (stream, cmd) = command(&mut w.fake).await;
    assert!(matches!(cmd, Command::AgentRead(_)), "{cmd:?}");
    let mut report = usage(1, 19_800_000, 0);
    report.status = UpstreamStatus::Quota;
    let ev = events(&session, AgentState::Running, vec![report]);
    w.fake
        .send(stream, Body::Result(Reply::AgentRead(ev)))
        .await;
    let (mut cancelled, mut stopped) = (false, false);
    // Until the attempt is over: answer what the Core asks; the person cancels at the first limit.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        let Ok((stream, cmd)) =
            tokio::time::timeout(std::time::Duration::from_millis(1500), command(&mut w.fake))
                .await
        else {
            break;
        };
        match cmd {
            Command::AgentLimit(_) => {
                if !cancelled {
                    let c = failover::cancel_run(&w.core.app.pool, &session)
                        .await
                        .unwrap();
                    assert_eq!(c.newest, session);
                    cancelled = true;
                }
                let ev = events(&session, AgentState::Running, vec![]);
                w.fake
                    .send(stream, Body::Result(Reply::AgentLimit(ev)))
                    .await;
            }
            Command::AgentStop(_) => {
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
            other => panic!("the cancelled run started something: {other:?}"),
        }
    }
    assert!(
        cancelled && stopped,
        "cancelled {cancelled}, stopped {stopped}"
    );
    until("the end", &w.core, &session, |s| !s.live()).await;
    let old = sessions::get(&w.core.app.pool, &session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old.state, "ended");
    assert_eq!(
        count(&w.core, "SELECT count(*) FROM core_agent_sessions").await,
        1
    );
    assert_eq!(
        count(&w.core, "SELECT count(*) FROM core_budget_holds").await,
        0
    );
    assert_eq!(
        count(
            &w.core,
            "SELECT count(*) FROM core_agent_sessions WHERE failover_done = 1"
        )
        .await,
        1
    );
}
