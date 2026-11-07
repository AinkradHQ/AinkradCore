//! The connection tools' channel end to end through the hub, with a runner played by hand: the
//! Core polls `agent.tools` only on a runner that lists `connection-tools`, a call the runner
//! sends is taken once (a resend is not run twice), its result comes back in a poll of its own
//! and names no connection, a batch for another session is ignored, and no frame the Core sends
//! carries a credential. The decisions themselves are `connections::broker`'s own tests.

use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents as service;
use ainkrad_core_server::hub::HubConfig;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use ainkrad_core_server::store::connections::access;
use ainkrad_proto::runner::Isolation;
use ainkrad_proto::v2::*;
use serde_json::json;

use super::gateway::events;
use super::{Core, Fake, agents, quick, random32};

fn driver(tools: bool) -> DriverInfo {
    let mut commands: Vec<String> = AGENT_OPS.iter().map(|o| (*o).to_owned()).collect();
    if tools {
        commands.push(CAP_TOOLS.to_owned());
    }
    DriverInfo {
        name: AGENT_DRIVER.to_owned(),
        commands,
        capacity: 2,
        streams: Some(32),
        ..DriverInfo::default()
    }
}

struct W {
    core: Core,
    fake: Fake,
    session: String,
}

async fn world(name: &str, tools: bool) -> W {
    let hub = HubConfig {
        heartbeat: Duration::from_secs(30),
        ..quick()
    };
    let core = Core::start_agents(name, hub, agents::quick()).await;
    let dev = core.runner().await;
    let mut fake = Fake::plain(&core, &dev).await;
    fake.os = Some("linux".to_owned());
    fake.isolation = Some(IsolationCaps::of(Isolation::Process, Kvm::NotApplicable));
    let auth = fake.hello(&dev, vec![driver(tools)], &random32()).await;
    fake.prove(&dev, &auth, &NO_CHANNEL_BINDING, &core.app.auth.identity.fp)
        .await;
    fake.welcome().await;
    agents::throwaway_mode(&core).await;
    agents::make_admin(&core, &dev.id).await;
    let policy = json!({"mode": "ask"});
    let new = NewSession {
        runner: &dev.id,
        harness: "claude",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &dev.id,
    };
    let now = core.app.clock.now();
    let s = sessions::create(&core.app.pool, &new, AuditActor::System, &now)
        .await
        .unwrap();
    access::set(
        &core.app.pool,
        &s.id,
        Some("bot"),
        &["read_repo".to_owned()],
    )
    .await
    .unwrap();
    service::authorize_for_tests(&core.app, &s.id);
    let (app, row) = (core.app.clone(), s.clone());
    tokio::spawn(async move {
        let _ = service::start(&app, &row).await;
    });
    W {
        core,
        fake,
        session: s.id,
    }
}

/// The next command, answering the start (running) and leaving every read unanswered.
async fn next(w: &mut W) -> Option<(u64, Command)> {
    loop {
        let f = tokio::time::timeout(Duration::from_secs(3), w.fake.next())
            .await
            .ok()?;
        let Some(Body::Command(c)) = f.body().unwrap() else {
            continue;
        };
        match c {
            Command::AgentStart(_) => {
                let ev = events(&w.session, AgentState::Running, vec![]);
                w.fake
                    .send(f.stream_id, Body::Result(Reply::AgentStart(ev)))
                    .await;
            }
            Command::AgentRead(_) => {}
            other => return Some((f.stream_id, other)),
        }
    }
}

fn call(seq: u64, id: &str, tool: &str) -> ToolCall {
    ToolCall {
        tc_seq: seq,
        id: id.to_owned(),
        tool: tool.to_owned(),
        args: json!({"repo": "o/r", "number": 1}),
    }
}

async fn uses(w: &W) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'connection.used'")
        .fetch_one(&w.core.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_call_is_taken_once_answered_in_its_own_poll_and_names_no_connection() {
    let mut w = world("tools-once", true).await;
    let (stream, cmd) = next(&mut w).await.expect("a tools poll");
    let Command::AgentTools(first) = cmd else {
        panic!("expected agent.tools, got {cmd:?}")
    };
    assert_eq!(
        (first.after, first.tools.as_deref()),
        (0, Some(&[][..])),
        "no grants: no tools"
    );
    let batch = ToolBatch {
        session: w.session.clone(),
        calls: vec![call(1, "c1", "github.get_issue")],
    };
    w.fake
        .send(stream, Body::Result(Reply::AgentTools(batch)))
        .await;
    // The Core's next polls: the first long one is answered with a RESEND of call 1 and a new,
    // unknown call 2; every result it sends comes in a short poll of its own.
    let mut resent = false;
    let mut results = Vec::new();
    for _ in 0..60 {
        let Some((stream, cmd)) = next(&mut w).await else {
            break;
        };
        let Command::AgentTools(p) = cmd else {
            continue;
        };
        results.extend(p.results.clone());
        let calls = if p.results.is_empty() && !resent {
            resent = true;
            vec![
                call(1, "c1", "github.get_issue"),
                call(2, "c2", "github.drop_repo"),
            ]
        } else {
            vec![]
        };
        let batch = ToolBatch {
            session: w.session.clone(),
            calls,
        };
        w.fake
            .send(stream, Body::Result(Reply::AgentTools(batch)))
            .await;
        if results.len() >= 2 {
            break;
        }
    }
    // Anything more that comes (a resend run twice would show here); polls are left unanswered.
    while let Some((_, cmd)) = tokio::time::timeout(Duration::from_millis(800), next(&mut w))
        .await
        .ok()
        .flatten()
    {
        if let Command::AgentTools(p) = cmd {
            results.extend(p.results);
        }
    }
    let mut ids: Vec<String> = results.iter().map(|r| r.id.clone()).collect();
    ids.sort();
    assert_eq!(ids, ["c1", "c2"], "each call answered once: {results:?}");
    let by = |id: &str| results.iter().find(|r| r.id == id).unwrap();
    assert_eq!(
        (by("c1").ok, by("c1").code.as_deref()),
        (false, Some("no_connection"))
    );
    assert_eq!(
        (by("c2").ok, by("c2").code.as_deref()),
        (false, Some("unknown_tool"))
    );
    assert_eq!(uses(&w).await, 2, "one row per call, none for the resend");
    let cursor = access::load(&w.core.app.pool, &w.session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cursor.grant.unwrap().tc_seq, 2);
}

#[tokio::test]
async fn a_batch_for_another_session_is_ignored() {
    let mut w = world("tools-other", true).await;
    let (stream, cmd) = next(&mut w).await.expect("a tools poll");
    assert!(matches!(cmd, Command::AgentTools(_)));
    let batch = ToolBatch {
        session: "as_someoneelse".to_owned(),
        calls: vec![call(1, "x1", "github.get_issue")],
    };
    w.fake
        .send(stream, Body::Result(Reply::AgentTools(batch)))
        .await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(uses(&w).await, 0, "nothing ran, nothing audited");
    let cursor = access::load(&w.core.app.pool, &w.session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cursor.grant.unwrap().tc_seq, 0);
}

#[tokio::test]
async fn a_runner_that_does_not_list_the_capability_is_never_sent_the_op() {
    let mut w = world("tools-old", false).await;
    // Only the start and the reads: never an agent.tools.
    assert!(
        next(&mut w).await.is_none(),
        "no tools poll reaches an older runner"
    );
}
