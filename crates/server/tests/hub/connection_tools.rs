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
    sqlx::query("UPDATE core_agent_sessions SET agent = 'bot' WHERE id = ?")
        .bind(&s.id)
        .execute(&core.app.pool)
        .await
        .unwrap();
    access::set(&core.app.pool, &s.id, &["read_repo".to_owned()])
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
    // No grants: no connection tools, only the Code Mode search every session has (E1.4).
    let names: Vec<&str> = first
        .tools
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|t| t.name.as_str())
        .collect();
    assert_eq!(
        (first.after, names),
        (0, vec!["ainkrad.search", "ainkrad.call"]),
        "no grants: only the search"
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
    // The resend of call 1 is answered from its stored result (so c1 may come twice), never run.
    ids.dedup();
    assert_eq!(ids, ["c1", "c2"], "each call answered: {results:?}");
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
    assert_eq!(cursor.grant.tc_seq, 2);
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
    assert_eq!(cursor.grant.tc_seq, 0);
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

/// Answers the first poll with `calls`, then collects every later `agent.tools` command for `secs`
/// WITHOUT answering them (so each open delivery stream stays open, as a slow runner's would).
async fn burst(w: &mut W, calls: Vec<ToolCall>, secs: u64, answer: bool) -> Vec<ToolsPoll> {
    let (stream, cmd) = next(w).await.expect("a tools poll");
    assert!(matches!(cmd, Command::AgentTools(_)));
    let batch = ToolBatch {
        session: w.session.clone(),
        calls,
    };
    w.fake
        .send(stream, Body::Result(Reply::AgentTools(batch)))
        .await;
    let mut seen = Vec::new();
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    while let Some(left) = end.checked_duration_since(tokio::time::Instant::now()) {
        let Ok(Some((stream, cmd))) = tokio::time::timeout(left, next(w)).await else {
            break;
        };
        if let Command::AgentTools(p) = cmd {
            // A delivery (it carries results) is answered when asked to; a long poll never is.
            if answer && !p.results.is_empty() {
                let empty = ToolBatch {
                    session: w.session.clone(),
                    calls: vec![],
                };
                w.fake
                    .send(stream, Body::Result(Reply::AgentTools(empty)))
                    .await;
            }
            seen.push(p);
        }
    }
    seen
}

#[tokio::test]
async fn a_burst_of_finished_calls_costs_one_delivery_stream_not_one_each() {
    let mut w = world("tools-burst", true).await;
    let calls: Vec<ToolCall> = (1..=32)
        .map(|n| call(n, &format!("c{n}"), "github.get_issue"))
        .collect();
    let polls = burst(&mut w, calls, 2, false).await;
    // The runner answers none of them: the Core still has at most ONE delivery stream open for
    // the session (the long poll that follows is the other), however many calls finished.
    let deliveries: Vec<&ToolsPoll> = polls.iter().filter(|p| !p.results.is_empty()).collect();
    assert_eq!(deliveries.len(), 1, "one delivery stream: {}", polls.len());
    assert!(!deliveries[0].results.is_empty());
    assert_eq!(uses(&w).await, 32, "all 32 were taken and audited");
}

#[tokio::test]
async fn a_call_past_the_next_number_is_answered_out_of_order_and_not_run() {
    let mut w = world("tools-gap", true).await;
    let calls = vec![
        call(1, "c1", "github.get_issue"),
        call(3, "c3", "github.get_issue"),
    ];
    let polls = burst(&mut w, calls, 2, true).await;
    let results: Vec<&ToolResult> = polls.iter().flat_map(|p| p.results.iter()).collect();
    let by = |id: &str| results.iter().find(|r| r.id == id).copied();
    assert_eq!(
        by("c3").and_then(|r| r.code.as_deref()),
        Some("out_of_order")
    );
    assert_eq!(
        by("c1").and_then(|r| r.code.as_deref()),
        Some("no_connection")
    );
    assert_eq!(
        uses(&w).await,
        1,
        "only the in-order call ran and was audited"
    );
    let cursor = access::load(&w.core.app.pool, &w.session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cursor.grant.tc_seq, 3, "the cursor moved past the gap");
}

#[tokio::test]
async fn setting_a_sessions_allowlist_starts_its_supervisor() {
    let w = world("tools-hook", false).await;
    let id = "as_hookonlysession".to_owned();
    sqlx::query("INSERT INTO core_agent_sessions (id, runner, harness, policy, state, created_by, created_at, updated_at, user_id) \
         SELECT ?, runner, harness, policy, 'starting', created_by, created_at, updated_at, user_id FROM core_agent_sessions WHERE id = ?")
        .bind(&id)
        .bind(&w.session)
        .execute(&w.core.app.pool)
        .await
        .unwrap();
    assert!(!w.core.app.connections.is_supervised(&id));
    service_set_access(&w, &id).await;
    assert!(
        w.core.app.connections.is_supervised(&id),
        "the hook started it"
    );
}

async fn service_set_access(w: &W, id: &str) {
    ainkrad_core_server::connections::broker::set_access(
        &w.core.app,
        id,
        &["read_repo".to_owned()],
    )
    .await
    .unwrap();
}

/// The next delivery (a poll that carries results), skipping long polls; `answer` says how it ends.
async fn delivery(w: &mut W, how: Option<ErrorCode>) -> ToolsPoll {
    loop {
        let (stream, cmd) = next(w).await.expect("a delivery");
        let Command::AgentTools(p) = cmd else {
            continue;
        };
        if p.results.is_empty() {
            continue;
        }
        match how {
            Some(code) => {
                let e = StreamError::new(code, "the runner is busy");
                w.fake.send(stream, Body::Error(e)).await;
            }
            None => {
                let empty = ToolBatch {
                    session: w.session.clone(),
                    calls: vec![],
                };
                w.fake
                    .send(stream, Body::Result(Reply::AgentTools(empty)))
                    .await;
            }
        }
        return p;
    }
}

#[tokio::test]
async fn a_result_is_kept_through_failed_deliveries_until_the_runner_takes_it() {
    let mut w = world("tools-keep", true).await;
    let (stream, _) = next(&mut w).await.expect("a tools poll");
    let batch = ToolBatch {
        session: w.session.clone(),
        calls: vec![call(1, "c1", "github.get_issue")],
    };
    w.fake
        .send(stream, Body::Result(Reply::AgentTools(batch)))
        .await;
    // Six failed deliveries (past the old three tries): the same result is offered each time.
    for _ in 0..6 {
        let p = delivery(&mut w, Some(ErrorCode::Busy)).await;
        assert_eq!(p.results[0].id, "c1");
    }
    let p = delivery(&mut w, None).await;
    assert_eq!(
        (p.results[0].id.as_str(), p.results[0].code.as_deref()),
        ("c1", Some("no_connection"))
    );
    assert_eq!(
        uses(&w).await,
        1,
        "one call, one row, however often it was offered"
    );
}

#[tokio::test]
async fn a_call_the_core_already_took_is_answered_from_its_stored_result_not_run_again() {
    let mut w = world("tools-resend", true).await;
    let mut answers = Vec::new();
    let mut resent = false;
    let mut first = true;
    for _ in 0..40 {
        let Some((stream, cmd)) = next(&mut w).await else {
            break;
        };
        let Command::AgentTools(p) = cmd else {
            continue;
        };
        let calls = if p.results.is_empty() && first {
            first = false;
            vec![call(1, "c1", "github.get_issue")]
        } else if p.results.is_empty() && !resent && !answers.is_empty() {
            // The runner reconnected and sends the same call again.
            resent = true;
            vec![call(1, "c1", "github.get_issue")]
        } else {
            vec![]
        };
        answers.extend(p.results.clone());
        let batch = ToolBatch {
            session: w.session.clone(),
            calls,
        };
        w.fake
            .send(stream, Body::Result(Reply::AgentTools(batch)))
            .await;
        if answers.len() >= 2 {
            break;
        }
    }
    assert_eq!(answers.len(), 2, "answered twice: {answers:?}");
    assert_eq!(answers[0].id, "c1");
    assert_eq!(
        (&answers[1].id, &answers[1].code),
        (&answers[0].id, &answers[0].code),
        "from the stored result"
    );
    assert_eq!(uses(&w).await, 1, "it did not run again");
}

#[tokio::test]
async fn a_result_that_can_never_be_delivered_is_audited_when_its_session_ends() {
    let mut w = world("tools-undelivered", true).await;
    let (stream, _) = next(&mut w).await.expect("a tools poll");
    let batch = ToolBatch {
        session: w.session.clone(),
        calls: vec![call(1, "c1", "github.get_issue")],
    };
    w.fake
        .send(stream, Body::Result(Reply::AgentTools(batch)))
        .await;
    let _ = delivery(&mut w, Some(ErrorCode::Busy)).await;
    let over = json!({"kind": "succeeded"});
    let now = w.core.app.clock.now();
    sessions::end(&w.core.app.pool, &w.session, "ended", &over, &now)
        .await
        .unwrap();
    for _ in 0..80 {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events WHERE action = 'connection.used' AND details LIKE '%result_undelivered%'",
        )
        .fetch_one(&w.core.app.pool)
        .await
        .unwrap();
        if n == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no result_undelivered row");
}
