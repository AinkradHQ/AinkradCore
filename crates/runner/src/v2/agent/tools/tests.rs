use std::sync::Arc;

use ainkrad_proto::v2::{ConnTool, MAX_ARGS_BYTES, ToolResult, ToolsPoll};
use serde_json::json;

use super::*;

const SHORT: Duration = Duration::from_millis(300);

fn tool(name: &str) -> ConnTool {
    ConnTool {
        name: name.to_owned(),
        description: "d".to_owned(),
        write: false,
        input_schema: None,
    }
}

fn poll(after: u64, results: Vec<ToolResult>, tools: Option<Vec<ConnTool>>) -> ToolsPoll {
    ToolsPoll {
        session: "as_a".to_owned(),
        after,
        wait_ms: Some(200),
        results,
        tools,
    }
}

fn ok(id: &str) -> ToolResult {
    ToolResult {
        id: id.to_owned(),
        ok: true,
        result: Some(json!({"n": 1})),
        code: None,
        message: None,
    }
}

#[tokio::test]
async fn a_call_waits_for_the_core_and_gets_its_result() {
    let t = Arc::new(Tools::default());
    t.poll(
        &poll(0, vec![], Some(vec![tool("github.get_issue")])),
        SHORT,
    )
    .await;
    let caller = {
        let t = t.clone();
        tokio::spawn(async move {
            t.call("as_a", "github.get_issue", json!({"repo": "o/r"}))
                .await
        })
    };
    let batch = t.poll(&poll(0, vec![], None), SHORT).await;
    assert_eq!(batch.calls.len(), 1);
    let c = &batch.calls[0];
    assert_eq!((c.tc_seq, c.tool.as_str()), (1, "github.get_issue"));
    // Resent until acknowledged, with the same number.
    let again = t.poll(&poll(0, vec![], None), SHORT).await;
    assert_eq!(again.calls[0].tc_seq, 1);
    let acked = t.poll(&poll(1, vec![ok(&c.id)], None), SHORT).await;
    assert!(acked.calls.is_empty());
    let r = caller.await.unwrap();
    assert!(r.ok && r.result.unwrap()["n"] == 1);
}

#[tokio::test]
async fn an_unlisted_tool_oversize_arguments_and_a_flood_are_refused_here() {
    let t = Tools::default();
    let r = t
        .call_within("as_a", "github.get_issue", json!({}), SHORT)
        .await;
    assert_eq!(r.code.as_deref(), Some("unknown_tool"), "no list yet");
    t.poll(
        &poll(0, vec![], Some(vec![tool("github.get_issue")])),
        SHORT,
    )
    .await;
    let big = json!({"x": "y".repeat(MAX_ARGS_BYTES)});
    let r = t.call_within("as_a", "github.get_issue", big, SHORT).await;
    assert_eq!(r.code.as_deref(), Some("bad_args"));
    // An empty list takes every tool away.
    t.poll(&poll(0, vec![], Some(vec![])), SHORT).await;
    let r = t
        .call_within("as_a", "github.get_issue", json!({}), SHORT)
        .await;
    assert_eq!(r.code.as_deref(), Some("unknown_tool"));
    assert!(t.list("as_a").is_empty());
}

#[tokio::test]
async fn a_call_the_core_never_answers_times_out_and_a_stray_result_is_dropped() {
    let t = Tools::default();
    t.poll(
        &poll(0, vec![], Some(vec![tool("github.get_issue")])),
        SHORT,
    )
    .await;
    let r = t
        .call_within(
            "as_a",
            "github.get_issue",
            json!({}),
            Duration::from_millis(100),
        )
        .await;
    assert_eq!(r.code.as_deref(), Some("timed_out"));
    // A result for no waiting call changes nothing.
    t.poll(&poll(0, vec![ok("c999")], None), SHORT).await;
}

#[tokio::test]
async fn numbering_starts_above_the_cores_cursor_after_a_restart() {
    let t = Arc::new(Tools::default());
    t.poll(&poll(41, vec![], Some(vec![tool("jira.get_issue")])), SHORT)
        .await;
    let caller = {
        let t = t.clone();
        tokio::spawn(async move {
            t.call_within("as_a", "jira.get_issue", json!({}), SHORT)
                .await
        })
    };
    let batch = t.poll(&poll(41, vec![], None), SHORT).await;
    assert_eq!(batch.calls[0].tc_seq, 42);
    drop(caller);
}

#[tokio::test]
async fn forgetting_a_session_ends_its_waiting_calls() {
    let t = Arc::new(Tools::default());
    t.poll(
        &poll(0, vec![], Some(vec![tool("github.get_issue")])),
        SHORT,
    )
    .await;
    let caller = {
        let t = t.clone();
        tokio::spawn(async move { t.call("as_a", "github.get_issue", json!({})).await })
    };
    t.poll(&poll(0, vec![], None), SHORT).await;
    t.forget("as_a");
    let r = caller.await.unwrap();
    assert_eq!(r.code.as_deref(), Some("session_over"));
}

#[tokio::test]
async fn an_unknown_session_makes_no_state_and_a_stale_epochs_result_matches_nothing() {
    let t = Arc::new(Tools::default());
    let r = t
        .call_within("as_nobody", "github.get_issue", json!({}), SHORT)
        .await;
    assert_eq!(r.code.as_deref(), Some("unknown_tool"));
    assert!(
        t.sessions.lock().unwrap().is_empty(),
        "no entry for a session nobody polled"
    );
    t.poll(
        &poll(0, vec![], Some(vec![tool("github.get_issue")])),
        SHORT,
    )
    .await;
    let caller = {
        let t = t.clone();
        tokio::spawn(async move { t.call("as_a", "github.get_issue", json!({})).await })
    };
    let batch = t.poll(&poll(0, vec![], None), SHORT).await;
    let id = batch.calls[0].id.clone();
    assert!(id.contains('-') && id.len() > 4, "{id}");
    // A result for the same counter of another epoch (a call from before a restart) is dropped.
    let (epoch, n) = id.split_once('-').unwrap();
    let stale = format!(
        "{}-{n}",
        if epoch == "00000000" {
            "00000001"
        } else {
            "00000000"
        }
    );
    t.poll(&poll(1, vec![ok(&stale)], None), SHORT).await;
    assert!(
        !caller.is_finished(),
        "the stale result did not resolve the call"
    );
    t.poll(&poll(1, vec![ok(&id)], None), SHORT).await;
    assert!(caller.await.unwrap().ok);
}

#[tokio::test]
async fn a_write_that_the_core_never_answers_is_outcome_unknown_and_a_read_is_timed_out() {
    let t = Tools::default();
    let list = vec![
        tool("github.get_issue"),
        ConnTool {
            name: "github.create_issue".to_owned(),
            description: "d".to_owned(),
            write: true,
            input_schema: None,
        },
    ];
    t.poll(&poll(0, vec![], Some(list)), SHORT).await;
    let short = Duration::from_millis(80);
    let w = t
        .call_within("as_a", "github.create_issue", json!({}), short)
        .await;
    assert_eq!(w.code.as_deref(), Some("outcome_unknown"));
    assert!(w.message.unwrap().contains("check before retrying"));
    let r = t
        .call_within("as_a", "github.get_issue", json!({}), short)
        .await;
    assert_eq!(r.code.as_deref(), Some("timed_out"));
}

#[tokio::test]
async fn a_changed_list_ticks_subscribers_and_an_unchanged_one_does_not() {
    let t = Tools::default();
    let mut rx = t.subscribe();
    t.poll(
        &poll(0, vec![], Some(vec![tool("github.get_issue")])),
        SHORT,
    )
    .await;
    assert!(rx.has_changed().unwrap());
    rx.mark_unchanged();
    t.poll(
        &poll(0, vec![], Some(vec![tool("github.get_issue")])),
        SHORT,
    )
    .await;
    assert!(!rx.has_changed().unwrap(), "the same list is not a change");
    // A schema over the cap is dropped (the tool is listed with an open object); a name that is
    // not an operation's shape is not listed at all.
    let big = ConnTool {
        input_schema: Some(json!({"description": "x".repeat(ainkrad_proto::v2::MAX_SCHEMA_BYTES)})),
        ..tool("github.get_repo")
    };
    t.poll(&poll(0, vec![], Some(vec![big, tool("Bad Name")])), SHORT)
        .await;
    let listed = t.list("as_a");
    assert_eq!(listed.len(), 1);
    assert!(listed[0].input_schema.is_none());
}

#[tokio::test]
async fn a_call_whose_future_is_dropped_stops_waiting() {
    let t = Arc::new(Tools::default());
    t.poll(
        &poll(0, vec![], Some(vec![tool("github.get_issue")])),
        SHORT,
    )
    .await;
    for _ in 0..MAX_PENDING + 5 {
        let call = t.call_within(
            "as_a",
            "github.get_issue",
            json!({}),
            Duration::from_secs(60),
        );
        // The caller gives up (a connection closed): dropped while waiting.
        let _ = tokio::time::timeout(Duration::from_millis(5), call).await;
    }
    let r = t
        .call_within(
            "as_a",
            "github.get_issue",
            json!({}),
            Duration::from_millis(30),
        )
        .await;
    assert_ne!(
        r.code.as_deref(),
        Some("rate_limited"),
        "dropped calls leaked slots"
    );
}

fn big(n: usize) -> serde_json::Value {
    json!({"repo": "o/r", "body": "x".repeat(n)})
}

/// The abort loop of the review: calls of ~380 KB whose caller goes away over and over, the Core
/// not taking them. Nothing stays held, and the Core is never handed a call nobody waits for.
#[tokio::test]
async fn abandoned_calls_leave_the_queue_and_are_never_sent() {
    let t = Arc::new(Tools::default());
    t.poll(
        &poll(0, vec![], Some(vec![tool("github.get_issue")])),
        SHORT,
    )
    .await;
    for _ in 0..200 {
        let call = t.call_within(
            "as_a",
            "github.get_issue",
            big(380_000),
            Duration::from_secs(60),
        );
        let _ = tokio::time::timeout(Duration::from_millis(2), call).await;
        assert_eq!(t.held("as_a"), (0, 0), "an abandoned call is still held");
    }
    let batch = t
        .poll(&poll(0, vec![], None), Duration::from_millis(50))
        .await;
    assert!(
        batch.calls.is_empty(),
        "the Core was sent an abandoned call"
    );
}

/// A call already numbered cannot be recalled (a gap would be refused), so what the abandoned ones
/// hold is bounded in calls and bytes, and given back when the Core acknowledges.
#[tokio::test]
async fn sent_but_abandoned_calls_are_capped_and_freed_by_the_acknowledgement() {
    let t = Arc::new(Tools::default());
    t.poll(
        &poll(0, vec![], Some(vec![tool("github.get_issue")])),
        SHORT,
    )
    .await;
    let mut busy = false;
    for i in 0..MAX_HELD_CALLS + 10 {
        let t2 = t.clone();
        let h = tokio::spawn(async move {
            t2.call_within(
                "as_a",
                "github.get_issue",
                json!({"repo": "o/r"}),
                Duration::from_secs(60),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        if h.is_finished() {
            assert_eq!(h.await.unwrap().code.as_deref(), Some("busy"), "call {i}");
            busy = true;
            break;
        }
        // The Core takes the call (it is numbered) and never acknowledges it; its caller leaves.
        t.poll(&poll(0, vec![], None), Duration::from_millis(5))
            .await;
        h.abort();
        let _ = h.await;
    }
    assert!(busy, "abandoned sent calls grew without a bound");
    assert_eq!(t.held("as_a").0, MAX_HELD_CALLS);
    t.poll(
        &poll(MAX_HELD_CALLS as u64, vec![], None),
        Duration::from_millis(5),
    )
    .await;
    assert_eq!(t.held("as_a"), (0, 0), "the acknowledgement frees them");
}

#[tokio::test]
async fn bytes_held_are_capped_per_session_and_across_the_runner_and_given_back_at_the_end() {
    let t = Arc::new(Tools::default());
    for s in ["as_a", "as_b"] {
        let p = ToolsPoll {
            session: s.to_owned(),
            ..poll(0, vec![], Some(vec![tool("github.get_issue")]))
        };
        t.poll(&p, SHORT).await;
    }
    // Calls that wait (their callers stay) fill the session's byte budget.
    let mut waiting = Vec::new();
    let mut refused = None;
    for _ in 0..8 {
        let t2 = t.clone();
        let h = tokio::spawn(async move {
            t2.call_within(
                "as_a",
                "github.get_issue",
                big(380_000),
                Duration::from_secs(30),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        if h.is_finished() {
            refused = Some(h.await.unwrap());
            break;
        }
        waiting.push(h);
    }
    assert_eq!(refused.expect("no refusal").code.as_deref(), Some("busy"));
    assert!(waiting.len() * 380_000 <= MAX_HELD_BYTES);
    // Another session has its own budget until the runner's total is spent.
    assert!(t.held("as_b").1 >= waiting.len() * 380_000);
    t.forget("as_a");
    assert_eq!(
        t.held("as_b").1,
        0,
        "forgetting a session gives its bytes back"
    );
    for h in waiting {
        assert_eq!(h.await.unwrap().code.as_deref(), Some("session_over"));
    }
}

/// The review's late poll: a poll in flight when the session ends must not make its state again
/// (every pass of its wait loop used to insert), and ends at once when the session is forgotten.
#[tokio::test]
async fn a_poll_in_flight_across_the_end_makes_no_state_and_ends_at_once() {
    let t = Arc::new(Tools::default());
    t.open("as_a");
    let p = ToolsPoll {
        wait_ms: Some(5000),
        ..poll(0, vec![], None)
    };
    let started = tokio::time::Instant::now();
    let h = {
        let t = t.clone();
        tokio::spawn(async move { t.poll_live(&p, Duration::from_secs(5)).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    t.forget("as_a");
    let batch = h.await.unwrap();
    assert!(batch.calls.is_empty());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the poll waited out its time"
    );
    assert!(
        !t.holds("as_a"),
        "a poll in flight brought the ended session's state back"
    );
    // A poll for a session that was never opened makes nothing either, after its wait.
    let p = ToolsPoll {
        session: "as_z".to_owned(),
        wait_ms: Some(100),
        ..poll(0, vec![], Some(vec![tool("github.get_issue")]))
    };
    t.poll_live(&p, Duration::from_secs(1)).await;
    assert!(!t.holds("as_z"));
    assert!(t.list("as_z").is_empty());
}
