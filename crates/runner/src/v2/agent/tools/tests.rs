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
