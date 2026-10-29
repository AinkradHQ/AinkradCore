//! Codex adapter tests against NDJSON recorded from `codex-cli` 0.154.0 on 2026-10-21 (the E0.3
//! spike run of this scenario, `gpt-5.6-luna`; temp paths scrubbed to `/tmp/citadel-fixture`,
//! the home dir to `/Users/user`, host and installation ids blanked).

use std::path::PathBuf;

use serde_json::{Value, json};

use super::*;

const APPROVE_INTERRUPT: &str = include_str!("../../tests/fixtures/codex/approve-interrupt.ndjson");
const RESUME: &str = include_str!("../../tests/fixtures/codex/resume.ndjson");
const THREAD: &str = "01a15de7-a588-7043-b035-fd057868af05";

fn replay(fixture: &str, decoder: &mut Decoder) -> Vec<HarnessEvent> {
    fixture
        .lines()
        .flat_map(|line| decoder.decode(&serde_json::from_str::<Value>(line).unwrap()))
        .collect()
}

fn turn_ends(events: &[HarnessEvent]) -> Vec<&TurnOutcome> {
    events
        .iter()
        .filter_map(|e| match e {
            HarnessEvent::TurnEnded { outcome } => Some(outcome),
            _ => None,
        })
        .collect()
}

fn usages(events: &[HarnessEvent]) -> Vec<Usage> {
    events
        .iter()
        .filter_map(|e| match e {
            HarnessEvent::Usage(u) => Some(*u),
            _ => None,
        })
        .collect()
}

#[test]
fn decodes_a_turn_with_an_approval_then_an_interrupted_turn() {
    let mut decoder = Decoder::default();
    let events = replay(APPROVE_INTERRUPT, &mut decoder);
    let (id, tool, input) = events
        .iter()
        .find_map(|e| match e {
            HarnessEvent::ApprovalRequested { id, tool, input } => Some((id, tool, input)),
            _ => None,
        })
        .expect("the write asked for approval");
    assert_eq!(tool, "fileChange");
    // The approval names only the item; the adapter hands over the item with its paths.
    assert_eq!(
        input["changes"][0]["path"],
        "/tmp/citadel-fixture/hello.txt"
    );
    // The JSON-RPC id was the number 0, and goes back as a number.
    assert_eq!(decoder.pending[id], json!(0));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, HarnessEvent::ToolUse { name, .. } if name == "fileChange"))
    );
    assert!(events.contains(&HarnessEvent::AssistantText {
        text: "done".to_owned()
    }));
    assert_eq!(
        turn_ends(&events),
        [&TurnOutcome::Success, &TurnOutcome::Interrupted]
    );
    let first = Usage {
        input: 32047 - 21888,
        output: 78,
        cache_read: 21888,
        cache_write: 0,
        cost_usd: None,
    };
    // The interrupted turn reported nothing new: zero, not the first turn again.
    assert_eq!(usages(&events), [first, Usage::default()]);
    assert_eq!(decoder.totals, first);
    assert_eq!(decoder.turn, None);
}

#[test]
fn a_resumed_thread_counts_only_its_own_turn() {
    let mut decoder = Decoder::default();
    let events = replay(RESUME, &mut decoder);
    assert!(events.contains(&HarnessEvent::AssistantText {
        text: "hello.txt".to_owned()
    }));
    assert_eq!(turn_ends(&events), [&TurnOutcome::Success]);
    // Codex replays the thread's old totals on resume; they are the baseline, not this turn.
    let turn = Usage {
        input: (54650 - 41216) - (32047 - 21888),
        output: 84 - 78,
        cache_read: 41216 - 21888,
        cache_write: 0,
        cost_usd: None,
    };
    assert_eq!(usages(&events), [turn]);
    assert_eq!(decoder.totals.cost_usd, None, "codex reports no cost");
}

#[test]
fn unserved_server_requests_are_refused_not_left_hanging() {
    let mut decoder = Decoder::default();
    for method in [
        "item/tool/requestUserInput",
        "item/permissions/requestApproval",
    ] {
        let request = json!({"id": 7, "method": method, "params": {}});
        assert_eq!(decoder.decode(&request), []);
    }
    assert_eq!(decoder.replies.len(), 2);
    assert_eq!(decoder.replies[0]["id"], 7);
    assert_eq!(decoder.replies[0]["error"]["code"], -32601);
    assert!(decoder.pending.is_empty());
}

#[test]
fn failed_and_refused_turns_are_failures_with_a_code() {
    let mut decoder = Decoder::default();
    let failed = json!({"method": "turn/completed", "params": {"turn": {"id": "t",
        "status": "failed", "error": {"message": "usage limit reached",
        "codexErrorInfo": "usageLimitExceeded"}}}});
    assert_eq!(
        turn_ends(&decoder.decode(&failed)),
        [&TurnOutcome::Failed {
            reason: "usage limit reached".to_owned(),
            code: "usageLimitExceeded".to_owned()
        }]
    );
    decoder.turn_starts.push(9);
    let refused = json!({"id": 9, "error": {"code": -32600, "message": "bad model"}});
    assert_eq!(
        decoder.decode(&refused),
        [HarnessEvent::TurnEnded {
            outcome: TurnOutcome::Failed {
                reason: "bad model".to_owned(),
                code: "turn_start".to_owned()
            }
        }]
    );
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("citadel-codex-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A fake `codex`: records its argv and env, plays a fixture, then records its first four
/// stdin lines (initialize, initialized, thread/start, turn/start).
fn fake_codex(dir: &std::path::Path, fixture: &str) -> PathBuf {
    std::fs::write(dir.join("fixture.ndjson"), fixture).unwrap();
    let script = dir.join("codex");
    let d = dir.display();
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {d}/argv\nenv > {d}/env\n\
             cat {d}/fixture.ndjson\nhead -n 4 > {d}/stdin\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    script
}

/// Through a real process: argv is `app-server` only; the prompt and the instructions go over
/// stdin; the child sees only the allowlist plus its own `CODEX_HOME`.
#[tokio::test]
async fn the_prompt_goes_by_stdin_and_the_config_stays_isolated() {
    let dir = scratch("isolation");
    let cwd = dir.join("work");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::write(dir.join("instructions.md"), "INSTRUCTIONS-CANARY").unwrap();
    let spec = Spec {
        program: Some(fake_codex(&dir, APPROVE_INTERRUPT)),
        cwd,
        model: "gpt-5.6-luna".to_owned(),
        instructions: Some(dir.join("instructions.md")),
        config_dir: dir.join("codex-home"),
        env_allow: vec!["PATH".to_owned()],
        ..Spec::default()
    };
    let mut codex = Codex::start(&spec).await.unwrap();
    codex
        .send("PROMPT-CANARY fix the flaky test")
        .await
        .unwrap();
    let mut events = vec![];
    while let Some(event) = codex.next().await {
        events.push(event);
    }
    assert_eq!(
        events.first(),
        Some(&HarnessEvent::SessionStarted {
            id: THREAD.to_owned()
        })
    );
    assert_eq!(events.last(), Some(&HarnessEvent::Exited { code: Some(0) }));
    assert_eq!(codex.usage().output, 78);

    let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
    assert_eq!(argv, "app-server\n");
    let stdin = std::fs::read_to_string(dir.join("stdin")).unwrap();
    let lines: Vec<Value> = stdin
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let methods: Vec<_> = lines
        .iter()
        .map(|l| l["method"].as_str().unwrap())
        .collect();
    assert_eq!(
        methods,
        ["initialize", "initialized", "thread/start", "turn/start"]
    );
    assert_eq!(
        lines[2]["params"]["developerInstructions"],
        "INSTRUCTIONS-CANARY"
    );
    assert_eq!(lines[2]["params"]["approvalPolicy"], "untrusted");
    assert_eq!(lines[2]["params"]["approvalsReviewer"], "user");
    assert_eq!(lines[3]["params"]["threadId"], THREAD);
    assert!(stdin.contains("PROMPT-CANARY"));

    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    let home = format!("CODEX_HOME={}", spec.config_dir.display());
    assert!(env.lines().any(|l| l == home), "{env}");
    for line in env.lines() {
        let name = line.split('=').next().unwrap();
        // `sh` adds PWD, SHLVL and `_` itself.
        assert!(
            ["PATH", "CODEX_HOME", "PWD", "SHLVL", "_", "OLDPWD"].contains(&name),
            "leaked {name}"
        );
        assert!(!line.contains("/.codex"), "points at a user config: {line}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resume_names_the_thread_and_skips_the_history() {
    let params = thread_params(&Spec::default(), Some("t-1")).unwrap();
    assert_eq!(params["threadId"], "t-1");
    assert_eq!(params["excludeTurns"], true);
    assert!(thread_params(&Spec::default(), None).unwrap()["threadId"].is_null());
    let mcp = Spec {
        mcp_config: Some("mcp.json".into()),
        ..Spec::default()
    };
    assert!(thread_params(&mcp, None).is_err(), "never silently dropped");
}

/// E3.8: the meter, fed this harness's events, sees tokens before each turn ends and counts
/// what the adapter counts.
#[test]
fn the_meter_counts_mid_turn_and_matches_the_totals() {
    for fixture in [APPROVE_INTERRUPT, RESUME] {
        let mut decoder = Decoder::default();
        let events = replay(fixture, &mut decoder);
        let mut meter = crate::Meter::default();
        let mut mid_turn = false;
        for e in &events {
            mid_turn |= meter.see(e) && matches!(e, HarnessEvent::UsageSoFar(_));
        }
        assert!(mid_turn, "no usage before the turn ended");
        assert_eq!(meter.total().input, decoder.totals.input);
        assert_eq!(
            crate::tokens(&meter.total()),
            crate::tokens(&decoder.totals)
        );
    }
}

/// E3.10: a sandboxed run acts without asking; any other asks.
#[test]
fn only_a_sandboxed_run_skips_approvals() {
    let asks = thread_params(&Spec::default(), None).unwrap();
    assert_eq!(asks["approvalPolicy"], "untrusted");
    let sandboxed = Spec {
        sandboxed: true,
        ..Spec::default()
    };
    let never = thread_params(&sandboxed, None).unwrap();
    assert_eq!(never["approvalPolicy"], "never");
    assert_eq!(never["sandbox"], "workspace-write");
}

/// E3.10: `decline` has no reason, so the reason follows as a `turn/steer` of the turn.
#[tokio::test]
async fn a_denial_steers_its_reason_into_the_turn() {
    let dir = scratch("steer");
    let script = fake_codex(&dir, APPROVE_INTERRUPT);
    let body = std::fs::read_to_string(&script).unwrap();
    std::fs::write(&script, body.replace("head -n 4", "head -n 6")).unwrap();
    let spec = Spec {
        program: Some(script),
        cwd: dir.clone(),
        model: "gpt-5.6-luna".to_owned(),
        config_dir: dir.join("codex-home"),
        env_allow: vec!["PATH".to_owned()],
        ..Spec::default()
    };
    let mut codex = Codex::start(&spec).await.unwrap();
    codex.send("go").await.unwrap();
    let id = loop {
        if let Some(HarnessEvent::ApprovalRequested { id, .. }) = codex.next().await {
            break id;
        }
    };
    let deny = Decision::Deny {
        reason: "writes outside the worktree need a reviewer".to_owned(),
    };
    codex.approve(&id, deny).await.unwrap();
    while codex.next().await.is_some() {}
    let stdin = std::fs::read_to_string(dir.join("stdin")).unwrap();
    let lines: Vec<Value> = stdin
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines[4]["result"]["decision"], "decline");
    let steer = &lines[5];
    assert_eq!(steer["method"], "turn/steer");
    assert_eq!(steer["params"]["threadId"], THREAD);
    assert!(steer["params"]["expectedTurnId"].is_string(), "{steer}");
    let text = steer["params"]["input"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("writes outside the worktree need a reviewer"),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// E4.2: the MCP file becomes the thread's `config.mcp_servers`, sent over stdin.
#[test]
fn the_mcp_config_goes_in_the_thread_config() {
    let dir = std::env::temp_dir().join(format!("citadel-codex-mcp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("mcp.json");
    let servers = mcp_config("http://127.0.0.1:7700/mcp/v1", "cit_run_x");
    std::fs::write(&file, servers.to_string()).unwrap();
    let spec = Spec {
        mcp_config: Some(file),
        ..Spec::default()
    };
    let params = thread_params(&spec, None).unwrap();
    let citadel = &params["config"]["mcp_servers"]["citadel"];
    assert_eq!(citadel["url"], "http://127.0.0.1:7700/mcp/v1");
    assert_eq!(citadel["http_headers"]["Authorization"], "Bearer cit_run_x");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A completed tool item is a `ToolResult` (1.18); a command's exit code and output come with
/// it, and a non-zero exit is a failure.
#[test]
fn tool_results_follow_their_items() {
    let events = replay(APPROVE_INTERRUPT, &mut Decoder::default());
    let id = "exec-60401db6-dc76-4b61-977d-31285c5e1615";
    assert!(events.contains(&HarnessEvent::ToolResult {
        id: id.to_owned(),
        ok: true,
        exit_code: None,
        output: "/tmp/citadel-fixture/hello.txt".to_owned(),
    }));
    let failed = serde_json::json!({"method": "item/completed", "params": {"item": {
        "type": "commandExecution", "id": "c1", "status": "failed", "exitCode": 101,
        "aggregatedOutput": "error[E0308]"}}});
    assert_eq!(
        Decoder::default().decode(&failed),
        [HarnessEvent::ToolResult {
            id: "c1".to_owned(),
            ok: false,
            exit_code: Some(101),
            output: "error[E0308]".to_owned(),
        }]
    );
}

/// A newer Codex's additions (notifications, item types, fields, stray responses) are
/// ignored: the recorded turns decode to the same events.
#[test]
fn ignores_unknown_notifications_and_fields() {
    let unknown = [
        json!({"jsonrpc": "2.0", "method": "future/notification", "params": {"x": 1}}),
        json!({"jsonrpc": "2.0", "method": "item/started",
            "params": {"item": {"type": "futureItem", "id": "f1"}}}),
        json!({"jsonrpc": "2.0", "method": "item/completed",
            "params": {"item": {"type": "futureItem", "id": "f1"}}}),
        json!({"jsonrpc": "2.0", "id": 9999, "result": {"future": true}}),
    ];
    for fixture in [APPROVE_INTERRUPT, RESUME] {
        let newer = crate::newer_cli(fixture, &unknown);
        let want = replay(fixture, &mut Decoder::default());
        let mut decoder = Decoder::default();
        assert_eq!(replay(&newer, &mut decoder), want);
        assert!(decoder.refused.is_none());
    }
}

/// An unserved request is refused; when the process then ends mid-turn the turn fails as
/// `protocol`; a completed turn in between clears it.
#[test]
fn an_unserved_request_then_an_exit_is_a_protocol_failure() {
    let mut decoder = Decoder::default();
    let ask = json!({"jsonrpc": "2.0", "id": 7, "method": "future/request", "params": {}});
    assert_eq!(decoder.decode(&ask), []);
    assert_eq!(decoder.replies[0]["error"]["code"], -32601);
    let Some(HarnessEvent::TurnEnded {
        outcome: TurnOutcome::Failed { reason, code },
    }) = decoder.ended_early()
    else {
        panic!("a protocol failure");
    };
    assert_eq!(
        (code.as_str(), reason.as_str()),
        (
            crate::PROTOCOL,
            "exited after Citadel refused its request future/request"
        )
    );
    decoder.decode(&ask);
    let done = json!({"jsonrpc": "2.0", "method": "turn/completed",
        "params": {"turn": {"id": "t", "status": "completed"}}});
    decoder.decode(&done);
    assert_eq!(decoder.ended_early(), None);
}
