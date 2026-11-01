//! Claude adapter tests against NDJSON recorded from `claude` 2.1.306 on 2026-10-21 (haiku,
//! the live test's scenario; temp paths scrubbed to `/tmp/citadel-fixture`).

use std::path::PathBuf;

use serde_json::{Value, json};

use super::*;

const APPROVE_INTERRUPT: &str =
    include_str!("../../tests/fixtures/claude/approve-interrupt.ndjson");
const RESUME: &str = include_str!("../../tests/fixtures/claude/resume.ndjson");
const SESSION: &str = "fe32e515-ac31-4946-95d6-ab54ab9bfeb2";

/// Decodes a fixture; `interrupt_after` turns marks the next turn as interrupted.
fn replay(fixture: &str, interrupt_after: Option<usize>) -> (Vec<HarnessEvent>, Decoder) {
    let mut decoder = Decoder::default();
    let mut events = vec![];
    for line in fixture.lines() {
        let message: Value = serde_json::from_str(line).unwrap();
        for event in decoder.decode(&message) {
            let ended = matches!(event, HarnessEvent::TurnEnded { .. });
            events.push(event);
            let turns = events
                .iter()
                .filter(|e| matches!(e, HarnessEvent::TurnEnded { .. }))
                .count();
            if ended && Some(turns) == interrupt_after {
                decoder.interrupting = true;
            }
        }
    }
    (events, decoder)
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

#[test]
fn decodes_a_turn_with_an_approval_then_an_interrupted_turn() {
    let (events, decoder) = replay(APPROVE_INTERRUPT, Some(1));
    // `system/init` comes at both turn starts; the session is announced once.
    let sessions: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, HarnessEvent::SessionStarted { .. }))
        .collect();
    assert_eq!(
        sessions,
        [&HarnessEvent::SessionStarted {
            id: SESSION.to_owned()
        }]
    );
    let approval = events
        .iter()
        .find_map(|e| match e {
            HarnessEvent::ApprovalRequested { id, tool, input } => Some((id, tool, input)),
            _ => None,
        })
        .expect("the write asked for approval");
    assert_eq!(approval.1, "Write");
    assert_eq!(approval.2["content"], "hi");
    assert_eq!(decoder.pending[approval.0], *approval.2);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, HarnessEvent::ToolUse { name, .. } if name == "Write"))
    );
    assert!(events.contains(&HarnessEvent::AssistantText {
        text: "done".to_owned()
    }));
    assert_eq!(
        turn_ends(&events),
        [&TurnOutcome::Success, &TurnOutcome::Interrupted]
    );
    assert_eq!(
        events.iter().find(|e| matches!(e, HarnessEvent::Usage(_))),
        Some(&HarnessEvent::Usage(Usage {
            input: 4,
            output: 207,
            cache_read: 32422,
            cache_write: 6411,
            cost_usd: Some(0.00171032),
        }))
    );
    assert_eq!(decoder.totals.output, 207);
    assert_eq!(decoder.totals.cost_usd, Some(0.00171032));
}

#[test]
fn an_error_turn_nobody_interrupted_is_a_failure() {
    let (events, _) = replay(APPROVE_INTERRUPT, None);
    let ends = turn_ends(&events);
    let TurnOutcome::Failed { code, reason } = ends[1] else {
        panic!("{ends:?}");
    };
    assert_eq!(code, "error_during_execution");
    assert!(!reason.is_empty());
}

#[test]
fn a_resumed_session_keeps_its_id_and_its_memory() {
    let (events, decoder) = replay(RESUME, None);
    assert_eq!(
        events[0],
        HarnessEvent::SessionStarted {
            id: SESSION.to_owned()
        }
    );
    assert!(events.contains(&HarnessEvent::AssistantText {
        text: "hello.txt".to_owned()
    }));
    assert_eq!(turn_ends(&events), [&TurnOutcome::Success]);
    // Cost is the session's, cumulative across the resume.
    assert_eq!(decoder.totals.cost_usd, Some(0.00198185));
}

#[test]
fn unknown_control_requests_are_refused_not_left_hanging() {
    let mut decoder = Decoder::default();
    let request = serde_json::json!({"type": "control_request", "request_id": "r1",
        "request": {"subtype": "hook_callback"}});
    assert_eq!(decoder.decode(&request), []);
    assert_eq!(decoder.replies[0]["response"]["subtype"], "error");
    assert_eq!(decoder.replies[0]["response"]["request_id"], "r1");
}

#[test]
fn session_ids_are_v4_uuids() {
    let id = new_session_id().unwrap();
    assert_eq!(id.len(), 36);
    assert_eq!(&id[14..15], "4");
    assert_ne!(id, new_session_id().unwrap());
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ainkrad-harness-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A fake `claude`: records its argv, env and first two stdin lines, then plays a fixture.
fn fake_claude(dir: &std::path::Path) -> PathBuf {
    let fixture = dir.join("fixture.ndjson");
    std::fs::write(&fixture, APPROVE_INTERRUPT).unwrap();
    let script = dir.join("claude");
    let d = dir.display();
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {d}/argv\nenv > {d}/env\n\
             head -n 2 > {d}/stdin\ncat {}\n",
            fixture.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    script
}

/// Through a real process: the prompt goes over stdin, never argv; the child sees only the
/// allowlist plus its own config dir; the events come out and the stream ends with `Exited`.
#[tokio::test]
async fn the_prompt_goes_by_stdin_and_the_config_stays_isolated() {
    let dir = scratch("isolation");
    let cwd = dir.join("work");
    std::fs::create_dir_all(&cwd).unwrap();
    let spec = Spec {
        program: Some(fake_claude(&dir)),
        cwd,
        process_dir: None,
        model: "haiku".to_owned(),
        instructions: Some(dir.join("instructions.md")),
        mcp_config: Some(dir.join("mcp.json")),
        config_dir: dir.join("config"),
        env_allow: vec!["PATH".to_owned()],
        env: vec![("GIT_CONFIG_GLOBAL".to_owned(), "/runner/git/config".into())],
        session_id: Some(SESSION.to_owned()),
        sandboxed: false,
        accept_edits: false,
        backend: None,
    };
    let prompt = "PROMPT-CANARY fix the flaky test";
    let mut claude = Claude::start(&spec).await.unwrap();
    claude.send(prompt).await.unwrap();
    let mut events = vec![];
    while let Some(event) = claude.next().await {
        events.push(event);
    }
    assert_eq!(events.last(), Some(&HarnessEvent::Exited { code: Some(0) }));
    assert!(events.contains(&HarnessEvent::SessionStarted {
        id: SESSION.to_owned()
    }));
    assert_eq!(claude.usage().output, 207);

    let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
    assert!(!argv.contains("CANARY"), "{argv}");
    assert_eq!(
        argv.lines().map(str::to_owned).collect::<Vec<_>>(),
        args(&spec, None)
    );
    for flag in ["--strict-mcp-config", "--permission-prompt-tool"] {
        assert!(argv.lines().any(|a| a == flag), "{flag} missing");
    }
    assert!(argv.contains("--setting-sources\nlocal\n"));
    assert!(argv.contains("--allowedTools\nmcp__citadel\n"), "{argv}");
    assert!(!argv.contains("--bare"));
    let stdin = std::fs::read_to_string(dir.join("stdin")).unwrap();
    assert!(stdin.contains("PROMPT-CANARY"), "{stdin}");

    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    let config = format!("CLAUDE_CONFIG_DIR={}", spec.config_dir.display());
    assert!(env.lines().any(|l| l == config), "{env}");
    assert!(
        env.contains("GIT_CONFIG_GLOBAL=/runner/git/config\n"),
        "{env}"
    );
    for line in env.lines() {
        let name = line.split('=').next().unwrap();
        // `sh` adds PWD, SHLVL and `_` itself.
        assert!(
            [
                "PATH",
                "CLAUDE_CONFIG_DIR",
                "GIT_CONFIG_GLOBAL",
                "PWD",
                "SHLVL",
                "_",
                "OLDPWD"
            ]
            .contains(&name),
            "leaked {name}"
        );
        assert!(
            !line.contains("/.claude"),
            "points at a user config: {line}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn every_run_hides_claude_codes_commit_and_pr_attribution() {
    let argv = args(&Spec::default(), None);
    let at = argv
        .iter()
        .position(|a| a == "--settings")
        .expect("--settings");
    let settings: Value = serde_json::from_str(&argv[at + 1]).unwrap();
    assert_eq!(settings["attribution"]["commit"], "");
    assert_eq!(settings["attribution"]["pr"], "");
}

#[test]
fn resume_replaces_the_new_session_id() {
    let spec = Spec {
        session_id: Some("new".to_owned()),
        ..Spec::default()
    };
    let argv = args(&spec, Some("old")).join(" ");
    assert!(argv.ends_with("--resume old"), "{argv}");
    assert!(!argv.contains("--session-id"));
}

/// E3.8: the meter sees each turn's tokens from its assistant messages before the turn ends.
/// The interrupted turn reports zero, so the meter counts what its messages showed: more
/// than the adapter's totals, by that message's use.
#[test]
fn the_meter_counts_mid_turn_and_keeps_an_interrupted_turn() {
    let (events, decoder) = replay(APPROVE_INTERRUPT, Some(1));
    let mut meter = crate::Meter::default();
    let mut mid_turn = false;
    for e in &events {
        mid_turn |= meter.see(e) && matches!(e, HarnessEvent::UsageSoFar(_));
    }
    assert!(mid_turn);
    // The interrupted turn's one message: 2 in, 7 out, 19574 cache read, 49 cache write.
    let seen = crate::tokens(&meter.total());
    assert_eq!(seen, crate::tokens(&decoder.totals) + 2 + 7 + 19574 + 49);
    let (events, decoder) = replay(RESUME, None);
    let mut meter = crate::Meter::default();
    for e in &events {
        meter.see(e);
    }
    assert_eq!(
        crate::tokens(&meter.total()),
        crate::tokens(&decoder.totals)
    );
}

/// E3.10: Claude's own permission mode accepts edits only when the policy does.
#[test]
fn the_permission_mode_follows_the_spec() {
    let mode = |spec: &Spec| {
        let args = args(spec, None);
        let at = args.iter().position(|a| a == "--permission-mode").unwrap();
        args[at + 1].clone()
    };
    assert_eq!(mode(&Spec::default()), "default");
    let edits = Spec {
        accept_edits: true,
        ..Spec::default()
    };
    assert_eq!(mode(&edits), "acceptEdits");
}

/// The recorded `rate_limit_event` (E15.2): both plan windows, their use and reset times.
#[test]
fn rate_limit_events_carry_the_plan_windows() {
    let (events, _) = replay(APPROVE_INTERRUPT, Some(1));
    let limit = events
        .iter()
        .find(|e| matches!(e, HarnessEvent::RateLimit { .. }))
        .expect("the fixture has one");
    let HarnessEvent::RateLimit { status, windows } = limit else {
        unreachable!();
    };
    assert_eq!(status, "allowed");
    let mut windows = windows.clone();
    windows.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(
        windows,
        [
            RateWindow {
                name: "five_hour".to_owned(),
                utilization: 0.13,
                resets_at: Some(1792608000),
            },
            RateWindow {
                name: "seven_day".to_owned(),
                utilization: 0.5,
                resets_at: Some(1792922400),
            },
        ]
    );
    let wire = serde_json::to_value(limit).unwrap();
    assert_eq!(wire["type"], "rate_limit");
    assert!(wire["windows"][0]["utilization"].as_f64().is_some());
}

/// An API refusal keeps its HTTP status in the code, for `classify` (E15.3).
#[test]
fn an_api_refusal_carries_its_status() {
    let mut decoder = Decoder::default();
    let refused = serde_json::json!({"type": "result", "subtype": "success", "is_error": true,
        "api_error_status": 429, "result": "API Error: 429 rate_limit_error", "usage": {}});
    let events = decoder.decode(&refused);
    let ends = turn_ends(&events);
    let TurnOutcome::Failed { code, reason } = ends[0] else {
        panic!("{ends:?}");
    };
    assert_eq!(code, "success:429");
    assert_eq!(
        crate::classify(code, reason),
        crate::ErrorClass::RateLimited
    );
}

/// Every tool call's end is a `ToolResult` (1.18): the recorded write worked; a failed Bash
/// call carries its exit code from the error text.
#[test]
fn tool_results_follow_their_calls() {
    let (events, _) = replay(APPROVE_INTERRUPT, None);
    let used = events
        .iter()
        .position(|e| matches!(e, HarnessEvent::ToolUse { .. }));
    let ended = events.iter().position(|e| {
        matches!(e, HarnessEvent::ToolResult { id, ok: true, exit_code: None, output }
            if id == "toolu_01DRcgYncTTz8ViwJoUqMnza" && output.starts_with("File created"))
    });
    assert!(
        used.unwrap() < ended.expect("the write's result"),
        "{events:?}"
    );

    let failed = serde_json::json!({"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t1", "is_error": true,
         "content": [{"type": "text", "text": "Error: Exit code 2\nno such file"}]}]}});
    assert_eq!(
        Decoder::default().decode(&failed),
        [HarnessEvent::ToolResult {
            id: "t1".to_owned(),
            ok: false,
            exit_code: Some(2),
            output: "Error: Exit code 2\nno such file".to_owned(),
        }]
    );
    let prompt = serde_json::json!({"type": "user", "message": {"role": "user", "content": "hi"}});
    assert!(
        Decoder::default().decode(&prompt).is_empty(),
        "a prompt is no result"
    );
}

/// A newer Claude's additions (message types, content blocks, fields) are ignored: the
/// recorded turns decode to the same events.
#[test]
fn ignores_unknown_messages_and_fields() {
    let unknown = [
        json!({"type": "future_event", "data": {"x": 1}}),
        json!({"type": "system", "subtype": "future_subtype", "session_id": "other"}),
        json!({"type": "assistant", "message": {"content": [{"type": "future_block", "x": 1}]}}),
        json!({"type": "user", "message": {"content": [{"type": "future_block"}]}}),
    ];
    for fixture in [APPROVE_INTERRUPT, RESUME] {
        let newer = crate::newer_cli(fixture, &unknown);
        let (want, _) = replay(fixture, Some(1));
        let (got, decoder) = replay(&newer, Some(1));
        assert_eq!(got, want);
        assert!(decoder.replies.is_empty() && decoder.refused.is_none());
    }
}

/// An unknown control request is refused; when the process then ends without a result the
/// turn fails as `protocol`, readable; a result in between clears it.
#[test]
fn an_unknown_control_request_then_an_exit_is_a_protocol_failure() {
    let mut decoder = Decoder::default();
    let ask = json!({"type": "control_request", "request_id": "r1",
        "request": {"subtype": "future_hook", "x": 1}});
    assert_eq!(decoder.decode(&ask), []);
    assert_eq!(decoder.replies[0]["response"]["subtype"], "error");
    let Some(HarnessEvent::TurnEnded {
        outcome: TurnOutcome::Failed { reason, code },
    }) = decoder.ended_early()
    else {
        panic!("a protocol failure");
    };
    assert_eq!(code, crate::PROTOCOL);
    assert_eq!(
        reason,
        "exited after an unrecognised control request (future_hook)"
    );
    assert_eq!(crate::classify(&code, &reason), crate::ErrorClass::Protocol);
    assert_eq!(decoder.ended_early(), None, "reported once");

    decoder.decode(&ask);
    decoder.decode(&json!({"type": "result", "subtype": "success", "is_error": false}));
    assert_eq!(decoder.ended_early(), None, "a finished turn clears it");
}
