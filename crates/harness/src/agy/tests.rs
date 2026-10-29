//! agy adapter tests against NDJSON recorded from `agy` 1.4.4 on 2026-10-21 (the live test's
//! scenario, `gemini-3.8-flash-low`; temp paths scrubbed to `/tmp/citadel-fixture`). The
//! recording ran logged in as the user through a wrapper, since the runner's private home had
//! no login.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::*;

const SANDBOXED_INTERRUPT: &str =
    include_str!("../../tests/fixtures/agy/sandboxed-interrupt.ndjson");
const RESUME: &str = include_str!("../../tests/fixtures/agy/resume.ndjson");
const CONVERSATION: &str = "aac72386-e52e-4b4f-b486-f1a71f8cfb58";

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

fn tokens(input: u64, output: u64) -> Usage {
    Usage {
        input,
        output,
        ..Usage::default()
    }
}

#[test]
fn decodes_a_turn_then_an_interrupted_one() {
    let mut decoder = Decoder::default();
    let events = replay(SANDBOXED_INTERRUPT, &mut decoder);
    assert_eq!(
        events[0],
        HarnessEvent::SessionStarted {
            id: CONVERSATION.to_owned()
        }
    );
    // Tool steps update twice (ACTIVE, DONE); announced once. 1.4.4 names it `write_file`.
    let tools: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, HarnessEvent::ToolUse { .. }))
        .collect();
    assert!(
        matches!(tools[..], [HarnessEvent::ToolUse { name, input, .. }]
            if name == "write_file" && input["Path"] == "/tmp/citadel-fixture/hello.txt"),
        "{tools:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, HarnessEvent::ApprovalRequested { .. })),
        "agy never asks"
    );
    // Streamed deltas come out as one text per step.
    assert!(events.contains(&HarnessEvent::AssistantText {
        text: "done".to_owned()
    }));
    assert_eq!(
        turn_ends(&events),
        [&TurnOutcome::Success, &TurnOutcome::Interrupted]
    );
    // Interrupted before the model answered: nothing more spent.
    assert_eq!(usages(&events), [tokens(19318, 75), tokens(0, 0)]);
    assert_eq!(decoder.totals.cost_usd, None, "agy reports no cost");
}

#[test]
fn a_resumed_conversation_counts_its_own_steps_not_the_old_total() {
    let mut decoder = Decoder {
        resumed: true,
        ..Decoder::default()
    };
    let events = replay(RESUME, &mut decoder);
    assert_eq!(
        events[0],
        HarnessEvent::SessionStarted {
            id: CONVERSATION.to_owned()
        }
    );
    assert!(events.contains(&HarnessEvent::AssistantText {
        text: "hello.txt".to_owned()
    }));
    assert_eq!(turn_ends(&events), [&TurnOutcome::Success]);
    // `result.usage` says 29357: the whole conversation. This turn's step was 10039.
    assert_eq!(usages(&events), [tokens(10039, 3)]);
}

/// From the E0.3 run (1.4.2): an interrupt mid-answer spends tokens no step reports; the
/// cumulative total does.
#[test]
fn an_interrupted_turn_counts_what_it_spent() {
    let mut decoder = Decoder::default();
    let result = |status: &str, error: Option<&str>, input: u64| {
        json!({"event": "result", "result": {"status": status, "error": error,
            "usage": {"input_tokens": input, "output_tokens": 80, "thinking_tokens": 2}}})
    };
    decoder.decode(&result("SUCCESS", None, 17777));
    let events = decoder.decode(&result("ERROR", Some("interrupted"), 26829));
    assert_eq!(
        events,
        [
            HarnessEvent::Usage(tokens(26829 - 17777, 0)),
            HarnessEvent::TurnEnded {
                outcome: TurnOutcome::Interrupted
            }
        ]
    );
    // Recorded with a fresh, logged-out home.
    let failed = json!({"event": "result", "result": {"conversation_id": "", "status": "ERROR",
        "error": "authentication failed or timed out", "usage": {}}});
    assert_eq!(
        turn_ends(&decoder.decode(&failed)),
        [&TurnOutcome::Failed {
            reason: "authentication failed or timed out".to_owned(),
            code: "error".to_owned()
        }]
    );
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("citadel-agy-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A fake `agy`: records argv, env and its first stdin line, plays the fixture's first turn,
/// then waits; SIGINT ends it the way agy does. Perl catches it, not a shell `trap`: a shell
/// started with SIGINT ignored (a background job's) cannot trap it, and agy can.
fn fake_agy(dir: &Path) -> PathBuf {
    let first_turn: String = SANDBOXED_INTERRUPT
        .lines()
        .take_while(|l| !l.contains(r#""event":"result""#))
        .chain(
            SANDBOXED_INTERRUPT
                .lines()
                .filter(|l| l.contains("SUCCESS")),
        )
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(dir.join("fixture.ndjson"), first_turn).unwrap();
    let script = dir.join("agy");
    let d = dir.display();
    let interrupted = r#"{"event":"result","result":{"status":"ERROR","error":"interrupted","usage":{"input_tokens":19400,"output_tokens":75}}}"#;
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {d}/argv\nenv > {d}/env\n\
             head -n 1 > {d}/stdin\n\
             exec perl -e '$| = 1; $SIG{{INT}} = sub {{ print qq({interrupted}\\n); exit 1 }}; \
             print `cat {d}/fixture.ndjson`; sleep 30'\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    script
}

fn spec(dir: &Path) -> Spec {
    let cwd = dir.join("work");
    std::fs::create_dir_all(&cwd).unwrap();
    Spec {
        program: Some(fake_agy(dir)),
        cwd,
        model: "gemini-3.8-flash-low".to_owned(),
        config_dir: dir.join("agy-home"),
        env_allow: vec!["PATH".to_owned(), "HOME".to_owned()],
        sandboxed: true,
        ..Spec::default()
    }
}

/// Through a real process: the prompt goes over stdin, never argv; `HOME` is the runner's
/// private home holding the runner's settings; SIGINT ends the turn and the process.
#[tokio::test]
async fn sandboxed_with_its_own_settings_and_interrupted_by_signal() {
    let dir = scratch("isolation");
    let spec = spec(&dir);
    let mut agy = Agy::start(&spec).await.unwrap();
    agy.send("PROMPT-CANARY fix the flaky test").await.unwrap();
    let mut events = vec![];
    while !events.contains(&HarnessEvent::TurnEnded {
        outcome: TurnOutcome::Success,
    }) {
        events.push(agy.next().await.unwrap());
    }
    agy.interrupt().await.unwrap();
    let mut rest = vec![];
    while let Some(event) = agy.next().await {
        rest.push(event);
    }
    assert_eq!(
        rest,
        [
            HarnessEvent::Usage(tokens(19400 - 19318, 0)),
            HarnessEvent::TurnEnded {
                outcome: TurnOutcome::Interrupted
            },
            HarnessEvent::Exited { code: Some(1) }
        ]
    );
    assert!(
        agy.approve("1", Decision::Allow).await.is_err(),
        "nothing to approve"
    );

    let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
    assert!(!argv.contains("CANARY"), "{argv}");
    assert_eq!(
        argv.lines().map(str::to_owned).collect::<Vec<_>>(),
        args(&spec, None)
    );
    assert!(argv.contains("--sandbox\n--mode\naccept-edits\n"), "{argv}");
    assert!(argv.ends_with("-p=\n"), "-p= must be last: {argv}");
    assert!(!argv.contains("dangerously"));
    let stdin = std::fs::read_to_string(dir.join("stdin")).unwrap();
    assert!(stdin.contains("PROMPT-CANARY"), "{stdin}");

    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    let home = format!("HOME={}", spec.config_dir.display());
    assert!(
        env.lines().any(|l| l == home),
        "the allowlisted HOME is replaced: {env}"
    );
    for line in env.lines() {
        let name = line.split('=').next().unwrap();
        // `sh` adds PWD, SHLVL and `_` itself.
        assert!(
            ["PATH", "HOME", "PWD", "SHLVL", "_", "OLDPWD"].contains(&name),
            "leaked {name}"
        );
    }
    let settings = spec
        .config_dir
        .join(".gemini/antigravity-cli/settings.json");
    assert_eq!(std::fs::read_to_string(settings).unwrap(), SETTINGS);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn refuses_to_start_unless_sandboxed() {
    let dir = scratch("unsandboxed");
    let spec = Spec {
        sandboxed: false,
        ..spec(&dir)
    };
    let error = Agy::start(&spec).await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(!dir.join("argv").exists(), "never spawned");
    assert!(!spec.config_dir.exists(), "no settings written");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resume_continues_the_conversation() {
    let argv = args(&Spec::default(), Some("c-1")).join(" ");
    assert!(argv.ends_with("--conversation c-1 -p="), "{argv}");
}

/// E3.8: the meter, fed this harness's events, sees tokens before each turn ends and counts
/// what the adapter counts.
#[test]
fn the_meter_counts_mid_turn_and_matches_the_totals() {
    for fixture in [SANDBOXED_INTERRUPT, RESUME] {
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

/// E4.2: the MCP and instructions files are linked into agy's home, and a later run without
/// them leaves no stale link behind.
#[test]
fn links_the_mcp_config_and_instructions_into_its_home() {
    let dir = std::env::temp_dir().join(format!("citadel-agy-links-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mcp, notes) = (dir.join("mcp.json"), dir.join("instructions.md"));
    std::fs::write(&mcp, mcp_config("http://h/mcp/v1", "t").to_string()).unwrap();
    std::fs::write(&notes, "# Skill").unwrap();
    let mut spec = Spec {
        config_dir: dir.join("home"),
        mcp_config: Some(mcp.clone()),
        instructions: Some(notes),
        ..Spec::default()
    };
    link_files(&spec).unwrap();
    let linked = dir.join("home/.gemini/config/mcp_config.json");
    assert_eq!(std::fs::read_link(&linked).unwrap(), mcp);
    let config: Value = serde_json::from_str(&std::fs::read_to_string(&linked).unwrap()).unwrap();
    assert_eq!(
        config["mcpServers"]["citadel"]["serverUrl"],
        "http://h/mcp/v1"
    );
    let gemini_md = dir.join("home/.gemini/GEMINI.md");
    assert_eq!(std::fs::read_to_string(&gemini_md).unwrap(), "# Skill");

    spec.mcp_config = None;
    spec.instructions = None;
    link_files(&spec).unwrap();
    assert!(
        std::fs::symlink_metadata(&linked).is_err(),
        "stale link removed"
    );
    assert!(std::fs::symlink_metadata(&gemini_md).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A tool step's end is a `ToolResult` (1.18), without output: agy reports none.
#[test]
fn tool_results_follow_their_steps() {
    let events = replay(SANDBOXED_INTERRUPT, &mut Decoder::default());
    assert!(events.contains(&HarnessEvent::ToolResult {
        id: "2".to_owned(),
        ok: true,
        exit_code: None,
        output: String::new(),
    }));
}

/// A newer agy's additions (events, step types, fields) are ignored: the recorded turns
/// decode to the same events.
#[test]
fn ignores_unknown_events_and_fields() {
    let unknown = [
        json!({"event": "future_event", "future_event": {"x": 1}}),
        json!({"event": "step_update", "step_update": {"step_type": "future_step",
            "step_index": 999, "state": "DONE"}}),
    ];
    for fixture in [SANDBOXED_INTERRUPT, RESUME] {
        let newer = crate::newer_cli(fixture, &unknown);
        let want = replay(fixture, &mut Decoder::default());
        assert_eq!(replay(&newer, &mut Decoder::default()), want);
    }
}
