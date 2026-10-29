//! OpenCode adapter tests against SSE events recorded from `opencode` 1.18.34 on 2026-10-21 (the
//! live test's scenario, `opencode/nemotron-3.5-lightning-free`, through a wrapper that tapped
//! `/event`; temp paths scrubbed to `/tmp/citadel-fixture`, global plugin/catalog noise
//! dropped).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

const APPROVE_INTERRUPT: &str =
    include_str!("../../tests/fixtures/opencode/approve-interrupt.ndjson");
const RESUME: &str = include_str!("../../tests/fixtures/opencode/resume.ndjson");
const SESSION: &str = "ses_ea123926cffexkivT8skS14mxL";

fn replay(fixture: &str, decoder: &mut Decoder) -> Vec<HarnessEvent> {
    decoder.session = SESSION.to_owned();
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
    assert_eq!(id, "per_15edc86e50015P4CxalPkHziEy");
    assert_eq!(tool, "edit");
    assert_eq!(input["filepath"], "/tmp/citadel-fixture/hello.txt");
    // The tool is announced once, though its part updates three times.
    let tools: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, HarnessEvent::ToolUse { .. }))
        .collect();
    assert!(
        matches!(tools[..], [HarnessEvent::ToolUse { name, input, .. }]
            if name == "write" && input["content"] == "hi"),
        "{tools:?}"
    );
    // The user's own prompt is not assistant text.
    let texts: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            HarnessEvent::AssistantText { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, ["done"]);
    // `session.idle` comes twice after the abort; the second ends no turn.
    assert_eq!(
        turn_ends(&events),
        [&TurnOutcome::Success, &TurnOutcome::Interrupted]
    );
    // Each assistant message completes twice on the wire; it counts once.
    assert_eq!(
        events.iter().find(|e| matches!(e, HarnessEvent::Usage(_))),
        Some(&HarnessEvent::Usage(Usage {
            input: 8589 + 354,
            output: 84 + 44 + 3 + 10,
            cache_read: 8384,
            cache_write: 0,
            cost_usd: Some(0.0),
        }))
    );
    assert_eq!(decoder.totals.output, 141);
}

#[test]
fn a_resumed_session_remembers_and_carries_its_cost_forward() {
    let mut decoder = Decoder {
        cost: 0.25,
        ..Decoder::default()
    };
    let events = replay(RESUME, &mut decoder);
    assert!(events.contains(&HarnessEvent::AssistantText {
        text: "hello.txt".to_owned()
    }));
    assert_eq!(turn_ends(&events), [&TurnOutcome::Success]);
    assert_eq!(decoder.totals.input, 367);
    // The session's cost so far, from the session object, plus this turn's (free) steps.
    assert_eq!(decoder.totals.cost_usd, Some(0.25));
}

#[test]
fn a_stale_error_does_not_fail_the_next_turn() {
    let mut decoder = Decoder {
        session: "s".to_owned(),
        ..Decoder::default()
    };
    let event = |kind: &str, properties: Value| {
        let mut properties = properties;
        properties["sessionID"] = "s".into();
        json!({"type": kind, "properties": properties})
    };
    let busy = event("session.status", json!({"status": {"type": "busy"}}));
    let error = event(
        "session.error",
        json!({"error": {"name": "ProviderAuthError", "data": {"message": "key expired"}}}),
    );
    let step = event(
        "message.updated",
        json!({"info": {"id": "m", "role": "assistant", "time": {"completed": 1},
            "tokens": {"input": 5, "output": 1}, "cost": 0.5}}),
    );
    let idle = event("session.idle", json!({}));
    let mut ends = vec![];
    for e in [&busy, &step, &error, &idle, &busy, &idle, &idle] {
        ends.extend(decoder.decode(e));
    }
    assert_eq!(
        turn_ends(&ends),
        [
            &TurnOutcome::Failed {
                reason: "key expired".to_owned(),
                code: "ProviderAuthError".to_owned()
            },
            &TurnOutcome::Success
        ]
    );
    assert_eq!(decoder.totals.cost_usd, Some(0.5));
    // Another session's events are not ours.
    let other = json!({"type": "session.idle", "properties": {"sessionID": "x"}});
    decoder.busy = true;
    assert_eq!(decoder.decode(&other), []);
}

fn scratch(name: &str) -> PathBuf {
    let tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let dir = tmp.join(format!("citadel-opencode-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One request as the fake server saw it: request line, `authorization` header, body.
type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

/// A fake `opencode serve` API: replies per path, and streams `events` on `/event`.
async fn fake_server(events: &'static str, seen: Seen) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let (head, body) = loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    raw.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&raw).into_owned();
                    let Some((head, body)) = text.split_once("\r\n\r\n") else {
                        continue;
                    };
                    let length = head
                        .lines()
                        .find_map(|l| {
                            l.to_lowercase()
                                .strip_prefix("content-length: ")
                                .map(str::to_owned)
                        })
                        .map_or(0, |n| n.trim().parse().unwrap());
                    if body.len() >= length {
                        break (head.to_owned(), body.to_owned());
                    }
                };
                let line = head.lines().next().unwrap().to_owned();
                let auth = head
                    .lines()
                    .find_map(|l| l.strip_prefix("authorization: "))
                    .unwrap_or("")
                    .to_owned();
                seen.lock().unwrap().push((line.clone(), auth, body));
                let reply = |status: &str, body: String| {
                    format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let response = if line.starts_with("GET /event") {
                    let mut stream = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
                                      connection: close\r\n\r\n"
                        .to_owned();
                    for event in events.lines() {
                        stream.push_str(&format!("data: {event}\n\n"));
                    }
                    stream
                } else if line.starts_with("POST /session?") {
                    reply("200 OK", json!({"id": SESSION, "cost": 0.0}).to_string())
                } else if line.contains("/prompt_async?") {
                    "HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n".to_owned()
                } else {
                    reply("200 OK", "true".to_owned())
                };
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    port
}

/// Through a real process and a fake API: argv is the server only; the prompt goes in a
/// request body; every request carries the server's password; the child sees only the
/// allowlist plus its own isolated dirs.
#[tokio::test]
async fn the_prompt_goes_by_http_and_the_config_stays_isolated() {
    let dir = scratch("isolation");
    let cwd = dir.join("work");
    std::fs::create_dir_all(&cwd).unwrap();
    let seen = Seen::default();
    let port = fake_server(APPROVE_INTERRUPT, seen.clone()).await;
    let script = dir.join("opencode");
    let d = dir.display();
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {d}/argv\nenv > {d}/env\n\
             echo 'opencode server listening on http://127.0.0.1:{port}'\nexec sleep 30\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let spec = Spec {
        program: Some(script),
        cwd: cwd.clone(),
        model: "opencode/free-model".to_owned(),
        instructions: Some(dir.join("instructions.md")),
        config_dir: dir.join("config"),
        env_allow: vec!["PATH".to_owned()],
        ..Spec::default()
    };
    let mut opencode = OpenCode::start(&spec).await.unwrap();
    opencode
        .send("PROMPT-CANARY fix the flaky test")
        .await
        .unwrap();
    let mut events = vec![];
    while events
        .iter()
        .filter(|e| matches!(e, HarnessEvent::TurnEnded { .. }))
        .count()
        < 2
    {
        let event = opencode.next().await.unwrap();
        if let HarnessEvent::ApprovalRequested { id, .. } = &event {
            opencode.approve(id, Decision::Allow).await.unwrap();
        }
        events.push(event);
    }
    opencode.interrupt().await.unwrap();
    opencode.stop().await;
    assert_eq!(
        events[0],
        HarnessEvent::SessionStarted {
            id: SESSION.to_owned()
        }
    );

    let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
    assert_eq!(argv, "serve\n--port\n0\n--hostname\n127.0.0.1\n");
    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    let password = env
        .lines()
        .find_map(|l| l.strip_prefix("OPENCODE_SERVER_PASSWORD="))
        .expect("the server has a password");
    let config = dir.join("config").display().to_string();
    for line in env.lines() {
        let (name, value) = line.split_once('=').unwrap();
        // `sh` adds PWD, SHLVL and `_` itself.
        let ours = name.starts_with("OPENCODE_") || name.starts_with("XDG_");
        assert!(
            ours || ["PATH", "PWD", "SHLVL", "_", "OLDPWD"].contains(&name),
            "leaked {name}"
        );
        if name.starts_with("XDG_") {
            assert!(value.starts_with(&config), "{line}");
        }
    }
    assert!(env.contains("OPENCODE_DISABLE_CLAUDE_CODE=1"));
    assert!(env.contains("instructions.md"), "instructions go by path");

    let seen = seen.lock().unwrap();
    let lines: Vec<_> = seen.iter().map(|(line, ..)| line.as_str()).collect();
    let directory = format!("directory={}", cwd.display()).replace('/', "%2F");
    for line in &lines {
        assert!(line.contains(&directory), "{line}");
    }
    let auth = |(_, auth, _): &(String, String, String)| auth.clone();
    let basic = seen.iter().map(auth).collect::<Vec<_>>();
    assert!(basic.iter().all(|a| a.starts_with("Basic ")), "{basic:?}");
    assert!(!basic[0].contains(password), "base64, not the raw password");
    let request = |prefix: &str| {
        seen.iter()
            .find(|(line, ..)| line.starts_with(prefix))
            .map(|(_, _, body)| serde_json::from_str::<Value>(body).unwrap_or(Value::Null))
            .unwrap_or_else(|| panic!("no {prefix} in {lines:?}"))
    };
    assert_eq!(request("POST /session?"), permissions(&spec));
    let prompt = request(&format!("POST /session/{SESSION}/prompt_async"));
    assert_eq!(
        prompt["parts"][0]["text"],
        "PROMPT-CANARY fix the flaky test"
    );
    assert_eq!(
        prompt["model"],
        json!({"providerID": "opencode", "modelID": "free-model"})
    );
    assert_eq!(
        request("POST /permission/per_15edc86e50015P4CxalPkHziEy/reply"),
        json!({"reply": "once"})
    );
    request(&format!("POST /session/{SESSION}/abort"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_model_without_a_provider_is_refused_before_spawning() {
    let spec = Spec {
        program: Some("/nonexistent/opencode".into()),
        model: "gpt".to_owned(),
        ..Spec::default()
    };
    let error = OpenCode::start(&spec).await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
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

/// E3.10: ask by default; edits allowed when accepted; everything when sandboxed.
#[test]
fn permissions_follow_the_spec() {
    let actions = |spec: &Spec| -> Vec<String> {
        permissions(spec)["permission"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                format!(
                    "{}={}",
                    r["permission"].as_str().unwrap(),
                    r["action"].as_str().unwrap()
                )
            })
            .collect()
    };
    let ask = Spec::default();
    assert_eq!(actions(&ask), ["edit=ask", "bash=ask", "webfetch=ask"]);
    let edits = Spec {
        accept_edits: true,
        ..Spec::default()
    };
    assert_eq!(actions(&edits), ["edit=allow", "bash=ask", "webfetch=ask"]);
    let sandboxed = Spec {
        sandboxed: true,
        ..Spec::default()
    };
    assert_eq!(
        actions(&sandboxed),
        ["edit=allow", "bash=allow", "webfetch=allow"]
    );
}

/// E4.2: the MCP file goes by path (`OPENCODE_CONFIG`); its token is in neither argv nor env.
#[test]
fn the_mcp_config_goes_by_path() {
    let spec = Spec {
        mcp_config: Some("/runs/private/mcp.json".into()),
        ..Spec::default()
    };
    let env = env(&spec, "pw");
    assert!(env.contains(&("OPENCODE_CONFIG", "/runs/private/mcp.json".into())));
    let config = mcp_config("http://127.0.0.1:7700/mcp/v1", "cit_run_x");
    let server = &config["mcp"]["citadel"];
    assert_eq!(server["type"], "remote");
    assert_eq!(server["headers"]["Authorization"], "Bearer cit_run_x");
    assert_eq!(server["oauth"], false);
}

/// A tool part that completes (or errs) is a `ToolResult`, once, after its `ToolUse` (1.18).
#[test]
fn tool_results_follow_their_calls() {
    let events = replay(APPROVE_INTERRUPT, &mut Decoder::default());
    let id = "call-33c5dedd-4cd6-4506-8ccf-51d963f40d05";
    let results: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, HarnessEvent::ToolResult { .. }))
        .collect();
    assert_eq!(
        results,
        [&HarnessEvent::ToolResult {
            id: id.to_owned(),
            ok: true,
            exit_code: None,
            output: "Wrote file successfully.".to_owned(),
        }]
    );
    let used = events
        .iter()
        .position(|e| matches!(e, HarnessEvent::ToolUse { .. }));
    let ended = events
        .iter()
        .position(|e| matches!(e, HarnessEvent::ToolResult { .. }));
    assert!(used < ended);
}

/// A newer OpenCode's additions (event types, part types, fields) are ignored: the recorded
/// turns decode to the same events.
#[test]
fn ignores_unknown_events_and_fields() {
    let unknown = [
        json!({"type": "future.event", "properties": {"sessionID": SESSION, "x": 1}}),
        json!({"type": "message.part.updated", "properties": {"sessionID": SESSION,
            "part": {"type": "future-part", "id": "p1", "sessionID": SESSION,
                     "messageID": "m1"}}}),
    ];
    for fixture in [APPROVE_INTERRUPT, RESUME] {
        let newer = crate::newer_cli(fixture, &unknown);
        let want = replay(fixture, &mut Decoder::default());
        assert_eq!(replay(&newer, &mut Decoder::default()), want);
    }
}
