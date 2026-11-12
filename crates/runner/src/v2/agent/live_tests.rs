//! Live AI sessions (N41) through the real `HarnessExecutor` and a fake `claude` that reads
//! stream-json from stdin and answers each message: one process serves many messages, the state
//! is `waiting` between answers, a turn can be stopped, a killed process is started again with
//! the harness's own resume, and an approval can be answered mid-turn.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ainkrad_proto::v2::AgentRead;

use super::tests::{dirs, start};
use super::*;
use crate::HarnessExecutor;

const SESSION: &str = "as_livea0000000000000000000001";

/// A fake `claude`. Each launch appends its pid and argv to `spawns`. A user line `slow` starts a
/// turn that only an interrupt ends, `ask` asks for a tool approval and reports the answer,
/// `bye` ends the turn and then exits by itself, anything else is answered `echo:<text>`.
fn fake(dir: &Path) -> HarnessExecutor {
    std::fs::create_dir_all(dir).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    let script = format!(
        r#"#!/usr/bin/perl
exit 0 if $ENV{{AINKRAD_EXEC_PROBE}};
$| = 1;
open(my $log, '>>', "{d}/spawns"); print $log "$$ @ARGV\n"; close $log;
my $sid = 'S';
for my $i (0..$#ARGV) {{ $sid = $ARGV[$i + 1] if $ARGV[$i] eq '--session-id' || $ARGV[$i] eq '--resume'; }}
print qq({{"type":"system","subtype":"init","session_id":"$sid"}}\n);
my $n = 0;
sub say {{ $n++; print qq({{"type":"assistant","message":{{"id":"m$$-$n","content":[{{"type":"text","text":"$_[0]"}}],"usage":{{"input_tokens":1,"output_tokens":1}}}}}}\n); }}
sub done {{ print qq({{"type":"result","subtype":"success","is_error":false,"total_cost_usd":0.01,"usage":{{"input_tokens":1,"output_tokens":1}}}}\n); }}
my $asking = 0;
while (my $line = <STDIN>) {{
    if ($line =~ /"subtype":"interrupt"/) {{
        print qq({{"type":"result","subtype":"error_during_execution","is_error":true,"usage":{{}}}}\n);
    }} elsif ($line =~ /"type":"control_response"/) {{
        if ($asking) {{ $asking = 0; say(($line =~ /"behavior":"(\w+)"/) ? "answer:$1" : "answer:?"); done(); }}
    }} elsif ($line =~ /"type":"user"/ && $line =~ /"content":"([^"]*)"/) {{
        my $t = $1;
        if ($t eq 'slow') {{ say('working'); }}
        elsif ($t eq 'ask') {{
            $asking = 1;
            print qq({{"type":"control_request","request_id":"a1","request":{{"subtype":"can_use_tool","tool_name":"Bash","display_name":"Bash","input":{{"command":"rm -rf scratch"}}}}}}\n);
        }}
        elsif ($t eq 'bye') {{ say('echo:bye'); done(); select(undef, undef, undef, 0.3); exit 0; }}
        else {{ say("echo:$t"); done(); }}
    }}
}}
"#
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    crate::exec_ready(&bin);
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex
}

fn live(session: &str, prompt: Option<&str>) -> AgentStart {
    AgentStart {
        prompt: prompt.map(str::to_owned),
        live: true,
        ..start(session, "claude")
    }
}

/// Everything the session holds, once `done` says so (30 s at most).
async fn until(d: &AgentDriver, what: &str, done: impl Fn(&AgentEvents) -> bool) -> AgentEvents {
    let end = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let read = AgentRead {
            session: SESSION.to_owned(),
            after: 0,
            wait_ms: Some(100),
            gw_after: 0,
        };
        let ev = d.read(&read).await.unwrap();
        if done(&ev) {
            return ev;
        }
        // Every read answers at once (the entries are never acknowledged): let the session work.
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            tokio::time::Instant::now() < end,
            "{what}: {:?} {:?}",
            ev.state,
            ev.entries
        );
    }
}

fn count(ev: &AgentEvents, kind: &str) -> usize {
    ev.entries.iter().filter(|e| e.body["type"] == kind).count()
}

fn said(ev: &AgentEvents) -> Vec<String> {
    ev.entries
        .iter()
        .filter(|e| e.body["type"] == "assistant_text")
        .map(|e| e.body["text"].as_str().unwrap().to_owned())
        .collect()
}

fn spawns(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("spawns"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn waiting(n: usize) -> impl Fn(&AgentEvents) -> bool {
    move |ev| ev.state == AgentState::Waiting && count(ev, "waiting") >= n
}

fn driver(name: &str) -> (Arc<AgentDriver>, crate::workspace::tests::TestDir) {
    let (root, config) = dirs(name);
    let ex = fake(&root.0);
    (Arc::new(AgentDriver::new(config, ex).unwrap()), root)
}

#[tokio::test]
async fn one_process_serves_three_messages_and_waits_between_them() {
    let (d, root) = driver("live-three");
    let ev = d.start(live(SESSION, Some("one"))).unwrap();
    assert_eq!(ev.state, AgentState::Running);
    let ev = until(&d, "the first answer", waiting(1)).await;
    assert_eq!(said(&ev), ["echo:one"]);
    assert_eq!(
        d.states()[SESSION],
        AgentState::Waiting,
        "idle between answers"
    );
    // The idle session still holds its slot.
    assert!(holds_slot(AgentState::Waiting));
    for (i, text) in ["two", "three"].into_iter().enumerate() {
        let ev = d.send(SESSION, text.to_owned()).unwrap();
        assert_eq!(ev.state, AgentState::Running, "a message wakes it");
        until(&d, text, waiting(i + 2)).await;
    }
    let ev = until(&d, "all", waiting(3)).await;
    assert_eq!(said(&ev), ["echo:one", "echo:two", "echo:three"]);
    assert_eq!(count(&ev, "turn_ended"), 3);
    assert_eq!(
        spawns(&root.0).len(),
        1,
        "one process for the whole conversation"
    );
    // The cost of the conversation so far is reported between turns.
    assert!(ev.usage.is_some());
    d.stop(AgentStop {
        session: SESSION.to_owned(),
        kill: false,
        turn: false,
    })
    .unwrap();
    let ev = until(&d, "the end", |e| e.state == AgentState::Ended).await;
    assert!(
        matches!(ev.outcome, Some(Outcome::Cancelled { .. })),
        "{:?}",
        ev.outcome
    );
}

#[tokio::test]
async fn a_session_with_no_first_message_waits_for_one() {
    let (d, root) = driver("live-empty");
    d.start(live(SESSION, None)).unwrap();
    let ev = until(&d, "ready", waiting(1)).await;
    assert!(
        said(&ev).is_empty() && count(&ev, "turn_ended") == 0,
        "no turn ran"
    );
    assert_eq!(spawns(&root.0).len(), 1, "the harness is up");
    d.send(SESSION, "hello".to_owned()).unwrap();
    let ev = until(&d, "the answer", waiting(2)).await;
    assert_eq!(said(&ev), ["echo:hello"]);
    assert_eq!(spawns(&root.0).len(), 1);
}

#[tokio::test]
async fn stopping_a_turn_leaves_the_session_waiting() {
    let (d, root) = driver("live-stop");
    d.start(live(SESSION, Some("slow"))).unwrap();
    until(&d, "a running answer", |e| said(e) == ["working"]).await;
    assert_eq!(d.states()[SESSION], AgentState::Running);
    let turn = AgentStop {
        session: SESSION.to_owned(),
        kill: false,
        turn: true,
    };
    d.stop(turn.clone()).unwrap();
    let ev = until(&d, "the stopped answer", waiting(1)).await;
    let ended = ev
        .entries
        .iter()
        .find(|e| e.body["type"] == "turn_ended")
        .unwrap();
    assert_eq!(ended.body["outcome"]["kind"], "interrupted");
    assert!(ev.outcome.is_none(), "the session did not end");
    // Nothing runs: a stop of the turn is a no-op, and the same process takes the next message.
    d.stop(turn).unwrap();
    d.send(SESSION, "again".to_owned()).unwrap();
    let ev = until(&d, "the next answer", waiting(2)).await;
    assert_eq!(said(&ev), ["working", "echo:again"]);
    assert_eq!(spawns(&root.0).len(), 1);
}

#[tokio::test]
async fn an_approval_is_answered_mid_turn_and_a_stopped_turn_denies_it() {
    let (d, _root) = driver("live-approve");
    d.start(live(SESSION, Some("ask"))).unwrap();
    let ev = until(&d, "the approval", |e| count(e, "approval_request") == 1).await;
    assert_eq!(ev.state, AgentState::Running);
    let id = ev
        .entries
        .iter()
        .find(|e| e.body["type"] == "approval_request")
        .unwrap()
        .body["id"]
        .as_str()
        .unwrap()
        .to_owned();
    d.decide(AgentDecide {
        session: SESSION.to_owned(),
        request: id,
        approved: true,
        reply: None,
    })
    .unwrap();
    let ev = until(&d, "the answer", waiting(1)).await;
    assert_eq!(said(&ev), ["answer:allow"]);
    // The same again, but the user stops the turn instead of answering: it is denied.
    d.send(SESSION, "ask".to_owned()).unwrap();
    until(&d, "the second approval", |e| {
        count(e, "approval_request") == 2
    })
    .await;
    d.stop(AgentStop {
        session: SESSION.to_owned(),
        kill: false,
        turn: true,
    })
    .unwrap();
    let ev = until(&d, "the stopped turn", waiting(2)).await;
    assert_eq!(said(&ev), ["answer:allow", "answer:deny"]);
}

#[tokio::test]
async fn a_killed_process_is_started_again_with_resume_at_the_next_message() {
    let (d, root) = driver("live-restart");
    d.start(live(SESSION, Some("one"))).unwrap();
    until(&d, "the first answer", waiting(1)).await;
    let first = spawns(&root.0);
    let pid = first[0].split(' ').next().unwrap().to_owned();
    assert!(!first[0].contains("--resume"), "{first:?}");
    // The process goes away while idle (a crash, the host's sleep): the session still waits.
    let _ = std::process::Command::new("kill")
        .args(["-9", &pid])
        .status();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(d.states()[SESSION], AgentState::Waiting);
    d.send(SESSION, "two".to_owned()).unwrap();
    let ev = until(&d, "the answer after the restart", waiting(2)).await;
    assert_eq!(said(&ev), ["echo:one", "echo:two"]);
    let all = spawns(&root.0);
    assert_eq!(all.len(), 2, "{all:?}");
    assert!(
        all[1].contains("--resume"),
        "resumed by the harness's own id: {all:?}"
    );
    let session = all[1]
        .split("--resume ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap();
    assert!(first[0].contains(session), "the same session id: {all:?}");
}

#[tokio::test]
async fn a_live_session_the_core_resumes_waits_and_starts_its_harness_at_the_next_message() {
    let (d, root) = driver("live-resumed");
    let resumed = AgentStart {
        resume: Some("S1".to_owned()),
        epoch: 1,
        ..live(SESSION, None)
    };
    d.start(resumed).unwrap();
    until(&d, "waiting", waiting(1)).await;
    assert!(
        spawns(&root.0).is_empty(),
        "no harness until a message needs it"
    );
    d.send(SESSION, "hi".to_owned()).unwrap();
    let ev = until(&d, "the answer", waiting(2)).await;
    assert_eq!(said(&ev), ["echo:hi"]);
    let all = spawns(&root.0);
    assert_eq!(all.len(), 1);
    assert!(all[0].contains("--resume S1"), "{all:?}");
}

#[tokio::test]
async fn the_cli_exiting_by_itself_ends_the_session() {
    let (d, _root) = driver("live-exit");
    d.start(live(SESSION, Some("bye"))).unwrap();
    let ev = until(&d, "the end", |e| e.state == AgentState::Ended).await;
    assert_eq!(ev.outcome, Some(Outcome::Succeeded));
}

#[tokio::test]
async fn a_restarted_runner_reloads_a_waiting_session_as_interrupted() {
    let (root, config) = dirs("live-reload");
    let d = Arc::new(AgentDriver::new(config.clone(), fake(&root.0)).unwrap());
    d.start(live(SESSION, Some("one"))).unwrap();
    until(&d, "waiting", waiting(1)).await;
    drop(d);
    let d = AgentDriver::new(config, fake(&root.0)).unwrap();
    assert_eq!(d.states()[SESSION], AgentState::Interrupted);
}
