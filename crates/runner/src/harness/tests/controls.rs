//! The admin's controls of a running job (1.19, decision #34), against a fake `claude`: a
//! pause lets the tool call in flight finish, then ends the run `Cancelled`; a message is the
//! harness's next turn, and the run goes on.

use std::time::Instant;

use super::*;
use crate::Control;

/// A fake `claude`: one tool call (`t1`, 400 ms), then, in `message` mode, the end of the turn;
/// each later `user` line is a turn answering `got: <text>`. An interrupt ends the turn
/// interrupted and the process.
fn fake(dir: &Path, mode: &str) -> HarnessExecutor {
    let bin = dir.join("claude");
    let script = format!(
        r#"#!/usr/bin/perl
use IO::Select;
use Time::HiRes qw(sleep);
exit 0 if $ENV{{AINKRAD_EXEC_PROBE}};
$| = 1;
my $in = IO::Select->new(\*STDIN);
<STDIN>; <STDIN>;
print qq({{"type":"system","subtype":"init","session_id":"S"}}\n);
print qq({{"type":"assistant","message":{{"id":"m1","content":[{{"type":"tool_use","id":"t1","name":"Bash","input":{{"command":"cargo test"}}}}]}}}}\n);
sleep 0.4;
print qq({{"type":"user","message":{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"t1","content":"ok"}}]}}}}\n);
print qq({{"type":"result","subtype":"success","is_error":false,"usage":{{}}}}\n) if "{mode}" eq "message";
while (1) {{
    next unless $in->can_read(0.05);
    my $line = <STDIN>;
    exit 0 unless defined $line;
    if ($line =~ /"interrupt"/) {{
        print qq({{"type":"result","subtype":"error_during_execution","is_error":true,"usage":{{}}}}\n);
        exit 0;
    }}
    if ($line =~ /"content":"([^"]*)"/) {{
        print qq({{"type":"assistant","message":{{"id":"m2","content":[{{"type":"text","text":"got: $1"}}]}}}}\n);
        print qq({{"type":"result","subtype":"success","is_error":false,"usage":{{}}}}\n);
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

/// Runs the job, putting `control` in once its `tool_use` is reported: its outcome, how long
/// that took, its chunks.
async fn work(ex: &HarnessExecutor, control: Control) -> (Outcome, Duration, Vec<Value>) {
    let job = job("claude");
    ex.start(&job).await.unwrap();
    let (tx, mut rx) = mpsc::channel(4096);
    let mut control = Some(control);
    let (mut chunks, mut since) = (vec![], Instant::now());
    let watch = async {
        while let Some(report) = rx.recv().await {
            let Report::Event(chunk) = report else {
                continue;
            };
            if chunk["type"] == "tool_use"
                && let Some(c) = control.take()
            {
                since = Instant::now();
                ex.control(job.run, c);
            }
            chunks.push(chunk);
        }
    };
    let (outcome, ()) = tokio::join!(ex.run(&job, RunToken::new("t".to_owned()), tx), watch);
    (outcome, since.elapsed(), chunks)
}

#[tokio::test]
async fn a_pause_lets_the_tool_call_finish_then_ends_the_run() {
    let dir = scratch("pause");
    let ex = fake(&dir, "pause");
    let (outcome, took, chunks) = work(&ex, Control::Pause).await;
    assert_eq!(
        outcome,
        Outcome::Cancelled {
            reason: "paused by admin".to_owned()
        }
    );
    assert!(
        took >= Duration::from_millis(300),
        "waited for t1: {took:?}"
    );
    let result = chunks.iter().find(|c| c["type"] == "tool_result").unwrap();
    assert_eq!(
        (&result["id"], &result["status"]),
        (&json!("t1"), &json!("ok"))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_message_is_the_next_turn_and_the_run_goes_on() {
    let dir = scratch("message");
    let ex = fake(&dir, "message");
    let text = "use the in-memory transport".to_owned();
    let (outcome, _, chunks) = work(&ex, Control::Message { id: 9, text }).await;
    assert_eq!(outcome, Outcome::Succeeded);
    let types: Vec<_> = chunks.iter().filter_map(|c| c["type"].as_str()).collect();
    let given = types.iter().position(|t| *t == "user_message").unwrap();
    let first_end = types.iter().position(|t| *t == "turn_ended").unwrap();
    assert!(first_end < given, "given after the first turn: {types:?}");
    assert_eq!(chunks[given]["id"], 9);
    assert!(
        chunks
            .iter()
            .any(|c| c["text"] == "got: use the in-memory transport"),
        "{chunks:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
