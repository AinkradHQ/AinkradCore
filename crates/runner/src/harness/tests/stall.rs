//! The progress watchdog (E15.7, pain #3), against a fake `claude`: one that goes silent and
//! one that only keeps saying "working on it" are both stopped at the stall limit and end
//! `Stalled`; one that keeps calling tools runs to its end.

use std::time::Instant;

use ainkrad_proto::runner::RunLimits;

use super::*;

/// A fake `claude` that announces its session, then every 50 ms: nothing (`silent`), the same
/// line with more tokens (`chatter`), or a tool call, finishing after 20 (`busy`). Any input
/// after the prompt (the runner's interrupt) or EOF ends it.
fn fake(dir: &Path, mode: &str) -> HarnessExecutor {
    let bin = dir.join("claude");
    let script = format!(
        r#"#!/usr/bin/perl
use IO::Select;
$| = 1;
my $in = IO::Select->new(\*STDIN);
<STDIN>; <STDIN>;
print qq({{"type":"system","subtype":"init","session_id":"S"}}\n);
my $n = 0;
while (1) {{
    exit 0 if $in->can_read(0.05);
    $n++;
    if ("{mode}" eq "chatter") {{
        print qq({{"type":"assistant","message":{{"id":"m$n","content":[{{"type":"text","text":"working on it"}}],"usage":{{"input_tokens":10,"output_tokens":$n}}}}}}\n);
    }} elsif ("{mode}" eq "busy") {{
        print qq({{"type":"assistant","message":{{"id":"m$n","content":[{{"type":"tool_use","id":"t$n","name":"Bash","input":{{}}}}]}}}}\n);
        if ($n >= 20) {{
            print qq({{"type":"result","subtype":"success","is_error":false,"usage":{{}}}}\n);
        }}
    }}
}}
"#
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex
}

/// Runs `job` to its end: its outcome, how long it took, and its progress reports.
async fn work(ex: &HarnessExecutor, job: &Job) -> (Outcome, Duration, usize) {
    ex.start(job).await.unwrap();
    let (tx, mut rx) = mpsc::channel(4096);
    let started = Instant::now();
    let outcome = ex.run(job, RunToken::new("t".to_owned()), tx).await;
    let took = started.elapsed();
    let progress = std::iter::from_fn(|| rx.try_recv().ok())
        .filter(|r| matches!(r, Report::Progress { .. }))
        .count();
    (outcome, took, progress)
}

#[tokio::test]
async fn a_silent_harness_is_stopped_at_the_stall_limit() {
    let dir = scratch("stall-silent");
    let mut ex = fake(&dir, "silent");
    ex.stall_after = Duration::from_millis(400);
    let (outcome, took, _) = work(&ex, &job("claude")).await;
    assert_eq!(outcome, Outcome::Stalled);
    assert!(took >= Duration::from_millis(400), "{took:?}");
    assert!(
        took < Duration::from_secs(4),
        "stopped at the limit: {took:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_harness_that_only_says_it_is_working_is_stalled() {
    let dir = scratch("stall-chatter");
    let mut ex = fake(&dir, "chatter");
    // Long enough for the fake to start and answer once under a loaded test run.
    ex.stall_after = Duration::from_millis(1500);
    let (outcome, took, progress) = work(&ex, &job("claude")).await;
    assert_eq!(outcome, Outcome::Stalled, "its first line was all it did");
    assert!(took < Duration::from_secs(6), "{took:?}");
    assert_eq!(progress, 1, "the first answer, nothing after it");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_harness_calling_tools_is_never_stalled() {
    let dir = scratch("stall-busy");
    let ex = fake(&dir, "busy");
    // The server's stall limit (`Assign.limits`) beats the executor's own.
    let job = Job {
        limits: Some(RunLimits {
            approval_timeout_secs: 60,
            max_resumes: 0,
            resume_backoff_ms: 10,
            resume_backoff_max_ms: 10,
            warm_max: 0,
            stall_after_secs: 1,
            tool_output_bytes: 2048,
            fallback_on_model_unavailable: true,
            fallback_on_rate_limited: true,
            fallback_on_quota: true,
            fallback_on_unhealthy: true,
        }),
        ..job("claude")
    };
    let (outcome, took, progress) = work(&ex, &job).await;
    assert_eq!(outcome, Outcome::Succeeded);
    assert!(
        took > Duration::from_secs(1),
        "longer than the limit: {took:?}"
    );
    assert!(progress >= 1, "progress was reported");

    let _ = std::fs::remove_dir_all(&dir);
}
