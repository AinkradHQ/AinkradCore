//! Provider drops inside a run (E15.4), against a fake `claude` that loses its turn: a reset
//! stream or an overloaded API resumes the same session in the same run and finishes; too
//! many drops give the entry up to the fallback chain; a permanent error is not retried, nor
//! is a process that ends over a request a newer CLI sent (a protocol failure).

use ainkrad_proto::runner::Route;

use super::*;

const FIXTURE: &str = include_str!("../../../../harness/tests/fixtures/claude/resume.ndjson");

/// A fake `claude` whose first `drops` starts (of models starting `flaky`, or of any model
/// when `flaky_only` is false) lose the turn the way `mode` says: `exit` (the stream resets
/// after the session began), `529` (Anthropic overloaded) or `boom` (a permanent failure).
/// Every start's argv and stdin are logged.
fn fake(dir: &Path, mode: &str, drops: u32, flaky_only: bool) -> HarnessExecutor {
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    std::fs::write(dir.join("left"), drops.to_string()).unwrap();
    let init = serde_json::json!({"type": "system", "subtype": "init", "session_id": "SESSION"});
    let partial = serde_json::json!({"type": "assistant", "message": {"id": "m-drop",
        "content": [{"type": "text", "text": "working"}],
        "usage": {"input_tokens": 100, "output_tokens": 1}}});
    let lost = match mode {
        "529" => serde_json::json!({"type": "result", "subtype": "error_during_execution",
            "is_error": true, "api_error_status": 529, "usage": {},
            "result": r#"API Error: 529 {"type":"error","error":{"type":"overloaded_error"}}"#})
        .to_string(),
        "boom" => serde_json::json!({"type": "result", "subtype": "error_during_execution",
            "is_error": true, "result": "boom", "usage": {}})
        .to_string(),
        // A newer CLI's control request the adapter refuses, then the CLI gives up.
        "protocol" => serde_json::json!({"type": "control_request", "request_id": "r1",
            "request": {"subtype": "future_hook"}})
        .to_string(),
        _ => String::new(),
    };
    std::fs::write(
        dir.join("lost.ndjson"),
        format!("{init}\n{partial}\n{lost}\n"),
    )
    .unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    let flaky = if flaky_only { "flaky*" } else { "*" };
    let script = format!(
        "#!/bin/sh\necho \"$*\" >> {d}/starts\nmodel=\n\
         while [ $# -gt 0 ]; do [ \"$1\" = --model ] && model=$2; shift; done\n\
         head -n 2 >> {d}/stdin\nleft=$(cat {d}/left)\n\
         case $model in {flaky}) ;; *) left=0 ;; esac\n\
         if [ \"$left\" -gt 0 ]; then echo $((left - 1)) > {d}/left; cat {d}/lost.ndjson; \
         exit 1; fi\ncat {d}/fixture.ndjson\n"
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex.resume_backoff = Duration::from_millis(10);
    ex
}

async fn work(ex: &HarnessExecutor, job: &Job) -> (Outcome, Vec<Report>) {
    ex.start(job).await.unwrap();
    let (tx, mut rx) = mpsc::channel(256);
    let outcome = ex.run(job, RunToken::new("t".to_owned()), tx).await;
    (outcome, std::iter::from_fn(|| rx.try_recv().ok()).collect())
}

fn drops(reports: &[Report]) -> usize {
    reports
        .iter()
        .filter(|r| matches!(r, Report::Dropped { .. }))
        .count()
}

#[tokio::test]
async fn a_reset_stream_resumes_the_same_session_and_the_run_finishes() {
    let dir = scratch("drop-exit");
    let ex = fake(&dir, "exit", 1, false);
    let job = job("claude");
    let (outcome, reports) = work(&ex, &job).await;
    assert_eq!(outcome, Outcome::Succeeded);
    assert_eq!(drops(&reports), 1);
    let starts = std::fs::read_to_string(dir.join("starts")).unwrap();
    let starts: Vec<&str> = starts.lines().collect();
    assert_eq!(starts.len(), 2, "one resume: {starts:?}");
    assert!(starts[0].contains("--session-id "), "{}", starts[0]);
    assert!(starts[1].contains("--resume SESSION"), "{}", starts[1]);
    let stdin = std::fs::read_to_string(dir.join("stdin")).unwrap();
    assert!(stdin.contains("CIT-3"), "the first turn's prompt");
    assert!(
        stdin.contains("dropped in the middle of your turn"),
        "{stdin}"
    );
    // The dropped attempt's 100 input tokens count with the resumed turn's.
    let last = reports.iter().rev().find_map(|r| match r {
        Report::Usage(u) => Some(*u),
        _ => None,
    });
    assert!(last.unwrap().input >= 100);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn an_overloaded_api_is_resumed_until_the_entry_is_given_up_to_the_fallback() {
    let dir = scratch("drop-529");
    let ex = fake(&dir, "529", 99, true);
    let job = Job {
        model: "flaky-opus".to_owned(),
        fallbacks: vec![Route {
            harness: "claude".to_owned(),
            model: "haiku".to_owned(),
            account: None,
        }],
        ..job("claude")
    };
    let (outcome, reports) = work(&ex, &job).await;
    assert_eq!(outcome, Outcome::Succeeded);
    assert_eq!(drops(&reports), 3, "max_resumes 2: the third drop gives up");
    let fallback = reports.iter().find_map(|r| match r {
        Report::Fallback {
            model,
            class,
            reason,
            ..
        } => Some((model.clone(), class.clone(), reason.clone())),
        _ => None,
    });
    let (model, class, reason) = fallback.expect("fell back");
    assert_eq!((model.as_str(), class.as_str()), ("haiku", "unhealthy"));
    assert!(
        reason.starts_with("the provider dropped the turn 3 times; last: API Error: 529"),
        "{reason}"
    );
    let starts = std::fs::read_to_string(dir.join("starts")).unwrap();
    assert_eq!(starts.lines().count(), 4, "3 on flaky-opus, 1 on haiku");

    // Alone, the given-up entry fails with its drops.
    let dir2 = scratch("drop-529-alone");
    let ex = fake(&dir2, "529", 99, true);
    let alone = Job {
        fallbacks: vec![],
        ..job
    };
    let (outcome, _) = work(&ex, &alone).await;
    assert!(
        matches!(&outcome, Outcome::Failed { fingerprint: Some(f), .. } if f == "claude:provider_dropped"),
        "{outcome:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[tokio::test]
async fn a_permanent_error_fails_fast_without_a_resume() {
    let dir = scratch("drop-boom");
    let ex = fake(&dir, "boom", 1, false);
    let (outcome, reports) = work(&ex, &job("claude")).await;
    assert!(
        matches!(&outcome, Outcome::Failed { reason, .. } if reason == "boom"),
        "{outcome:?}"
    );
    assert_eq!(drops(&reports), 0);
    let starts = std::fs::read_to_string(dir.join("starts")).unwrap();
    assert_eq!(starts.lines().count(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_servers_limits_replace_the_runners_own() {
    use ainkrad_proto::runner::RunLimits;
    let dir = scratch("drop-limits");
    let ex = fake(&dir, "529", 99, true);
    // The server allows no resume (`Assign.limits`, 1.11): the first drop gives the entry up.
    let older = job("claude");
    let job = Job {
        model: "flaky-opus".to_owned(),
        limits: Some(RunLimits {
            approval_timeout_secs: 1,
            max_resumes: 0,
            resume_backoff_ms: 10,
            resume_backoff_max_ms: 10,
            warm_max: 0,
            stall_after_secs: 600,
            tool_output_bytes: 2048,
            fallback_on_model_unavailable: true,
            fallback_on_rate_limited: true,
            fallback_on_quota: true,
            fallback_on_unhealthy: true,
        }),
        ..job("claude")
    };
    let (outcome, reports) = work(&ex, &job).await;
    assert_eq!(drops(&reports), 1, "not the executor's 2 resumes");
    assert!(
        matches!(&outcome, Outcome::Failed { reason, .. } if reason.contains("1 times")),
        "{outcome:?}"
    );
    let l = ex.limits(&job);
    assert_eq!(l.approval_timeout, Duration::from_secs(1));
    assert_eq!(ex.limits(&older).max_resumes, 2, "an older server: its own");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A newer CLI that ends its turn over a control request the adapter does not know is no
/// provider drop: the run fails at once as `claude:protocol`, naming the version.
#[tokio::test]
async fn a_newer_clis_unknown_request_fails_as_protocol_without_a_resume() {
    let dir = scratch("drop-protocol");
    let ex = fake(&dir, "protocol", 1, false);
    ex.versions
        .lock()
        .unwrap()
        .insert("claude".to_owned(), "2.2.0".to_owned());
    let (outcome, reports) = work(&ex, &job("claude")).await;
    assert_eq!(
        outcome,
        Outcome::Failed {
            reason: "claude 2.2.0: exited after an unrecognised control request (future_hook)"
                .to_owned(),
            fingerprint: Some("claude:protocol".to_owned()),
        }
    );
    assert_eq!(drops(&reports), 0);
    let starts = std::fs::read_to_string(dir.join("starts")).unwrap();
    assert_eq!(starts.lines().count(), 1, "no resume");
    let _ = std::fs::remove_dir_all(&dir);
}
