use std::os::unix::fs::PermissionsExt;

use ainkrad_harness::Usage;
use ainkrad_proto::runner::{Policy, TokenCaps, Tokens};
use serde_json::Value;

use super::turn::reached;
use super::*;

const FIXTURE: &str =
    include_str!("../../../harness/tests/fixtures/claude/approve-interrupt.ndjson");

fn job(harness: &str) -> Job {
    Job {
        run: 7,
        agent: 1,
        issue: Some(3),
        harness: harness.to_owned(),
        model: "haiku".to_owned(),
        context_ref: "citadel://issues/3".to_owned(),
        workspace: None,
        token_cap: None,
        token_caps: None,
        policy: Policy::default(),
        issue_key: Some("CIT-3".to_owned()),
        instructions: None,
        account: None,
        fallbacks: vec![],
        limits: None,
        resume_session: None,
        prompt: None,
        repos: vec![],
    }
}

/// The transcript chunks reported so far.
fn chunks(rx: &mut mpsc::Receiver<Report>) -> Vec<Value> {
    std::iter::from_fn(|| rx.try_recv().ok())
        .filter_map(|r| match r {
            Report::Event(e) => Some(e),
            Report::Usage(_)
            | Report::Approval { .. }
            | Report::Fallback { .. }
            | Report::Dropped { .. }
            | Report::Progress { .. } => None,
        })
        .collect()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ainkrad-runner-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn other_harnesses_fail_to_start() {
    let dir = scratch("unsupported");
    let ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    assert!(ex.start(&job("pi")).await.is_err());
    assert_eq!(
        ex.start(&job("codex")).await,
        Ok(None),
        "codex names its own thread"
    );
    assert!(dir.join("config/codex").is_dir());
}

/// A fake `claude` playing a recorded run: the executor reports the session it picked,
/// forwards the events, denies the out-of-dir write, and maps the turn's end.
#[tokio::test]
async fn works_a_run_through_claude() {
    let dir = scratch("run");
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    // Plays the first turn only (up to its `result`), like a run.
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {d}/argv\nhead -n 2 > /dev/null\n\
             sed '/\"type\":\"result\"/q' {d}/fixture.ndjson\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    // Nobody reviews the escalated write: it is denied when the wait runs out.
    ex.approval_timeout = Duration::from_millis(50);
    // The write's output is cut to its head and tail (1.18).
    ex.tool_output = 16;

    let job = job("claude");
    let session = ex.start(&job).await.unwrap().unwrap();
    let (tx, mut rx) = mpsc::channel(256);
    let outcome = ex.run(&job, RunToken::new("t".to_owned()), tx).await;
    assert_eq!(outcome, Outcome::Succeeded);

    let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
    assert!(
        argv.contains(&format!("--session-id\n{session}\n")),
        "{argv}"
    );
    assert!(
        !argv.contains("citadel://issues/3"),
        "the prompt went by argv"
    );
    let mut types = vec![];
    let events = chunks(&mut rx);
    for event in &events {
        types.push(event["type"].as_str().unwrap().to_owned());
    }
    let result = events.iter().find(|e| e["type"] == "tool_result").unwrap();
    assert_eq!(
        (&result["name"], &result["status"], &result["exit_code"]),
        (&json!("Write"), &json!("ok"), &Value::Null),
        "{result}"
    );
    let output = result["output"].as_str().unwrap();
    assert!(
        output.starts_with("File\n… ") && output.contains("bytes cut"),
        "{output}"
    );
    assert!(result["output_bytes"].as_u64().unwrap() > 100, "{result}");
    assert!(result["duration_ms"].is_u64(), "{result}");
    for kind in [
        "session_started",
        "tool_use",
        "approval_requested",
        "approval_escalated",
        "approval_decided",
        "tool_result",
        "usage",
        "turn_ended",
    ] {
        assert!(
            types.iter().any(|t| t == kind),
            "{kind} missing from {types:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A job naming a session to continue (E15.5) resumes it, told to go on; any other job is a
/// new session (`works_a_run_through_claude`).
#[tokio::test]
async fn a_job_naming_a_session_continues_it() {
    let dir = scratch("continue");
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {d}/argv\nhead -n 2 > {d}/stdin\n\
             sed '/\"type\":\"result\"/q' {d}/fixture.ndjson\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex.approval_timeout = Duration::from_millis(50);
    let job = Job {
        resume_session: Some("prev-session".to_owned()),
        ..job("claude")
    };
    assert_eq!(ex.start(&job).await, Ok(Some("prev-session".to_owned())));
    let (tx, _rx) = mpsc::channel(256);
    ex.run(&job, RunToken::new("t".to_owned()), tx).await;
    let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
    assert!(argv.contains("--resume\nprev-session\n"), "{argv}");
    assert!(!argv.contains("--session-id"), "{argv}");
    let stdin = std::fs::read_to_string(dir.join("stdin")).unwrap();
    assert!(stdin.contains("Continue the task"), "{stdin}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The probe reports installed harnesses with their versions and leaves missing ones out.
#[tokio::test]
async fn probes_installed_harnesses_only() {
    let dir = scratch("probe");
    let fake = |name: &str, line: &str| {
        let bin = dir.join(name);
        std::fs::write(&bin, format!("#!/bin/sh\necho '{line}'\n")).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    };
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    let claude_line = format!("{} (Claude Code)", claude::VERSION);
    ex.bins
        .insert("claude".to_owned(), fake("claude", &claude_line));
    ex.bins
        .insert("codex".to_owned(), fake("codex", "codex-cli 0.1.0"));
    for name in ["opencode", "agy"] {
        ex.bins.insert(name.to_owned(), dir.join("not-installed"));
    }
    let found = ex.probe(std::time::Duration::from_secs(5)).await;
    let want: BTreeMap<String, String> = [
        ("claude".to_owned(), claude::VERSION.to_owned()),
        ("codex".to_owned(), "0.1.0".to_owned()),
    ]
    .into();
    assert_eq!(found, want);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 20 runs on one repo start at once: every worktree is set up, none trips over git's lock
/// files, and each sits on its issue's branch.
#[tokio::test]
async fn twenty_parallel_runs_on_one_repo_set_up_without_lock_errors() {
    let dir = scratch("parallel").canonicalize().unwrap();
    let repo = crate::workspace::tests::origin(&dir);
    let ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    let jobs: Vec<Job> = (1..=20)
        .map(|n| Job {
            run: n,
            issue: Some(n),
            workspace: Some(crate::workspace::tests::ws(&repo, n)),
            ..job("codex")
        })
        .collect();
    let started = futures_util::future::join_all(jobs.iter().map(|j| ex.start(j))).await;
    for (n, result) in (1..).zip(started) {
        assert_eq!(result, Ok(None), "run {n}");
        let head = crate::workspace::tests::git(
            &ex.cwd(&jobs[n as usize - 1]),
            &["rev-parse", "--abbrev-ref", "HEAD"],
        );
        assert_eq!(head.trim(), format!("citadel/CIT-{n}"));
    }
    assert_eq!(ex.workspaces(), (1..=20).collect::<Vec<_>>());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_work_root_must_sit_outside_home_and_instruction_files() {
    let dir = scratch("roots").canonicalize().unwrap();
    let at = |root: &str| HarnessExecutor::new(dir.join(root), dir.join("config"));
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    assert_eq!(at("runs").check_roots(&home), Ok(()));
    let why = at("home/runs").check_roots(&home).unwrap_err();
    assert!(why.contains("inside the home"), "{why}");
    std::fs::create_dir_all(dir.join("proj")).unwrap();
    std::fs::write(dir.join("proj/AGENTS.md"), "be nice").unwrap();
    let why = at("proj/runs").check_roots(&home).unwrap_err();
    assert!(why.contains("AGENTS.md"), "{why}");
    let relative = HarnessExecutor::new(PathBuf::from("runs"), dir.join("config"));
    assert!(relative.check_roots(&home).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Token cap (E3.8): a fake `claude` playing its recorded turn is stopped at the cap, from
/// the job or, when the job carries none, the runner's default; the run ends `TokenCap` with
/// its usage reported. Under the cap the run finishes and reports the turn's totals.
#[tokio::test]
async fn a_run_reaching_its_token_cap_is_stopped_with_its_usage_reported() {
    let dir = scratch("cap");
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\nhead -n 2 > /dev/null\nsed '/\"type\":\"result\"/q' {d}/fixture.ndjson\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex.approval_timeout = Duration::from_millis(50);
    // The turn's first assistant message: 2 in, 3 out, 13163 cache read, 6096 cache write.
    let first = Tokens {
        input: 2,
        output: 3,
        cache_read: 13163,
        cache_write: 6096,
        cost_usd_micros: None,
    };
    let result = Tokens {
        input: 4,
        output: 207,
        cache_read: 32422,
        cache_write: 6411,
        // The result's `total_cost_usd`, 0.00171032, forwarded (E7.3).
        cost_usd_micros: Some(1710),
    };
    for (cap, default, outcome, usage) in [
        (Some(100), DEFAULT_TOKEN_CAP, Outcome::TokenCap, first),
        (None, 100, Outcome::TokenCap, first),
        (Some(1_000_000), 100, Outcome::Succeeded, result),
    ] {
        ex.default_token_cap = default;
        let job = Job {
            token_cap: cap,
            ..job("claude")
        };
        ex.start(&job).await.unwrap();
        let (tx, mut rx) = mpsc::channel(256);
        let token = RunToken::new("t".to_owned());
        assert_eq!(ex.run(&job, token, tx).await, outcome, "cap {cap:?}");
        let reports: Vec<Report> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(reports.last(), Some(&Report::Usage(usage)), "cap {cap:?}");
        let ended = reports
            .iter()
            .any(|r| matches!(r, Report::Event(e) if e["type"] == "turn_ended"));
        assert_eq!(ended, outcome == Outcome::Succeeded, "stopped mid-turn");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A harness that dies says why with its stderr tail, which reaches no log on its own;
/// the run's task redacts the reason (`work`).
#[tokio::test]
async fn a_dead_harness_fails_with_its_stderr_tail() {
    let dir = scratch("stderr");
    let bin = dir.join("claude");
    let script = "#!/bin/sh\necho 'starting' >&2\necho 'fatal: bad key sk-ant-api03-planted0123456789abcdef' >&2\nexit 3\n";
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    let job = job("claude");
    ex.start(&job).await.unwrap();
    let (tx, _rx) = mpsc::channel(256);
    let Outcome::Failed { reason, .. } = ex.run(&job, RunToken::new("t".to_owned()), tx).await
    else {
        panic!("not a failure");
    };
    assert!(
        reason.contains("stderr: starting\nfatal: bad key sk-ant-"),
        "{reason}"
    );
}

/// The child is gone before the runner writes its prompt: the write is EPIPE, and the run
/// still fails as a dead harness with its stderr tail, not as a broken pipe.
#[tokio::test]
async fn a_harness_dead_before_the_prompt_fails_with_its_stderr_tail() {
    let dir = scratch("epipe");
    let bin = dir.join("claude");
    let script = "#!/bin/sh\necho 'fatal: gone before the prompt' >&2\nexit 3\n";
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    let job = job("claude");
    ex.start(&job).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let (tx, _rx) = mpsc::channel(256);
    let Outcome::Failed { reason, .. } = ex.run(&job, RunToken::new("t".to_owned()), tx).await
    else {
        panic!("not a failure");
    };
    assert!(
        reason.contains("stderr: fatal: gone before the prompt"),
        "{reason}"
    );
    assert!(!reason.contains("Broken pipe"), "{reason}");
}

/// Secrets for redaction: allowlisted env values marked secret, and the askpass's answers.
#[tokio::test]
async fn secrets_are_the_marked_env_values_and_the_askpass_answers() {
    let dir = scratch("secrets");
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.secret_env = vec!["PATH".to_owned(), "NOT_ALLOWED_ANYWAY".to_owned()];
    let askpass = dir.join("askpass");
    let answers = "#!/bin/sh\ncase \"$1\" in Username*) echo citadel-bot ;; *) echo pa55w0rd-from-askpass ;; esac\n";
    std::fs::write(&askpass, answers).unwrap();
    std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o755)).unwrap();
    ex.workspaces.askpass = Some(askpass);
    let secrets = ex.secrets().await;
    let path = std::env::var("PATH").unwrap();
    assert_eq!(
        secrets,
        vec![
            ("env:PATH".to_owned(), path),
            ("git_askpass".to_owned(), "citadel-bot".to_owned()),
            ("git_askpass".to_owned(), "pa55w0rd-from-askpass".to_owned()),
        ]
    );
}

mod accounts;
mod controls;
mod disk;
mod drops;
mod env;
mod fallbacks;
mod mcp;
mod others;
mod permissions;
mod stall;
mod waits;
mod warm;

/// Usage with `fresh` input and output tokens and `cached` cache reads (1.27 weights).
fn spent(fresh: u64, cached: u64) -> Usage {
    Usage {
        input: fresh,
        output: 0,
        cache_read: cached,
        cache_write: 0,
        cost_usd: None,
    }
}

#[test]
fn cache_reads_count_a_tenth_against_run_token_cap() {
    let run = |run, divisor| TokenCaps {
        exact: None,
        run,
        cache_weight_divisor: divisor,
    };
    // 3.1M cache tokens and 300 output tokens: a re-read context, not work done.
    let rereads = Usage {
        input: 0,
        output: 300,
        cache_read: 3_100_000,
        cache_write: 0,
        cost_usd: None,
    };
    assert!(!reached(&run(3_000_000, 10), &rereads));
    // 3.1M fresh tokens are the work the cap is for.
    assert!(reached(&run(3_000_000, 10), &spent(3_100_000, 0)));
    // A divisor of 1 counts every token in full, as before 1.27.
    assert!(reached(&run(3_000_000, 1), &rereads));
}

#[test]
fn budgets_count_cache_reads_in_full() {
    // The budget's cap is exact: the same re-read context stops it, however cheap it is for
    // `run.token_cap`.
    let budget = TokenCaps {
        exact: Some(3_000_000),
        run: u64::MAX,
        cache_weight_divisor: 10,
    };
    assert!(reached(&budget, &spent(0, 3_100_000)));
    assert!(!reached(&budget, &spent(0, 2_999_999)));
}

#[test]
fn a_run_without_token_caps_counts_every_token_against_its_token_cap() {
    let legacy = Job {
        token_cap: Some(100),
        ..job("claude")
    };
    let caps = legacy.caps(DEFAULT_TOKEN_CAP);
    assert_eq!(caps.least(), 100);
    assert!(reached(&caps, &spent(0, 100)));
    let none = Job {
        token_cap: None,
        ..job("claude")
    };
    assert_eq!(none.caps(7).least(), 7);
    let split = Job {
        token_caps: Some(TokenCaps {
            exact: Some(50),
            run: 900,
            cache_weight_divisor: 10,
        }),
        ..job("claude")
    };
    assert_eq!(split.caps(DEFAULT_TOKEN_CAP), split.token_caps.unwrap());
}
