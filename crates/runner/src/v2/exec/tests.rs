//! The `exec` driver on its own: limits, process groups, reaping, environment, redaction.

use std::collections::BTreeMap;

use ainkrad_proto::v2::ExecLimits;

use super::*;

pub(crate) const RUNNER_KEY: &str = "cit_runner_planted0123456789abcdefghijklmnop";
pub(crate) const PLANTED: &str = "planted-aws-secret-0123456789";

/// A driver with a planted secret in the runner's env (not allow-listed) and the runner key
/// registered with its redactor.
pub(crate) fn driver(capacity: u32) -> ExecDriver {
    let mut redactor = Redactor::new();
    redactor.known("runner_key", RUNNER_KEY);
    let mut env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    env.push(("AWS_SECRET_ACCESS_KEY".into(), PLANTED.into()));
    let config = ExecConfig {
        capacity,
        kill_grace: Duration::from_millis(300),
        env_allow: vec!["PATH".to_owned()],
        env,
        ..ExecConfig::default()
    };
    ExecDriver::new(config, redactor)
}

pub(crate) fn sh(script: &str, timeout_ms: u64, max_output_bytes: Option<u64>) -> ExecRun {
    ExecRun {
        program: "/bin/sh".to_owned(),
        args: vec!["-c".to_owned(), script.to_owned()],
        cwd: None,
        env: BTreeMap::new(),
        env_pass: vec![],
        limits: ExecLimits {
            timeout_ms: Some(timeout_ms),
            max_output_bytes,
        },
    }
}

fn never() -> oneshot::Receiver<()> {
    let (tx, rx) = oneshot::channel();
    std::mem::forget(tx);
    rx
}

/// Process `pid`'s state letter (`Z` for a zombie), or `None` when it is gone.
fn state(pid: u32) -> Option<char> {
    let out = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().chars().next()
}

/// Our own children that are zombies. Another test's child can be one for an instant before
/// tokio reaps it, so a leak is one that stays.
fn zombie_children() -> Vec<String> {
    let me = std::process::id().to_string();
    let mut zombies = vec![];
    for _ in 0..20 {
        let out = std::process::Command::new("ps")
            .args(["-A", "-o", "ppid=,pid=,stat="])
            .output()
            .expect("ps");
        zombies = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                (f.len() == 3 && f[0] == me && f[2].starts_with('Z')).then(|| l.to_owned())
            })
            .collect();
        if zombies.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    zombies
}

#[tokio::test]
async fn a_runaway_command_is_killed_at_its_timeout_with_its_grandchildren() {
    let d = driver(1);
    let started = Instant::now();
    let r = d
        .run(&sh("sleep 30 & echo $!; wait", 200, None), never())
        .await
        .unwrap();
    assert!(r.timed_out, "{r:?}");
    assert_eq!(r.exit_code, None);
    assert!(started.elapsed() < Duration::from_secs(5));
    let grandchild: u32 = r.stdout.text.trim().parse().unwrap();
    // Gone, or a zombie of whoever adopted it (PID 1 in a container may not reap).
    assert!(
        matches!(state(grandchild), None | Some('Z')),
        "{grandchild} survived"
    );
}

#[tokio::test]
async fn a_child_ignoring_term_gets_kill_after_the_grace() {
    let d = driver(1);
    let started = Instant::now();
    let script = "trap '' TERM; echo ready; while :; do sleep 0.05; done";
    let r = d.run(&sh(script, 200, None), never()).await.unwrap();
    assert!(r.timed_out);
    assert_eq!(r.exit_code, None);
    assert_eq!(r.stdout.text, "ready\n");
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(500), "no grace: {took:?}");
    assert!(took < Duration::from_secs(5), "{took:?}");
}

#[tokio::test]
async fn a_hundred_runs_leave_no_zombie() {
    let d = driver(1);
    for i in 0..100 {
        // Normal exit, timeout, and cancel, with a background grandchild each time.
        let (script, timeout) = match i % 3 {
            0 => ("sleep 30 & exit 3", 5_000),
            _ => ("sleep 30 & sleep 30", 20),
        };
        let cancel = if i % 3 == 2 {
            let (tx, rx) = oneshot::channel();
            drop(tx);
            rx
        } else {
            never()
        };
        let r = d.run(&sh(script, timeout, None), cancel).await;
        match i % 3 {
            0 => assert_eq!(r.unwrap().exit_code, Some(3)),
            1 => assert!(r.unwrap().timed_out),
            _ => assert_eq!(r.unwrap_err().code, ErrorCode::Cancelled),
        }
    }
    assert_eq!(zombie_children(), Vec::<String>::new());
}

#[tokio::test]
async fn output_past_the_limit_is_cut_and_marked() {
    let d = driver(1);
    let r = d
        .run(
            &sh("head -c 100000 /dev/zero | tr '\\0' a", 5_000, Some(1000)),
            never(),
        )
        .await
        .unwrap();
    assert_eq!(r.exit_code, Some(0));
    assert!(r.stdout.truncated);
    assert_eq!(r.stdout.bytes, 100_000);
    assert_eq!(
        r.stdout.text,
        format!("{}{TRUNCATED_MARKER}", "a".repeat(1000))
    );
    assert!(!r.stderr.truncated);
}

#[tokio::test]
async fn a_secret_across_the_cut_is_still_masked() {
    let d = driver(1);
    // The key starts 10 bytes before the limit.
    let script = format!("printf '%990s{RUNNER_KEY}tail' x");
    let r = d
        .run(&sh(&script, 5_000, Some(1000)), never())
        .await
        .unwrap();
    assert!(r.stdout.truncated);
    assert!(
        !r.stdout.text.contains(&RUNNER_KEY[..10]),
        "{}",
        r.stdout.text
    );
}

#[tokio::test]
async fn the_child_env_is_the_allow_list_only() {
    let d = driver(1);
    let mut req = sh("env", 5_000, None);
    req.program = "/usr/bin/env".to_owned();
    req.args.clear();
    // The Core asks for the planted secret too: it is not on the runner's allow-list.
    req.env_pass = vec![
        "PATH".to_owned(),
        "AWS_SECRET_ACCESS_KEY".to_owned(),
        "HOME".to_owned(),
    ];
    req.env = BTreeMap::from([("LANG".to_owned(), "C".to_owned())]);
    let r = d.run(&req, never()).await.unwrap();
    let names: Vec<&str> = r
        .stdout
        .text
        .lines()
        .filter_map(|l| l.split('=').next())
        .collect();
    assert_eq!(names.len(), 2, "{}", r.stdout.text);
    assert!(names.contains(&"PATH") && names.contains(&"LANG"));
    assert!(!r.stdout.text.contains(PLANTED));
}

#[tokio::test]
async fn bad_requests_are_refused_before_spawning() {
    let d = driver(1);
    let mut req = sh("true", 1_000, None);
    req.cwd = Some("relative".to_owned());
    assert_eq!(
        d.run(&req, never()).await.unwrap_err().code,
        ErrorCode::InvalidArgs
    );
    req.cwd = None;
    req.program = "/nonexistent/program".to_owned();
    assert_eq!(
        d.run(&req, never()).await.unwrap_err().code,
        ErrorCode::SpawnFailed
    );
}
