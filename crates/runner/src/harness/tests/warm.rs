//! Warm harness servers (E15.6): a long-lived harness that served a run well serves the
//! agent's next one as a new session on the same process; turned off, every run starts one.

use ainkrad_harness::Spec;
use ainkrad_proto::runner::RunnerLimits;

use super::*;

/// A fake `codex app-server` that serves any number of threads: it logs each spawn and its
/// working dir, answers `initialize`, numbers each `thread/start`, and completes each turn at
/// once.
fn fake_codex(dir: &Path) -> PathBuf {
    let bin = dir.join("codex");
    let d = dir.display();
    let script = format!(
        r#"#!/usr/bin/perl
$| = 1;
use Cwd;
open(my $log, '>>', '{d}/spawns'); print $log "spawn in ", getcwd(), "\n"; close($log);
my $n = 0;
while (my $line = <STDIN>) {{
    my ($id) = $line =~ /"id":(\d+)/;
    my ($method) = $line =~ /"method":"([^"]+)"/;
    next unless defined $id && defined $method;
    if ($method eq 'initialize') {{ print qq({{"id":$id,"result":{{}}}}\n); }}
    elsif ($method eq 'thread/start') {{
        $n++; print qq({{"id":$id,"result":{{"thread":{{"id":"thread-$n"}}}}}}\n);
    }}
    elsif ($method eq 'turn/start') {{
        print qq({{"id":$id,"result":{{"turn":{{"id":"turn-$n"}}}}}}\n);
        print qq({{"method":"turn/completed","params":{{"threadId":"thread-$n","turn":{{"id":"turn-$n","status":"completed","error":null}}}}}}\n);
    }}
}}
"#
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

/// Runs `job` to its end: its outcome and its transcript.
async fn work(ex: &HarnessExecutor, job: &Job) -> (Outcome, Vec<Value>) {
    ex.start(job).await.unwrap();
    let (tx, mut rx) = mpsc::channel(256);
    let outcome = ex.run(job, RunToken::new("t".to_owned()), tx).await;
    (outcome, chunks(&mut rx))
}

fn session(events: &[Value]) -> String {
    let started = events.iter().find(|e| e["type"] == "session_started");
    started.expect("a session")["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn a_warm_server_takes_the_next_task_as_a_new_session() {
    let dir = scratch("warm");
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("codex".to_owned(), fake_codex(&dir));
    ex.warm_max = 2;
    let first = Job {
        model: String::new(),
        ..job("codex")
    };
    let second = Job {
        run: 8,
        ..first.clone()
    };

    let (outcome, events) = work(&ex, &first).await;
    assert_eq!(outcome, Outcome::Succeeded);
    assert_eq!(session(&events), "thread-1");
    assert_eq!(ex.warm_idle(), 1, "kept for the next run");
    let (outcome, events) = work(&ex, &second).await;
    assert_eq!(outcome, Outcome::Succeeded);
    assert!(
        events.iter().any(|e| e["type"] == "harness_reused"),
        "{events:?}"
    );
    assert_eq!(
        session(&events),
        "thread-2",
        "a new session, not the last run's"
    );
    let spawns = std::fs::read_to_string(dir.join("spawns")).unwrap();
    assert_eq!(spawns.lines().count(), 1, "one process for both runs");

    // Another agent's run gets its own process.
    let other = Job {
        run: 9,
        agent: 2,
        ..first.clone()
    };
    work(&ex, &other).await;
    let spawns = std::fs::read_to_string(dir.join("spawns")).unwrap();
    assert_eq!(spawns.lines().count(), 2);
    assert_eq!(ex.warm_idle(), 2);
    // A warm server works from the work root, which outlives every worktree (E15.9).
    let root = dir.join("work").canonicalize().unwrap();
    for spawn in spawns.lines() {
        assert_eq!(spawn, format!("spawn in {}", root.display()));
    }

    // Idle past `runner.warm_idle_secs`, they are stopped by the clean-up pass.
    let limits = RunnerLimits {
        warm_idle_secs: 3600,
        ..RunnerLimits::default()
    };
    ex.set_limits(limits);
    ex.housekeep().await;
    assert_eq!(ex.warm_idle(), 2, "not idle long enough");
    ex.set_limits(RunnerLimits {
        warm_idle_secs: 0,
        ..limits
    });
    ex.housekeep().await;
    assert_eq!(ex.warm_idle(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn turned_off_every_run_starts_its_own_process() {
    let dir = scratch("cold");
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("codex".to_owned(), fake_codex(&dir));
    let first = Job {
        model: String::new(),
        ..job("codex")
    };
    let (_, events) = work(&ex, &first).await;
    assert_eq!(session(&events), "thread-1");
    let (_, events) = work(
        &ex,
        &Job {
            run: 8,
            ..first.clone()
        },
    )
    .await;
    assert_eq!(
        session(&events),
        "thread-1",
        "a new process numbers from 1 again"
    );
    assert!(!events.iter().any(|e| e["type"] == "harness_reused"));
    let spawns = std::fs::read_to_string(dir.join("spawns")).unwrap();
    assert_eq!(spawns.lines().count(), 2);
    assert_eq!(ex.warm_idle(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_changed_runner_env_is_a_new_warm_key() {
    let spec = |value: &str| Spec {
        env: vec![("BASH_MAX_TIMEOUT_MS".into(), value.into())],
        ..Spec::default()
    };
    let job = job("codex");
    assert_ne!(
        super::super::warm::key(&job, &spec("1200000")),
        super::super::warm::key(&job, &spec("600000")),
        "a warm process started with other env is not reused"
    );
    assert_eq!(
        super::super::warm::key(&job, &spec("1200000")),
        super::super::warm::key(&job, &spec("1200000")),
    );
}
