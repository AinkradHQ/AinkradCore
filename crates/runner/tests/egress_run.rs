//! E8a-01.4 vector 16 and the refusals in `routes.rs`, through the real entry points: a v2 agent
//! session (`ProcessSandbox::prepare`, then `HarnessExecutor::run` with the environment `prepare`
//! produced) and a v1-style executor. A fake `codex` runs inside the real bubblewrap sandbox and
//! reports what it could reach. The v1 runner mode has no sandbox at all (its sandboxed runs are
//! refused), so for it the vector is: no `AINKRAD_*` control variable can be set from `--env`.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::Write;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_proto::runner::{Outcome, Policy, RunToken};
use ainkrad_proto::v2::AgentStart;
use ainkrad_runner::egress::Policy as Egress;
use ainkrad_runner::v2::ProcessSandbox;
use ainkrad_runner::v2::agent::Sandbox;
use ainkrad_runner::{Executor, HarnessExecutor, Job};

fn listener() -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            h.fetch_add(1, Ordering::SeqCst);
            let _ = c.write_all(b"hi");
        }
    });
    (port, hits)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("egress-run-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.canonicalize().unwrap()
}

/// A fake `codex app-server`: writes what it can reach to `$TMPDIR/probe` (and its environment to
/// `$TMPDIR/env`), then serves one thread and completes its turn.
fn fake_codex(dir: &Path, target: u16, canary: u16) -> PathBuf {
    // Its own directory: the sandbox binds a program's directory read-only after the session's
    // writable ones, so it must not be an ancestor of them.
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    let bin = dir.join("bin/codex");
    let script = format!(
        r#"#!/usr/bin/perl
use IO::Socket::INET;
$| = 1;
my $tmp = $ENV{{TMPDIR}} || '{d}';
open(my $env, '>', "$tmp/env"); for my $k (sort keys %ENV) {{ print $env "$k=$ENV{{$k}}\n" }} close($env);
sub ask {{
    my $t = shift;
    my $s;
    for (1..40) {{ $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => 47832, Timeout => 2) and last; select(undef, undef, undef, 0.1); }}
    return 'noproxy' unless $s;
    print $s "CONNECT $t HTTP/1.1\r\nHost: $t\r\n\r\n";
    my $l = <$s>; $l = '' unless defined $l; $l =~ s/\r?\n//;
    return $l;
}}
if ($ENV{{AINKRAD_EGRESS_SOCK}}) {{
    open(my $o, '>', "$tmp/probe");
    print $o "allowed=" . ask("127.0.0.1:{target}") . "\n";
    print $o "meta=" . ask("169.254.169.254:80") . "\n";
    my $d = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => {canary}, Timeout => 3);
    print $o "direct=" . ($d ? "reached" : "none") . "\n";
    close $o;
}}
while (my $line = <STDIN>) {{
    my ($id) = $line =~ /"id":(\d+)/;
    my ($method) = $line =~ /"method":"([^"]+)"/;
    next unless defined $id && defined $method;
    if ($method eq 'initialize') {{ print qq({{"id":$id,"result":{{}}}}\n); }}
    elsif ($method eq 'thread/start') {{ print qq({{"id":$id,"result":{{"thread":{{"id":"thread-1"}}}}}}\n); }}
    elsif ($method eq 'turn/start') {{
        print qq({{"id":$id,"result":{{"turn":{{"id":"turn-1"}}}}}}\n);
        print qq({{"method":"turn/completed","params":{{"threadId":"thread-1","turn":{{"id":"turn-1","status":"completed","error":null}}}}}}\n);
    }}
}}
"#,
        d = dir.display()
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

fn job() -> Job {
    Job {
        run: 7,
        agent: 1,
        issue: None,
        harness: "codex".to_owned(),
        model: String::new(),
        context_ref: "citadel://issues/3".to_owned(),
        workspace: None,
        token_cap: None,
        token_caps: None,
        policy: Policy::default(),
        issue_key: None,
        instructions: None,
        account: None,
        fallbacks: vec![],
        limits: None,
        resume_session: None,
        prompt: None,
        repos: vec![],
    }
}

fn start_request() -> AgentStart {
    AgentStart {
        session: "as_egress".to_owned(),
        harness: "codex".to_owned(),
        model: None,
        prompt: None,
        workspace: None,
        policy: Default::default(),
        resume: None,
        secrets: vec![],
        epoch: 0,
    }
}

/// What a v2 session's `prepare` hands the executor.
fn prepared(dir: &Path, ready: bool) -> Result<Vec<(String, String)>, String> {
    let state = dir.join("state");
    std::fs::create_dir_all(state.join("agents/as_egress")).unwrap();
    let mut sandbox =
        ProcessSandbox::new(state, dir.join("secrets")).with_network(Some("filtered".to_owned()));
    if ready {
        sandbox = sandbox.with_egress_ready();
    }
    let mut env = vec![];
    sandbox.prepare(&start_request(), &mut env)?;
    Ok(env)
}

fn executor(dir: &Path, target: u16, canary: u16) -> HarnessExecutor {
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins
        .insert("codex".to_owned(), fake_codex(dir, target, canary));
    ex.forwarder = Some(PathBuf::from(env!("CARGO_BIN_EXE_ainkrad-runner")));
    std::fs::create_dir_all(dir.join("work/run-7")).unwrap();
    ex
}

async fn run(ex: &HarnessExecutor, env: Option<Vec<(String, String)>>) -> Outcome {
    let job = job();
    if let Some(env) = env {
        ex.session_env(job.run, Some(env));
    }
    ex.start(&job).await.unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(256);
    ex.run(&job, RunToken::new("t".to_owned()), tx).await
}

fn parse(path: &Path) -> HashMap<String, String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// Vector 16 (v2 path): prepare -> run. Vectors 1, 3, 13: the allowed destination is tunnelled,
/// metadata is refused, a direct connection to the host loopback finds no route. The runner's
/// `--env` carries a stale `allow` and a redirected egress socket: neither takes effect.
#[tokio::test]
async fn a_v2_session_reaches_only_the_proxy_even_with_a_stale_runner_env() {
    let dir = scratch("v2");
    let (target, target_hits) = listener();
    let (canary, canary_hits) = listener();
    let mut ex = executor(&dir, target, canary).with_env(vec![
        ("AINKRAD_SANDBOX_NETWORK".to_owned(), "allow".to_owned()),
        (
            "AINKRAD_SANDBOX_EGRESS_SOCK".to_owned(),
            "/tmp/evil.sock".to_owned(),
        ),
    ]);
    ex.egress = Some(Arc::new(
        Egress::parse("127.0.0.1/32", "", &target.to_string()).unwrap(),
    ));
    let env = prepared(&dir, true).unwrap();
    assert!(
        env.iter()
            .any(|(k, v)| k == "AINKRAD_SANDBOX_NETWORK" && v == "filtered")
    );
    let outcome = run(&ex, Some(env)).await;
    assert_eq!(outcome, Outcome::Succeeded);

    let tmp = dir.join("state/private-tmp/as_egress");
    let probe = parse(&tmp.join("probe"));
    assert!(probe["allowed"].contains(" 200 "), "{probe:?}");
    assert!(probe["meta"].contains(" 403 "), "{probe:?}");
    assert_eq!(
        probe["direct"], "none",
        "the host loopback was reachable: {probe:?}"
    );
    assert_eq!(target_hits.load(Ordering::SeqCst), 1);
    assert_eq!(canary_hits.load(Ordering::SeqCst), 0);
    let seen = parse(&tmp.join("env"));
    assert_eq!(seen["HTTPS_PROXY"], "http://127.0.0.1:47832");
    assert_eq!(seen["NO_PROXY"], "127.0.0.1,localhost");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_filtered_run_without_a_policy_is_refused_and_the_harness_never_starts() {
    let dir = scratch("nopolicy");
    let ex = executor(&dir, 1, 2);
    assert!(ex.egress.is_none());
    let env = prepared(&dir, true).unwrap();
    let outcome = run(&ex, Some(env)).await;
    let Outcome::Failed {
        reason,
        fingerprint,
    } = outcome
    else {
        panic!("a filtered run without a policy must not start: {outcome:?}");
    };
    assert!(reason.contains("egress policy"), "{reason}");
    assert_eq!(fingerprint.as_deref(), Some("sandbox"));
    assert!(
        !dir.join("state/private-tmp/as_egress/env").exists(),
        "the harness started"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_proxy_that_cannot_start_refuses_the_run() {
    let dir = scratch("nosocket");
    let (target, _) = listener();
    // A work root so deep that the run's socket path exceeds what a unix socket can bind.
    let deep = dir.join("w".repeat(100));
    let mut ex = executor(&dir, target, 2);
    ex.work_root = deep.clone();
    std::fs::create_dir_all(deep.join("run-7")).unwrap();
    ex.egress = Some(Arc::new(Egress::parse("", "", "").unwrap()));
    let env = prepared(&dir, true).unwrap();
    let outcome = run(&ex, Some(env)).await;
    let Outcome::Failed {
        reason,
        fingerprint,
    } = outcome
    else {
        panic!("an unstartable proxy must refuse the run: {outcome:?}");
    };
    assert!(reason.contains("egress proxy"), "{reason}");
    assert_eq!(fingerprint.as_deref(), Some("sandbox"));
    assert!(
        !dir.join("state/private-tmp/as_egress/env").exists(),
        "the harness started"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Vector 16 (v1 path): this mode has no sandbox, and `--env` cannot carry a control variable
/// that would give a run one or change its network mode.
#[tokio::test]
async fn a_v1_executor_passes_no_control_variable_to_a_harness() {
    let dir = scratch("v1");
    let ex = executor(&dir, 1, 2).with_env(vec![
        ("AINKRAD_SANDBOX".to_owned(), "1".to_owned()),
        ("AINKRAD_SANDBOX_NETWORK".to_owned(), "allow".to_owned()),
        ("KEEP".to_owned(), "yes".to_owned()),
    ]);
    // No session env: a v1 job.
    let outcome = run(&ex, None).await;
    assert_eq!(outcome, Outcome::Succeeded);
    let seen = parse(&dir.join("env"));
    assert_eq!(seen.get("KEEP").map(String::as_str), Some("yes"));
    assert!(!seen.keys().any(|k| k.starts_with("AINKRAD_")), "{seen:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn prepare_refuses_filtered_on_a_runner_that_did_not_prove_the_filter() {
    let dir = scratch("unproven");
    let err = prepared(&dir, false).unwrap_err();
    assert!(err.contains("filtered"), "{err}");
    assert!(prepared(&dir, true).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The runner and the sandbox builder read a repeated network mode the same way (the last value):
/// with `deny` last, a run with no egress policy is not refused for a `filtered` earlier in the
/// list, and nothing is proxied.
#[tokio::test]
async fn the_runner_and_the_builder_agree_on_a_repeated_network_mode() {
    let dir = scratch("last");
    let ex = executor(&dir, 1, 2);
    assert!(ex.egress.is_none());
    let mut env = prepared(&dir, true).unwrap();
    env.push(("AINKRAD_SANDBOX_NETWORK".to_owned(), "deny".to_owned()));
    let outcome = run(&ex, Some(env)).await;
    assert_eq!(outcome, Outcome::Succeeded);
    let seen = parse(&dir.join("state/private-tmp/as_egress/env"));
    assert!(!seen.contains_key("HTTPS_PROXY"), "{seen:?}");
    assert!(!dir.join("state/private-tmp/as_egress/probe").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
