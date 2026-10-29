//! The runner's `--env` pairs (`with_env`) reach every harness process, and no secret the
//! runner holds: a variable outside the allowlist and the pairs stays absent.

use super::*;

/// A fake `codex app-server` that writes the environment it was started with to `dir/env`,
/// then serves one thread and completes its turn.
fn fake_codex_recording_env(dir: &Path) -> PathBuf {
    let bin = dir.join("codex");
    let d = dir.display();
    let script = format!(
        r#"#!/usr/bin/perl
$| = 1;
open(my $env, '>', '{d}/env'); for my $k (sort keys %ENV) {{ print $env "$k=$ENV{{$k}}\n" }} close($env);
while (my $line = <STDIN>) {{
    my ($id) = $line =~ /"id":(\d+)/;
    my ($method) = $line =~ /"method":"([^"]+)"/;
    next unless defined $id && defined $method;
    if ($method eq 'initialize') {{ print qq({{"id":$id,"result":{{}}}}\n); }}
    elsif ($method eq 'thread/start') {{
        print qq({{"id":$id,"result":{{"thread":{{"id":"thread-1"}}}}}}\n);
    }}
    elsif ($method eq 'turn/start') {{
        print qq({{"id":$id,"result":{{"turn":{{"id":"turn-1"}}}}}}\n);
        print qq({{"method":"turn/completed","params":{{"threadId":"thread-1","turn":{{"id":"turn-1","status":"completed","error":null}}}}}}\n);
    }}
}}
"#
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

#[tokio::test]
async fn the_runner_env_reaches_the_harness_but_no_secret_and_no_other_variable() {
    let dir = scratch("env");
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config")).with_env(vec![
        ("BASH_MAX_TIMEOUT_MS".to_owned(), "1200000".to_owned()),
        (
            "ANTHROPIC_API_KEY".to_owned(),
            "from-the-runner-env".to_owned(),
        ),
    ]);
    ex.bins
        .insert("codex".to_owned(), fake_codex_recording_env(&dir));
    let job = Job {
        model: String::new(),
        ..job("codex")
    };
    ex.start(&job).await.unwrap();
    let (tx, _rx) = mpsc::channel(256);
    let outcome = ex.run(&job, RunToken::new("t".to_owned()), tx).await;
    assert_eq!(outcome, Outcome::Succeeded);

    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    assert!(
        env.lines().any(|l| l == "BASH_MAX_TIMEOUT_MS=1200000"),
        "{env}"
    );
    assert!(!env.contains("from-the-runner-env"), "{env}");
    // Cargo sets this in the test process, so its absence from the harness's environment
    // shows that only the allowlist and the pairs get through.
    assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
    assert!(!env.contains("CARGO_MANIFEST_DIR="), "{env}");
}
