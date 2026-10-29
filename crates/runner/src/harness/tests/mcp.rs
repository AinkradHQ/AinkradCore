//! The agent interface (E4.2): the harness gets the run's MCP config and instructions by
//! private file, the token never in argv, env or transcript, and the files go when the run ends.

use super::*;

#[tokio::test]
async fn a_run_gets_a_private_mcp_config_that_dies_with_it() {
    let dir = scratch("mcp");
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    // Keeps its argv, env, stdin, and the MCP file's mode and contents while it runs.
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {d}/argv\nenv > {d}/env\n\
             mcp=$(sed -n '/^--mcp-config$/{{n;p;}}' {d}/argv)\n\
             notes=$(sed -n '/^--append-system-prompt-file$/{{n;p;}}' {d}/argv)\n\
             perl -e 'printf \"%o\\n\", (stat $ARGV[0])[2] & 07777' \"$mcp\" > {d}/mode\n\
             cp \"$mcp\" {d}/mcp.json\ncp \"$notes\" {d}/notes.md\n\
             head -n 2 > {d}/stdin\nsed '/\"type\":\"result\"/q' {d}/fixture.ndjson\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex.approval_timeout = Duration::from_millis(50);
    ex.mcp_url = mcp_url("ws://127.0.0.1:7700/runner/v1/connect");

    let job = Job {
        instructions: Some("# Skill: rust (v1)\n\nWrite Rust.\n".to_owned()),
        prompt: Some("You are the Developer on CIT-3. Your job on this wake: ship it.".to_owned()),
        ..job("claude")
    };
    ex.start(&job).await.unwrap();
    let (tx, mut rx) = mpsc::channel(256);
    let secret = "cit_run_0123456789abcdef";
    let outcome = ex.run(&job, RunToken::new(secret.to_owned()), tx).await;
    assert_eq!(outcome, Outcome::Succeeded);

    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
    assert_eq!(read("mode").trim(), "600");
    let config: Value = serde_json::from_str(&read("mcp.json")).unwrap();
    let server = &config["mcpServers"]["citadel"];
    assert_eq!(server["url"], "http://127.0.0.1:7700/mcp/v1");
    assert_eq!(
        server["headers"]["Authorization"],
        format!("Bearer {secret}")
    );
    let notes = read("notes.md");
    assert!(notes.starts_with("# Skill: rust (v1)\n\nWrite Rust.\n\n## Citadel from your shell"));
    // The server's prompt (1.22) is the run's first turn.
    let prompt = "You are the Developer on CIT-3. Your job on this wake: ship it.";
    assert!(read("stdin").contains(prompt), "{}", read("stdin"));
    for leak in ["argv", "env", "stdin"] {
        assert!(!read(leak).contains(secret), "the token is in {leak}");
    }
    for chunk in chunks(&mut rx) {
        assert!(
            !chunk.to_string().contains(secret),
            "the token is in {chunk}"
        );
    }
    let private = dir.join("work/private");
    assert_eq!(
        left(&private),
        ["bin"],
        "the run's files are gone; the CLI stays"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// What is left in the private dir: only the runner's `citadel` CLI (E15.18), no secret.
fn left(private: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(private)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A cancelled run (its future dropped mid-turn) still loses its files.
#[tokio::test]
async fn a_cancelled_run_loses_its_files_too() {
    let dir = scratch("mcp-cancel");
    let bin = dir.join("claude");
    std::fs::write(&bin, "#!/bin/sh\nexec sleep 30\n").unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex.mcp_url = mcp_url("ws://127.0.0.1:7700/runner/v1/connect");
    let job = job("claude");
    ex.start(&job).await.unwrap();
    let (tx, _rx) = mpsc::channel(256);
    let token = RunToken::new("cit_run_x".to_owned());
    let run = ex.run(&job, token, tx);
    let cut = tokio::time::timeout(Duration::from_millis(300), run).await;
    assert!(cut.is_err(), "still running when dropped");
    let private = dir.join("work/private");
    assert_eq!(left(&private), ["bin"]);
    let _ = std::fs::remove_dir_all(&dir);
}
