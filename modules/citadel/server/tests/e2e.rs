//! The Phase A end-to-end run (E4.4), deterministic: `scripts/e2e.sh`'s flow with a fake
//! harness, so `make test` covers it without a model. The admin CLI seeds a company, agent,
//! project (with a git repo) and issue; the `citadel-server` binary serves on a loopback port;
//! a real runner (`HarnessExecutor`) works the run through a fake `claude` that does what an
//! agent would: it reads its MCP config, then starts, comments on and finishes the issue
//! through `/mcp/v1` with curl, and plays a recorded turn. Then the same checks as the script.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use ainkrad_harness::claude;
use ainkrad_runner::{Config, HarnessExecutor, mcp_url};
use sqlx::SqlitePool;

const RESULT: &str = include_str!("../../../../crates/harness/tests/fixtures/claude/resume.ndjson");

/// A fake `claude`: the agent's three MCP calls with curl, then a recorded turn. It keeps the
/// bearer it was given in `auth`, so the test can look for it where it must not be.
fn fake_claude(dir: &Path) -> PathBuf {
    std::fs::write(dir.join("result.ndjson"), RESULT).unwrap();
    let d = dir.display();
    let call = |name: &str, args: &str| {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{args}}}}}"#
        );
        format!(
            "printf 'Authorization: %s\\n' \"$auth\" | curl -sS -H @- \
             -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
             --data '{body}' \"$url\" >> {d}/calls\necho >> {d}/calls\n"
        )
    };
    let script = format!(
        "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = --mcp-config ] && cfg=$2; shift; done\n\
         field() {{ perl -MJSON::PP -0777 -ne \"print decode_json(\\$_)->{{mcpServers}}{{citadel}}$1\" \"$cfg\"; }}\n\
         url=$(field '{{url}}')\nauth=$(field '{{headers}}{{Authorization}}')\n\
         printf '%s' \"$auth\" > {d}/auth\nhead -n 2 > /dev/null\n{}{}{}cat {d}/result.ndjson\n",
        call("transition", r#"{"transition":"start"}"#),
        call("comment", r#"{"body":"e2e: hello from the fake agent"}"#),
        call("transition", r#"{"transition":"done"}"#),
    );
    let bin = dir.join("claude");
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    bin
}

/// Runs the server binary with `args` and returns what it printed (the new id).
fn cli(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_citadel-server"))
        .args(args)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{args:?}: {err}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// A count from `sql`, its one parameter bound to `id`.
async fn count(pool: &SqlitePool, sql: &'static str, id: &str) -> i64 {
    let id: i64 = id.parse().unwrap();
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn an_agent_works_an_issue_through_mcp_end_to_end() {
    let dir = std::env::temp_dir().join(format!("citadel-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // The runner refuses local paths (E2-10): the repo is served over HTTPS by the git fixture,
    // and only this test's runner trusts the fixture's throwaway CA (see `ainkrad_gitfixture`).
    let served = dir.join("served");
    std::fs::create_dir_all(&served).unwrap();
    ainkrad_gitfixture::bare_repo(&served, "repo.git", |_| {});
    let ca = ainkrad_gitfixture::Ca::new(&dir.join("ca"));
    let git_server = ainkrad_gitfixture::Server::start(
        &ca,
        ainkrad_gitfixture::Config {
            root: served,
            ..Default::default()
        },
    )
    .await;
    let db = dir.join("citadel.db");
    let db_arg = db.to_str().unwrap();
    let repo = git_server.url("127.0.0.1", "repo.git");

    let company = cli(&["company", "add", db_arg, "E2E Co"]);
    let agent = cli(&[
        "agent",
        "add",
        db_arg,
        &company,
        "Dev",
        "--harness",
        "claude",
    ]);
    // A new agent waits on its hire approval (E6.4); approve it so it can run.
    let hire = cli(&["approval", "list", db_arg, &company]);
    let hire = hire.split('\t').next().unwrap().to_owned();
    cli(&["approval", "approve", db_arg, &hire]);
    let project = cli(&[
        "project",
        "add",
        db_arg,
        &company,
        "E2E",
        "E2E project",
        "--repo",
        &repo,
    ]);
    let key = cli(&["runner", "add", db_arg, "e2e"]);
    let issue = cli(&[
        "issue",
        "add",
        db_arg,
        &project,
        "Report in",
        "--assignee",
        &agent,
    ]);

    // A one-point task: small (E15.5), so it must also start fast (E15.6).
    cli(&["issue", "estimate", db_arg, &issue, "1"]);

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bind = format!("127.0.0.1:{port}");
    let mut server = tokio::process::Command::new(env!("CARGO_BIN_EXE_citadel-server"))
        .args(["serve", db_arg, "--bind", &bind])
        .stderr(std::fs::File::create(dir.join("server.log")).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(&bind).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let url = format!("ws://{bind}/runner/v1/connect");
    let mut executor = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    executor.workspaces.git = ca.git_shim(&dir);
    executor.bins.insert("claude".to_owned(), fake_claude(&dir));
    executor.mcp_url = mcp_url(&url);
    executor
        .workspaces
        .set_identity(Some("Citadel E2E"), Some("e2e@citadel.invalid"))
        .await
        .unwrap();
    let config = Config {
        log: None,
        url,
        key: key.clone(),
        tags: vec![],
        harnesses: [("claude".to_owned(), claude::VERSION.to_owned())].into(),
    };
    let runner = tokio::spawn(ainkrad_runner::run(config, executor));

    let pool = citadel_server::store::connect(&db).await.unwrap();
    let ended = "SELECT count(*) FROM runs WHERE issue_id = ? \
                 AND state NOT IN ('queued', 'claimed', 'running')";
    for _ in 0..600 {
        if count(&pool, ended, &issue).await > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    runner.abort();
    let _ = server.kill().await;

    let calls = std::fs::read_to_string(dir.join("calls")).unwrap_or_default();
    let (state, reason): (String, Option<String>) =
        sqlx::query_as("SELECT state, terminal_reason FROM runs ORDER BY id LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state, "succeeded", "{reason:?}; calls: {calls}");
    assert!(reason.is_some());
    assert!(!calls.contains("\"isError\":true"), "{calls}");
    let done = "SELECT count(*) FROM issues WHERE id = ? AND state = 'done'";
    assert_eq!(count(&pool, done, &issue).await, 1, "the agent moved it");
    let by_agent = "SELECT count(*) FROM comments WHERE author_agent_id = ? AND run_id = 1";
    assert_eq!(count(&pool, by_agent, &agent).await, 1);
    let usage = "SELECT count(*) FROM cost_events WHERE run_id = ? \
                 AND input_tokens + output_tokens > 0";
    assert!(count(&pool, usage, "1").await >= 1, "usage recorded");
    let chunks = "SELECT count(*) FROM run_events WHERE run_id = ?";
    assert!(count(&pool, chunks, "1").await > 0, "transcript stored");
    let mcp = "SELECT count(*) FROM audit_events WHERE run_id = ? AND action LIKE 'mcp.%' \
               AND actor_kind = 'agent'";
    assert_eq!(
        count(&pool, mcp, "1").await,
        3,
        "each call audited as the agent"
    );

    // Stage timings (E15.6): every stage stamped, in order, and this small task's first token
    // inside the `latency.first_token_budget_secs` default (10 s), so nothing was warned.
    let (stages, ordered): (String, bool) = sqlx::query_as(
        "SELECT printf('wake→claim %.3fs, claim→workspace %.3fs, workspace→harness %.3fs, \
             harness→first token %.3fs, wake→first token %.3fs, first token→end %.3fs', \
             (julianday(claimed_at) - julianday(woken_at)) * 86400, \
             (julianday(started_at) - julianday(claimed_at)) * 86400, \
             (julianday(harness_started_at) - julianday(started_at)) * 86400, \
             (julianday(first_token_at) - julianday(harness_started_at)) * 86400, \
             (julianday(first_token_at) - julianday(woken_at)) * 86400, \
             (julianday(ended_at) - julianday(first_token_at)) * 86400), \
         julianday(woken_at) <= julianday(claimed_at) \
             AND julianday(claimed_at) <= julianday(started_at) \
             AND julianday(started_at) <= julianday(harness_started_at) \
             AND julianday(harness_started_at) <= julianday(first_token_at) \
             AND julianday(first_token_at) <= julianday(ended_at) \
             AND (julianday(first_token_at) - julianday(woken_at)) * 86400 < 10 \
         FROM runs WHERE id = 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    eprintln!("e2e stage timings: {stages}");
    let tier: Option<String> = sqlx::query_scalar("SELECT tier FROM runs WHERE id = 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tier.as_deref(), Some("small"));
    assert!(ordered, "{stages}");
    let slow =
        "SELECT count(*) FROM audit_events WHERE run_id = ? AND action = 'run.first_token_slow'";
    assert_eq!(count(&pool, slow, "1").await, 0, "{stages}");

    // The token the harness held, and the runner key, are nowhere they must not be.
    let auth = std::fs::read_to_string(dir.join("auth")).unwrap();
    let token = auth.strip_prefix("Bearer ").expect("a bearer").to_owned();
    assert!(token.starts_with("cit_run_"));
    let payloads: Vec<String> = sqlx::query_scalar("SELECT payload FROM run_events")
        .fetch_all(&pool)
        .await
        .unwrap();
    let log = std::fs::read_to_string(dir.join("server.log")).unwrap();
    for text in payloads.iter().chain([&log]) {
        assert!(
            !text.contains(&token) && !text.contains(&key),
            "leaked: {text}"
        );
    }
    let private = dir.join("work/private");
    // Only the runner's `citadel` CLI stays (E15.18); it holds no secret.
    let left: Vec<_> = std::fs::read_dir(private)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, ["bin"], "run files removed");
    let _ = std::fs::remove_dir_all(&dir);
}
