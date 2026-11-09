//! Accounts end to end (E15.1): three accounts of one company take turns, each run's harness
//! gets its own account's config dir and token, and no token ever reaches the server: not
//! the database file, its WAL, a transcript, a log line, or an argv.

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use citadel_core::audit::AuditActor;
use citadel_core::org::Harness;
use citadel_server::store::exec::{list_run_events, list_runs};
use citadel_server::store::gov::{assign_account, create_account, new_account};
use ainkrad_runner::HarnessExecutor;

use super::support::*;
use crate::harness::{agent, assign, company, issue, runner};

const FIXTURE: &str = include_str!("../../../../../crates/harness/tests/fixtures/claude/resume.ndjson");
const TOKENS: [&str; 3] = [
    "sk-ant-oat01-first-account-planted-1111",
    "sk-ant-oat01-second-account-planted-2222",
    "sk-ant-oat01-third-account-planted-3333",
];

fn on_disk(path: &std::path::Path) -> Vec<u8> {
    let mut bytes = std::fs::read(path).unwrap();
    bytes.extend(std::fs::read(path.with_extension("db-wal")).unwrap_or_default());
    bytes
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// A runner host: a fake `claude` that records its config dir and token, says the token in
/// its transcript, then plays a recorded turn; and the accounts' token files.
fn host(dir: &std::path::Path) -> HarnessExecutor {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    let leak = r#"{"type":"assistant","message":{"id":"leak","content":[{"type":"text","text":"my token is %s"}]}}"#;
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> {d}/argv\n\
             echo \"$CLAUDE_CONFIG_DIR $CLAUDE_CODE_OAUTH_TOKEN\" >> {d}/seen\n\
             head -n 2 > /dev/null\nprintf '{leak}\\n' \"$CLAUDE_CODE_OAUTH_TOKEN\"\n\
             cat {d}/fixture.ndjson\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex.usage_every = Duration::from_millis(10);
    std::fs::create_dir_all(&ex.credentials_dir).unwrap();
    for (n, token) in TOKENS.iter().enumerate() {
        let file = ex.credentials_dir.join(format!("claude-{n}.token"));
        std::fs::write(file, token).unwrap();
    }
    ex
}

#[tokio::test]
async fn three_accounts_take_turns_and_their_tokens_stay_on_the_runner() {
    let logs = logs();
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let (other, _) = company(pool, "B").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let by = AuditActor::System;
    for n in 0..3 {
        let file = Some(format!("claude-{n}.token"));
        let label = format!("claude-{n}");
        let new = new_account(pool, Harness::Claude, &label, file, None, None, None);
        let a = create_account(pool, &new.await.unwrap(), by).await.unwrap();
        assign_account(pool, a.id, c, true, by).await.unwrap();
    }
    // B's account is never A's to use.
    let new = new_account(pool, Harness::Claude, "claude-b", None, None, None, None);
    let b = create_account(pool, &new.await.unwrap(), by).await.unwrap();
    assign_account(pool, b.id, other, true, by).await.unwrap();
    for _ in 0..3 {
        assign(pool, issue(pool, p).await, dev).await;
    }
    runner(pool, "box", &[]).await;

    let dir = std::env::temp_dir().join(format!("citadel-accounts-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    stack.runner("box", &[], host(&dir));
    let done = "SELECT count(*) = 3 FROM runs WHERE state = 'succeeded'";
    until(pool, "three runs to succeed", done).await;

    let accounts: BTreeSet<i64> =
        sqlx::query_scalar("SELECT account_id FROM runs WHERE account_id IS NOT NULL")
            .fetch_all(pool)
            .await
            .unwrap()
            .into_iter()
            .collect();
    assert_eq!(accounts.len(), 3, "each run on another account");
    assert!(!accounts.contains(&b.id.0));
    let seen = std::fs::read_to_string(dir.join("seen")).unwrap();
    let pairs: BTreeSet<String> = seen.lines().map(str::to_owned).collect();
    let want: BTreeSet<String> = (0..3)
        .map(|n| {
            let config = dir.join(format!("config/accounts/claude-{n}"));
            format!("{} {}", config.display(), TOKENS[n])
        })
        .collect();
    assert_eq!(pairs, want, "each account's own config dir and token");

    // Each account keeps Claude's plan-limit report (E15.2).
    let reported: i64 =
        sqlx::query_scalar("SELECT count(*) FROM accounts WHERE signal LIKE '%five_hour%'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(reported, 3);

    let mut said = String::new();
    for run in list_runs(pool, dev).await.unwrap() {
        for e in list_run_events(pool, run.id).await.unwrap() {
            said.push_str(&e.payload.to_string());
        }
    }
    assert!(said.contains("my token is [redacted:"), "{said}");
    let disk = on_disk(&stack.db.path);
    let logged = logs.text();
    let argv = std::fs::read(dir.join("argv")).unwrap();
    for token in TOKENS {
        assert!(!contains(&disk, token), "a token reached the database");
        assert!(!contains(&logged, token), "a token reached the logs");
        assert!(!contains(&argv, token), "a token went by argv");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
