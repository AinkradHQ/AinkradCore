//! Runner registration from the command line: `ainkrad-core-server runner add` prints a key a
//! runner connects with; `runner list` never shows one; `runner revoke` cuts the key off,
//! the socket it has open included.

use ainkrad_runner::{Config, Error, FakeExecutor};
use std::collections::BTreeMap;

use super::support::*;
use crate::harness::{agent, assign, company, count, issue};

/// `ainkrad-core-server runner …` on the stack's database: its stdout, or its stderr on failure.
/// Awaited, not blocking: the server shares this test's runtime, and a server frozen inside
/// a write transaction would hold the database lock the CLI waits for.
async fn cli(stack: &Stack, args: &[&str]) -> Result<String, String> {
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .arg("runner")
        .arg(args[0])
        .arg(&stack.db.path)
        .args(&args[1..])
        .output()
        .await
        .unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    match out.status.success() {
        true => Ok(String::from_utf8(out.stdout).unwrap()),
        false => Err(stderr),
    }
}

#[tokio::test]
async fn add_connect_list_and_revoke() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    assign(pool, issue(pool, p).await, dev).await;

    let key = cli(&stack, &["add", "box-1", "--tags", "linux,gpu"])
        .await
        .unwrap();
    let key = key.trim().to_owned();
    assert!(key.starts_with("cit_runner_") && key.len() == "cit_runner_".len() + 64);
    let again = cli(&stack, &["add", "box-2"]).await.unwrap();
    assert_ne!(again.trim(), key, "every key is fresh");
    assert!(
        cli(&stack, &["add", "box-1"]).await.is_err(),
        "names are unique"
    );

    let listed = cli(&stack, &["list"]).await.unwrap();
    assert!(
        listed.contains("box-1") && listed.contains("linux,gpu"),
        "{listed}"
    );
    assert!(listed.contains("box-2"), "{listed}");
    assert!(
        !listed.contains(&key) && !listed.contains("cit_runner_"),
        "{listed}"
    );

    let config = |key: &str| Config {
        log: None,
        url: stack.url(),
        key: key.to_owned(),
        tags: vec!["linux".to_owned()],
        harnesses: BTreeMap::from([(
            "claude".to_owned(),
            ainkrad_harness::claude::VERSION.to_owned(),
        )]),
    };
    let daemon = tokio::spawn(ainkrad_runner::run(config(&key), FakeExecutor::default()));
    let done = "SELECT count(*) FROM runs WHERE state = 'succeeded'";
    until(pool, "the registered runner to finish a job", done).await;

    // Idle now and connected: revoking closes its socket, and its key no longer connects.
    let revoked = cli(&stack, &["revoke", "box-1"]).await;
    assert!(revoked.is_ok(), "{revoked:?}");
    let stopped = tokio::time::timeout(std::time::Duration::from_secs(10), daemon);
    let stopped = stopped.await.expect("the revoked runner stops").unwrap();
    assert!(matches!(stopped, Error::Refused(401)), "{stopped}");
    let refused = ainkrad_runner::run(config(&key), FakeExecutor::default()).await;
    assert!(matches!(refused, Error::Refused(401)), "{refused}");
    assert_eq!(count(pool, "SELECT count(*) FROM runners").await, 1);
    // Its finished run stays, with no runner.
    let kept = "SELECT count(*) FROM runs WHERE state = 'succeeded' AND runner_id IS NULL";
    assert_eq!(count(pool, kept).await, 1);
    assert!(
        cli(&stack, &["revoke", "box-1"])
            .await
            .unwrap_err()
            .contains("no runner")
    );
}

/// A runner holding a live run cannot be revoked: its run ends first (`delete_runner`).
#[tokio::test]
async fn revoke_is_refused_while_the_runner_holds_a_live_run() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    assign(pool, issue(pool, p).await, dev).await;
    let key = cli(&stack, &["add", "box"]).await.unwrap();
    let (held, _tokens, release) = held();
    stack.runner(key.trim(), &["linux"], held);
    until(
        pool,
        "the run to start",
        "SELECT count(*) FROM runs WHERE state = 'running'",
    )
    .await;

    let why = cli(&stack, &["revoke", "box"]).await.unwrap_err();
    assert!(why.contains("holds live runs"), "{why}");
    release.notify_one();
    let done = "SELECT count(*) FROM runs WHERE state = 'succeeded'";
    until(pool, "the run to end", done).await;
    assert!(cli(&stack, &["revoke", "box"]).await.is_ok());
}

/// `ainkrad-core-server <noun> <verb> <db> …` on the stack's database (E5.1): its stdout, or its
/// stderr on failure.
async fn seed(stack: &Stack, noun_verb: [&str; 2], args: &[&str]) -> Result<String, String> {
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(noun_verb)
        .arg(&stack.db.path)
        .args(args)
        .output()
        .await
        .unwrap();
    match out.status.success() {
        true => Ok(String::from_utf8(out.stdout).unwrap()),
        false => Err(String::from_utf8(out.stderr).unwrap()),
    }
}

#[tokio::test]
async fn epic_add_and_issue_move() {
    use ainkrad_core::work::{BacklogFilter, EpicId};
    use ainkrad_core_server::store::work::{backlog_page, get_epic};

    let stack = Stack::new().await;
    let pool = stack.pool();
    let (_, p) = company(pool, "A").await;
    let ids = [
        issue(pool, p).await,
        issue(pool, p).await,
        issue(pool, p).await,
    ];

    let epic = seed(&stack, ["epic", "add"], &[&p.0.to_string(), "Engine"]).await;
    let epic = EpicId(epic.unwrap().trim().parse().unwrap());
    let stored = get_epic(pool, epic).await.unwrap().unwrap();
    assert_eq!((stored.project_id, stored.title.as_str()), (p, "Engine"));

    let [a, b, c] = ids.map(|i| i.0.to_string());
    for to in [
        vec![c.as_str(), "top"],
        vec![a.as_str(), "after", b.as_str()],
    ] {
        let moved = seed(&stack, ["issue", "move"], &to).await.unwrap();
        assert_eq!(moved.trim(), to[0]);
    }
    let order: Vec<_> = backlog_page(pool, p, &BacklogFilter::default(), 0, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.id)
        .collect();
    assert_eq!(order, [ids[2], ids[1], ids[0]]);
    let by_admin = "SELECT count(*) FROM audit_events WHERE action = 'issue.moved' \
                    AND actor_kind = 'user' AND actor_id = 1";
    assert_eq!(count(pool, by_admin).await, 2);

    let usage = seed(&stack, ["issue", "move"], &[&a, "sideways"]).await;
    assert!(usage.unwrap_err().contains("usage"));
    let missing = seed(&stack, ["issue", "move"], &["999", "top"]).await;
    assert!(missing.is_err());
}
