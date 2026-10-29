//! Harness permissions end to end (E3.10): a real `HarnessExecutor` drives a fake `claude`
//! playing a recorded write. Under the default policy the write becomes a
//! `permission_escalation` approval and the run waits; the reviewer's decision reaches
//! Claude. A sandboxed project on a sandboxed runner acts without asking.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ainkrad_core::audit::AuditActor;
use ainkrad_core::gov::{ApprovalKind, ApprovalStatus};
use ainkrad_core::work::UserId;
use ainkrad_core_server::store::gov::{list_approvals, update_approval};
use ainkrad_core_server::store::work::set_project_policy;
use ainkrad_proto::runner::{PermissionMode, Policy};
use ainkrad_runner::HarnessExecutor;
use serde_json::Value;

use super::support::*;
use crate::harness::{agent, assign, company, count, issue, runner};

const FIXTURE: &str =
    include_str!("../../../harness/tests/fixtures/claude/approve-interrupt.ndjson");

/// A runner whose `claude` plays the recorded turn and keeps what it is sent.
fn executor(dir: &Path) -> HarnessExecutor {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    let script =
        format!("#!/bin/sh\nsed '/\"type\":\"result\"/q' {d}/fixture.ndjson\ncat > {d}/stdin\n");
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("citadel-perm-{}-{name}", std::process::id()))
}

/// Claude's answer to the recorded approval.
fn answered(dir: &Path) -> Value {
    std::fs::read_to_string(dir.join("stdin"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|m| m["type"] == "control_response")
        .expect("no answer")["response"]["response"]
        .clone()
}

#[tokio::test]
async fn a_call_outside_the_policy_waits_for_a_reviewer() {
    for (approve, reply) in [(true, None), (false, Some("ask Ahmed first"))] {
        let stack = Stack::new().await;
        let pool = stack.pool();
        let (c, p) = company(pool, "A").await;
        let dev = agent(pool, c, "Dev", &[], None).await;
        let i = issue(pool, p).await;
        assign(pool, i, dev).await;
        runner(pool, "box", &[]).await;
        // Not the 15-minute default: the runner gets it in `Assign.limits` (1.11) and sends it
        // back with the request, and the server must expire the approval at this one (1.5).
        setting(pool, "approval.deadline.permission_escalation", 120).await;
        let dir = scratch(&format!("review-{approve}"));
        stack.runner("box", &[], executor(&dir));

        let pending = "SELECT count(*) FROM approvals WHERE status = 'pending'";
        until(pool, "the escalation", pending).await;
        let mut approval = list_approvals(pool, c).await.unwrap().remove(0);
        assert_eq!(approval.kind, ApprovalKind::PermissionEscalation);
        assert_eq!(approval.issue_id, Some(i));
        assert_eq!(approval.requested_by, dev);
        let deadline: String =
            sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?, '+120 seconds')")
                .bind(stack.now())
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(approval.expires_at, Some(deadline), "the runner's timeout");
        let payload: Value = serde_json::from_str(&approval.payload).unwrap();
        assert_eq!(payload["tool"], "Write");
        assert_eq!(
            payload["input"]["file_path"],
            "/tmp/citadel-fixture/work/hello.txt"
        );
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let running = "SELECT count(*) FROM runs WHERE state = 'running'";
        assert_eq!(count(pool, running).await, 1, "the run waits");

        approval.status = match approve {
            true => ApprovalStatus::Approved,
            false => ApprovalStatus::Rejected,
        };
        approval.decided_by = Some(UserId(1));
        approval.reply = reply.map(str::to_owned);
        assert!(update_approval(pool, &approval).await.unwrap());
        let done = "SELECT count(*) FROM runs WHERE state = 'succeeded'";
        until(pool, "the run to finish", done).await;
        let sent = answered(&dir);
        match approve {
            true => assert_eq!(sent["behavior"], "allow", "{sent}"),
            false => {
                assert_eq!(sent["behavior"], "deny", "{sent}");
                assert_eq!(sent["message"], "ask Ahmed first");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The project's policy travels with the run: sandboxed on a sandboxed runner acts unasked;
/// the same project on a runner that is not sandboxed is refused there.
#[tokio::test]
async fn a_sandboxed_project_acts_unasked_only_on_a_sandboxed_runner() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let sandboxed = Policy {
        mode: PermissionMode::Sandboxed,
        allow: vec![],
        sandboxed: true,
    };
    assert!(
        set_project_policy(pool, p, &sandboxed, AuditActor::System)
            .await
            .unwrap()
    );
    assign(pool, issue(pool, p).await, dev).await;
    runner(pool, "plain", &[]).await;
    runner(pool, "box", &[]).await;

    let plain = scratch("plain");
    let plain_runner = stack.runner("plain", &[], executor(&plain));
    let refused = "SELECT count(*) FROM runs WHERE state = 'failed' \
                   AND terminal_reason LIKE '%must be sandboxed%'";
    until(pool, "the plain runner to refuse", refused).await;
    plain_runner.abort();
    // Until the server sees it gone, its session still dispatches: the retry would go to it.
    let gone = "SELECT count(*) FROM runners WHERE name = 'plain' AND status = 'offline'";
    until(pool, "the server to drop the plain runner", gone).await;
    // The retry is due after its backoff.
    stack.advance(31);

    let dir = scratch("sandboxed");
    let mut ex = executor(&dir);
    ex.sandboxed = true;
    stack.runner("box", &[], ex);
    let done = "SELECT count(*) FROM runs WHERE state = 'succeeded'";
    until(pool, "the sandboxed run", done).await;
    assert_eq!(answered(&dir)["behavior"], "allow");
    assert_eq!(count(pool, "SELECT count(*) FROM approvals").await, 0);
    for d in [plain, dir] {
        let _ = std::fs::remove_dir_all(&d);
    }
}
