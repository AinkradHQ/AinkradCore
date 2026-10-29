//! Project permission policies and permission escalations (E3.10).

use citadel_core::audit::AuditActor;
use citadel_core::gov::ApprovalKind;
use citadel_core::work::ProjectId;
use ainkrad_proto::runner::{PermissionMode, Policy};
use serde_json::json;

use super::lease::{assigned, working};
use super::wake::runner;
use super::*;
use crate::store::gov::get_approval;
use crate::store::work::{get_issue, issue_policy, set_project_policy};

const NOW: &str = "2026-10-21T10:00:00.000Z";

#[tokio::test]
async fn the_default_policy_asks_and_sandboxed_needs_sandboxed_runs() {
    let db = db().await;
    let pool = &db.pool;
    let (_, i) = fixture(pool, "A").await;
    assert_eq!(issue_policy(pool, i).await.unwrap(), Policy::default());
    assert_eq!(
        issue_policy(pool, IssueId(999)).await.unwrap(),
        Policy::default()
    );
    let project = get_issue(pool, i).await.unwrap().unwrap().project_id;

    let edits = Policy {
        mode: PermissionMode::AcceptEdits,
        allow: vec!["Bash:cargo test".to_owned()],
        sandboxed: false,
    };
    assert!(
        set_project_policy(pool, project, &edits, AuditActor::System)
            .await
            .unwrap()
    );
    assert_eq!(issue_policy(pool, i).await.unwrap(), edits);

    let unsafe_auto = Policy {
        mode: PermissionMode::Sandboxed,
        ..Policy::default()
    };
    let refused = set_project_policy(pool, project, &unsafe_auto, AuditActor::System).await;
    assert!(
        matches!(refused, Err(Error::InvalidArgument(_))),
        "{refused:?}"
    );
    let blank = Policy {
        allow: vec![" ".to_owned()],
        ..Policy::default()
    };
    assert!(
        set_project_policy(pool, project, &blank, AuditActor::System)
            .await
            .is_err()
    );
    assert_eq!(issue_policy(pool, i).await.unwrap(), edits, "unchanged");
    let gone = set_project_policy(pool, ProjectId(999), &edits, AuditActor::System).await;
    assert!(!gone.unwrap());
    let audited: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'project.policy_set' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(audited.len(), 1, "only the change that held: {audited:?}");
    assert!(audited[0].contains("accept_edits"), "{audited:?}");
}

#[tokio::test]
async fn an_escalation_is_one_approval_per_run_and_request() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = assigned(pool, "A").await;
    let run = working(pool, runner(pool, "mac").await, NOW).await;
    let input = json!({"command": "rm -rf build"});
    let first = escalate(pool, &run, "req-1", "Bash", &input, None, NOW)
        .await
        .unwrap();
    assert_eq!(
        escalate(pool, &run, "req-1", "Bash", &input, None, NOW)
            .await
            .unwrap(),
        first
    );
    let second = escalate(pool, &run, "req-2", "Bash", &input, None, NOW)
        .await
        .unwrap();
    assert_ne!(second, first);

    let a = get_approval(pool, first).await.unwrap().unwrap();
    assert_eq!(a.kind, ApprovalKind::PermissionEscalation);
    assert_eq!(
        (a.issue_id, a.agent_id, a.requested_by),
        (Some(i), Some(dev), dev)
    );
    let payload: serde_json::Value = serde_json::from_str(&a.payload).unwrap();
    assert_eq!(
        payload,
        json!({"run": run.id.0, "request": "req-1", "tool": "Bash", "input": input})
    );
}

/// A permission escalation expires at the runner's deadline, or as soon as its run ends;
/// either way it is closed with the reason, by nobody, and audited. A decision after the
/// deadline is refused.
#[tokio::test]
async fn escalations_expire_at_the_deadline_or_when_the_run_ends() {
    use crate::store::exec::tick;
    use crate::store::gov::{DecideError, decide_approval, expire_approvals};
    use citadel_core::audit::AuditActor;
    use citadel_core::exec::RunEvent;
    use citadel_core::gov::{ApprovalId, ApprovalStatus};

    let db = db().await;
    let pool = &db.pool;
    assigned(pool, "A").await;
    let run = working(pool, runner(pool, "mac").await, NOW).await;
    let input = json!({});
    let late = escalate(pool, &run, "late", "Bash", &input, None, NOW)
        .await
        .unwrap();
    let a = get_approval(pool, late).await.unwrap().unwrap();
    assert_eq!(a.expires_at.as_deref(), Some("2026-10-21T10:15:00.000Z"));

    let before = expire_approvals(pool, "2026-10-21T10:14:59.000Z")
        .await
        .unwrap();
    assert!(before.is_empty());
    let expired = expire_approvals(pool, "2026-10-21T10:15:00.000Z")
        .await
        .unwrap();
    assert_eq!(expired, [late]);
    let a = get_approval(pool, late).await.unwrap().unwrap();
    assert_eq!((a.status, a.decided_by), (ApprovalStatus::Expired, None));
    assert_eq!(
        a.reply.as_deref(),
        Some("expired: no decision by 2026-10-21T10:15:00.000Z")
    );
    let again = decide_approval(pool, late, true, UserId(1), None, NOW).await;
    assert!(matches!(
        again,
        Err(DecideError::NotPending(ApprovalStatus::Expired))
    ));

    // Deciding past a deadline the scheduler has not reached yet expires it there and then.
    let third = escalate(
        pool,
        &run,
        "third",
        "Bash",
        &input,
        None,
        "2026-10-21T10:16:00.000Z",
    );
    let third = third.await.unwrap();
    let after = decide_approval(
        pool,
        third,
        true,
        UserId(1),
        None,
        "2026-10-21T10:31:00.000Z",
    );
    assert!(matches!(after.await, Err(DecideError::Expired)));

    // The run ends before anyone decides: its escalation expires on the next look.
    let open = escalate(
        pool,
        &run,
        "open",
        "Bash",
        &input,
        None,
        "2026-10-21T10:30:00.000Z",
    )
    .await
    .unwrap();
    let cancel = RunEvent::Cancel {
        reason: "stop".to_owned(),
    };
    let at = "2026-10-21T10:32:00.000Z";
    transition_run(pool, run.id, AuditActor::System, &cancel, at)
        .await
        .unwrap();
    assert_eq!(expire_approvals(pool, at).await.unwrap(), [open]);
    let a = get_approval(pool, open).await.unwrap().unwrap();
    assert_eq!(a.reply, Some(format!("expired: run {} ended", run.id.0)));
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'approval.expired' \
         AND actor_kind = 'system'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(audited, 3);

    // Any kind with a deadline expires, and the scheduler's tick does it.
    let merge = sqlx::query_scalar::<_, i64>(
        "INSERT INTO approvals (company_id, kind, requested_by_agent_id, expires_at) \
         SELECT company_id, 'pr_merge', id, '2026-10-21T12:00:00.000Z' FROM agents LIMIT 1 \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let report = tick(pool, "2026-10-21T12:00:00.000Z").await.unwrap();
    assert_eq!(report.expired, [ApprovalId(merge)]);
}

/// The server expires an escalation when its runner gives up on it: at the timeout the
/// runner sent, not a fixed 15 minutes. A decision reaches the waiting run through its runner,
/// with the reply also on the issue; no follow-up run is queued for it.
#[tokio::test]
async fn an_escalation_follows_the_runners_timeout_and_queues_no_wake() {
    use crate::store::gov::decide_approval;
    use crate::store::work::list_comments;
    use citadel_core::work::UserId;

    let db = db().await;
    let pool = &db.pool;
    let (_, i) = assigned(pool, "A").await;
    let run = working(pool, runner(pool, "mac").await, NOW).await;
    let input = json!({"command": "make deploy"});
    let short = escalate(pool, &run, "short", "Bash", &input, Some(90), NOW)
        .await
        .unwrap();
    let old = escalate(pool, &run, "old", "Bash", &input, None, NOW)
        .await
        .unwrap();
    let at = |id| async move { get_approval(pool, id).await.unwrap().unwrap().expires_at };
    assert_eq!(at(short).await.as_deref(), Some("2026-10-21T10:01:30.000Z"));
    assert_eq!(at(old).await.as_deref(), Some("2026-10-21T10:15:00.000Z"));

    let wakes_before: i64 = sqlx::query_scalar("SELECT count(*) FROM wake_requests")
        .fetch_one(pool)
        .await
        .unwrap();
    let a = decide_approval(pool, short, false, UserId(1), Some("not on a Friday"), NOW)
        .await
        .unwrap();
    assert_eq!(a.reply.as_deref(), Some("not on a Friday"));
    let wakes_after: i64 = sqlx::query_scalar("SELECT count(*) FROM wake_requests")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(wakes_after, wakes_before);
    let thread = list_comments(pool, i).await.unwrap();
    assert_eq!(
        thread.last().unwrap().body,
        "Permission for Bash rejected: not on a Friday"
    );
}
