//! The admin's controls (decision #34): pause and resume, stop, message, wake a runner, and the
//! stuck list's nudge, reassign and allow-for-issue; each audited as the admin.

use citadel_core::exec::RunEvent;
use citadel_core::gov::ApprovalStatus;
use citadel_core::work::ProjectMode;
use serde_json::json;

use super::*;
use crate::store::exec::{
    allowed_by_rule, append_run_event, escalate, get_run, stuck_report, take_controls,
    transition_run,
};
use crate::store::gov::get_approval;

async fn count(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Audit rows of `action` by the admin (user 1).
async fn by_admin(pool: &SqlitePool, action: &str) -> i64 {
    let sql = format!(
        "SELECT count(*) FROM audit_events WHERE action = '{action}' \
         AND actor_kind = 'user' AND actor_id = 1"
    );
    count(pool, &sql).await
}

#[tokio::test]
async fn pause_parks_the_agent_and_resume_wakes_it() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/agents/{}/pause", a.agent.0);

    let paused = fx.ok_post(&uri, json!({})).await;
    assert_eq!(
        (&paused["status"], &paused["paused_at"]),
        (&json!("paused"), &json!(NOW))
    );
    assert_eq!(by_admin(pool, "agent.paused").await, 1);
    assert_eq!(fx.post(&uri, json!({})).await.0, StatusCode::CONFLICT);
    // Its running run is told to pause (it finishes its tool call first, on the runner).
    let controls = take_controls(pool, a.runner, &["pause"], NOW)
        .await
        .unwrap();
    assert_eq!(
        controls,
        [(1, a.run.id.0, "pause".to_owned(), String::new())]
    );
    // The runner ends it so; its issue waits on the paused agent by design, never stuck.
    let ended = RunEvent::Cancel {
        reason: "paused by admin".to_owned(),
    };
    transition_run(pool, a.run.id, AuditActor::Runner(a.runner), &ended, NOW)
        .await
        .unwrap();
    let stuck = stuck_report(pool, "2026-10-29T10:00:00.000Z")
        .await
        .unwrap();
    assert!(
        stuck.iter().all(|s| s.issue_id != Some(a.issue)),
        "{stuck:?}"
    );

    let uri = format!("/api/v1/agents/{}/resume", a.agent.0);
    let resumed = fx.ok_post(&uri, json!({})).await;
    assert_eq!(resumed["status"], "active");
    assert!(resumed["paused_at"].is_null());
    assert_eq!(by_admin(pool, "agent.resumed").await, 1);
    let woken = format!(
        "SELECT count(*) FROM wake_requests WHERE agent_id = {} AND issue_id = {} \
         AND source = 'manual' AND status = 'pending'",
        a.agent.0, a.issue.0
    );
    assert_eq!(count(pool, &woken).await, 1, "woken on its issue again");
    assert_eq!(fx.post(&uri, json!({})).await.0, StatusCode::CONFLICT);

    // The whole company: every active agent, then back.
    let c = format!("/api/v1/companies/{}", a.company.0);
    let all = fx.ok_post(&format!("{c}/pause"), json!({})).await;
    assert_eq!(all["agent_ids"], json!([a.agent.0]));
    let none = fx.ok_post(&format!("{c}/pause"), json!({})).await;
    assert_eq!(none["agent_ids"], json!([]));
    let back = fx.ok_post(&format!("{c}/resume"), json!({})).await;
    assert_eq!(back["agent_ids"], json!([a.agent.0]));
}

#[tokio::test]
async fn stop_ends_the_run_now_and_tells_its_runner() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/runs/{}/stop", a.run.id.0);
    let stopped = fx.ok_post(&uri, json!({})).await;
    assert_eq!(
        (&stopped["state"], &stopped["terminal_reason"]),
        (&json!("cancelled"), &json!("stopped by admin"))
    );
    assert_eq!(by_admin(pool, "run.cancelled").await, 1);
    let lease = format!("SELECT count(*) FROM leases WHERE run_id = {}", a.run.id.0);
    assert_eq!(count(pool, &lease).await, 0, "its lease went with it");
    let told = take_controls(pool, a.runner, &["stop"], NOW).await.unwrap();
    assert_eq!(told.len(), 1, "{told:?}");
    assert!(
        take_controls(pool, a.runner, &["stop"], NOW)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(fx.post(&uri, json!({})).await.0, StatusCode::CONFLICT);
    assert_eq!(
        fx.post("/api/v1/runs/99/stop", json!({})).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_message_reaches_the_live_run_else_becomes_a_comment() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/runs/{}/messages", a.run.id.0);
    assert_eq!(
        fx.post(&uri, json!({"body": " "})).await.0,
        StatusCode::BAD_REQUEST
    );

    let first = fx
        .ok_post(&uri, json!({"body": "use the in-memory transport"}))
        .await;
    assert_eq!(first["delivered_as"], "run");
    let again = json!({"body": "and add a test", "idempotency_key": "k1"});
    let second = fx.ok_post(&uri, again.clone()).await;
    assert_eq!(
        fx.ok_post(&uri, again).await,
        second,
        "a retry is taken once"
    );
    assert_eq!(by_admin(pool, "run.messaged").await, 2);
    let sent = take_controls(pool, a.runner, &["message"], NOW)
        .await
        .unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].3, "use the in-memory transport");

    // The runner gives the first to the harness; the run ends before taking the second.
    let given = json!({"type": "user_message", "id": first["message_id"], "text": "…"});
    append_run_event(pool, a.run.id, a.runner, 1, &given, NOW)
        .await
        .unwrap();
    let done = RunEvent::Succeed;
    transition_run(pool, a.run.id, AuditActor::Runner(a.runner), &done, NOW)
        .await
        .unwrap();
    let comments = format!(
        "SELECT count(*) FROM comments WHERE issue_id = {} AND author_user_id = 1 \
         AND body = 'and add a test'",
        a.issue.0
    );
    assert_eq!(
        count(pool, &comments).await,
        1,
        "the untaken one is a comment"
    );
    let first_too = "SELECT count(*) FROM comments WHERE body = 'use the in-memory transport'";
    assert_eq!(count(pool, first_too).await, 0, "the delivered one is not");
    let woke = format!(
        "SELECT count(*) FROM wake_requests WHERE agent_id = {} AND source = 'comment'",
        a.agent.0
    );
    assert_eq!(count(pool, &woke).await, 1, "and wakes the run's agent");

    // To a run that has ended: a comment at once.
    let late = fx.ok_post(&uri, json!({"body": "one more thing"})).await;
    assert_eq!(late["delivered_as"], "comment");
    assert!(late["comment_id"].is_i64());
}

#[tokio::test]
async fn nudge_and_reassign_move_a_stuck_issue() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/issues/{}/nudge", a.issue.0);
    let nudged = fx.ok_post(&uri, json!({})).await;
    assert_eq!(nudged["agent_id"], a.agent.0);
    assert_eq!(nudged["wake_status"], "pending");
    assert_eq!(by_admin(pool, "issue.nudged").await, 1);

    // Reassign: only to an active agent of its team (no team: of its company).
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let reassign = format!("/api/v1/issues/{}/reassign", a.issue.0);
    let theirs = json!({"agent_id": b.agent.0});
    assert_eq!(fx.post(&reassign, theirs).await.0, StatusCode::BAD_REQUEST);
    let mate = create_agent(
        pool,
        &NewAgent {
            company_id: a.company,
            name: "Wren".to_owned(),
            role: "Developer".to_owned(),
            org_role: OrgRole::None,
            reports_to: None,
            harness: Harness::Claude,
            model: String::new(),
            runner_tags: vec![],
            status: AgentStatus::Active,
        },
    )
    .await
    .unwrap();
    let moved = fx.ok_post(&reassign, json!({"agent_id": mate.id.0})).await;
    assert_eq!(moved["next_actor"]["agent_id"], mate.id.0, "{moved}");
    let woke = format!(
        "SELECT count(*) FROM wake_requests WHERE agent_id = {}",
        mate.id.0
    );
    assert_eq!(
        count(pool, &woke).await,
        1,
        "the engine wakes the new next actor"
    );

    // An issue waiting on a person has no agent to nudge.
    let human = json!({"next": {"kind": "human", "user_id": 1}});
    let t = format!("/api/v1/issues/{}/transition", a.issue.0);
    let _ = fx
        .ok_post(&t, json!({"kind": "reassign", "next": human["next"]}))
        .await;
    assert_eq!(fx.post(&uri, json!({})).await.0, StatusCode::CONFLICT);
}

#[tokio::test]
async fn allow_for_issue_approves_and_lets_the_same_call_through_until_it_expires() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let run = get_run(pool, a.run.id).await.unwrap().unwrap();
    let input = json!({"command": "cargo test -p one"});
    let approval = escalate(pool, &run, "r1", "Bash", &input, Some(900), NOW)
        .await
        .unwrap();
    let uri = format!("/api/v1/approvals/{}/allow-for-issue", approval.0);
    let decided = fx.ok_post(&uri, json!({"reply": "ok for this one"})).await;
    assert_eq!(decided["status"], "approved");
    let a2 = get_approval(pool, approval).await.unwrap().unwrap();
    assert_eq!(a2.status, ApprovalStatus::Approved);
    assert_eq!(by_admin(pool, "approval.allowed_for_issue").await, 1);
    assert_eq!(
        fx.post(&uri, json!({})).await.0,
        StatusCode::CONFLICT,
        "decided"
    );

    // The same command prefix goes ahead without asking; another does not.
    let same = json!({"command": "cargo test -p two"});
    let rule = allowed_by_rule(pool, &run, "r2", "Bash", &same, NOW)
        .await
        .unwrap();
    assert_eq!(rule.as_deref(), Some("Bash:cargo test"));
    let other = json!({"command": "curl https://example.com"});
    let none = allowed_by_rule(pool, &run, "r3", "Bash", &other, NOW)
        .await
        .unwrap();
    assert_eq!(none, None);
    let audited = "SELECT count(*) FROM audit_events WHERE action = 'run.allowed_by_rule'";
    assert_eq!(count(pool, audited).await, 1);
    // A day later (`approval.issue_allow_secs`) it asks again.
    let later = "2026-10-23T10:00:01.000Z";
    let gone = allowed_by_rule(pool, &run, "r4", "Bash", &same, later)
        .await
        .unwrap();
    assert_eq!(gone, None);

    // Only a permission escalation can be allowed for its issue.
    let ask = citadel_core::gov::NewApproval {
        company_id: a.company,
        kind: citadel_core::gov::ApprovalKind::BudgetOverrun,
        issue_id: Some(a.issue),
        sprint_id: None,
        agent_id: None,
        requested_by: a.agent,
        payload: "{}".to_owned(),
    };
    let budget = crate::store::gov::open_approval(pool, &ask, NOW)
        .await
        .unwrap();
    let uri = format!("/api/v1/approvals/{}/allow-for-issue", budget.id.0);
    assert_eq!(fx.post(&uri, json!({})).await.0, StatusCode::CONFLICT);
}

#[tokio::test]
async fn waking_a_runner_is_marked_audited_and_pushed() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/runners/{}/wake", a.runner.0);
    let woken = fx.ok_post(&uri, json!({})).await;
    assert_eq!(woken["wake_requested_at"], NOW);
    assert_eq!(by_admin(pool, "runner.wake_requested").await, 1);
    let events = crate::store::events::list_events(pool, 0, 1000)
        .await
        .unwrap();
    let push = events
        .iter()
        .find_map(crate::push::notification)
        .filter(|n| n.kind == "runner")
        .expect("a push");
    assert_eq!(push.data["wake"], true);
    crate::store::exec::runner_woke(pool, a.runner)
        .await
        .unwrap();
    let runners = fx.ok("/api/v1/runners").await;
    assert!(
        runners[0]["wake_requested_at"].is_null(),
        "cleared once it connects"
    );
    assert_eq!(
        fx.post("/api/v1/runners/99/wake", json!({})).await.0,
        StatusCode::NOT_FOUND
    );
}
