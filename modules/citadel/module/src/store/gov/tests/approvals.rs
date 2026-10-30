//! The approvals service (E7.1): every kind's decision is recorded once with the reply;
//! deadlines are per kind and configurable; expiry closes what is past its deadline. Sprint
//! commits are covered with the work slice, permission escalations with the run engine.
//!
//! The monolith's tests also asserted the requester's wake and comment, the hire and the
//! expiry's effect on the hired agent: those need the wake queue (S7), the hire gate (S3) and
//! the comments (S4), so each is an `#[ignore]`d stub below and a reduced runnable twin checks
//! what this slice owns.

use serde_json::json;

use super::*;
use crate::domain::gov::Approval;
use crate::domain::work::{IssueId, IssueKind, IssueState, NewIssue, NextActor};
use crate::store::work::create_issue;

const NOW: &str = "2026-10-22T10:00:00.000Z";

pub(super) async fn issue(pool: &SqlitePool, project: &Project) -> IssueId {
    let new = NewIssue {
        project_id: project.id,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Ship it".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Human(ADMIN)),
        points: None,
        sprint_id: None,
    };
    create_issue(pool, &new).await.unwrap().id
}

/// Opens one approval of `kind` (a merge, or a budget overrun on a fresh budget) requested by
/// `agent` about `issue`.
pub(super) async fn open(
    pool: &SqlitePool,
    c: CompanyId,
    agent: AgentId,
    issue: IssueId,
    kind: ApprovalKind,
) -> Approval {
    let budget = NewBudget {
        scope: BudgetScope::Company(c),
        period: BudgetPeriod::Total,
        token_cap: 10,
        usd_cap_micros: None,
        warn_at_percent: 80,
        hard_stop: true,
    };
    let budget = set_budget(pool, &budget, BY).await.unwrap();
    let new = NewApproval {
        company_id: c,
        kind,
        issue_id: Some(issue),
        sprint_id: None,
        agent_id: None,
        requested_by: agent,
        payload: json!({"summary": "merge #12", "budget": budget.id.0, "period": "total"})
            .to_string(),
    };
    open_approval(pool, &new, NOW).await.unwrap()
}

async fn audited(pool: &SqlitePool, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(format!("citadel.{action}"))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn every_kind_is_decided_once_with_the_reply() {
    let db = db().await;
    let pool = &db.pool;
    let (c, po, p) = fixture(pool, "A").await;
    for kind in [ApprovalKind::PrMerge, ApprovalKind::BudgetOverrun] {
        for approve in [true, false] {
            let i = issue(pool, &p).await;
            let a = open(pool, c, po, i, kind).await;
            assert_eq!(a.expires_at, None, "no deadline by default");
            let reply = format!("{} because reasons", kind.as_str());
            let decided = match (kind, approve) {
                (ApprovalKind::BudgetOverrun, true) => {
                    let no_raise = decide_approval(pool, a.id, true, ADMIN, None, NOW).await;
                    assert!(matches!(no_raise, Err(DecideError::Raise)), "{no_raise:?}");
                    approve_budget_raise(pool, a.id, 500, ADMIN, Some(&reply), NOW).await
                }
                _ => decide_approval(pool, a.id, approve, ADMIN, Some(&reply), NOW).await,
            }
            .unwrap();
            let verdict = decided.status.as_str();
            assert_eq!(verdict, if approve { "approved" } else { "rejected" });
            assert_eq!(decided.reply.as_deref(), Some(reply.as_str()));
            assert_eq!(decided.decided_by, Some(ADMIN));

            // Never twice: a second decision is refused, a later expiry passes it by.
            let again = decide_approval(pool, a.id, !approve, ADMIN, Some("no"), NOW).await;
            assert!(
                matches!(again, Err(DecideError::NotPending(_))),
                "{again:?}"
            );
            let later = expire_approvals(pool, "2027-10-22T10:00:00.000Z").await;
            assert!(later.unwrap().is_empty());
        }
    }
    assert_eq!(audited(pool, "approval.approved").await, 2);
    assert_eq!(audited(pool, "approval.rejected").await, 2);
    assert_eq!(audited(pool, "approval.pending").await, 4);
    // The approved overrun raised its budget's period by 500 tokens.
    let raised: i64 =
        sqlx::query_scalar("SELECT coalesce(sum(raised), 0) FROM citadel_budget_spend")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(raised, 500);
    assert_eq!(audited(pool, "budget.raised").await, 1);
}

#[tokio::test]
#[ignore = "S7: needs the wake queue; S3: hire_agent; S4: issue comments"]
async fn every_kind_wakes_its_requester_once_with_the_reply() {
    todo!("monolith store/gov/tests/approvals.rs: wake + comment per kind, incl. hire_agent")
}

#[tokio::test]
#[ignore = "S3: hire_agent; S7: needs the wake queue"]
async fn a_hire_a_human_asked_for_wakes_nobody() {
    todo!("monolith store/gov/tests/approvals.rs: a human-requested hire wakes nobody")
}

/// Sets the server-wide deadline setting of `kind` (0: none).
async fn set_deadline(pool: &SqlitePool, kind: ApprovalKind, secs: i64) {
    let name = format!("approval.deadline.{}", kind.as_str());
    crate::settings::handle()
        .set(pool, &name, &secs.to_string(), BY, NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn deadlines_are_per_kind_and_expiry_closes_the_approval() {
    let db = db().await;
    let pool = &db.pool;
    let (c, po, p) = fixture(pool, "A").await;
    let i = issue(pool, &p).await;
    let name = "approval.deadline.permission_escalation";
    assert_eq!(crate::settings::value(pool, name).await.unwrap(), 900);
    set_deadline(pool, ApprovalKind::PrMerge, 3600).await;
    let audited_sets: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'setting.set'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(audited_sets >= 1, "a setting change is audited");

    let merge = open(pool, c, po, i, ApprovalKind::PrMerge).await;
    let budget = open(pool, c, po, i, ApprovalKind::BudgetOverrun).await;
    assert_eq!(
        merge.expires_at.as_deref(),
        Some("2026-10-22T11:00:00.000Z")
    );
    assert_eq!(budget.expires_at, None, "its kind has no deadline");

    let early = expire_approvals(pool, "2026-10-22T10:59:59.000Z").await;
    assert!(early.unwrap().is_empty());
    let due = "2026-10-22T11:00:00.000Z";
    let expired = expire_approvals(pool, due).await.unwrap();
    assert_eq!(expired, [merge.id]);
    let gone = get_approval(pool, merge.id).await.unwrap().unwrap();
    assert_eq!(
        gone.decided_at.as_deref(),
        Some(due),
        "expired at the tick's now"
    );
    assert_eq!(gone.status, ApprovalStatus::Expired);
    assert_eq!(
        gone.reply.as_deref(),
        Some(format!("expired: no decision by {due}").as_str())
    );
    assert_eq!(audited(pool, "approval.expired").await, 1);
    assert!(expire_approvals(pool, due).await.unwrap().is_empty());
    let late = decide_approval(pool, merge.id, true, ADMIN, None, due).await;
    assert!(matches!(late, Err(DecideError::NotPending(_))), "{late:?}");

    set_deadline(pool, ApprovalKind::PrMerge, 0).await;
    assert_eq!(
        open(pool, c, po, i, ApprovalKind::PrMerge).await.expires_at,
        None
    );
}

#[tokio::test]
async fn a_decision_past_its_deadline_finds_it_expired() {
    let db = db().await;
    let pool = &db.pool;
    let (c, po, p) = fixture(pool, "A").await;
    let i = issue(pool, &p).await;
    set_deadline(pool, ApprovalKind::PrMerge, 60).await;
    let a = open(pool, c, po, i, ApprovalKind::PrMerge).await;
    let late = "2026-10-22T10:05:00.000Z";
    let r = decide_approval(pool, a.id, true, ADMIN, None, late).await;
    assert!(matches!(r, Err(DecideError::Expired)), "{r:?}");
    let missing = decide_approval(
        pool,
        crate::domain::gov::ApprovalId(99),
        true,
        ADMIN,
        None,
        NOW,
    )
    .await;
    assert!(matches!(missing, Err(DecideError::NotFound)), "{missing:?}");
}

#[tokio::test]
#[ignore = "S3: hire_agent (the expired hire is terminated); S7: needs the wake queue; S4: comments"]
async fn deadlines_are_per_kind_and_expiry_tells_the_requester() {
    todo!("monolith store/gov/tests/approvals.rs: hire expiry, requester wake, no comment")
}
