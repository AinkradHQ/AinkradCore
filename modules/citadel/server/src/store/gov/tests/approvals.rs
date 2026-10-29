//! The approvals service (E7.1): every kind's decision wakes its requester once, with the
//! reply; deadlines are per kind and configurable; expiry tells the requester too. Sprint
//! commits are covered in `work/tests/gate.rs`, permission escalations in
//! `exec/tests/escalation.rs`.

use crate::store::settings;
use citadel_core::audit::AuditActor;
use citadel_core::gov::{Approval, ApprovalId};
use citadel_core::settings::{Key, Scope};
use citadel_core::work::{IssueId, IssueKind, IssueState, NewIssue, NextActor};

use serde_json::json;

use super::*;
use crate::store::org::{get_agent, hire_agent};
use crate::store::work::{create_issue, list_comments};

const NOW: &str = "2026-10-22T10:00:00.000Z";
const BY: AuditActor = AuditActor::User(ADMIN);

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

/// (agent, issue, reason) of every approval wake, oldest first.
async fn wakes(pool: &SqlitePool) -> Vec<(i64, Option<i64>, String)> {
    sqlx::query_as(
        "SELECT agent_id, issue_id, reason FROM wake_requests WHERE source = 'approval' \
         ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Opens one approval of `kind` requested by `agent` (a hire about a new agent; the others
/// about `issue`).
pub(super) async fn open(
    pool: &SqlitePool,
    c: CompanyId,
    agent: AgentId,
    issue: IssueId,
    kind: ApprovalKind,
) -> Approval {
    if kind == ApprovalKind::HireAgent {
        let new = NewAgent {
            company_id: c,
            name: "QA 2".to_owned(),
            role: "QA".to_owned(),
            org_role: OrgRole::None,
            reports_to: None,
            harness: Harness::Codex,
            model: "gpt-5".to_owned(),
            runner_tags: vec![],
            status: AgentStatus::PendingApproval,
        };
        return hire_agent(pool, &new, Some(agent), "tests pile up", BY, NOW)
            .await
            .unwrap()
            .1;
    }
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

#[tokio::test]
async fn every_kind_wakes_its_requester_once_with_the_reply() {
    let db = db().await;
    let pool = &db.pool;
    let (c, po, p) = fixture(pool, "A").await;
    let kinds = [
        (ApprovalKind::PrMerge, "PR merge"),
        (ApprovalKind::BudgetOverrun, "Budget overrun"),
        (ApprovalKind::HireAgent, "Hire of QA 2"),
    ];
    let mut seen = 0;
    for (kind, subject) in kinds {
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

            let all = wakes(pool).await;
            assert_eq!(all.len(), seen + 1, "{kind:?} woke once");
            seen += 1;
            let (agent, on, reason) = all.last().unwrap().clone();
            let about = (kind != ApprovalKind::HireAgent).then_some(i.0);
            assert_eq!((agent, on), (po.0, about));
            let want = format!("approval {}: {subject} {verdict}: {reply}", a.id.0);
            assert_eq!(reason, want);
            if let Some(i) = about {
                let thread = list_comments(pool, IssueId(i)).await.unwrap();
                assert_eq!(thread.len(), 1);
                assert_eq!(thread[0].body, format!("{subject} {verdict}: {reply}"));
            }

            // Never twice: a second decision is refused, a later expiry passes it by.
            let again = decide_approval(pool, a.id, !approve, ADMIN, Some("no"), NOW).await;
            assert!(
                matches!(again, Err(DecideError::NotPending(_))),
                "{again:?}"
            );
            let later = expire_approvals(pool, "2027-10-22T10:00:00.000Z").await;
            assert!(later.unwrap().is_empty());
            assert_eq!(wakes(pool).await.len(), seen);
        }
    }
}

#[tokio::test]
async fn a_hire_a_human_asked_for_wakes_nobody() {
    let db = db().await;
    let pool = &db.pool;
    let (c, _, _) = fixture(pool, "A").await;
    let new = NewAgent {
        company_id: c,
        name: "Dev".to_owned(),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Claude,
        model: "sonnet".to_owned(),
        runner_tags: vec![],
        status: AgentStatus::PendingApproval,
    };
    let (dev, hire) = hire_agent(pool, &new, None, "needed", BY, NOW)
        .await
        .unwrap();
    assert_eq!(hire.requested_by, dev.id);
    decide_approval(pool, hire.id, true, ADMIN, Some("welcome"), NOW)
        .await
        .unwrap();
    assert!(wakes(pool).await.is_empty());
}

/// Sets the server-wide deadline setting of `kind` (0: none).
async fn set_deadline(pool: &SqlitePool, kind: ApprovalKind, secs: i64) {
    let key = Key::approval_deadline(kind);
    settings::set(pool, key, Scope::Server, &secs.to_string(), BY, NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn deadlines_are_per_kind_and_expiry_tells_the_requester() {
    let db = db().await;
    let pool = &db.pool;
    let (c, po, p) = fixture(pool, "A").await;
    let i = issue(pool, &p).await;
    let key = Key::approval_deadline(ApprovalKind::PermissionEscalation);
    assert_eq!(
        settings::value(pool, key, Scope::Server).await.unwrap(),
        900
    );
    for kind in [ApprovalKind::PrMerge, ApprovalKind::HireAgent] {
        set_deadline(pool, kind, 3600).await;
    }
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'setting.set'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(audited, 2);

    let merge = open(pool, c, po, i, ApprovalKind::PrMerge).await;
    let hire = open(pool, c, po, i, ApprovalKind::HireAgent).await;
    let budget = open(pool, c, po, i, ApprovalKind::BudgetOverrun).await;
    assert_eq!(
        merge.expires_at.as_deref(),
        Some("2026-10-22T11:00:00.000Z")
    );
    assert_eq!(hire.expires_at, merge.expires_at);
    assert_eq!(budget.expires_at, None, "its kind has no deadline");

    let early = expire_approvals(pool, "2026-10-22T10:59:59.000Z").await;
    assert!(early.unwrap().is_empty());
    let due = "2026-10-22T11:00:00.000Z";
    let mut expired = expire_approvals(pool, due).await.unwrap();
    expired.sort_by_key(|a: &ApprovalId| a.0);
    assert_eq!(expired, [merge.id, hire.id]);
    let gone = crate::store::gov::get_approval(pool, merge.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        gone.decided_at.as_deref(),
        Some(due),
        "expired at the tick's now"
    );
    let reasons: Vec<String> = wakes(pool).await.into_iter().map(|w| w.2).collect();
    assert_eq!(
        reasons,
        [
            format!(
                "approval {}: PR merge expired: no decision by {due}",
                merge.id.0
            ),
            format!(
                "approval {}: Hire of QA 2 expired: no decision by {due}",
                hire.id.0
            ),
        ]
    );
    assert!(
        list_comments(pool, i).await.unwrap().is_empty(),
        "no decider, no comment"
    );
    let hired = get_agent(pool, hire.agent_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        hired.status,
        AgentStatus::Terminated,
        "an expired hire is not hired"
    );
    assert!(expire_approvals(pool, due).await.unwrap().is_empty());
    assert_eq!(wakes(pool).await.len(), 2, "expiry wakes once");

    set_deadline(pool, ApprovalKind::PrMerge, 0).await;
    assert_eq!(
        open(pool, c, po, i, ApprovalKind::PrMerge).await.expires_at,
        None
    );
}
