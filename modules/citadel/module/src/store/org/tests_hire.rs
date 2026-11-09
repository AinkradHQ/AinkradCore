//! The hire gate (E6.4): a new agent waits on its approval and is never dispatched until it is
//! approved; a rejection terminates it; nothing else activates it; only a company's first CEO
//! starts active. Ported from `store/org/tests/hire.rs`.
//!
//! Adapted: `decide_approval` is the approvals slice's (S5), so a decision is written by raw SQL
//! and `hire_decided_in` (what `decide_approval` calls) is called with it. The wake/runner
//! dispatch half (`enqueue_wake`, `dispatch_next`) needs the run engine (S7) and is not ported.

use super::hire::hire_decided_in;
use super::tests_util::*;
use super::*;
use crate::domain::gov::{Approval, ApprovalKind, ApprovalStatus};
use crate::domain::org::{AgentStatus, OrgRole};
use crate::domain::work::UserId;
use sqlx::SqlitePool;

/// Decides the hire approval as the admin (what `gov::decide_approval` does for it).
async fn decide(pool: &SqlitePool, a: &Approval, approved: bool, reply: Option<&str>) {
    let status = if approved { "approved" } else { "rejected" };
    sqlx::query(
        "UPDATE citadel_approvals SET status = ?, decided_by_user_id = 1, reply = ?, \
         decided_at = ? WHERE id = ?",
    )
    .bind(status)
    .bind(reply)
    .bind(NOW)
    .bind(a.id.0)
    .execute(pool)
    .await
    .unwrap();
    let mut d = a.clone();
    d.status = if approved {
        ApprovalStatus::Approved
    } else {
        ApprovalStatus::Rejected
    };
    d.decided_by = Some(UserId(1));
    d.reply = reply.map(str::to_owned);
    let mut conn = pool.acquire().await.unwrap();
    hire_decided_in(&mut conn, &d, BY).await.unwrap();
}

#[tokio::test]
async fn an_unapproved_agent_never_activates() {
    let db = db().await;
    let pool = &db.pool;
    let c = create_company(pool, "A").await.unwrap();
    let po = create_agent(pool, &new_agent(c.id, "Po", OrgRole::None))
        .await
        .unwrap();
    let new = NewAgent {
        runner_tags: vec![],
        status: AgentStatus::Active,
        ..new_agent(c.id, "Dev", OrgRole::None)
    };
    let (dev, hire) = hire_agent(
        pool,
        &new,
        Some(po.id),
        "the backlog needs a pair of hands",
        BY,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(
        dev.status,
        AgentStatus::PendingApproval,
        "whatever was asked"
    );
    assert_eq!(
        (hire.kind, hire.status, hire.agent_id, hire.requested_by),
        (
            ApprovalKind::HireAgent,
            ApprovalStatus::Pending,
            Some(dev.id),
            po.id
        )
    );
    let payload: serde_json::Value = serde_json::from_str(&hire.payload).unwrap();
    assert_eq!(
        payload["justification"],
        "the backlog needs a pair of hands"
    );
    assert_eq!(payload["harness"], "claude");

    // Nothing but the approval activates it.
    let mut raw = dev.clone();
    raw.status = AgentStatus::Active;
    let e = update_agent(pool, &raw).await.unwrap_err();
    assert!(
        is_raised(
            &e,
            "an agent is hired only through an approved hire_agent approval"
        ),
        "{e}"
    );

    decide(pool, &hire, true, Some("welcome")).await;
    assert_eq!(
        get_agent(pool, dev.id).await.unwrap().unwrap().status,
        AgentStatus::Active
    );

    let (qa, hire) = hire_agent(
        pool,
        &new_agent(c.id, "Qa", OrgRole::None),
        None,
        "QA",
        BY,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(
        hire.requested_by, qa.id,
        "a human's hire is requested by the hire itself"
    );
    decide(pool, &hire, false, None).await;
    assert_eq!(
        get_agent(pool, qa.id).await.unwrap().unwrap().status,
        AgentStatus::Terminated
    );
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE entity_kind = 'agent' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "citadel.agent.hire_requested",
            "citadel.agent.hired",
            "citadel.agent.hire_requested",
            "citadel.agent.hire_rejected"
        ]
    );
}

#[tokio::test]
async fn hires_are_checked_and_only_the_first_ceo_bootstraps() {
    let db = db().await;
    let pool = &db.pool;
    let a = create_company(pool, "A").await.unwrap();
    let b = create_company(pool, "B").await.unwrap();
    let outsider = create_agent(pool, &new_agent(b.id, "Out", OrgRole::None))
        .await
        .unwrap();
    let dev = new_agent(a.id, "Dev", OrgRole::None);
    let e = hire_agent(pool, &dev, Some(outsider.id), "why", BY, NOW).await;
    assert!(matches!(e, Err(OrgError::OtherCompany)), "{e:?}");
    let e = hire_agent(pool, &dev, None, "  ", BY, NOW).await;
    assert!(
        matches!(e, Err(OrgError::Db(Error::InvalidArgument(_)))),
        "{e:?}"
    );

    let e = bootstrap_ceo(pool, &dev, BY).await;
    assert!(matches!(e, Err(OrgError::NotBootstrap)), "{e:?}");
    let ceo = bootstrap_ceo(pool, &new_agent(a.id, "Ceo", OrgRole::Ceo), BY)
        .await
        .unwrap();
    assert_eq!(ceo.status, AgentStatus::Active);
    let e = bootstrap_ceo(pool, &new_agent(a.id, "Ceo2", OrgRole::Ceo), BY).await;
    assert!(matches!(e, Err(OrgError::NotBootstrap)), "{e:?}");
}
