//! The hire gate (E6.4): a new agent waits on its approval and is never dispatched until it is
//! approved; a rejection terminates it; nothing else activates it; only a company's first CEO
//! starts active.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::exec::{NewRunner, NewWakeRequest, WakeSource};
use ainkrad_core::gov::{ApprovalKind, ApprovalStatus};
use ainkrad_core::work::UserId;

use super::*;
use crate::store::exec::{create_runner, dispatch_next, enqueue_wake};
use crate::store::gov::decide_approval;

const ADMIN: UserId = UserId(1);
const BY: AuditActor = AuditActor::User(ADMIN);
const NOW: &str = "2026-10-21T10:00:00.000Z";

fn is_raised(e: &Error, message: &str) -> bool {
    matches!(e, Error::Database(d) if d.message() == message)
}

#[tokio::test]
async fn an_unapproved_agent_never_runs() {
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

    let wake = NewWakeRequest {
        agent_id: dev.id,
        issue_id: None,
        source: WakeSource::Manual,
        reason: "try".to_owned(),
        idempotency_key: "hire-test".to_owned(),
        not_before: None,
    };
    enqueue_wake(pool, &wake).await.unwrap();
    let runner = NewRunner {
        name: "box".to_owned(),
        tags: vec![],
    };
    let runner = create_runner(pool, &runner, "box").await.unwrap().id;
    let dispatch = || dispatch_next(pool, runner, &[], &Harness::ALL, NOW);
    assert!(
        dispatch().await.unwrap().is_none(),
        "pending: not dispatched"
    );

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

    decide_approval(pool, hire.id, true, ADMIN, Some("welcome"), NOW)
        .await
        .unwrap();
    assert_eq!(
        get_agent(pool, dev.id).await.unwrap().unwrap().status,
        AgentStatus::Active
    );
    let run = dispatch().await.unwrap().expect("hired: dispatched");
    assert_eq!(run.agent_id, dev.id);

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
    decide_approval(pool, hire.id, false, ADMIN, None, NOW)
        .await
        .unwrap();
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
            "agent.hire_requested",
            "agent.hired",
            "agent.hire_requested",
            "agent.hire_rejected"
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
