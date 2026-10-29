//! Approvals with a reply, and costs.

use citadel_core::gov::{ApprovalKind, BudgetPeriod, BudgetScope, NewApproval, NewBudget};
use citadel_core::work::ProjectMode;
use serde_json::json;

use super::*;
use crate::store::exec::list_wake_requests;
use crate::store::gov::{open_approval, set_budget};

#[tokio::test]
async fn the_inbox_lists_pending_and_a_reply_reaches_the_agent() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let ask = |s: &Seed| NewApproval {
        company_id: s.company,
        kind: ApprovalKind::BudgetOverrun,
        issue_id: Some(s.issue),
        sprint_id: None,
        agent_id: None,
        requested_by: s.agent,
        payload: json!({"budget": 7}).to_string(),
    };
    let mine = open_approval(&fx.app.pool, &ask(&a), NOW).await.unwrap();
    open_approval(&fx.app.pool, &ask(&b), NOW).await.unwrap();

    let uri = format!("/api/v1/companies/{}/approvals?pending=true", a.company.0);
    let inbox = fx.ok(&uri).await;
    assert_eq!(inbox.as_array().unwrap().len(), 1, "only A's: {inbox}");
    assert_eq!(inbox[0]["kind"], "budget_overrun");
    assert_eq!(inbox[0]["payload"], json!({"budget": 7}));
    assert!(
        inbox[0]["created_at"]
            .as_str()
            .is_some_and(|t| t.ends_with('Z'))
    );
    assert!(inbox[0]["decided_at"].is_null(), "pending: not decided");

    let decide = format!("/api/v1/approvals/{}/decision", mine.id.0);
    let (status, _) = fx
        .post(&decide, json!({"approve": false, "raise_tokens": 5}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a raise only with approve");
    let wakes_before = list_wake_requests(&fx.app.pool, a.agent)
        .await
        .unwrap()
        .len();
    let decided = fx
        .ok_post(&decide, json!({"approve": false, "reply": "Rebase first."}))
        .await;
    assert_eq!(decided["status"], "rejected");
    assert_eq!(decided["reply"], "Rebase first.");
    assert_eq!(decided["decided_by"], 1);
    assert_eq!(decided["decided_at"], NOW, "decided at the engine's now");
    assert_eq!(decided["created_at"], inbox[0]["created_at"]);
    let wakes = list_wake_requests(&fx.app.pool, a.agent).await.unwrap();
    assert!(wakes.len() > wakes_before, "the reply wakes the agent");
    let (status, body) = fx.post(&decide, json!({"approve": true})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(fx.ok(&uri).await, json!([]));
    let (status, _) = fx
        .post("/api/v1/approvals/99/decision", json!({"approve": true}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn costs_report_tokens_and_budgets() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = NewBudget {
        scope: BudgetScope::Company(a.company),
        period: BudgetPeriod::Month,
        token_cap: 1000,
        usd_cap_micros: None,
        warn_at_percent: 80,
        hard_stop: true,
    };
    set_budget(&fx.app.pool, &b, super::super::BY)
        .await
        .unwrap();
    let costs = fx
        .ok(&format!("/api/v1/companies/{}/costs", a.company.0))
        .await;
    assert_eq!(costs["report"]["runs"], 0);
    let budget = &costs["budgets"][0];
    assert_eq!(
        budget["scope"],
        json!({"kind": "company", "company_id": a.company.0})
    );
    assert_eq!(
        (budget["period"].clone(), budget["period_key"].clone()),
        (json!("month"), json!("2026-10"))
    );
    assert_eq!(
        fx.get("/api/v1/companies/99/costs").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fx.get("/api/v1/sprints/99/costs").await.0,
        StatusCode::NOT_FOUND
    );
}
