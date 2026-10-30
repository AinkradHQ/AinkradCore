//! The governance routes end to end through the Core's client gate (ported from the monolith's
//! `api/v1/tests/{gov,money}.rs`): approvals with a reply, prices and budget caps.
//!
//! Left as `#[ignore]`d stubs, each with its blocker: the cost reports (S7: they read the run
//! table), the reply waking the agent (S7: the wake queue), and the two issue/runner tests the
//! monolith kept in `money.rs` (S4 and S7 routes).

mod common;
mod gov_seed;

use axum::http::{Method, StatusCode};
use citadel_module::domain::gov::{ApprovalKind, NewApproval};
use citadel_module::store::gov::open_approval;
use common::*;
use gov_seed::*;
use serde_json::{Value, json};

async fn count(fx: &Fx, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn put(fx: &Fx, uri: &str, body: Value) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), Method::PUT, uri, Some(body)).await
}

async fn post(fx: &Fx, uri: &str, body: Value) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), Method::POST, uri, Some(body)).await
}

async fn get(fx: &Fx, uri: &str) -> (StatusCode, Value) {
    call(fx, Some(&fx.dev), Method::GET, uri, None).await
}

#[tokio::test]
async fn the_inbox_lists_pending_and_a_reply_is_recorded() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA").await;
    let b = seed(pool, "B", "BBB").await;
    let ask = |s: &Seed| NewApproval {
        company_id: s.company,
        kind: ApprovalKind::BudgetOverrun,
        issue_id: Some(s.issue),
        sprint_id: None,
        agent_id: None,
        requested_by: s.agent,
        payload: json!({"budget": 7}).to_string(),
    };
    let mine = open_approval(pool, &ask(&a), NOW).await.unwrap();
    open_approval(pool, &ask(&b), NOW).await.unwrap();

    let uri = format!("/companies/{}/approvals?pending=true", a.company.0);
    let (status, inbox) = get(&fx, &uri).await;
    assert_eq!(status, StatusCode::OK, "{inbox}");
    assert_eq!(inbox.as_array().unwrap().len(), 1, "only A's: {inbox}");
    assert_eq!(inbox[0]["kind"], "budget_overrun");
    assert_eq!(inbox[0]["payload"], json!({"budget": 7}));
    assert!(
        inbox[0]["created_at"]
            .as_str()
            .is_some_and(|t| t.ends_with('Z'))
    );
    assert!(inbox[0]["decided_at"].is_null(), "pending: not decided");

    let decide = format!("/approvals/{}/decide", mine.id.0);
    let (status, _) = post(&fx, &decide, json!({"approve": false, "raise_tokens": 5})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a raise only with approve");
    let (status, decided) = post(
        &fx,
        &decide,
        json!({"approve": false, "reply": "Rebase first."}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{decided}");
    assert_eq!(decided["status"], "rejected");
    assert_eq!(decided["reply"], "Rebase first.");
    assert_eq!(decided["decided_by"], 1);
    // Adapted: the app's clock is the real one, so the time is checked for its shape.
    assert!(
        decided["decided_at"]
            .as_str()
            .is_some_and(|t| t.ends_with('Z')),
        "decided at the app's now: {decided}"
    );
    assert_eq!(decided["created_at"], inbox[0]["created_at"]);
    let (status, body) = post(&fx, &decide, json!({"approve": true})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(get(&fx, &uri).await.1, json!([]));
    let (status, _) = post(&fx, "/approvals/99/decide", json!({"approve": true})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(count(&fx, "SELECT count(*) FROM audit_events WHERE action = 'citadel.approval.rejected' AND actor_kind = 'user'").await, 1);
}

#[tokio::test]
#[ignore = "S7: the reply wakes the agent (needs the wake queue)"]
async fn a_reply_reaches_the_agent() {
    todo!("monolith api/v1/tests/gov.rs: list_wake_requests grows after the reply")
}

#[tokio::test]
#[ignore = "S7: cost_report reads the run table (getCompanyCosts, getSprintCosts)"]
async fn costs_report_tokens_and_budgets() {
    todo!("monolith api/v1/tests/gov.rs: GET /companies/{{id}}/costs and /sprints/{{id}}/costs")
}

#[tokio::test]
async fn prices_are_versioned_and_validated() {
    let fx = fx().await;
    let new = |input: f64| {
        json!({"harness": "claude", "model": "opus", "input_usd_per_mtok": input,
               "output_usd_per_mtok": 15.0, "cache_usd_per_mtok": 0.3})
    };
    let (status, first) = post(&fx, "/prices", new(3.0)).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(
        (&first["version"], &first["input_usd_per_mtok"]),
        (&json!(1), &json!(3.0))
    );
    let (_, second) = post(&fx, "/prices", new(2.5)).await;
    assert_eq!(second["version"], 2);
    let (_, all) = get(&fx, "/prices").await;
    assert_eq!(all.as_array().unwrap().len(), 1, "the latest only");
    assert_eq!(all[0]["input_usd_per_mtok"], 2.5);
    assert_eq!(
        post(&fx, "/prices", new(-1.0)).await.0,
        StatusCode::BAD_REQUEST
    );
    let blank = json!({"harness": "claude", "model": " ", "input_usd_per_mtok": 1.0,
                       "output_usd_per_mtok": 1.0, "cache_usd_per_mtok": 1.0});
    assert_eq!(post(&fx, "/prices", blank).await.0, StatusCode::BAD_REQUEST);
    let bad_harness = json!({"harness": "gemini", "model": "x", "input_usd_per_mtok": 1.0,
                             "output_usd_per_mtok": 1.0, "cache_usd_per_mtok": 1.0});
    assert_eq!(
        post(&fx, "/prices", bad_harness).await.0,
        StatusCode::BAD_REQUEST
    );
    let (_, history) = get(&fx, "/prices/history?harness=claude&model=opus").await;
    assert_eq!(history.as_array().unwrap().len(), 2);
    assert_eq!(history[0]["version"], 2, "newest first");
    let set = "SELECT count(*) FROM audit_events WHERE action = 'citadel.price.set' \
               AND actor_kind = 'user'";
    assert_eq!(count(&fx, set).await, 2);
}

#[tokio::test]
async fn budgets_are_set_in_their_company_only() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA").await;
    let b = seed(pool, "B", "BBB").await;
    let uri = format!("/companies/{}/budgets", a.company.0);
    let mine = json!({"scope": {"kind": "agent", "agent_id": a.agent.0}, "period": "month",
                      "token_cap": 500_000});
    let (status, set) = put(&fx, &uri, mine.clone()).await;
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(
        (&set["token_cap"], &set["warn_at_percent"]),
        (&json!(500_000), &json!(80))
    );
    assert_eq!(set["hard_stop"], true);
    let mut raised = mine.clone();
    raised["token_cap"] = json!(800_000);
    raised["warn_at_percent"] = json!(90);
    let (_, changed) = put(&fx, &uri, raised).await;
    assert_eq!(
        changed["budget_id"], set["budget_id"],
        "one per scope and period"
    );
    assert_eq!(changed["warn_at_percent"], 90);
    let theirs = json!({"scope": {"kind": "agent", "agent_id": b.agent.0}, "period": "month",
                        "token_cap": 1});
    assert_eq!(put(&fx, &uri, theirs).await.0, StatusCode::NOT_FOUND);
    let mut bad = mine.clone();
    bad["token_cap"] = json!(-5);
    assert_eq!(put(&fx, &uri, bad).await.0, StatusCode::BAD_REQUEST);
    let mut bad = mine;
    bad["period"] = json!("fortnight");
    assert_eq!(put(&fx, &uri, bad).await.0, StatusCode::BAD_REQUEST);
    let audited = "SELECT count(*) FROM audit_events WHERE action = 'citadel.budget.set' \
                   AND actor_kind = 'user'";
    assert_eq!(count(&fx, audited).await, 2);

    // Deleting it answers with the company's budgets left, and is audited.
    let id = set["budget_id"].as_i64().unwrap();
    let (status, left) = call(
        &fx,
        Some(&fx.dev),
        Method::DELETE,
        &format!("/budgets/{id}"),
        None,
    )
    .await;
    assert_eq!((status, left), (StatusCode::OK, json!([])));
    let (status, _) = call(
        &fx,
        Some(&fx.dev),
        Method::DELETE,
        &format!("/budgets/{id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "S4: POST /issues/{id}/backlog is the work slice's route (needs the run table too)"]
async fn an_issue_moves_to_the_backlog_once_no_run_works_on_it() {
    todo!("monolith api/v1/tests/money.rs")
}

#[tokio::test]
#[ignore = "S7: runner wake modes, the stuck report and the push classifier"]
async fn run_when_back_keeps_the_work_waiting_and_pushes_on_return() {
    todo!("monolith api/v1/tests/money.rs")
}

#[tokio::test]
async fn budgets_take_a_dollar_cap_and_an_issue_scope() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA").await;
    let uri = format!("/companies/{}/budgets", a.company.0);
    let body = json!({"scope": {"kind": "issue", "issue_id": a.issue.0}, "period": "total",
                      "token_cap": 0, "usd_cap_micros": 25_000_000});
    let (status, made) = post(&fx, &uri, body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{made}");
    assert_eq!(
        (
            &made["scope"],
            &made["usd_cap_micros"],
            &made["usd_spent_micros"]
        ),
        (
            &json!({"kind": "issue", "issue_id": a.issue.0}),
            &json!(25_000_000),
            &json!(0)
        )
    );
    assert_eq!(
        post(&fx, &uri, body).await.0,
        StatusCode::CONFLICT,
        "one per scope and period"
    );
    let neg = json!({"scope": {"kind": "company", "company_id": a.company.0}, "period": "day",
                     "token_cap": 1, "usd_cap_micros": -1});
    assert_eq!(put(&fx, &uri, neg).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "S7: apply_from past prices the run table's events (and listUnpriced reads it)"]
async fn prices_apply_to_the_past() {
    todo!(
        "monolith api/v1/tests/money.rs: apply_from past and GET /companies/{{id}}/costs/unpriced"
    )
}
