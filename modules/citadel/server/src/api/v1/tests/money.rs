//! Prices and budget caps from the app, moving an issue to the backlog, and "run when I'm back".

use citadel_core::exec::RunEvent;
use citadel_core::work::ProjectMode;
use serde_json::json;

use super::*;
use crate::store::exec::{runner_woke, stuck_report, transition_run};

async fn count(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn prices_are_versioned_and_validated() {
    let fx = fx().await;
    let new = |input: f64| {
        json!({"harness": "claude", "model": "opus", "input_usd_per_mtok": input,
               "output_usd_per_mtok": 15.0, "cache_usd_per_mtok": 0.3})
    };
    let first = fx.ok_post("/api/v1/prices", new(3.0)).await;
    assert_eq!(
        (&first["version"], &first["input_usd_per_mtok"]),
        (&json!(1), &json!(3.0))
    );
    let second = fx.ok_post("/api/v1/prices", new(2.5)).await;
    assert_eq!(second["version"], 2);
    let all = fx.ok("/api/v1/prices").await;
    assert_eq!(all.as_array().unwrap().len(), 1, "the latest only");
    assert_eq!(all[0]["input_usd_per_mtok"], 2.5);
    assert_eq!(
        fx.post("/api/v1/prices", new(-1.0)).await.0,
        StatusCode::BAD_REQUEST
    );
    let blank = json!({"harness": "claude", "model": " ", "input_usd_per_mtok": 1.0,
                       "output_usd_per_mtok": 1.0, "cache_usd_per_mtok": 1.0});
    assert_eq!(
        fx.post("/api/v1/prices", blank).await.0,
        StatusCode::BAD_REQUEST
    );
    let set =
        "SELECT count(*) FROM audit_events WHERE action = 'price.set' AND actor_kind = 'user'";
    assert_eq!(count(&fx.app.pool, set).await, 2);
}

#[tokio::test]
async fn budgets_are_set_in_their_company_only() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/companies/{}/budgets", a.company.0);
    let put = |body: Value| send(&fx.app, req(Method::PUT, &uri, Some(&fx.key), Some(body)));
    let mine = json!({"scope": {"kind": "agent", "agent_id": a.agent.0}, "period": "month",
                      "token_cap": 500_000});
    let (status, set) = put(mine.clone()).await;
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(
        (&set["token_cap"], &set["warn_at_percent"]),
        (&json!(500_000), &json!(80))
    );
    assert_eq!(set["hard_stop"], true);
    let mut raised = mine.clone();
    raised["token_cap"] = json!(800_000);
    raised["warn_at_percent"] = json!(90);
    let (_, changed) = put(raised).await;
    assert_eq!(
        changed["budget_id"], set["budget_id"],
        "one per scope and period"
    );
    assert_eq!(changed["warn_at_percent"], 90);
    let theirs = json!({"scope": {"kind": "agent", "agent_id": b.agent.0}, "period": "month",
                        "token_cap": 1});
    assert_eq!(put(theirs).await.0, StatusCode::NOT_FOUND);
    let mut bad = mine;
    bad["token_cap"] = json!(-5);
    assert_eq!(put(bad).await.0, StatusCode::BAD_REQUEST);
    let audited = "SELECT count(*) FROM audit_events WHERE action = 'budget.set' \
                   AND actor_kind = 'user'";
    assert_eq!(count(pool, audited).await, 2);
}

#[tokio::test]
async fn an_issue_moves_to_the_backlog_once_no_run_works_on_it() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/issues/{}/backlog", a.issue.0);
    assert_eq!(
        fx.post(&uri, json!({})).await.0,
        StatusCode::CONFLICT,
        "its run is live"
    );
    let by = AuditActor::Runner(a.runner);
    transition_run(pool, a.run.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap();
    let shelved = fx.ok_post(&uri, json!({})).await;
    assert_eq!(shelved["state"], "backlog");
    assert_eq!(shelved["next_actor"]["user_id"], 1, "{shelved}");
    let audited = "SELECT count(*) FROM audit_events WHERE action = 'issue.backlog'";
    assert_eq!(count(pool, audited).await, 1);
}

#[tokio::test]
async fn run_when_back_keeps_the_work_waiting_and_pushes_on_return() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    // A Mac-only agent with a wake no online runner can serve.
    sqlx::query("UPDATE agents SET runner_tags = '[\"macos\"]'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE runners SET tags = '[\"macos\"]', status = 'offline'")
        .execute(pool)
        .await
        .unwrap();
    let by = AuditActor::Runner(a.runner);
    transition_run(pool, a.run.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap();
    let uri = format!("/api/v1/issues/{}/nudge", a.issue.0);
    fx.ok_post(&uri, json!({})).await;
    let later = "2027-01-01T00:00:00.000Z";
    let waiting = |s: &[citadel_core::exec::StuckIssue]| {
        s.iter()
            .any(|s| s.kind == citadel_core::exec::StuckKind::WakeNoRunner)
    };
    assert!(
        waiting(&stuck_report(pool, later).await.unwrap()),
        "stuck before"
    );

    let wake = format!("/api/v1/runners/{}/wake", a.runner.0);
    assert_eq!(
        fx.post(&wake, json!({"when": "soon"})).await.0,
        StatusCode::BAD_REQUEST
    );
    let r = fx.ok_post(&wake, json!({"when": "when_back"})).await;
    assert_eq!(r["wake_mode"], "when_back");
    assert!(
        !waiting(&stuck_report(pool, later).await.unwrap()),
        "it waits for the runner"
    );
    let pushes = || async {
        let events = crate::store::events::list_events(pool, 0, 1000)
            .await
            .unwrap();
        events
            .iter()
            .filter_map(crate::push::notification)
            .filter(|n| n.kind == "runner")
            .map(|n| n.title)
            .collect::<Vec<_>>()
    };
    assert!(pushes().await.is_empty(), "nothing pushed while it sleeps");
    runner_woke(pool, a.runner).await.unwrap();
    assert_eq!(pushes().await, ["Runner back"]);
    runner_woke(pool, a.runner).await.unwrap();
    assert_eq!(pushes().await.len(), 1, "once per request");
}

#[tokio::test]
async fn budgets_take_a_dollar_cap_and_an_issue_scope_and_prices_apply_to_the_past() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/companies/{}/budgets", a.company.0);
    let body = json!({"scope": {"kind": "issue", "issue_id": a.issue.0}, "period": "total",
                      "token_cap": 0, "usd_cap_micros": 25_000_000});
    let (status, made) = send(&fx.app, req(Method::POST, &uri, Some(&fx.key), Some(body))).await;
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
    let neg = json!({"scope": {"kind": "company", "company_id": a.company.0}, "period": "day",
                     "token_cap": 1, "usd_cap_micros": -1});
    let put = send(&fx.app, req(Method::PUT, &uri, Some(&fx.key), Some(neg)));
    assert_eq!(put.await.0, StatusCode::BAD_REQUEST);

    let unpriced = format!("/api/v1/companies/{}/costs/unpriced", a.company.0);
    assert_eq!(fx.ok(&unpriced).await, json!([]));
    let price = json!({"harness": "claude", "model": "opus", "input_usd_per_mtok": 3.0,
                       "output_usd_per_mtok": 15.0, "cache_usd_per_mtok": 0.3,
                       "apply_from": "past"});
    let set = fx.ok_post("/api/v1/prices", price).await;
    assert_eq!(set["version"], 1);
    let audited = "SELECT count(*) FROM audit_events WHERE action = 'price.set' \
                   AND json_extract(details, '$.apply_from') = 'past'";
    assert_eq!(count(pool, audited).await, 1);
}
