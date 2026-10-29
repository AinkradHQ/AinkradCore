//! The stuck list's actions (release a dead checkout, retry a run on a runner, bump an issue),
//! budget create and delete, price history and a company's overridden settings: each audited,
//! and refused for another company's data.

use ainkrad_core::exec::RunEvent;
use serde_json::json;

use super::*;
use crate::api::v1::scope::COMPANY_HEADER;
use crate::store::exec::{stuck_report, transition_run};
use ainkrad_core::exec::StuckKind;

async fn count(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A request working in `company`.
async fn as_company(
    fx: &Fx,
    company: CompanyId,
    m: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut r = req(m, uri, Some(&fx.key), body);
    let v = company.0.to_string().parse().unwrap();
    r.headers_mut().insert(COMPANY_HEADER, v);
    send(&fx.app, r).await
}

async fn end(pool: &SqlitePool, s: &Seed) {
    let by = AuditActor::Runner(s.runner);
    transition_run(pool, s.run.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_dead_checkout_is_released_but_a_live_one_is_not() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let hold = "UPDATE issues SET checkout_run_id = ?, checked_out_at = ? WHERE id = ?";
    let held = |s: &Seed| sqlx::query(hold).bind(s.run.id.0).bind(NOW).bind(s.issue.0);
    held(&a).execute(pool).await.unwrap();
    let uri = format!("/api/v1/issues/{}/release-checkout", a.issue.0);
    let (status, got) = fx.post(&uri, json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT, "its run is live: {got}");

    end(pool, &a).await;
    // An engine error: the ended run still holds it.
    held(&a).execute(pool).await.unwrap();
    let released = fx.ok_post(&uri, json!({})).await;
    assert_eq!(released["checkout_run_id"], Value::Null);
    let audited = "SELECT count(*) FROM audit_events WHERE action = 'issue.released' \
                   AND actor_kind = 'user'";
    assert_eq!(count(pool, audited).await, 1);
    assert_eq!(
        fx.post(&uri, json!({})).await.0,
        StatusCode::CONFLICT,
        "not checked out"
    );

    let theirs = format!("/api/v1/issues/{}/release-checkout", b.issue.0);
    let (status, _) = as_company(&fx, a.company, Method::POST, &theirs, Some(json!({}))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "another company's issue");
}

#[tokio::test]
async fn a_run_is_retried_on_the_runner_picked_only() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let mac = NewRunner {
        name: "mac".to_owned(),
        tags: vec!["macos".to_owned()],
    };
    let (mac, _) = register_runner(pool, &mac).await.unwrap();
    let uri = format!("/api/v1/runs/{}/retry", a.run.id.0);
    let on = |runner: i64| json!({"runner_id": runner});
    assert_eq!(
        fx.post(&uri, on(mac.id.0)).await.0,
        StatusCode::CONFLICT,
        "still live"
    );
    end(pool, &a).await;
    assert_eq!(fx.post(&uri, on(999)).await.0, StatusCode::NOT_FOUND);
    sqlx::query("UPDATE agents SET runner_tags = '[\"xcode\"]' WHERE id = ?")
        .bind(a.agent.0)
        .execute(pool)
        .await
        .unwrap();
    let (status, got) = fx.post(&uri, on(mac.id.0)).await;
    assert_eq!(status, StatusCode::CONFLICT, "lacks the tag: {got}");
    sqlx::query("UPDATE agents SET runner_tags = '[\"macos\"]' WHERE id = ?")
        .bind(a.agent.0)
        .execute(pool)
        .await
        .unwrap();
    let set = |sql: &'static str| sqlx::query(sql).bind(mac.id.0).execute(pool);
    set("UPDATE runners SET harnesses = '{\"zzz\": \"1\"}' WHERE id = ?")
        .await
        .unwrap();
    let (status, got) = fx.post(&uri, on(mac.id.0)).await;
    assert_eq!(status, StatusCode::CONFLICT, "lacks the harness: {got}");
    set("UPDATE runners SET harnesses = NULL, drained_at = '2026-01-01' WHERE id = ?")
        .await
        .unwrap();
    let (status, got) = fx.post(&uri, on(mac.id.0)).await;
    assert_eq!(status, StatusCode::CONFLICT, "drained: {got}");
    set("UPDATE runners SET drained_at = NULL WHERE id = ?")
        .await
        .unwrap();

    let retried = fx.ok_post(&uri, on(mac.id.0)).await;
    assert_eq!(retried["runner_id"], mac.id.0);
    assert_eq!(retried["issue_id"], a.issue.0);
    sqlx::query("UPDATE runners SET status = 'online', tags = '[\"macos\"]' WHERE id = ?")
        .bind(a.runner.0)
        .execute(pool)
        .await
        .unwrap();
    let stuck = stuck_report(pool, "2027-01-01T00:00:00.000Z")
        .await
        .unwrap();
    let waits = stuck
        .iter()
        .any(|s| s.kind == StuckKind::WakeNoRunner && s.agent_id == Some(a.agent));
    assert!(waits, "only the offline mac may take it: {stuck:?}");
    let everywhere = ["macos".to_owned()];
    let other = dispatch_next(pool, a.runner, &everywhere, &Harness::ALL, NOW)
        .await
        .unwrap();
    assert!(other.is_none(), "pinned to the mac: {other:?}");
    let run = dispatch_next(pool, mac.id, &everywhere, &Harness::ALL, NOW)
        .await
        .unwrap()
        .expect("the mac takes it");
    assert_eq!((run.agent_id, run.issue_id), (a.agent, Some(a.issue)));
    let audited = "SELECT count(*) FROM audit_events WHERE action = 'run.retried'";
    assert_eq!(count(pool, audited).await, 1);

    let theirs = format!("/api/v1/runs/{}/retry", b.run.id.0);
    let (status, _) = as_company(&fx, a.company, Method::POST, &theirs, Some(on(mac.id.0))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "another company's run");
}

#[tokio::test]
async fn a_bumped_issue_goes_to_the_top_and_is_dispatched_first() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    end(pool, &a).await;
    let later = NewIssue {
        project_id: a.project,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Later".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Agent(a.agent)),
        points: None,
        sprint_id: None,
    };
    let later = create_issue(pool, &later).await.unwrap();
    for (n, issue) in [a.issue, later.id].into_iter().enumerate() {
        let w = NewWakeRequest {
            agent_id: a.agent,
            issue_id: Some(issue),
            source: WakeSource::Manual,
            reason: "test".to_owned(),
            idempotency_key: format!("bump-{n}"),
            not_before: None,
        };
        enqueue_wake(pool, &w).await.unwrap();
    }
    let uri = format!("/api/v1/issues/{}/priority", later.id.0);
    let bumped = fx.ok_post(&uri, json!({})).await;
    assert_eq!(bumped["priority"], true);
    let first = fx.ok(&format!("/api/v1/issues/{}", a.issue.0)).await;
    assert!(
        bumped["rank"].as_f64() < first["rank"].as_f64(),
        "{bumped} {first}"
    );
    let run = dispatch_next(pool, a.runner, &[], &Harness::ALL, NOW)
        .await
        .unwrap()
        .expect("a wake is due");
    assert_eq!(run.issue_id, Some(later.id), "the bumped issue first");

    let cleared = fx.ok_post(&uri, json!({"priority": false})).await;
    assert_eq!(
        (&cleared["priority"], &cleared["rank"]),
        (&json!(false), &bumped["rank"])
    );
    let audited = "SELECT count(*) FROM audit_events WHERE action = 'issue.priority_set'";
    assert_eq!(count(pool, audited).await, 2);
    let theirs = format!("/api/v1/issues/{}/priority", b.issue.0);
    let (status, _) = as_company(&fx, a.company, Method::POST, &theirs, Some(json!({}))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn budgets_are_created_once_and_deleted_in_their_company() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/companies/{}/budgets", a.company.0);
    let new = json!({"scope": {"kind": "project", "project_id": a.project.0}, "period": "week",
                     "token_cap": 9000});
    let made = fx.ok_post(&uri, new.clone()).await;
    assert_eq!(
        (&made["token_cap"], &made["spent"]),
        (&json!(9000), &json!(0))
    );
    assert_eq!(
        fx.post(&uri, new).await.0,
        StatusCode::CONFLICT,
        "one per scope and period"
    );
    let theirs = format!("/api/v1/companies/{}/budgets", b.company.0);
    let own = json!({"scope": {"kind": "company", "company_id": b.company.0}, "period": "day",
                     "token_cap": 1});
    let their_budget = fx.ok_post(&theirs, own).await["budget_id"]
        .as_i64()
        .unwrap();

    let gone = format!("/api/v1/budgets/{their_budget}");
    let (status, _) = as_company(&fx, a.company, Method::DELETE, &gone, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "another company's budget");
    let mine = format!("/api/v1/budgets/{}", made["budget_id"]);
    let (status, left) = send(&fx.app, req(Method::DELETE, &mine, Some(&fx.key), None)).await;
    assert_eq!((status, left), (StatusCode::OK, json!([])));
    let (status, _) = send(&fx.app, req(Method::DELETE, &mine, Some(&fx.key), None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for action in ["budget.created", "budget.deleted"] {
        let sql = format!("SELECT count(*) FROM audit_events WHERE action = '{action}'");
        assert_eq!(
            count(pool, &sql).await,
            if action == "budget.created" { 2 } else { 1 }
        );
    }
}

#[tokio::test]
async fn a_price_lists_every_version() {
    let fx = fx().await;
    for input in [3.0, 2.5] {
        let p = json!({"harness": "claude", "model": "opus", "input_usd_per_mtok": input,
                       "output_usd_per_mtok": 15.0, "cache_usd_per_mtok": 0.3});
        fx.ok_post("/api/v1/prices", p).await;
    }
    let all = fx
        .ok("/api/v1/prices/history?harness=claude&model=opus")
        .await;
    let versions: Vec<_> = all
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["version"].clone(), v["input_usd_per_mtok"].clone()))
        .collect();
    assert_eq!(versions, [(json!(2), json!(2.5)), (json!(1), json!(3.0))]);
    assert_eq!(all[0]["set_at"], NOW);
    let none = fx
        .ok("/api/v1/prices/history?harness=codex&model=opus")
        .await;
    assert_eq!(none, json!([]));
    assert_eq!(
        fx.get("/api/v1/prices/history?harness=nope&model=x")
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn a_company_lists_its_overridden_settings_only() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(pool, "B", "BBB", ProjectMode::Kanban).await;
    let set = |scope: String, value: i64| {
        let uri = format!("/api/v1/settings/{scope}/run.token_cap");
        send(
            &fx.app,
            req(
                Method::PUT,
                &uri,
                Some(&fx.key),
                Some(json!({"value": value})),
            ),
        )
    };
    for (scope, value) in [
        (format!("company:{}", a.company.0), 50_000),
        (format!("project:{}", a.project.0), 40_000),
        (format!("company:{}", b.company.0), 30_000),
        ("server".to_owned(), 60_000),
    ] {
        assert_eq!(set(scope, value).await.0, StatusCode::OK);
    }
    let uri = format!("/api/v1/companies/{}/settings/overridden", a.company.0);
    let all = fx.ok(&uri).await;
    let got: Vec<_> = all
        .as_array()
        .unwrap()
        .iter()
        .map(|o| (o["scope"].clone(), o["value"].clone()))
        .collect();
    assert_eq!(
        got,
        [
            (json!(format!("company:{}", a.company.0)), json!(50_000)),
            (json!(format!("project:{}", a.project.0)), json!(40_000)),
        ]
    );
    assert_eq!(
        (
            &all[0]["key"],
            &all[0]["set_by"]["user_id"],
            &all[0]["set_at"]
        ),
        (&json!("run.token_cap"), &json!(1), &json!(NOW))
    );
    let theirs = format!("/api/v1/companies/{}/settings/overridden", b.company.0);
    let (status, _) = as_company(&fx, a.company, Method::GET, &theirs, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
