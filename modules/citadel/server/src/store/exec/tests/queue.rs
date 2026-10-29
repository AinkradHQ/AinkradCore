//! Wake requests, leases, cost events and the comment → run link.

use citadel_core::audit::AuditActor;

use super::*;

#[tokio::test]
async fn wake_request_crud_and_idempotency_key_is_unique() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let new = NewWakeRequest {
        agent_id: dev,
        issue_id: Some(i),
        source: WakeSource::Assignment,
        reason: "assigned CIT-1".to_owned(),
        idempotency_key: "assign:CIT-1:dev".to_owned(),
        not_before: None,
    };
    let mut w = create_wake_request(pool, &new).await.unwrap();
    assert_eq!(
        (w.status, w.attempt, w.coalesced_count),
        (WakeStatus::Pending, 1, 0)
    );
    let again = create_wake_request(
        pool,
        &NewWakeRequest {
            reason: "assigned again".to_owned(),
            source: WakeSource::Comment,
            ..new.clone()
        },
    )
    .await
    .unwrap();
    assert_eq!(again, w);
    assert_eq!(
        list_wake_requests(pool, dev).await.unwrap(),
        vec![w.clone()]
    );
    let raw = sqlx::query(
        "INSERT INTO wake_requests (agent_id, source, reason, idempotency_key) \
         VALUES (?, 'manual', 'x', ?)",
    )
    .bind(dev.0)
    .bind(&new.idempotency_key)
    .execute(pool)
    .await
    .unwrap_err();
    assert!(is_constraint(&raw), "{raw}");

    w.status = WakeStatus::Dispatched;
    w.coalesced_count = 2;
    w.attempt = 2;
    w.not_before = Some("2026-10-21T10:01:00Z".to_owned());
    assert!(update_wake_request(pool, &w).await.unwrap());
    assert_eq!(get_wake_request(pool, w.id).await.unwrap(), Some(w.clone()));

    // A run started by the wake outlives it.
    let run = create_run(
        pool,
        &NewRun {
            wake_request_id: Some(w.id),
            ..new_run(dev, Some(i))
        },
    )
    .await
    .unwrap();
    assert!(delete_wake_request(pool, w.id).await.unwrap());
    assert_eq!(
        get_run(pool, run.id)
            .await
            .unwrap()
            .unwrap()
            .wake_request_id,
        None
    );
}

#[tokio::test]
async fn lease_crud_one_per_run() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let runner = create_runner(
        pool,
        &NewRunner {
            name: "r".to_owned(),
            tags: vec![],
        },
        "k",
    )
    .await
    .unwrap();
    let run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    let mut lease = Lease {
        run_id: run.id,
        runner_id: runner.id,
        expires_at: "2026-10-21T10:01:00Z".to_owned(),
        heartbeat_at: "2026-10-21T10:00:00Z".to_owned(),
    };
    create_lease(pool, &lease).await.unwrap();
    let second = create_lease(pool, &lease).await.unwrap_err();
    assert!(is_constraint(&second), "{second}");

    lease.heartbeat_at = "2026-10-21T10:00:30Z".to_owned();
    lease.expires_at = "2026-10-21T10:01:30Z".to_owned();
    assert!(update_lease(pool, &lease).await.unwrap());
    assert_eq!(get_lease(pool, run.id).await.unwrap(), Some(lease.clone()));
    assert_eq!(
        list_leases(pool, runner.id).await.unwrap(),
        vec![lease.clone()]
    );
    assert!(delete_lease(pool, run.id).await.unwrap());
    assert!(!delete_lease(pool, run.id).await.unwrap());

    // A lease goes with its run.
    create_lease(pool, &lease).await.unwrap();
    delete_run(pool, run.id).await.unwrap();
    assert_eq!(get_lease(pool, run.id).await.unwrap(), None);
}

#[tokio::test]
async fn cost_events_are_insert_only_and_idempotent() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    let new = NewCostEvent {
        run_id: run.id,
        agent_id: dev,
        issue_id: Some(i),
        usage: Usage {
            input_tokens: 10,
            output_tokens: 20,
            cache_tokens: 30,
            cost_usd_micros: Some(1_500),
        },
        idempotency_key: "run-1-usage-1".to_owned(),
    };
    let first = record_cost_event(pool, &new).await.unwrap();
    let again = record_cost_event(
        pool,
        &NewCostEvent {
            usage: Usage::default(),
            ..new.clone()
        },
    )
    .await
    .unwrap();
    assert_eq!(again, first);
    assert_eq!(
        get_cost_event(pool, first.id).await.unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        list_cost_events(pool, run.id).await.unwrap(),
        vec![first.clone()]
    );

    let edit = sqlx::query("UPDATE cost_events SET input_tokens = 0 WHERE id = ?")
        .bind(first.id.0)
        .execute(pool)
        .await
        .unwrap_err();
    assert!(is_raised(&edit, "cost events are insert-only"), "{edit}");

    // Must match the run's agent and issue.
    let other = agent(pool, CompanyId(1)).await;
    let wrong_agent = record_cost_event(
        pool,
        &NewCostEvent {
            agent_id: other,
            idempotency_key: "k2".to_owned(),
            ..new.clone()
        },
    )
    .await
    .unwrap_err();
    assert!(
        is_raised(&wrong_agent, "cost event does not match its run"),
        "{wrong_agent}"
    );
    let wrong_issue = record_cost_event(
        pool,
        &NewCostEvent {
            issue_id: None,
            idempotency_key: "k3".to_owned(),
            ..new.clone()
        },
    )
    .await
    .unwrap_err();
    assert!(
        is_raised(&wrong_issue, "cost event does not match its run"),
        "{wrong_issue}"
    );

    // The issue may go; the ledger entry stays.
    delete_issue(pool, i, AuditActor::System).await.unwrap();
    let kept = get_cost_event(pool, first.id).await.unwrap().unwrap();
    assert_eq!(kept.issue_id, None);
    assert_eq!(kept.usage, first.usage);
}

#[tokio::test]
async fn comment_run_links_to_runs_and_migrates_back_to_text() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    let post = |run_id, key: &str| NewComment {
        issue_id: i,
        author: Actor::Agent(dev),
        body: "Done".to_owned(),
        run_id,
        idempotency_key: Some(key.to_owned()),
    };
    let c = create_comment(pool, &post(Some(run.id), "k1"))
        .await
        .unwrap();
    assert_eq!(c.run_id, Some(run.id));
    let dangling = create_comment(pool, &post(Some(RunId(999)), "k2"))
        .await
        .unwrap_err();
    assert!(is_constraint(&dangling), "{dangling}");

    // Reverting this migration keeps the run id, as text.
    MIGRATOR.undo(pool, 20261021000002).await.unwrap();
    let text_id: Option<String> = sqlx::query_scalar("SELECT run_id FROM comments WHERE id = ?")
        .bind(c.id.0)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(text_id, Some(run.id.0.to_string()));
    MIGRATOR.run(pool).await.unwrap();
    assert_eq!(get_comment(pool, c.id).await.unwrap().unwrap().run_id, None);

    // The comment outlives its run.
    let run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    let c = create_comment(pool, &post(Some(run.id), "k3"))
        .await
        .unwrap();
    delete_run(pool, run.id).await.unwrap();
    assert_eq!(get_comment(pool, c.id).await.unwrap().unwrap().run_id, None);
}
