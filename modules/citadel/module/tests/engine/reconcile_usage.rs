//! Reconcile, usage, budgets and the cap.

use super::*;

// --- reconcile: runs follow sessions ---------------------------------------------------------

#[tokio::test]
async fn a_run_follows_its_session_to_success_and_releases_what_it_held() {
    let w = world().await;
    let run = w.running().await;
    sqlx::query("UPDATE citadel_issues SET checkout_run_id = ?, checked_out_at = ? WHERE id = ?")
        .bind(run.id.0)
        .bind(w.now())
        .bind(w.seed.issue)
        .execute(&w.app().pool)
        .await
        .unwrap();
    // It acted (any state-changing tool call), so its success is not "ended without acting".
    let mut conn = w.app().pool.acquire().await.unwrap();
    citadel_module::store::audit::append(
        &mut conn,
        citadel_module::store::audit::Event::new(AuditActor::System, "mcp.transition")
            .run(run.id.0),
    )
    .await
    .unwrap();
    drop(conn);
    w.report(
        &run,
        AgentState::Ended,
        vec![],
        tokens(10, 5),
        Some(Outcome::Succeeded),
    )
    .await;
    w.reconcile().await;
    let done = w.run(run.id).await;
    assert_eq!(done.state, RunState::Succeeded);
    assert_eq!(done.terminal_reason.as_deref(), Some("succeeded"));
    assert_eq!((done.usage.input_tokens, done.usage.output_tokens), (10, 5));
    let held: Option<i64> =
        sqlx::query_scalar("SELECT checkout_run_id FROM citadel_issues WHERE id = ?")
            .bind(w.seed.issue)
            .fetch_one(&w.app().pool)
            .await
            .unwrap();
    assert_eq!(held, None, "the issue is released when its run ends");
    // Again, and after a restart (a new pass over the same rows): nothing is repeated.
    let again = w.reconcile().await;
    assert_eq!(again, engine::Report::default());
    assert_eq!(count(&w, "SELECT count(*) FROM core_cost_events").await, 1);
    assert_eq!(
        count(
            &w,
            "SELECT count(*) FROM citadel_wake_requests WHERE source = 'retry'"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn a_session_the_gateway_serves_is_not_recorded_a_second_time_from_its_harness_meter() {
    // One ledger writer per session (KAN-435 G5): the gateway's reports record a session whose key
    // it serves, so the harness's own totals must not become a second set of rows.
    let w = world().await;
    let run = w.running().await;
    let sid = run.session_id.clone().unwrap();
    sqlx::query("UPDATE core_agent_sessions SET gateway_account_id = 7 WHERE id = ?")
        .bind(&sid)
        .execute(&w.app().pool)
        .await
        .unwrap();
    let fail = Outcome::Failed {
        reason: "tests red".into(),
        fingerprint: None,
    };
    w.report(&run, AgentState::Ended, vec![], tokens(10, 5), Some(fail))
        .await;
    w.reconcile().await;
    assert_eq!(w.run(run.id).await.state, RunState::Failed);
    assert_eq!(count(&w, "SELECT count(*) FROM core_cost_events").await, 0);
}

#[tokio::test]
async fn a_failed_session_schedules_bounded_retries_with_backoff() {
    let w = world().await;
    let mut run = w.running().await;
    for attempt in 1..=3 {
        let fail = Outcome::Failed {
            reason: "tests red".into(),
            fingerprint: None,
        };
        w.report(&run, AgentState::Ended, vec![], tokens(1, 1), Some(fail))
            .await;
        w.reconcile().await;
        let failed = w.run(run.id).await;
        assert_eq!(failed.state, RunState::Failed);
        assert_eq!(failed.terminal_reason.as_deref(), Some("tests red"));
        let retry: Option<(i64, Option<String>)> = sqlx::query_as(
            "SELECT attempt, not_before FROM citadel_wake_requests WHERE idempotency_key = ?",
        )
        .bind(format!("retry:run:{}", run.id.0))
        .fetch_optional(&w.app().pool)
        .await
        .unwrap();
        if attempt == 3 {
            assert!(retry.is_none(), "the last attempt is not retried");
            break;
        }
        let (n, not_before) = retry.expect("a retry wake");
        assert_eq!(n, attempt + 1);
        // Not before its backoff, then it runs.
        let early = engine::dispatch_next(w.app(), &w.host, &w.now())
            .await
            .unwrap();
        assert!(early.is_none(), "the backoff has not passed");
        let _ = not_before;
        let later = engine::dispatch_next(w.app(), &w.host, "2099-01-01T00:00:00.000Z")
            .await
            .unwrap();
        run = later.expect("the retry runs");
        w.report(&run, AgentState::Running, vec![], Tokens::default(), None)
            .await;
        w.reconcile().await;
    }
}

#[tokio::test]
async fn a_lost_session_ends_the_run_runner_lost() {
    let w = world().await;
    let run = w.running().await;
    let o = json!({"kind": "lost", "reason": "the runner never came back"});
    let sid = run.session_id.clone().unwrap();
    sessions::end(&w.app().pool, &sid, "lost", &o, &w.now())
        .await
        .unwrap();
    w.reconcile().await;
    let lost = w.run(run.id).await;
    assert_eq!(lost.state, RunState::RunnerLost);
    assert_eq!(
        count(
            &w,
            "SELECT count(*) FROM citadel_wake_requests WHERE source = 'retry'"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn a_claimed_run_whose_session_never_started_fails_after_the_grace() {
    let w = world().await;
    w.wake("assign:1").await;
    sqlx::query(
        "INSERT INTO citadel_runs (agent_id, issue_id, harness, state, runner, queued_at, claimed_at) \
         VALUES (?, ?, 'opencode', 'claimed', 'd_x', '2020-01-01T00:00:00.000Z', '2020-01-01T00:00:00.000Z')",
    )
    .bind(w.seed.agent)
    .bind(w.seed.issue)
    .execute(&w.app().pool)
    .await
    .unwrap();
    w.reconcile().await;
    let state: String = sqlx::query_scalar("SELECT state FROM citadel_runs")
        .fetch_one(&w.app().pool)
        .await
        .unwrap();
    assert_eq!(state, "failed");
}

#[tokio::test]
async fn a_session_no_live_run_owns_is_killed_but_a_clients_and_an_owned_one_are_not() {
    let w = world().await;
    let run = w.running().await;
    let policy = json!({});
    let runner = w.host.runners[0].clone();
    let dev: &str = &w.fx.dev.id;
    let old = "2020-01-01T00:00:00.000Z";
    let orphan = sessions::create_owned(
        &w.app().pool,
        &new_session(&runner, &policy, dev),
        Some("citadel"),
        AuditActor::System,
        old,
    )
    .await
    .unwrap();
    let clients = sessions::create(
        &w.app().pool,
        &new_session(&runner, &policy, dev),
        AuditActor::System,
        old,
    )
    .await
    .unwrap();
    let other = sessions::create_owned(
        &w.app().pool,
        &new_session(&runner, &policy, dev),
        Some("other"),
        AuditActor::System,
        old,
    )
    .await
    .unwrap();
    let report = w.reconcile().await;
    assert_eq!(report.orphans, 1);
    let told: Vec<String> = w
        .host
        .told
        .lock()
        .unwrap()
        .iter()
        .map(|(s, _)| s.clone())
        .collect();
    assert_eq!(
        told,
        vec![orphan.id.clone()],
        "only the orphan: not the client's, not another module's"
    );
    assert!(
        told.iter()
            .all(|s| s != &clients.id && s != &other.id && Some(s) != run.session_id.as_ref())
    );
}

// --- usage, budgets and the cap --------------------------------------------------------------

fn budget(w: &W, cap: i64) -> NewBudget {
    NewBudget {
        scope: BudgetScope::Agent(AgentId(w.seed.agent)),
        period: BudgetPeriod::Total,
        token_cap: cap,
        usd_cap_micros: None,
        warn_at_percent: 50,
        hard_stop: true,
    }
}

#[tokio::test]
async fn usage_moves_the_budget_once_and_warns_once() {
    let w = world().await;
    let b = gov::set_budget(&w.app().pool, &budget(&w, 1_000), AuditActor::System)
        .await
        .unwrap();
    let run = w.running().await;
    w.report(&run, AgentState::Running, vec![], tokens(300, 300), None)
        .await;
    w.reconcile().await;
    w.reconcile().await; // the same totals twice add nothing
    let spent: i64 = sqlx::query_scalar("SELECT tokens FROM core_budget_spend WHERE budget_id = ?")
        .bind(b.id.0)
        .fetch_one(&w.app().pool)
        .await
        .unwrap();
    assert_eq!(spent, 600);
    let warned = count(
        &w,
        "SELECT count(*) FROM audit_events WHERE action = 'citadel.budget.warning'",
    )
    .await;
    assert_eq!(warned, 1, "50% of 1000 was crossed once");
}

#[tokio::test]
async fn a_free_text_model_is_cleaned_for_the_ledger_and_one_runs_failure_does_not_stop_the_pass() {
    let w = world().await;
    let run = w.running().await;
    let long = "x".repeat(100);
    let cases = [
        ("claude-opus-4-6[1m]", "claude-opus-4-6_1m_".to_owned()),
        ("my model", "my_model".to_owned()),
        ("a@b", "a_b".to_owned()),
        ("c+d", "c_d".to_owned()),
        (long.as_str(), "x".repeat(80)),
    ];
    for (i, (given, want)) in cases.iter().enumerate() {
        sqlx::query("UPDATE citadel_runs SET model_used = ? WHERE id = ?")
            .bind(given)
            .bind(run.id.0)
            .execute(&w.app().pool)
            .await
            .unwrap();
        let total = 100 * (i as u64 + 1);
        w.report(&run, AgentState::Running, vec![], tokens(total, 0), None)
            .await;
        assert_eq!(w.reconcile().await.cost_events, 1, "{given}");
        let model: String =
            sqlx::query_scalar("SELECT model FROM core_cost_events ORDER BY id DESC LIMIT 1")
                .fetch_one(&w.app().pool)
                .await
                .unwrap();
        assert_eq!(&model, want, "{given}");
    }
    // A record the ledger cannot take is logged and left for the next pass; the pass itself goes on.
    sqlx::query(
        "CREATE TRIGGER refuse_cost BEFORE INSERT ON core_cost_events \
         BEGIN SELECT RAISE(ABORT, 'refused for the test'); END",
    )
    .execute(&w.app().pool)
    .await
    .unwrap();
    w.report(&run, AgentState::Running, vec![], tokens(900, 0), None)
        .await;
    assert_eq!(w.reconcile().await.cost_events, 0);
    sqlx::query("DROP TRIGGER refuse_cost")
        .execute(&w.app().pool)
        .await
        .unwrap();
    assert_eq!(
        w.reconcile().await.cost_events,
        1,
        "tried again, and recorded"
    );
}

#[tokio::test]
async fn an_exhausted_hard_stop_budget_kills_the_run_and_blocks_the_next_one() {
    let w = world().await;
    gov::set_budget(&w.app().pool, &budget(&w, 1_000), AuditActor::System)
        .await
        .unwrap();
    let run = w.running().await;
    w.report(&run, AgentState::Running, vec![], tokens(600, 500), None)
        .await;
    let report = w.reconcile().await;
    assert_eq!(report.capped, 1);
    assert_eq!(w.host.stops(), 1, "the harness is killed");
    let capped = w.run(run.id).await;
    assert_eq!(capped.state, RunState::Failed);
    assert_eq!(capped.terminal_reason.as_deref(), Some("token_cap"));
    assert_eq!(
        count(
            &w,
            "SELECT count(*) FROM citadel_wake_requests WHERE source = 'retry'"
        )
        .await,
        0,
        "a run stopped at its cap is never retried"
    );
    // A run stopped at its cap escalates its issue to the admin; hand it back to the agent so the
    // next wake is not stale.
    sqlx::query("UPDATE citadel_issues SET next_agent_id = ?, next_user_id = NULL WHERE id = ?")
        .bind(w.seed.agent)
        .bind(w.seed.issue)
        .execute(&w.app().pool)
        .await
        .unwrap();
    // The next wake is held back, and asks for one overrun approval, however often it is tried.
    w.wake("assign:2").await;
    for _ in 0..3 {
        assert!(w.dispatch().await.is_none(), "no budget, no run");
    }
    let overruns = count(
        &w,
        "SELECT count(*) FROM citadel_approvals WHERE kind = 'budget_overrun'",
    )
    .await;
    assert_eq!(overruns, 1);
    assert_eq!(
        w.host.started.lock().unwrap().len(),
        1,
        "no second session started"
    );
}

#[tokio::test]
async fn a_cap_whose_kill_the_runner_did_not_take_leaves_the_run_running() {
    let w = world().await;
    gov::set_budget(&w.app().pool, &budget(&w, 100), AuditActor::System)
        .await
        .unwrap();
    let run = w.running().await;
    w.report(&run, AgentState::Running, vec![], tokens(200, 0), None)
        .await;
    w.host.refuse.store(true, Ordering::SeqCst);
    w.reconcile().await;
    assert_eq!(
        w.run(run.id).await.state,
        RunState::Running,
        "a live harness is never marked over"
    );
    w.host.refuse.store(false, Ordering::SeqCst);
    w.reconcile().await;
    assert_eq!(
        w.run(run.id).await.terminal_reason.as_deref(),
        Some("token_cap")
    );
}

#[tokio::test]
async fn the_per_run_and_per_issue_caps_stop_a_run() {
    let w = world().await;
    let set = |name: &'static str, v: &'static str| {
        let pool = w.app().pool.clone();
        async move {
            let now = ainkrad_core_server::scheduler::SystemClock.now();
            citadel_module::settings::handle()
                .set(&pool, name, v, AuditActor::System, &now)
                .await
                .unwrap();
        }
    };
    use ainkrad_core_server::scheduler::Clock;
    set("run.token_cap", "1000").await;
    let run = w.running().await;
    w.report(&run, AgentState::Running, vec![], tokens(900, 200), None)
        .await;
    w.reconcile().await;
    let capped = w.run(run.id).await;
    assert_eq!(
        (capped.state, capped.terminal_reason.as_deref()),
        (RunState::Failed, Some("token_cap"))
    );
    // A run stopped at its cap escalates its issue to the admin; hand it back to the agent so the
    // next wake is not stale.
    sqlx::query("UPDATE citadel_issues SET next_agent_id = ?, next_user_id = NULL WHERE id = ?")
        .bind(w.seed.agent)
        .bind(w.seed.issue)
        .execute(&w.app().pool)
        .await
        .unwrap();
    // The issue's cap counts every run of the issue: a fresh run starts over its own cap, not its issue's.
    set("run.token_cap", "1000000").await;
    set("issue.token_cap", "1500").await;
    w.wake("assign:2").await;
    let next = engine::dispatch_next(w.app(), &w.host, &format!("{}9", "2099-01-01T00:00:00.00"))
        .await
        .unwrap();
    let next = next.expect("the issue's own cap does not stop admission, the run's usage does");
    w.report(&next, AgentState::Running, vec![], tokens(700, 0), None)
        .await;
    w.reconcile().await;
    assert_eq!(
        w.run(next.id).await.terminal_reason.as_deref(),
        Some("token_cap")
    );
}
