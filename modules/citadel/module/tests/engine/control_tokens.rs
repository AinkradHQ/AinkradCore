//! Cancel and kill, tool approvals, timers and the run token.

use super::*;

// --- cancel and kill ---------------------------------------------------------------------------

#[tokio::test]
async fn cancel_ends_the_run_only_after_the_runner_took_it_and_releases_the_issue() {
    let w = world().await;
    let run = w.running().await;
    sqlx::query("UPDATE citadel_issues SET checkout_run_id = ?, checked_out_at = ? WHERE id = ?")
        .bind(run.id.0)
        .bind(w.now())
        .bind(w.seed.issue)
        .execute(&w.app().pool)
        .await
        .unwrap();
    // The runner is away: not over, the request is kept.
    w.host.refuse.store(true, Ordering::SeqCst);
    let refused = engine::stop_run(w.app(), &w.host, run.id, true, &w.fx.dev.id, &w.now()).await;
    assert!(
        matches!(refused, Err(ControlError::Unreachable(_))),
        "{refused:?}"
    );
    let still = w.run(run.id).await;
    assert_eq!(still.state, RunState::Running);
    assert!(still.cancel_requested_at.is_some());
    let held: Option<i64> =
        sqlx::query_scalar("SELECT checkout_run_id FROM citadel_issues WHERE id = ?")
            .bind(w.seed.issue)
            .fetch_one(&w.app().pool)
            .await
            .unwrap();
    assert_eq!(
        held,
        Some(run.id.0),
        "still checked out while the harness lives"
    );
    // The runner is back: reconcile asks again, and the admin's word stands.
    w.host.refuse.store(false, Ordering::SeqCst);
    w.reconcile().await;
    let over = w.run(run.id).await;
    assert_eq!(over.state, RunState::Cancelled);
    let held: Option<i64> =
        sqlx::query_scalar("SELECT checkout_run_id FROM citadel_issues WHERE id = ?")
            .bind(w.seed.issue)
            .fetch_one(&w.app().pool)
            .await
            .unwrap();
    assert_eq!(held, None);
    assert_eq!(
        count(
            &w,
            "SELECT count(*) FROM citadel_wake_requests WHERE source = 'retry'"
        )
        .await,
        0,
        "a cancel is not retried"
    );
}

#[tokio::test]
async fn stopping_a_run_that_is_over_is_refused_and_sends_nothing() {
    let w = world().await;
    let run = w.running().await;
    w.report(
        &run,
        AgentState::Ended,
        vec![],
        Tokens::default(),
        Some(Outcome::Succeeded),
    )
    .await;
    w.reconcile().await;
    let before = w.host.told.lock().unwrap().len();
    for kill in [false, true] {
        let r = engine::stop_run(w.app(), &w.host, run.id, kill, &w.fx.dev.id, &w.now()).await;
        assert!(
            matches!(r, Err(ControlError::NotLive(RunState::Succeeded))),
            "{r:?}"
        );
    }
    assert_eq!(w.host.told.lock().unwrap().len(), before);
    let gone = engine::stop_run(w.app(), &w.host, RunId(9999), true, "d", &w.now()).await;
    assert!(matches!(gone, Err(ControlError::NotFound)));
}

#[tokio::test]
async fn a_message_reaches_only_a_running_run() {
    let w = world().await;
    w.wake("assign:1").await;
    let claimed = w.dispatch().await.unwrap();
    let early = engine::message_run(w.app(), &w.host, claimed.id, "hi", "d").await;
    assert!(
        matches!(early, Err(ControlError::NotLive(RunState::Claimed))),
        "{early:?}"
    );
    w.report(
        &claimed,
        AgentState::Running,
        vec![],
        Tokens::default(),
        None,
    )
    .await;
    w.reconcile().await;
    engine::message_run(w.app(), &w.host, claimed.id, "keep going", "d")
        .await
        .unwrap();
    assert!(
        matches!(w.host.told.lock().unwrap().last(), Some((_, Instruction::Send(t))) if t == "keep going")
    );
    let audited = count(&w, "SELECT count(*) FROM audit_events WHERE action = 'citadel.run.messaged' AND details LIKE '%keep going%'").await;
    assert_eq!(
        audited, 0,
        "the message text is never audited, only its length"
    );
}

// --- tool approvals ----------------------------------------------------------------------------

fn ask(seq: u64, id: &str) -> TranscriptEntry {
    TranscriptEntry {
        seq,
        at: 0,
        body: json!({"type": "approval_request", "id": id, "tool": "Bash", "input": {"command": "rm -rf build"}}),
    }
}

#[tokio::test]
async fn a_tool_request_becomes_one_approval_and_its_decision_is_told_once() {
    let w = world().await;
    let run = w.running().await;
    w.report(
        &run,
        AgentState::Running,
        vec![ask(1, "req-1")],
        Tokens::default(),
        None,
    )
    .await;
    for _ in 0..3 {
        w.reconcile().await;
    }
    let ids: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM citadel_approvals WHERE kind = 'permission_escalation'")
            .fetch_all(&w.app().pool)
            .await
            .unwrap();
    assert_eq!(
        ids.len(),
        1,
        "one approval per request, however many passes"
    );
    assert!(
        w.host.decisions().is_empty(),
        "nothing is allowed before someone decides"
    );
    gov::decide_approval(
        &w.app().pool,
        citadel_module::domain::gov::ApprovalId(ids[0]),
        true,
        citadel_module::domain::work::UserId(1),
        Some("fine"),
        &w.now(),
    )
    .await
    .unwrap();
    for _ in 0..3 {
        w.reconcile().await;
    }
    assert_eq!(w.host.decisions(), vec![true], "told once");
    // A second request, rejected: the harness is told no.
    w.report(
        &run,
        AgentState::Running,
        vec![ask(2, "req-2")],
        Tokens::default(),
        None,
    )
    .await;
    w.reconcile().await;
    let second: i64 = sqlx::query_scalar(
        "SELECT max(id) FROM citadel_approvals WHERE kind = 'permission_escalation'",
    )
    .fetch_one(&w.app().pool)
    .await
    .unwrap();
    assert_ne!(second, ids[0]);
    gov::decide_approval(
        &w.app().pool,
        citadel_module::domain::gov::ApprovalId(second),
        false,
        citadel_module::domain::work::UserId(1),
        None,
        &w.now(),
    )
    .await
    .unwrap();
    w.reconcile().await;
    assert_eq!(w.host.decisions(), vec![true, false]);
}

#[tokio::test]
async fn a_decision_the_runner_did_not_take_is_asked_again_and_a_dead_session_closes_it() {
    let w = world().await;
    let run = w.running().await;
    w.report(
        &run,
        AgentState::Running,
        vec![ask(1, "req-1")],
        Tokens::default(),
        None,
    )
    .await;
    w.reconcile().await;
    let id: i64 =
        sqlx::query_scalar("SELECT id FROM citadel_approvals WHERE kind = 'permission_escalation'")
            .fetch_one(&w.app().pool)
            .await
            .unwrap();
    gov::decide_approval(
        &w.app().pool,
        citadel_module::domain::gov::ApprovalId(id),
        true,
        citadel_module::domain::work::UserId(1),
        None,
        &w.now(),
    )
    .await
    .unwrap();
    w.host.refuse.store(true, Ordering::SeqCst);
    let r = w.reconcile().await;
    assert_eq!(r.relayed, 0, "not marked told while the runner refuses");
    w.host.refuse.store(false, Ordering::SeqCst);
    let r = w.reconcile().await;
    assert_eq!(r.relayed, 1);
}

// --- timers ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_timer_wakes_an_agent_with_work_once_per_slot_and_skips_an_idle_one() {
    let w = world().await;
    let agent = AgentId(w.seed.agent);
    engine::timer::set_agent_timer(&w.app().pool, agent, Some(60))
        .await
        .unwrap();
    let now = "2026-11-01T10:00:30.000Z";
    let first = engine::timer::fire_timers(&w.app().pool, now)
        .await
        .unwrap();
    assert_eq!(first.woken.len(), 1, "the issue waits on the agent");
    let again = engine::timer::fire_timers(&w.app().pool, "2026-11-01T10:00:50.000Z")
        .await
        .unwrap();
    assert!(
        again.woken.is_empty() && again.idle.is_empty(),
        "the slot has fired"
    );
    sqlx::query("UPDATE citadel_issues SET state = 'done'")
        .execute(&w.app().pool)
        .await
        .unwrap();
    sqlx::query("UPDATE citadel_wake_requests SET status = 'dispatched'")
        .execute(&w.app().pool)
        .await
        .unwrap();
    let idle = engine::timer::fire_timers(&w.app().pool, "2026-11-01T10:01:30.000Z")
        .await
        .unwrap();
    assert_eq!(
        (idle.woken.len(), idle.idle.len()),
        (0, 1),
        "nothing to act on: skipped, not fired"
    );
}

// --- the run token -----------------------------------------------------------------------------

#[tokio::test]
async fn a_run_token_is_scoped_to_one_live_run_and_dies_with_it() {
    let w = world().await;
    let other = seed(&w.app().pool, "B", "BBB", ProjectMode::Scrum).await;
    let run = w.running().await;
    let pool = &w.app().pool;
    let now = w.now();
    let t1 = engine::issue_run_token(pool, run.id, &now).await.unwrap();
    assert!(t1.expose().starts_with("cit_run_"));
    let scope = engine::authorize_run_token(pool, t1.expose(), &now)
        .await
        .unwrap();
    assert_eq!(
        (scope.run_id, scope.agent_id.0, scope.issue_id.map(|i| i.0)),
        (run.id, w.seed.agent, Some(w.seed.issue))
    );
    assert_ne!(
        scope.company_id.0, other.company,
        "the scope is the run's company, and no other"
    );
    // Only the hash is stored, and the token is in no audit row.
    assert_eq!(
        count(
            &w,
            &format!(
                "SELECT count(*) FROM citadel_run_tokens WHERE token_hash = '{}'",
                t1.expose()
            )
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &w,
            &format!(
                "SELECT count(*) FROM audit_events WHERE details LIKE '%{}%'",
                t1.expose()
            )
        )
        .await,
        0
    );
    // One live token per run: a new one revokes the old.
    let t2 = engine::issue_run_token(pool, run.id, &now).await.unwrap();
    assert!(matches!(
        engine::authorize_run_token(pool, t1.expose(), &now).await,
        Err(AuthError::Revoked)
    ));
    assert!(
        engine::authorize_run_token(pool, t2.expose(), &now)
            .await
            .is_ok()
    );
    // Short-lived: past its expiry it is refused.
    let late = "2099-01-01T00:00:00.000Z";
    assert!(matches!(
        engine::authorize_run_token(pool, t2.expose(), late).await,
        Err(AuthError::Expired)
    ));
    // A guess, a prefix of a real token, nothing.
    for bad in ["", "cit_run_", &t2.expose()[..20], "cit_run_00"] {
        assert!(
            matches!(
                engine::authorize_run_token(pool, bad, &now).await,
                Err(AuthError::Unknown)
            ),
            "{bad}"
        );
    }
    // The run ends: the token is revoked in the same transaction.
    w.report(
        &run,
        AgentState::Ended,
        vec![],
        Tokens::default(),
        Some(Outcome::Succeeded),
    )
    .await;
    w.reconcile().await;
    assert!(matches!(
        engine::authorize_run_token(pool, t2.expose(), &now).await,
        Err(AuthError::Revoked)
    ));
    assert!(matches!(
        engine::issue_run_token(pool, run.id, &now).await,
        Err(AuthError::RunNotLive)
    ));
}

#[tokio::test]
async fn no_token_is_issued_for_a_run_that_has_not_started() {
    let w = world().await;
    w.wake("assign:1").await;
    sqlx::query("INSERT INTO citadel_runs (agent_id, issue_id, harness) VALUES (?, ?, 'claude')")
        .bind(w.seed.agent)
        .bind(w.seed.issue)
        .execute(&w.app().pool)
        .await
        .unwrap();
    let queued: i64 = sqlx::query_scalar("SELECT id FROM citadel_runs")
        .fetch_one(&w.app().pool)
        .await
        .unwrap();
    let r = engine::issue_run_token(&w.app().pool, RunId(queued), &w.now()).await;
    assert!(matches!(r, Err(AuthError::RunNotLive)));
    assert!(matches!(
        engine::issue_run_token(&w.app().pool, RunId(777), &w.now()).await,
        Err(AuthError::RunNotLive)
    ));
}

#[tokio::test]
async fn cache_tokens_count_at_a_fraction_against_the_runs_own_cap() {
    let w = world().await;
    // The issue's own cap counts every token in full; this test is about the run's.
    citadel_module::settings::handle()
        .set(
            &w.app().pool,
            "issue.token_cap",
            "0",
            AuditActor::System,
            &w.now(),
        )
        .await
        .unwrap();
    let run = w.running().await;
    // 12M tokens of context re-read would be six caps in full; at a tenth it is 1.2M, under 2M.
    let cache = Tokens {
        input: 1_000,
        output: 1_000,
        cache_read: 12_000_000,
        ..Tokens::default()
    };
    w.report(&run, AgentState::Running, vec![], cache, None)
        .await;
    w.reconcile().await;
    assert_eq!(w.run(run.id).await.state, RunState::Running);
    let more = Tokens {
        cache_read: 30_000_000,
        ..cache
    };
    w.report(&run, AgentState::Running, vec![], more, None)
        .await;
    w.reconcile().await;
    assert_eq!(
        w.run(run.id).await.terminal_reason.as_deref(),
        Some("token_cap")
    );
}
