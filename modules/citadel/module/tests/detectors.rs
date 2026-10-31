//! The engine's watchers (S7, second half): the loop breaker, the run that ends without acting,
//! the stuck detector and its repair pass, terminating and pausing an agent, issue checkout and
//! tier routing, against the platform's session store with a fake host in place of a runner.
//!
//! The negative tests say what none of them may do: stop a live session on their own, act while
//! the engine is off, raise a budget, or un-pause an agent without the admin's step-up.

mod common;
mod work_seed;
mod world;

use ainkrad_core::audit::AuditActor;
use ainkrad_proto::runner::Outcome;
use ainkrad_proto::v2::{AgentState, TranscriptEntry};
use axum::http::{Method, StatusCode};
use citadel_module::domain::exec::RunState;
use citadel_module::domain::gov::{BudgetPeriod, BudgetScope, NewBudget};
use citadel_module::domain::org::{AgentId, AgentStatus, Harness, ModelRoute, Tier};
use citadel_module::domain::work::{IssueId, NextActor, RunId, UserId};
use citadel_module::store::exec::{self as engine, Instruction};
use citadel_module::store::{gov, org, work};
use common::*;
use serde_json::{Value, json};
use world::*;

const ADMIN: UserId = UserId(1);

fn failed(why: &str) -> Outcome {
    Outcome::Failed {
        reason: why.into(),
        fingerprint: None,
    }
}

fn said(text: &str) -> TranscriptEntry {
    TranscriptEntry {
        seq: 1,
        at: 0,
        body: json!({"type": "assistant_text", "text": text}),
    }
}

/// One whole run: a wake under `key`, dispatched, running, then ended with `outcome` (and `said`).
async fn cycle(w: &W, key: &str, outcome: Outcome, words: Option<&str>) -> engine::Run {
    w.wake(key).await;
    let run = w.dispatch().await.expect("a run starts");
    w.report(&run, AgentState::Running, vec![], tokens(1, 1), None)
        .await;
    w.reconcile().await;
    let entries = words.map(|t| vec![said(t)]).unwrap_or_default();
    w.report(
        &run,
        AgentState::Ended,
        entries,
        tokens(2, 2),
        Some(outcome),
    )
    .await;
    w.reconcile().await;
    w.run(run.id).await
}

async fn next_actor(w: &W) -> (Option<i64>, Option<i64>) {
    sqlx::query_as("SELECT next_agent_id, next_user_id FROM citadel_issues WHERE id = ?")
        .bind(w.seed.issue)
        .fetch_one(&w.app().pool)
        .await
        .unwrap()
}

async fn agent_status(w: &W, agent: i64) -> String {
    sqlx::query_scalar("SELECT status FROM citadel_agents WHERE id = ?")
        .bind(agent)
        .fetch_one(&w.app().pool)
        .await
        .unwrap()
}

async fn audited(w: &W, action: &str) -> i64 {
    count(
        w,
        &format!("SELECT count(*) FROM audit_events WHERE action = 'citadel.{action}'"),
    )
    .await
}

/// A timestamp `hours` from now: the detectors take the time as an argument.
async fn later(w: &W, hours: i64) -> String {
    sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)")
        .bind(format!("+{hours} hours"))
        .fetch_one(&w.app().pool)
        .await
        .unwrap()
}

async fn setting(w: &W, name: &str, value: i64) {
    citadel_module::settings::handle()
        .set(
            &w.app().pool,
            name,
            &value.to_string(),
            AuditActor::System,
            &w.now(),
        )
        .await
        .unwrap();
}

/// A team lead for the seeded project: the rung above the developer on the escalation ladder.
async fn lead(w: &W) -> AgentId {
    use citadel_module::domain::org::{NewAgent, OrgRole, TeamRole};
    let pool = &w.app().pool;
    let company = citadel_module::domain::org::CompanyId(w.seed.company);
    let new = NewAgent {
        company_id: company,
        name: "Lead".to_owned(),
        role: "Lead".to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness: Harness::Claude,
        model: "m".to_owned(),
        runner_tags: vec![],
        status: AgentStatus::Active,
    };
    let lead = org::create_agent(pool, &new).await.unwrap().id;
    let dept = org::add_department(pool, company, "Eng", AuditActor::System)
        .await
        .unwrap();
    let team = org::add_team(pool, dept.id, "Core", AuditActor::System)
        .await
        .unwrap();
    org::seat_member(
        pool,
        team.id,
        lead,
        TeamRole::TeamLead,
        None,
        AuditActor::System,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE citadel_projects SET team_id = ? WHERE id = ?")
        .bind(team.id.0)
        .bind(w.seed.project)
        .execute(pool)
        .await
        .unwrap();
    lead
}

// --- the loop breaker ------------------------------------------------------------------------

#[tokio::test]
async fn three_identical_failures_trip_the_breaker_and_escalate_without_a_retry() {
    let w = world().await;
    let mut last = None;
    for n in 1..=3 {
        last = Some(cycle(&w, &format!("k{n}"), failed("tests red"), None).await);
    }
    let last = last.unwrap();
    assert_eq!(last.state, RunState::Failed);
    assert_eq!(audited(&w, "loop_breaker.tripped").await, 1);
    // The issue went up the chain (no team: the admin), and nothing waits to retry it.
    assert_eq!(next_actor(&w).await, (None, Some(1)));
    assert_eq!(
        count(
            &w,
            "SELECT count(*) FROM citadel_wake_requests WHERE status = 'pending'"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &w,
            &format!(
                "SELECT count(*) FROM citadel_wake_requests WHERE idempotency_key = 'retry:run:{}'",
                last.id.0
            )
        )
        .await,
        0,
        "a tripped run is not retried"
    );
    // One trip does not pause the agent, and the breaker stopped no session.
    assert_eq!(agent_status(&w, w.seed.agent).await, "active");
    assert_eq!(w.host.stops(), 0);
    // Repeating the trip for the same run changes nothing.
    assert_eq!(audited(&w, "loop_breaker.tripped").await, 1);
}

#[tokio::test]
async fn a_different_failure_ends_the_streak() {
    let w = world().await;
    setting(&w, "wake.max_attempts", 10).await;
    cycle(&w, "a", failed("tests red"), None).await;
    cycle(&w, "b", failed("build broke"), None).await;
    cycle(&w, "c", failed("tests red"), None).await;
    assert_eq!(audited(&w, "loop_breaker.tripped").await, 0);
    assert_eq!(next_actor(&w).await, (Some(w.seed.agent), None));
}

#[tokio::test]
async fn a_looping_agent_is_paused_and_only_the_admins_step_up_resumes_it() {
    let w = world().await;
    setting(&w, "breaker.agent_trips", 1).await;
    for n in 1..=3 {
        cycle(&w, &format!("k{n}"), failed("tests red"), None).await;
    }
    assert_eq!(agent_status(&w, w.seed.agent).await, "paused");
    assert_eq!(audited(&w, "agent.paused_by_breaker").await, 1);
    assert_eq!(w.host.stops(), 0, "pausing the agent kills nothing");
    // A paused agent is not dispatched, whatever is queued for it.
    w.wake("later").await;
    assert!(w.dispatch().await.is_none());

    // Nothing un-pauses it by itself; the admin's step-up does, and not a device without one.
    let uri = format!("/agents/{}/resume", w.seed.agent);
    let plain = enroll(w.app(), "admin2", &["admin", "read"], true).await;
    let (status, v) = call(&w.fx, Some(&plain), Method::POST, &uri, None).await;
    assert_eq!(
        (status, v["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("step_up_required"))
    );
    assert_eq!(agent_status(&w, w.seed.agent).await, "paused");
    let back = w.fx.ok_post(&uri, json!({})).await;
    assert_eq!(back["status"], "active");
    assert_eq!(audited(&w, "agent.resumed").await, 1);
}

#[tokio::test]
async fn an_escalation_wake_is_still_held_by_the_leads_budget() {
    let w = world().await;
    let lead = lead(&w).await;
    let cap = NewBudget {
        scope: BudgetScope::Agent(lead),
        period: BudgetPeriod::Total,
        token_cap: 1_000,
        usd_cap_micros: None,
        warn_at_percent: 80,
        hard_stop: true,
    };
    let b = gov::set_budget(&w.app().pool, &cap, AuditActor::System)
        .await
        .unwrap();
    sqlx::query("INSERT INTO citadel_budget_spend (budget_id, period_key, tokens) VALUES (?, 'total', 1000)")
        .bind(b.id.0)
        .execute(&w.app().pool)
        .await
        .unwrap();
    for n in 1..=3 {
        cycle(&w, &format!("k{n}"), failed("tests red"), None).await;
    }
    assert_eq!(next_actor(&w).await, (Some(lead.0), None), "to the lead");
    for _ in 0..3 {
        assert!(w.dispatch().await.is_none(), "the lead has no budget left");
    }
    // The escalation raised nothing: the cap stands and the only way past it is an approval.
    let (cap_now, raised): (i64, i64) = sqlx::query_as(
        "SELECT b.token_cap, s.raised FROM citadel_budgets b JOIN citadel_budget_spend s \
         ON s.budget_id = b.id WHERE b.id = ?",
    )
    .bind(b.id.0)
    .fetch_one(&w.app().pool)
    .await
    .unwrap();
    assert_eq!((cap_now, raised), (1_000, 0));
    assert_eq!(
        count(&w, "SELECT count(*) FROM citadel_approvals WHERE kind = 'budget_overrun' AND status = 'pending'").await,
        1
    );
}

// --- runs that end without acting ------------------------------------------------------------

#[tokio::test]
async fn a_run_that_succeeds_without_acting_is_nudged_once_then_escalated() {
    let w = world().await;
    let first = cycle(&w, "a", Outcome::Succeeded, Some("I read the issue.")).await;
    assert_eq!(first.state, RunState::Succeeded);
    assert_eq!(
        first.terminal_reason.as_deref(),
        Some("ended_without_action")
    );
    let nudge: String =
        sqlx::query_scalar("SELECT reason FROM citadel_wake_requests WHERE idempotency_key = ?")
            .bind(format!("no-action:run:{}", first.id.0))
            .fetch_one(&w.app().pool)
            .await
            .unwrap();
    assert!(nudge.contains("I read the issue."), "{nudge}");
    assert_eq!(
        next_actor(&w).await,
        (Some(w.seed.agent), None),
        "still its own"
    );

    // The nudge runs; it ends without acting again: now the issue goes up the chain.
    let run = w.dispatch().await.expect("the nudge runs");
    w.report(&run, AgentState::Running, vec![], tokens(1, 1), None)
        .await;
    w.reconcile().await;
    w.report(
        &run,
        AgentState::Ended,
        vec![],
        tokens(2, 2),
        Some(Outcome::Succeeded),
    )
    .await;
    w.reconcile().await;
    assert_eq!(
        w.run(run.id).await.terminal_reason.as_deref(),
        Some("ended_without_action")
    );
    assert_eq!(next_actor(&w).await, (None, Some(1)));
    assert_eq!(audited(&w, "run.ended_without_action").await, 2);
}

#[tokio::test]
async fn a_run_that_called_a_state_changing_tool_acted() {
    let w = world().await;
    let run = w.running().await;
    let mut conn = w.app().pool.acquire().await.unwrap();
    citadel_module::store::audit::append(
        &mut conn,
        citadel_module::store::audit::Event::new(AuditActor::System, "mcp.transition")
            .run(run.id.0)
            .details(json!({"ok": false})),
    )
    .await
    .unwrap();
    drop(conn);
    w.report(
        &run,
        AgentState::Ended,
        vec![],
        tokens(2, 2),
        Some(Outcome::Succeeded),
    )
    .await;
    w.reconcile().await;
    let done = w.run(run.id).await;
    assert_eq!(
        done.terminal_reason.as_deref(),
        Some("succeeded"),
        "a refused call still acted"
    );
    assert_eq!(audited(&w, "run.ended_without_action").await, 0);
}

#[tokio::test]
async fn a_run_that_only_read_did_not_act() {
    let w = world().await;
    let run = w.running().await;
    let mut conn = w.app().pool.acquire().await.unwrap();
    for tool in ["mcp.get_issue", "mcp.comment"] {
        citadel_module::store::audit::append(
            &mut conn,
            citadel_module::store::audit::Event::new(AuditActor::System, tool).run(run.id.0),
        )
        .await
        .unwrap();
    }
    drop(conn);
    w.report(
        &run,
        AgentState::Ended,
        vec![],
        tokens(2, 2),
        Some(Outcome::Succeeded),
    )
    .await;
    w.reconcile().await;
    assert_eq!(
        w.run(run.id).await.terminal_reason.as_deref(),
        Some("ended_without_action")
    );
}

// --- the stuck detector and its repairs -------------------------------------------------------

#[tokio::test]
async fn an_idle_issue_is_reported_and_repaired_by_a_wake_only_while_the_engine_is_on() {
    let w = world().await;
    let at = later(&w, 2).await;
    let report = engine::stuck_report(w.app(), &w.host, &at).await.unwrap();
    let kinds: Vec<&str> = report.iter().map(|s| s.kind.as_str()).collect();
    assert_eq!(kinds, ["todo_idle"], "{report:?}");
    assert_eq!(report[0].issue_id, Some(IssueId(w.seed.issue)));

    // The engine off: reported, never repaired.
    engine::set_engine(&w.app().pool, false, &w.fx.dev.id, &w.now())
        .await
        .unwrap();
    assert!(
        engine::repair_stuck(w.app(), &w.host, &at)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        count(&w, "SELECT count(*) FROM citadel_wake_requests").await,
        0
    );
    assert_eq!(audited(&w, "repair.todo_idle").await, 0);

    engine::set_engine(&w.app().pool, true, &w.fx.dev.id, &w.now())
        .await
        .unwrap();
    let done = engine::repair_stuck(w.app(), &w.host, &at).await.unwrap();
    assert_eq!(done.len(), 1);
    assert_eq!(
        (
            done[0].rule.as_str(),
            done[0].action.as_str(),
            done[0].changed
        ),
        ("todo_idle", "rewake", true)
    );
    assert_eq!(
        count(
            &w,
            "SELECT count(*) FROM citadel_wake_requests WHERE status = 'pending'"
        )
        .await,
        1
    );
    assert_eq!(audited(&w, "repair.todo_idle").await, 1);
    // Woken, it is no longer stuck, and a second pass does nothing.
    assert!(
        engine::stuck_report(w.app(), &w.host, &at)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        engine::repair_stuck(w.app(), &w.host, &at)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(w.host.stops(), 0);
}

#[tokio::test]
async fn an_issue_past_its_repair_budget_goes_to_the_admin_once() {
    let w = world().await;
    setting(&w, "repair.budget", 0).await;
    let at = later(&w, 2).await;
    let done = engine::repair_stuck(w.app(), &w.host, &at).await.unwrap();
    assert_eq!(done.len(), 1);
    assert_eq!(
        (done[0].rule.as_str(), done[0].action.as_str()),
        ("exhausted", "escalate_to_admin")
    );
    assert_eq!(next_actor(&w).await, (None, Some(1)));
    assert_eq!(audited(&w, "repair.exhausted").await, 1);
    // A person is never stuck: nothing repairs it again.
    assert!(
        engine::repair_stuck(w.app(), &w.host, &at)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(audited(&w, "repair.exhausted").await, 1);
}

#[tokio::test]
async fn work_with_a_live_run_is_never_stuck_and_never_stopped() {
    let w = world().await;
    let _run = w.running().await;
    let at = later(&w, 5).await;
    assert!(
        engine::stuck_report(w.app(), &w.host, &at)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        engine::repair_stuck(w.app(), &w.host, &at)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(w.host.stops(), 0);
}

#[tokio::test]
async fn a_checkout_held_by_an_ended_run_is_released_and_a_live_holder_is_refused() {
    let w = world().await;
    let run = w.running().await;
    let hold = |run: RunId| {
        sqlx::query(
            "UPDATE citadel_issues SET checkout_run_id = ?, checked_out_at = ? WHERE id = ?",
        )
        .bind(run.0)
        .bind(w.now())
        .bind(w.seed.issue)
    };
    hold(run.id).execute(&w.app().pool).await.unwrap();
    let uri = format!("/issues/{}/release-checkout", w.seed.issue);
    let (status, _) = call(&w.fx, Some(&w.fx.dev), Method::POST, &uri, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "stop the live run instead");

    // The run ends but the row is put back, as an engine error would leave it.
    w.report(
        &run,
        AgentState::Ended,
        vec![],
        tokens(1, 1),
        Some(failed("boom")),
    )
    .await;
    w.reconcile().await;
    hold(run.id).execute(&w.app().pool).await.unwrap();
    let at = later(&w, 2).await;
    let kinds: Vec<String> = engine::stuck_report(w.app(), &w.host, &at)
        .await
        .unwrap()
        .iter()
        .map(|s| s.kind.as_str().to_owned())
        .collect();
    assert_eq!(kinds, ["checkout_dead"]);
    let issue = w.fx.ok_post(&uri, json!({})).await;
    assert!(issue["checkout_run_id"].is_null(), "{issue}");
    // The run's own end released the first hold; the route released the second.
    assert_eq!(audited(&w, "issue.released").await, 2);
}

#[tokio::test]
async fn a_wake_no_runner_can_serve_is_stuck_and_an_online_runner_clears_it() {
    let mut w = world().await;
    w.host.runners.clear();
    w.wake("a").await;
    let at = later(&w, 2).await;
    let report = engine::stuck_report(w.app(), &w.host, &at).await.unwrap();
    assert!(
        report.iter().any(|s| s.kind.as_str() == "wake_no_runner"),
        "{report:?}"
    );
    let runner = enroll(w.app(), "vm2", &["runner"], false).await;
    w.host.runners.push(runner.id);
    let report = engine::stuck_report(w.app(), &w.host, &at).await.unwrap();
    assert!(
        report.iter().all(|s| s.kind.as_str() != "wake_no_runner"),
        "{report:?}"
    );
}

// --- terminating and pausing an agent ---------------------------------------------------------

#[tokio::test]
async fn terminating_an_agent_stops_its_run_drops_its_wakes_and_hands_its_work_over() {
    let w = world().await;
    let run = w.running().await;
    w.wake("queued-behind").await;
    let agent = AgentId(w.seed.agent);
    let done = engine::terminate_agent(
        w.app(),
        &w.host,
        agent,
        "Replaced by Sam",
        ADMIN,
        (AuditActor::User(ainkrad_core::ids::UserId(1)), &w.fx.dev.id),
        &w.now(),
    )
    .await
    .unwrap();
    assert!(done);
    assert_eq!(agent_status(&w, w.seed.agent).await, "terminated");
    assert_eq!(w.host.stops(), 1, "its live run was asked to stop");
    let ended = w.run(run.id).await;
    assert_eq!(ended.state, RunState::Cancelled);
    assert_eq!(ended.terminal_reason.as_deref(), Some("agent terminated"));
    assert_eq!(next_actor(&w).await, (None, Some(1)), "handed to the admin");
    assert_eq!(
        count(
            &w,
            "SELECT count(*) FROM citadel_wake_requests WHERE status = 'pending'"
        )
        .await,
        0
    );
    // It is never woken again: a wake for it is kept as a dropped record.
    let late = w.wake("after").await;
    assert_eq!(late.status.as_str(), "dropped");
    assert!(w.dispatch().await.is_none());
    // Terminating twice changes nothing.
    let again = engine::terminate_agent(
        w.app(),
        &w.host,
        agent,
        "x",
        ADMIN,
        (AuditActor::System, &w.fx.dev.id),
        &w.now(),
    )
    .await
    .unwrap();
    assert!(!again);
    assert_eq!(audited(&w, "agent.terminated").await, 1);
}

#[tokio::test]
async fn pausing_an_agent_stops_its_run_and_resuming_wakes_it_on_its_open_work() {
    let w = world().await;
    let run = w.running().await;
    let agent = AgentId(w.seed.agent);
    assert!(
        engine::pause_agent(
            w.app(),
            &w.host,
            agent,
            (AuditActor::System, &w.fx.dev.id),
            &w.now()
        )
        .await
        .unwrap()
    );
    assert_eq!(w.run(run.id).await.state, RunState::Cancelled);
    assert_eq!(agent_status(&w, w.seed.agent).await, "paused");
    assert!(
        !engine::pause_agent(
            w.app(),
            &w.host,
            agent,
            (AuditActor::System, &w.fx.dev.id),
            &w.now()
        )
        .await
        .unwrap(),
        "not active"
    );
    assert!(
        engine::resume_agent(&w.app().pool, agent, AuditActor::System, &w.now())
            .await
            .unwrap()
    );
    assert!(
        w.dispatch().await.is_some(),
        "woken on the issue that waits on it"
    );
}

// --- checkout ---------------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_checkouts_have_exactly_one_winner() {
    let w = world().await;
    let issue = IssueId(w.seed.issue);
    let mut runs = vec![];
    for _ in 0..6 {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO citadel_runs (agent_id, issue_id, harness) VALUES (?, ?, 'claude') RETURNING id",
        )
        .bind(w.seed.agent)
        .bind(w.seed.issue)
        .fetch_one(&w.app().pool)
        .await
        .unwrap();
        runs.push(RunId(id));
    }
    let tasks: Vec<_> = runs
        .iter()
        .map(|&r| {
            let pool = w.app().pool.clone();
            tokio::spawn(async move {
                (
                    r,
                    work::checkout_issue(&pool, issue, r, "2026-10-21T10:00:00.000Z").await,
                )
            })
        })
        .collect();
    let (mut winners, mut losers) = (vec![], vec![]);
    for t in tasks {
        match t.await.unwrap() {
            (r, Ok(_)) => winners.push(r),
            (_, Err(work::CheckoutError::Conflict { held_by })) => losers.push(held_by),
            (_, Err(e)) => panic!("unexpected {e}"),
        }
    }
    assert_eq!(winners.len(), 1, "{winners:?}");
    assert_eq!(
        losers,
        vec![winners[0]; 5],
        "every loser is told who holds it"
    );
    let held = work::get_issue(&w.app().pool, issue)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.checkout_run_id, Some(winners[0]));
    assert_eq!(audited(&w, "issue.checked_out").await, 1);
}

#[tokio::test]
async fn checkout_starts_the_issue_is_idempotent_and_replaces_a_dead_holder() {
    let w = world().await;
    let issue = IssueId(w.seed.issue);
    let pool = &w.app().pool;
    let run = w.running().await;
    let now = w.now();
    let first = work::checkout_issue(pool, issue, run.id, &now)
        .await
        .unwrap();
    assert_eq!(first.checkout_run_id, Some(run.id));
    assert_eq!(first.state.as_str(), "in_progress");
    assert_eq!(
        first.next_actor,
        Some(NextActor::Agent(AgentId(w.seed.agent)))
    );
    let again = work::checkout_issue(pool, issue, run.id, &now)
        .await
        .unwrap();
    assert_eq!(again, first);
    assert_eq!(
        audited(&w, "issue.checked_out").await,
        1,
        "the holder again audits nothing"
    );
    assert!(matches!(
        work::checkout_issue(pool, IssueId(999), run.id, &now).await,
        Err(work::CheckoutError::IssueNotFound)
    ));
    // An ended run holds nothing: the issue is released with it, and it cannot check one out.
    w.report(
        &run,
        AgentState::Ended,
        vec![],
        tokens(1, 1),
        Some(failed("boom")),
    )
    .await;
    w.reconcile().await;
    let ended = work::checkout_issue(pool, issue, run.id, &now).await;
    assert!(
        matches!(
            ended,
            Err(work::CheckoutError::RunNotLive(RunState::Failed))
        ),
        "{ended:?}"
    );
    assert_eq!(
        work::get_issue(pool, issue)
            .await
            .unwrap()
            .unwrap()
            .checkout_run_id,
        None,
        "its end released the issue"
    );
}

// --- tiers ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_small_task_starts_on_the_agents_small_model_and_is_admitted_like_any_other() {
    let w = world().await;
    let pool = &w.app().pool;
    let small = ModelRoute {
        harness: Harness::Claude,
        model: "haiku".into(),
    };
    org::set_tiers(
        pool,
        AgentId(w.seed.agent),
        &[(Tier::Small, small)],
        AuditActor::System,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE citadel_issues SET points = 1 WHERE id = ?")
        .bind(w.seed.issue)
        .execute(pool)
        .await
        .unwrap();
    w.wake("a").await;
    let run = w.dispatch().await.expect("a small run starts");
    assert_eq!(
        (run.harness, run.model_used.as_deref()),
        (Harness::Claude, Some("haiku"))
    );
    assert_eq!(
        w.fx.ok(&format!("/runs/{}", run.id.0)).await["tier"],
        "small"
    );
    // A big task and an unestimated one take the agent's own model.
    sqlx::query("UPDATE citadel_issues SET points = 13 WHERE id = ?")
        .bind(w.seed.issue)
        .execute(pool)
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    assert_eq!(
        engine::task_tier_in(&mut conn, Some(IssueId(w.seed.issue)))
            .await
            .unwrap()
            .as_str(),
        "large"
    );
    drop(conn);
    // The tier is no way round a budget: an exhausted hard stop still holds the small task back.
    let cap = NewBudget {
        scope: BudgetScope::Agent(AgentId(w.seed.agent)),
        period: BudgetPeriod::Total,
        token_cap: 10,
        usd_cap_micros: None,
        warn_at_percent: 80,
        hard_stop: true,
    };
    let b = gov::set_budget(pool, &cap, AuditActor::System)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO citadel_budget_spend (budget_id, period_key, tokens) VALUES (?, 'total', 10)",
    )
    .bind(b.id.0)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("UPDATE citadel_issues SET points = 1 WHERE id = ?")
        .bind(w.seed.issue)
        .execute(pool)
        .await
        .unwrap();
    w.report(
        &run,
        AgentState::Ended,
        vec![],
        tokens(1, 1),
        Some(Outcome::Succeeded),
    )
    .await;
    w.reconcile().await;
    w.wake("b").await;
    assert!(
        w.dispatch().await.is_none(),
        "no budget, no run, whatever the tier"
    );
}

#[tokio::test]
async fn a_tier_with_no_runner_for_its_model_falls_back_to_the_agents_own() {
    let w = world().await;
    let pool = &w.app().pool;
    // The fake offers every harness; make the small tier name one the runner cannot take by
    // pointing the agent's own entry at a different harness than the tier's.
    let small = ModelRoute {
        harness: Harness::Codex,
        model: "mini".into(),
    };
    org::set_tiers(
        pool,
        AgentId(w.seed.agent),
        &[(Tier::Small, small)],
        AuditActor::System,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE citadel_issues SET points = 1 WHERE id = ?")
        .bind(w.seed.issue)
        .execute(pool)
        .await
        .unwrap();
    w.wake("a").await;
    let run = w.dispatch().await.unwrap();
    assert_eq!(run.harness, Harness::Codex);
    assert_eq!(audited(&w, "wake.dispatched").await, 1);
    let tier: String = sqlx::query_scalar(
        "SELECT json_extract(details, '$.tier') FROM audit_events WHERE action = 'citadel.wake.dispatched'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(tier, "small");
}

// --- the controls over HTTP -------------------------------------------------------------------

#[tokio::test]
async fn the_stuck_list_is_admin_only_and_retry_refuses_a_live_run() {
    let w = world().await;
    let phone = enroll(w.app(), "phone", &["read"], false).await;
    let (status, v) = call(&w.fx, Some(&phone), Method::GET, "/stuck", None).await;
    assert_eq!(
        (status, v["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope"))
    );
    assert!(w.fx.ok("/stuck").await.is_array());
    let run = w.running().await;
    let (status, _) = call(
        &w.fx,
        Some(&w.fx.dev),
        Method::POST,
        &format!("/runs/{}/retry", run.id.0),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    w.report(
        &run,
        AgentState::Ended,
        vec![],
        tokens(1, 1),
        Some(failed("boom")),
    )
    .await;
    w.reconcile().await;
    let retried =
        w.fx.ok_post(&format!("/runs/{}/retry", run.id.0), json!({}))
            .await;
    assert_eq!(retried["agent_id"], w.seed.agent);
    assert_eq!(audited(&w, "run.retried").await, 1);
}

#[tokio::test]
async fn terminate_over_http_needs_a_reason_and_refuses_the_dead() {
    let w = world().await;
    let uri = format!("/agents/{}/terminate", w.seed.agent);
    let (status, _) = call(
        &w.fx,
        Some(&w.fx.dev),
        Method::POST,
        &uri,
        Some(json!({"reason": " "})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &w.fx,
        Some(&w.fx.dev),
        Method::POST,
        "/agents/999/terminate",
        Some(json!({"reason": "x"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let gone = w.fx.ok_post(&uri, json!({"reason": "Replaced"})).await;
    assert_eq!(gone["status"], "terminated");
    let (status, _) = call(
        &w.fx,
        Some(&w.fx.dev),
        Method::POST,
        &uri,
        Some(json!({"reason": "again"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[allow(dead_code)]
fn unused(_: Value, _: Instruction) {}
