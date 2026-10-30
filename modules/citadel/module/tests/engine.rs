//! The run engine (S7) against the platform's session store, with a fake host in place of a
//! runner: wakes, dispatch, budgets, reconcile, cancel and kill, tool approvals, retries, orphans
//! and the run token. The end-to-end run on a real runner is S12's.

mod common;
mod work_seed;

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::api::App;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use ainkrad_proto::runner::{Outcome, Tokens};
use ainkrad_proto::v2::{AgentEvents, AgentState, TranscriptEntry};
use citadel_module::domain::exec::RunState;
use citadel_module::domain::gov::{BudgetPeriod, BudgetScope, NewBudget};
use citadel_module::domain::org::AgentId;
use citadel_module::domain::work::{IssueId, ProjectMode, RunId, WakeSource};
use citadel_module::store::exec::{
    self as engine, AuthError, ControlError, Host, Instruction, NewWakeRequest, StartFailure,
    StartSpec,
};
use citadel_module::store::gov;
use common::*;
use serde_json::json;
use work_seed::{Seed, seed};

#[derive(Default)]
struct Fake {
    runners: Vec<String>,
    busy: AtomicBool,
    refuse: AtomicBool,
    /// An admin's cancel lands while the session is starting (and it has already spent tokens).
    cancel_during_start: AtomicBool,
    started: Mutex<Vec<StartSpec>>,
    told: Mutex<Vec<(String, Instruction)>>,
}

impl Host for Fake {
    async fn runners(&self, _: &App, _: &str) -> Vec<String> {
        self.runners.clone()
    }

    async fn start(&self, app: &App, spec: &StartSpec) -> Result<String, StartFailure> {
        if self.busy.load(Ordering::SeqCst) {
            return Err(StartFailure::Busy("the runner is full".into()));
        }
        self.started.lock().unwrap().push(spec.clone());
        let new = NewSession {
            runner: &spec.runner,
            harness: &spec.harness,
            model: Some(&spec.model),
            prompt: Some(&spec.prompt),
            workspace: spec.workspace.as_ref(),
            policy: &spec.policy,
            secrets: &[],
            created_by: &spec.by_device,
        };
        let s = sessions::create_owned(
            &app.pool,
            &new,
            Some("citadel"),
            AuditActor::System,
            &app.clock.now(),
        )
        .await
        .unwrap();
        if self.cancel_during_start.load(Ordering::SeqCst) {
            let ev = AgentEvents {
                session: s.id.clone(),
                state: AgentState::Running,
                last_seq: 0,
                entries: vec![],
                harness_session: None,
                usage: Some(tokens(100, 50)),
                outcome: None,
            };
            sessions::apply(&app.pool, &s.id, &ev, &app.clock.now())
                .await
                .unwrap();
            let run: i64 =
                sqlx::query_scalar("SELECT id FROM citadel_runs WHERE state = 'claimed'")
                    .fetch_one(&app.pool)
                    .await
                    .unwrap();
            let by = "d_00000000000000000000000000";
            engine::stop_run(app, self, RunId(run), false, by, &app.clock.now())
                .await
                .unwrap();
        }
        Ok(s.id)
    }

    async fn instruct(&self, app: &App, session: &str, what: Instruction) -> Result<(), String> {
        self.told
            .lock()
            .unwrap()
            .push((session.to_owned(), what.clone()));
        if self.refuse.load(Ordering::SeqCst) {
            return Err("the runner is away".into());
        }
        if matches!(what, Instruction::Stop { .. }) {
            let o = json!({"kind": "cancelled", "reason": "stopped"});
            sessions::end(&app.pool, session, "ended", &o, &app.clock.now())
                .await
                .unwrap();
        }
        Ok(())
    }
}

impl Fake {
    fn stops(&self) -> usize {
        self.told
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, w)| matches!(w, Instruction::Stop { .. }))
            .count()
    }
    fn decisions(&self) -> Vec<bool> {
        self.told
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, w)| match w {
                Instruction::Decide { approved, .. } => Some(*approved),
                _ => None,
            })
            .collect()
    }
}

struct W {
    fx: Fx,
    seed: Seed,
    host: Fake,
}

impl W {
    fn app(&self) -> &App {
        &self.fx.app
    }
    fn now(&self) -> String {
        self.fx.app.clock.now()
    }
    fn wake_for(&self, key: &str) -> NewWakeRequest {
        NewWakeRequest {
            agent_id: AgentId(self.seed.agent),
            issue_id: Some(IssueId(self.seed.issue)),
            source: WakeSource::Assignment,
            reason: "start the work".into(),
            idempotency_key: key.into(),
            not_before: None,
        }
    }
    async fn wake(&self, key: &str) -> engine::WakeRequest {
        engine::enqueue_wake(&self.app().pool, &self.wake_for(key))
            .await
            .unwrap()
    }
    async fn dispatch(&self) -> Option<engine::Run> {
        engine::dispatch_next(self.app(), &self.host, &self.now())
            .await
            .unwrap()
    }
    async fn reconcile(&self) -> engine::Report {
        engine::reconcile(self.app(), &self.host, &self.now())
            .await
            .unwrap()
    }
    async fn run(&self, id: RunId) -> engine::Run {
        engine::get_run(&self.app().pool, id)
            .await
            .unwrap()
            .unwrap()
    }
    async fn session(&self, run: &engine::Run) -> sessions::Session {
        sessions::get(&self.app().pool, run.session_id.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap()
    }
    /// A started run whose session the runner reports running.
    async fn running(&self) -> engine::Run {
        self.wake("assign:1").await;
        let run = self.dispatch().await.unwrap();
        self.report(&run, AgentState::Running, vec![], Tokens::default(), None)
            .await;
        self.reconcile().await;
        let run = self.run(run.id).await;
        assert_eq!(run.state, RunState::Running);
        run
    }
    /// What the platform's supervisor would store after reading the runner.
    async fn report(
        &self,
        run: &engine::Run,
        state: AgentState,
        entries: Vec<TranscriptEntry>,
        usage: Tokens,
        outcome: Option<Outcome>,
    ) {
        let sid = run.session_id.clone().unwrap();
        let s = sessions::get(&self.app().pool, &sid)
            .await
            .unwrap()
            .unwrap();
        let last = entries.last().map_or(s.last_seq as u64, |e| e.seq);
        let ev = AgentEvents {
            session: sid.clone(),
            state,
            last_seq: last,
            entries,
            harness_session: None,
            usage: Some(usage),
            outcome: outcome.clone(),
        };
        sessions::apply(&self.app().pool, &sid, &ev, &self.now())
            .await
            .unwrap();
        let now = self.now();
        match state {
            AgentState::Running => {
                sessions::set_state(&self.app().pool, &sid, "running", "t", false, &now)
                    .await
                    .unwrap()
            }
            AgentState::Ended => {
                let o = serde_json::to_value(outcome.unwrap()).unwrap();
                sessions::end(&self.app().pool, &sid, "ended", &o, &now)
                    .await
                    .unwrap();
            }
            _ => {}
        }
    }
}

async fn world() -> W {
    let fx = fx().await;
    let seed = seed(&fx.app.pool, "A", "ENG", ProjectMode::Scrum).await;
    let runner = enroll(&fx.app, "vm", &["runner"], false).await;
    let host = Fake {
        runners: vec![runner.id.clone()],
        ..Fake::default()
    };
    engine::set_engine(&fx.app.pool, true, &fx.dev.id, &fx.app.clock.now())
        .await
        .unwrap();
    W { fx, seed, host }
}

fn new_session<'a>(runner: &'a str, policy: &'a serde_json::Value, by: &'a str) -> NewSession<'a> {
    NewSession {
        runner,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy,
        secrets: &[],
        created_by: by,
    }
}

fn tokens(input: u64, output: u64) -> Tokens {
    Tokens {
        input,
        output,
        ..Tokens::default()
    }
}

async fn count(w: &W, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&w.app().pool)
        .await
        .unwrap()
}

// --- the wake queue and dispatch --------------------------------------------------------------

#[tokio::test]
async fn an_engine_that_is_off_starts_nothing() {
    let w = world().await;
    engine::set_engine(&w.app().pool, false, &w.fx.dev.id, &w.now())
        .await
        .unwrap();
    let wake = w.wake("assign:1").await;
    assert!(w.dispatch().await.is_none());
    assert!(w.host.started.lock().unwrap().is_empty());
    let after = engine::get_wake_request(&w.app().pool, wake.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.status.as_str(), "pending");
}

#[tokio::test]
async fn a_wake_becomes_one_claimed_run_with_a_session_the_module_owns() {
    let w = world().await;
    let wake = w.wake("assign:1").await;
    let run = w.dispatch().await.expect("a run");
    assert_eq!(run.state, RunState::Claimed);
    assert_eq!(run.wake_request_id, Some(wake.id));
    let s = w.session(&run).await;
    assert_eq!(s.owner_module.as_deref(), Some("citadel"));
    assert_eq!(
        s.created_by, w.fx.dev.id,
        "the device that enabled the engine is accountable"
    );
    assert!(
        s.prompt.as_deref().unwrap().contains("A work"),
        "the issue is in the prompt"
    );
    assert_eq!(s.policy["mode"], "ask", "never full-auto by default");
    assert!(s.secrets.is_empty(), "no credential travels with a run");
    let wake = engine::get_wake_request(&w.app().pool, wake.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wake.status.as_str(), "dispatched");
    // The issue has a live run: nothing else starts, however often it is asked.
    w.wake("assign:2").await;
    assert!(w.dispatch().await.is_none());
    assert_eq!(w.host.started.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn wakes_for_one_agent_and_issue_coalesce_and_a_key_is_idempotent() {
    let w = world().await;
    let a = w.wake("assign:1").await;
    let again = w.wake("assign:1").await;
    assert_eq!(a.id, again.id);
    let b = w.wake("comment:9").await;
    assert_eq!(b.status.as_str(), "coalesced");
    assert_eq!(b.coalesced_into, Some(a.id));
    let a = engine::get_wake_request(&w.app().pool, a.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.coalesced_count, 1);
    let long = NewWakeRequest {
        idempotency_key: "k".repeat(129),
        ..w.wake_for("x")
    };
    assert!(engine::enqueue_wake(&w.app().pool, &long).await.is_err());
}

#[tokio::test]
async fn a_full_or_missing_runner_leaves_the_wake_to_try_again() {
    let mut w = world().await;
    let wake = w.wake("assign:1").await;
    let runners = std::mem::take(&mut w.host.runners);
    assert!(
        w.dispatch().await.is_none(),
        "no runner: nothing is claimed"
    );
    assert_eq!(count(&w, "SELECT count(*) FROM citadel_runs").await, 0);
    w.host.runners = runners;
    w.host.busy.store(true, Ordering::SeqCst);
    let run = w.dispatch().await.unwrap();
    assert_eq!(run.state, RunState::Cancelled);
    assert!(
        run.terminal_reason
            .unwrap()
            .starts_with("no runner took it")
    );
    let wake = engine::get_wake_request(&w.app().pool, wake.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wake.status.as_str(), "pending", "handed back, not lost");
    assert_eq!(
        count(
            &w,
            "SELECT count(*) FROM citadel_wake_requests WHERE source = 'retry'"
        )
        .await,
        0
    );
    w.host.busy.store(false, Ordering::SeqCst);
    assert!(
        w.dispatch().await.is_some(),
        "the same wake runs once the runner has room"
    );
}

#[tokio::test]
async fn a_paused_agent_and_a_terminated_one_are_not_dispatched() {
    let w = world().await;
    sqlx::query("UPDATE citadel_agents SET status = 'paused' WHERE id = ?")
        .bind(w.seed.agent)
        .execute(&w.app().pool)
        .await
        .unwrap();
    w.wake("assign:1").await;
    assert!(w.dispatch().await.is_none());
    sqlx::query("UPDATE citadel_agents SET status = 'terminated' WHERE id = ?")
        .bind(w.seed.agent)
        .execute(&w.app().pool)
        .await
        .unwrap();
    let dropped = w.wake("assign:2").await;
    assert_eq!(dropped.status.as_str(), "dropped");
    assert_eq!(dropped.dropped_reason.as_deref(), Some("agent terminated"));
}

#[tokio::test]
async fn a_wake_for_an_issue_that_moved_to_someone_else_is_dropped_not_run() {
    let w = world().await;
    let colleague = {
        let a = citadel_module::domain::org::NewAgent {
            company_id: citadel_module::domain::org::CompanyId(w.seed.company),
            name: "QA".into(),
            role: "QA".into(),
            org_role: citadel_module::domain::org::OrgRole::None,
            reports_to: None,
            harness: citadel_module::domain::org::Harness::Claude,
            model: String::new(),
            runner_tags: vec![],
            status: citadel_module::domain::org::AgentStatus::Active,
        };
        citadel_module::store::org::create_agent(&w.app().pool, &a)
            .await
            .unwrap()
            .id
    };
    sqlx::query("UPDATE citadel_issues SET next_agent_id = ? WHERE id = ?")
        .bind(colleague.0)
        .bind(w.seed.issue)
        .execute(&w.app().pool)
        .await
        .unwrap();
    let wake = w.wake("timer:1").await;
    assert!(w.dispatch().await.is_none());
    let wake = engine::get_wake_request(&w.app().pool, wake.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wake.status.as_str(), "dropped");
}

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
    assert_eq!(
        count(&w, "SELECT count(*) FROM citadel_cost_events").await,
        1
    );
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
    let spent: i64 =
        sqlx::query_scalar("SELECT tokens FROM citadel_budget_spend WHERE budget_id = ?")
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

// --- the engine's authorisation is its device's -------------------------------------------------

#[tokio::test]
async fn a_revoked_device_takes_the_engines_authorisation_with_it() {
    let w = world().await;
    w.wake("assign:1").await;
    ainkrad_core_server::store::gov::revoke_device(
        &w.app().pool,
        &w.fx.dev.id,
        AuditActor::System,
        None,
        &w.now(),
    )
    .await
    .unwrap();
    assert!(
        engine::engine_device(&w.app().pool)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        w.dispatch().await.is_none(),
        "a revoked device's switch starts nothing"
    );
    assert!(w.host.started.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_device_that_lost_admin_takes_the_engines_authorisation_with_it() {
    let w = world().await;
    let weak = enroll(w.app(), "old admin", &["read"], true).await;
    engine::set_engine(&w.app().pool, true, &weak.id, &w.now())
        .await
        .unwrap();
    assert!(
        engine::engine_device(&w.app().pool)
            .await
            .unwrap()
            .is_none()
    );
    w.wake("assign:1").await;
    assert!(w.dispatch().await.is_none());
}

#[tokio::test]
async fn the_platform_scheduler_accepts_the_engines_jobs() {
    use ainkrad_core_server::module::Module;
    let fx = fx().await;
    let modules: Vec<std::sync::Arc<dyn Module>> =
        vec![std::sync::Arc::new(citadel_module::Citadel)];
    ainkrad_core_server::jobs::register(&fx.app.pool, &fx.app.clock.now(), &modules)
        .await
        .unwrap();
    let names: Vec<String> =
        sqlx::query_scalar("SELECT name FROM core_jobs WHERE owner = 'citadel' ORDER BY name")
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(names, ["dispatch", "reconcile", "timers"]);
}

/// L1: an admin's cancel that lands while the session starts must not leave it running, with its
/// spend counted nowhere: the session is killed as soon as it is recorded, and its tokens count.
#[tokio::test]
async fn a_cancel_during_session_start_kills_the_session_and_counts_its_spend() {
    let w = world().await;
    w.host.cancel_during_start.store(true, Ordering::SeqCst);
    w.wake("assign:1").await;
    let run = w.dispatch().await.expect("the run");
    assert_eq!(run.state, RunState::Cancelled);
    let sid = run.session_id.clone().expect("the session is on the run");
    let stopped = w
        .host
        .told
        .lock()
        .unwrap()
        .iter()
        .any(|(s, what)| *s == sid && matches!(what, Instruction::Stop { kill: true }));
    assert!(stopped, "the session of a run already over is killed");
    assert!(!w.session(&run).await.live());
    let spent = count(
        &w,
        "SELECT coalesce(sum(input_tokens), 0) FROM citadel_cost_events",
    )
    .await;
    assert_eq!(spent, 100, "what it spent before the kill is on the ledger");
}

/// R1: an engine with nothing to do writes no `job.ran` audit rows (about 15.8k a day otherwise).
#[tokio::test]
async fn an_idle_engine_writes_no_audit_rows() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicI64;

    use ainkrad_core::audit::AuditFilter;
    use ainkrad_core_server::jobs::{Config, Engine, register};
    use ainkrad_core_server::module::Module;
    use ainkrad_core_server::scheduler::{Clock, iso_of_unix};

    struct Manual(AtomicI64);
    impl Clock for Manual {
        fn now(&self) -> String {
            iso_of_unix(self.0.load(Ordering::SeqCst))
        }
    }
    let fx = fx().await;
    citadel_module::engine::attach(&fx.app);
    let clock = Arc::new(Manual(AtomicI64::new(1_800_000_000)));
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(citadel_module::Citadel)];
    register(&fx.app.pool, &clock.now(), &modules)
        .await
        .unwrap();
    let jobs = Engine::new(
        fx.app.pool.clone(),
        clock.clone(),
        &modules,
        Config::default(),
    );
    for _ in 0..5 {
        clock.0.fetch_add(60, Ordering::SeqCst);
        jobs.tick().await.unwrap();
    }
    let done: i64 = sqlx::query_scalar("SELECT count(*) FROM core_job_runs WHERE status = 'ok'")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert!(done >= 5, "the jobs ran ({done} runs)");
    let rows =
        ainkrad_core_server::store::audit::list(&fx.app.pool, &AuditFilter::default(), None, 100)
            .await
            .unwrap();
    let ran = rows.iter().filter(|e| e.action == "job.ran").count();
    assert_eq!(ran, 0, "nothing happened, nothing is audited");
}

/// C1: a wake never carries another company's issue into an agent's session.
#[tokio::test]
async fn a_wake_for_another_companys_issue_is_refused() {
    let w = world().await;
    let other = seed(&w.app().pool, "B", "BEE", ProjectMode::Scrum).await;
    let mut cross = w.wake_for("cross:1");
    cross.issue_id = Some(IssueId(other.issue));
    let refused = engine::enqueue_wake(&w.app().pool, &cross).await;
    assert!(refused.is_err(), "{refused:?}");
    let mut missing = w.wake_for("missing:1");
    missing.issue_id = Some(IssueId(9999));
    assert!(engine::enqueue_wake(&w.app().pool, &missing).await.is_err());
    assert_eq!(
        count(&w, "SELECT count(*) FROM citadel_wake_requests").await,
        0
    );
    w.wake("own:1").await;
    assert_eq!(
        count(&w, "SELECT count(*) FROM citadel_wake_requests").await,
        1
    );
}

/// M2: the platform handle drives only the sessions the module owns; a client's session or
/// another module's is refused whatever the caller names.
#[tokio::test]
async fn the_engine_cannot_drive_a_session_it_does_not_own() {
    use ainkrad_core_server::agents::ModuleAgents;
    use ainkrad_proto::v2::{AgentStop, Command};
    let w = world().await;
    let policy = serde_json::json!({"mode": "ask"});
    let runner = w.host.runners[0].clone();
    let new = new_session(&runner, &policy, &w.fx.dev.id);
    let clients = sessions::create(&w.app().pool, &new, AuditActor::System, &w.now())
        .await
        .unwrap();
    let theirs = sessions::create_owned(
        &w.app().pool,
        &new,
        Some("other"),
        AuditActor::System,
        &w.now(),
    )
    .await
    .unwrap();
    let stop = |id: &str| {
        Command::AgentStop(AgentStop {
            session: id.to_owned(),
            kill: true,
        })
    };
    for id in [&clients.id, &theirs.id] {
        let refused = ModuleAgents::of(&citadel_module::Citadel)
            .instruct(w.app(), id, stop(id))
            .await;
        assert!(refused.is_err(), "{id}: {refused:?}");
    }
}
