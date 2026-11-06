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
            let ev = AgentEvents { gateway: vec![], plan_limit: None,
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
        let ev = AgentEvents { gateway: vec![], plan_limit: None,
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

#[path = "engine/authorisation.rs"]
mod authorisation;
#[path = "engine/control_tokens.rs"]
mod control_tokens;
#[path = "engine/reconcile_usage.rs"]
mod reconcile_usage;
