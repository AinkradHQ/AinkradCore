//! The run engine's test world: a Core with Citadel mounted, a seeded company, an online fake
//! runner host, and helpers to wake, dispatch, reconcile and report a session's state. Shared by
//! the engine's detectors and controls tests.
#![allow(dead_code, unused_imports)]

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::api::App;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use ainkrad_proto::runner::{Outcome, Tokens};
use ainkrad_proto::v2::{AgentEvents, AgentState, TranscriptEntry};
use citadel_module::domain::exec::RunState;
use citadel_module::domain::org::AgentId;
use citadel_module::domain::work::{IssueId, ProjectMode, RunId, WakeSource};
use citadel_module::store::exec::{
    self as engine, Host, Instruction, NewWakeRequest, StartFailure, StartSpec,
};
use serde_json::json;

use crate::common::*;
use crate::work_seed::{Seed, seed};

#[derive(Default)]
pub struct Fake {
    pub runners: Vec<String>,
    /// The harnesses the runners offer; every one when `None`.
    pub harnesses: Option<Vec<&'static str>>,
    pub busy: AtomicBool,
    pub refuse: AtomicBool,
    /// An admin's cancel lands while the session is starting (and it has already spent tokens).
    pub cancel_during_start: AtomicBool,
    pub started: Mutex<Vec<StartSpec>>,
    pub told: Mutex<Vec<(String, Instruction)>>,
}

impl Host for Fake {
    async fn runners(&self, _: &App, harness: &str) -> Vec<String> {
        match &self.harnesses {
            Some(only) if !only.contains(&harness) => vec![],
            _ => self.runners.clone(),
        }
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
    pub fn stops(&self) -> usize {
        self.told
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, w)| matches!(w, Instruction::Stop { .. }))
            .count()
    }
    pub fn decisions(&self) -> Vec<bool> {
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

pub struct W {
    pub fx: Fx,
    pub seed: Seed,
    pub host: Fake,
}

impl W {
    pub fn app(&self) -> &App {
        &self.fx.app
    }
    pub fn now(&self) -> String {
        self.fx.app.clock.now()
    }
    pub fn wake_for(&self, key: &str) -> NewWakeRequest {
        NewWakeRequest {
            agent_id: AgentId(self.seed.agent),
            issue_id: Some(IssueId(self.seed.issue)),
            source: WakeSource::Assignment,
            reason: "start the work".into(),
            idempotency_key: key.into(),
            not_before: None,
        }
    }
    pub async fn wake(&self, key: &str) -> engine::WakeRequest {
        engine::enqueue_wake(&self.app().pool, &self.wake_for(key))
            .await
            .unwrap()
    }
    pub async fn dispatch(&self) -> Option<engine::Run> {
        engine::dispatch_next(self.app(), &self.host, &self.now())
            .await
            .unwrap()
    }
    pub async fn reconcile(&self) -> engine::Report {
        engine::reconcile(self.app(), &self.host, &self.now())
            .await
            .unwrap()
    }
    pub async fn run(&self, id: RunId) -> engine::Run {
        engine::get_run(&self.app().pool, id)
            .await
            .unwrap()
            .unwrap()
    }
    pub async fn session(&self, run: &engine::Run) -> sessions::Session {
        sessions::get(&self.app().pool, run.session_id.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap()
    }
    /// A started run whose session the runner reports running.
    pub async fn running(&self) -> engine::Run {
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
    pub async fn report(
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

pub async fn world() -> W {
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

pub fn new_session<'a>(
    runner: &'a str,
    policy: &'a serde_json::Value,
    by: &'a str,
) -> NewSession<'a> {
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

pub fn tokens(input: u64, output: u64) -> Tokens {
    Tokens {
        input,
        output,
        ..Tokens::default()
    }
}

pub async fn count(w: &W, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&w.app().pool)
        .await
        .unwrap()
}
