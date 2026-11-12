//! A live AI session (N41) end to end: the real Core (service, store, hub) and a real runner daemon
//! with its agent driver, and a harness stand-in that behaves as a live harness does (it reports
//! `waiting` after each answer and takes each message in the same run). A session created with no
//! first message is `waiting` at once; its pending message is delivered by the supervisor and
//! answered by the one run; the Core's state events say `waiting` and `running`; a stop ends it.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents as service;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use ainkrad_proto::runner::{Outcome, RunToken};
use ainkrad_proto::v2::{AgentStop, Command};
use ainkrad_runner::{Control, Executor, Job, Report};
use serde_json::json;
use tokio::sync::{Notify, mpsc};

use super::agents::{finished, make_admin, run_runner, state_of, until};
use super::runner::{paired, state};
use super::{Core, quick};

/// What a live harness does: `waiting`, then for each message an answer and `waiting` again.
#[derive(Clone, Default)]
struct Live {
    live: Arc<AtomicBool>,
    inbox: Arc<Mutex<VecDeque<String>>>,
    wake: Arc<Notify>,
    paused: Arc<AtomicBool>,
    runs: Arc<AtomicUsize>,
}

impl Executor for Live {
    async fn start(&self, job: &Job) -> Result<Option<String>, String> {
        Ok(Some(format!("h-{}", job.context_ref)))
    }

    async fn run(&self, _: &Job, _: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        self.runs.fetch_add(1, Ordering::SeqCst);
        assert!(self.live.load(Ordering::SeqCst), "the Core starts it live");
        let say = |event| reports.send(Report::Event(event));
        let _ = say(json!({"type": "waiting", "outcome": "ready"})).await;
        loop {
            if self.paused.load(Ordering::SeqCst) {
                return Outcome::Cancelled {
                    reason: "stopped".to_owned(),
                };
            }
            let next = self.inbox.lock().unwrap().pop_front();
            let Some(text) = next else {
                self.wake.notified().await;
                continue;
            };
            let _ = say(json!({"type": "user_message", "id": 1, "text": text})).await;
            let _ = say(json!({"type": "assistant_text", "text": format!("echo:{text}")})).await;
            let _ = say(json!({"type": "turn_ended", "outcome": {"kind": "success"}})).await;
            let _ = say(json!({"type": "waiting", "outcome": "success"})).await;
        }
    }

    fn control(&self, _: i64, control: Control) {
        match control {
            Control::Live => self.live.store(true, Ordering::SeqCst),
            Control::Message { text, .. } => self.inbox.lock().unwrap().push_back(text),
            Control::Pause => self.paused.store(true, Ordering::SeqCst),
            _ => {}
        }
        self.wake.notify_one();
    }
}

async fn waiting(core: &Core, id: &str, since_seq: i64) -> sessions::Session {
    for _ in 0..500 {
        let s = state_of(core, id).await;
        if s.api_state() == "waiting" && s.last_seq > since_seq {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{id} never waited: {:?}", state_of(core, id).await);
}

fn texts(t: &[ainkrad_proto::v2::TranscriptEntry]) -> Vec<String> {
    t.iter()
        .filter(|e| e.body["type"] == "assistant_text")
        .map(|e| e.body["text"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn a_session_with_no_first_message_waits_and_one_run_answers_every_message() {
    let core = Core::start("live", quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("live");
    paired(&core, &base, None, &st).await;
    let exec = Live::default();
    let r = run_runner(&core, &base, &st, exec.clone()).await;
    make_admin(&core, &r.id).await;
    let policy = json!({"mode": "ask"});
    let new = NewSession {
        runner: &r.id,
        harness: "fake",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &r.id,
    };
    let s = sessions::create(
        &core.app.pool,
        &new,
        AuditActor::System,
        &core.app.clock.now(),
    )
    .await
    .unwrap();
    sessions::configure(&core.app.pool, &s.id, true, None)
        .await
        .unwrap();
    let s = state_of(&core, &s.id).await;
    service::authorize_for_tests(&core.app, &s.id);
    service::start(&core.app, &s).await.unwrap();

    // No message was sent, and the session already waits for one, holding its slot.
    let idle = waiting(&core, &s.id, 0).await;
    assert_eq!(
        idle.state, "running",
        "stored running: it keeps its slot and supervisor"
    );
    assert!(idle.waiting_since.is_some());
    assert!(idle.title.is_none());

    // A message that waited for the runner (here: pending) is delivered by the supervisor.
    sqlx::query("UPDATE core_agent_sessions SET pending = 'hello' WHERE id = ?")
        .bind(&s.id)
        .execute(&core.app.pool)
        .await
        .unwrap();
    let after_first = waiting(&core, &s.id, idle.last_seq + 1).await;
    assert!(after_first.pending.is_none(), "delivered once");
    sqlx::query("UPDATE core_agent_sessions SET pending = 'again' WHERE id = ?")
        .bind(&s.id)
        .execute(&core.app.pool)
        .await
        .unwrap();
    let second = waiting(&core, &s.id, after_first.last_seq + 1).await;
    let t = sessions::transcript(&core.app.pool, &s.id, 0, 1000)
        .await
        .unwrap();
    assert_eq!(texts(&t), ["echo:hello", "echo:again"]);
    assert!(second.waiting_since.is_some());
    assert_eq!(
        exec.runs.load(Ordering::SeqCst),
        1,
        "one run for the whole conversation"
    );

    // The state events say what happened: waiting, then running, then waiting.
    let kinds: Vec<(String, String)> = sqlx::query_as(
        "SELECT json_extract(payload, '$.state'), json_extract(payload, '$.reason') \
         FROM events WHERE kind = 'agent.state' ORDER BY seq",
    )
    .fetch_all(&core.app.pool)
    .await
    .unwrap();
    let states: Vec<&str> = kinds.iter().map(|(s, _)| s.as_str()).collect();
    assert!(
        states
            .windows(3)
            .any(|w| w == ["waiting", "running", "waiting"]),
        "{kinds:?}"
    );

    // Stop ends it, with the runner's word for it.
    let stop = Command::AgentStop(AgentStop {
        session: s.id.clone(),
        kill: false,
        turn: false,
    });
    let proof = Some(ainkrad_core_server::hub::Elevated::for_tests());
    service::ask(&core.app, &r.id, stop, Duration::from_secs(5), proof)
        .await
        .unwrap();
    let (ended, _) = finished(&core, &s.id).await;
    assert_eq!(ended.state, "ended");
    assert!(ended.waiting_since.is_none());
    until("the live harness left", || {
        exec.paused.load(Ordering::SeqCst)
    })
    .await;
    r.halt().await;
    let _ = std::fs::remove_dir_all(&st.0);
}
