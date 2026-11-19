//! Stopping one sub-agent (E6) end to end: the real Core (routes, store, hub) and a real runner
//! daemon with its agent driver. `stopAgentSubagent` on a running `Task` call reaches the session's
//! run as `Control::StopSubagent` with that call's id, the answer goes on, the stop is audited, and
//! once the call has its result the same id is no running sub-agent (404). The Claude end
//! (`stop_task`) is `ainkrad_harness::claude::tests`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents as service;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use ainkrad_proto::runner::{Outcome, RunToken};
use ainkrad_runner::{Control, Executor, Job, Report};
use serde_json::json;
use tokio::sync::{Notify, mpsc};

use super::agents::{make_admin, run_runner, state_of, until};
use super::runner::{paired, state};
use super::{Core, quick};

const CALL: &str = "toolu_sub1";

/// A live harness whose one answer starts a sub-agent (`Task`) and ends it when told to stop it.
#[derive(Clone, Default)]
struct WithSubagent {
    stops: Arc<Mutex<Vec<String>>>,
    wake: Arc<Notify>,
}

impl Executor for WithSubagent {
    async fn start(&self, job: &Job) -> Result<Option<String>, String> {
        Ok(Some(format!("h-{}", job.context_ref)))
    }

    async fn run(&self, _: &Job, _: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        let say = |event| reports.send(Report::Event(event));
        let _ = say(json!({"type": "user_message", "id": 1, "text": "go"})).await;
        let _ = say(json!({"type": "tool_use", "id": CALL, "name": "Task",
                            "input": {"description": "look around"}}))
        .await;
        while self.stops.lock().unwrap().is_empty() {
            self.wake.notified().await;
        }
        let _ = say(json!({"type": "tool_result", "id": CALL, "name": "Task",
                            "status": "error", "output": "stopped"}))
        .await;
        let _ = say(json!({"type": "assistant_text", "text": "went on"})).await;
        let _ = say(json!({"type": "turn_ended", "outcome": {"kind": "success"}})).await;
        let _ = say(json!({"type": "waiting", "outcome": "success"})).await;
        // The session stays up until the test ends.
        std::future::pending().await
    }

    fn control(&self, _: i64, control: Control) {
        if let Control::StopSubagent(id) = control {
            self.stops.lock().unwrap().push(id);
            self.wake.notify_one();
        }
    }
}

async fn http(
    core: &Core,
    dev: &ainkrad_core_server::auth::testing::TestDevice,
    path: &str,
) -> (u16, serde_json::Value) {
    let mut req = reqwest::Client::new().post(format!("http://{}{path}", core.host));
    for (n, v) in dev.headers("POST", path, b"") {
        req = req.header(n, v);
    }
    let res = req.send().await.unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(serde_json::Value::Null))
}

async fn has(core: &Core, id: &str, kind: &str) -> bool {
    let t = sessions::transcript(&core.app.pool, id, 0, 1000)
        .await
        .unwrap();
    t.iter().any(|e| e.body["type"] == kind)
}

#[tokio::test]
async fn a_running_sub_agent_is_stopped_alone_and_audited() {
    let core = Core::start("subagents", quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("subagents");
    paired(&core, &base, None, &st).await;
    let exec = WithSubagent::default();
    let r = run_runner(&core, &base, &st, exec.clone()).await;
    make_admin(&core, &r.id).await;
    let policy = json!({"mode": "ask"});
    let new = NewSession {
        runner: &r.id,
        harness: "claude",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &r.id,
    };
    let now = core.app.clock.now();
    let s = sessions::create(&core.app.pool, &new, AuditActor::System, &now)
        .await
        .unwrap();
    let s = state_of(&core, &s.id).await;
    service::authorize_for_tests(&core.app, &s.id);
    service::start(&core.app, &s).await.unwrap();
    // Poll the store for the sub-agent's call, never right after the start.
    for _ in 0..500 {
        if has(&core, &s.id, "tool_use").await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        has(&core, &s.id, "tool_use").await,
        "the Task call is stored"
    );

    let dev = core.device("device", &["read", "agent", "admin"]).await;
    let sid = dev.session.lock().unwrap().clone().unwrap();
    let until_s = ainkrad_core_server::scheduler::Clock::unix(&*core.app.clock) + 300;
    assert!(core.app.auth.elevate(&sid, &dev.id, until_s));
    dev.unlock(&core.app.auth, until_s + 3300);
    let path = format!("/api/v1/agent-sessions/{}/subagents/{CALL}/stop", s.id);
    let (status, got) = http(&core, &dev, &path).await;
    assert_eq!(status, 200, "{got}");
    assert_eq!(got["can_stop_subagents"], true, "{got}");
    until("the run was told to stop the sub-agent", || {
        exec.stops.lock().unwrap().as_slice() == [CALL]
    })
    .await;
    let audited: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'agent.subagent_stopped'",
    )
    .fetch_all(&core.app.pool)
    .await
    .unwrap();
    assert_eq!(audited.len(), 1);
    assert!(audited[0].contains(CALL), "{audited:?}");

    // The answer went on; once the call has its result it is no running sub-agent.
    for _ in 0..500 {
        if has(&core, &s.id, "turn_ended").await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(has(&core, &s.id, "turn_ended").await, "the answer went on");
    assert!(
        state_of(&core, &s.id).await.live(),
        "the session is not over"
    );
    let (status, got) = http(&core, &dev, &path).await;
    assert_eq!(
        (status, got["code"].as_str()),
        (404, Some("unknown_subagent"))
    );
    assert_eq!(exec.stops.lock().unwrap().len(), 1, "nothing more was sent");
}
