//! The admin's controls over the wire (1.19, decision #34): a pause reaches the run's runner as
//! `Pause` and the run ends `cancelled: paused by admin`; a message reaches it as `Message` and
//! is marked delivered by its `user_message` chunk; a stop is `Cancel`, and the runner, its run
//! dropped, takes the next one. A policy the admin sets mid-run reaches it as `PolicyUpdate`
//! (1.24).

use std::sync::{Arc, Mutex};

use citadel_core::audit::AuditActor;
use citadel_core::exec::RunId;
use citadel_core::work::UserId;
use citadel_server::store::exec::{message_run, pause_agent, stop_run};
use citadel_server::store::work::set_project_policy;
use ainkrad_proto::runner::{Outcome, PermissionMode, Policy, RunToken};
use ainkrad_runner::{Control, Executor, Job, Report};
use tokio::sync::{Notify, mpsc};

use super::support::*;
use crate::harness::{agent, assign, company, issue, runner};

const ADMIN: AuditActor = AuditActor::User(UserId(1));

/// Works until paused (then ends as the real runner does); says when it takes a message.
#[derive(Clone, Default)]
struct Obeys {
    inbox: Arc<Mutex<Vec<Control>>>,
    arrived: Arc<Notify>,
}

impl Executor for Obeys {
    async fn start(&self, _: &Job) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn run(&self, _: &Job, _: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        loop {
            let taken: Vec<Control> = std::mem::take(&mut *self.inbox.lock().unwrap());
            for control in taken {
                match control {
                    Control::Pause => {
                        return Outcome::Cancelled {
                            reason: "paused by admin".to_owned(),
                        };
                    }
                    Control::Message { id, text } => {
                        let chunk = serde_json::json!({"type": "user_message", "id": id,
                            "text": text});
                        let _ = reports.send(Report::Event(chunk)).await;
                    }
                    Control::Policy(policy) => {
                        let chunk = serde_json::json!({"type": "policy_update",
                            "allow": policy.allow});
                        let _ = reports.send(Report::Event(chunk)).await;
                    }
                }
            }
            self.arrived.notified().await;
        }
    }

    fn control(&self, _: i64, control: Control) {
        self.inbox.lock().unwrap().push(control);
        self.arrived.notify_one();
    }
}

#[tokio::test]
async fn controls_reach_the_runner_holding_the_run() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let (dev, qa) = (
        agent(pool, c, "Dev", &[], None).await,
        agent(pool, c, "QA", &[], None).await,
    );
    let (one, two) = (issue(pool, p).await, issue(pool, p).await);
    runner(pool, "box", &[]).await;
    assign(pool, one, dev).await;
    stack.runner("box", &[], Obeys::default());
    until(
        pool,
        "the run to start",
        "SELECT count(*) FROM runs WHERE state = 'running'",
    )
    .await;
    let run = RunId(1);

    // A message: delivered by the runner's chunk.
    message_run(
        pool,
        run,
        UserId(1),
        "use the in-memory transport",
        None,
        &stack.now(),
    )
    .await
    .unwrap();
    let delivered = "SELECT count(*) FROM run_controls c JOIN run_events e \
                     ON e.run_id = c.run_id AND e.kind = 'user_message' \
                     WHERE c.kind = 'message' AND c.delivered_at IS NOT NULL";
    until(pool, "the message to be delivered", delivered).await;

    // A policy set mid-run: the run's runner gets it once.
    let policy = Policy {
        mode: PermissionMode::Ask,
        allow: vec!["Bash:git fetch".to_owned()],
        sandboxed: false,
    };
    assert!(set_project_policy(pool, p, &policy, ADMIN).await.unwrap());
    let updated = "SELECT count(*) FROM run_events WHERE run_id = 1 AND kind = 'policy_update' \
                   AND payload LIKE '%git fetch%'";
    until(pool, "the policy to reach the run", updated).await;

    // A pause: the runner ends the run.
    assert!(pause_agent(pool, dev, ADMIN, &stack.now()).await.unwrap());
    let paused = "SELECT count(*) FROM runs WHERE id = 1 AND state = 'cancelled' \
                  AND terminal_reason = 'paused by admin'";
    until(pool, "the run to end paused", paused).await;

    // A stop: the run ends now and the runner drops it, then takes the next one.
    assign(pool, two, qa).await;
    until(
        pool,
        "the next run",
        "SELECT count(*) FROM runs WHERE id = 2 AND state = 'running'",
    )
    .await;
    let stopped = stop_run(pool, RunId(2), ADMIN, &stack.now()).await.unwrap();
    assert_eq!(stopped.terminal_reason.as_deref(), Some("stopped by admin"));
    let told = "SELECT count(*) FROM run_controls WHERE run_id = 2 AND kind = 'stop' \
                AND sent_at IS NOT NULL";
    until(pool, "the runner to be told", told).await;
    assign(pool, one, qa).await;
    until(
        pool,
        "the runner to take more work",
        "SELECT count(*) FROM runs WHERE id = 3",
    )
    .await;
}
