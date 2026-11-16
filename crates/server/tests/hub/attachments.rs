//! Attachments (E4) end to end: the real Core (service, store, hub) and a real runner daemon with
//! its agent driver. A file kept with a session reaches the runner with the message that names
//! it, lands in the session's folder under `.ainkrad/attachments/`, and the text the harness gets
//! names its path (`@<path>` for Claude Code); the same for a pending message the supervisor
//! delivers; another session's attachment never leaves the Core.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents as service;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use ainkrad_core_server::store::attachments::{self, NewAttachment};
use ainkrad_proto::runner::{Outcome, RunToken};
use ainkrad_runner::{Control, Executor, Job, Report};
use serde_json::json;
use tokio::sync::{Notify, mpsc};

use super::agents::{make_admin, run_runner, state_of, until};
use super::runner::{paired, state};
use super::{Core, quick};

/// A live harness in `dir` that records every message it is given.
#[derive(Clone)]
struct InFolder {
    dir: PathBuf,
    got: Arc<Mutex<Vec<String>>>,
    stop: Arc<Notify>,
}

impl Executor for InFolder {
    async fn start(&self, job: &Job) -> Result<Option<String>, String> {
        Ok(Some(format!("h-{}", job.context_ref)))
    }

    async fn run(&self, _: &Job, _: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        let _ = reports
            .send(Report::Event(
                json!({"type": "waiting", "outcome": "ready"}),
            ))
            .await;
        self.stop.notified().await;
        Outcome::Cancelled {
            reason: "stopped".to_owned(),
        }
    }

    fn control(&self, _: i64, control: Control) {
        if let Control::Message { text, .. } = control {
            self.got.lock().unwrap().push(text);
        }
    }

    fn work_dir(&self, _: &Job) -> Option<PathBuf> {
        Some(self.dir.clone())
    }
}

async fn session(core: &Core, runner: &str) -> sessions::Session {
    let policy = json!({"mode": "ask"});
    let new = NewSession {
        runner,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: runner,
    };
    let now = core.app.clock.now();
    let s = sessions::create(&core.app.pool, &new, AuditActor::System, &now)
        .await
        .unwrap();
    sessions::configure(&core.app.pool, &s.id, true, None)
        .await
        .unwrap();
    state_of(core, &s.id).await
}

async fn attach(core: &Core, s: &sessions::Session, id: &str, name: &str, data: &[u8]) {
    let new = NewAttachment {
        id,
        session: &s.id,
        name,
        content_type: Some("image/png"),
        sha256: &"0".repeat(64),
        data,
        created_by: &s.created_by,
    };
    assert!(
        attachments::add(&core.app.pool, &new, &core.app.clock.now())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_file_sent_with_a_message_lands_in_the_session_folder_and_the_message_names_it() {
    let core = Core::start("attachments", quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("attachments");
    paired(&core, &base, None, &st).await;
    let dir = std::env::temp_dir().join(format!("ainkrad-e4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let exec = InFolder {
        dir: dir.clone(),
        got: Arc::default(),
        stop: Arc::default(),
    };
    let r = run_runner(&core, &base, &st, exec.clone()).await;
    make_admin(&core, &r.id).await;
    let s = session(&core, &r.id).await;
    service::authorize_for_tests(&core.app, &s.id);
    service::start(&core.app, &s).await.unwrap();
    let s = {
        let mut s = state_of(&core, &s.id).await;
        for _ in 0..500 {
            if s.folder.is_some() && s.api_state() == "waiting" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            s = state_of(&core, &s.id).await;
        }
        s
    };
    let landed = dir.canonicalize().unwrap().join(".ainkrad/attachments");

    // A message to the running session: the file first, then the text naming it.
    attach(&core, &s, "at_shot1", "screen shot.png", b"\x89PNG one").await;
    let proof = Some(ainkrad_core_server::hub::Elevated::for_tests());
    service::attach::send_with(&core.app, &s, "look".into(), &["at_shot1".into()], proof)
        .await
        .unwrap();
    let first = landed.join("at_shot1-screen_shot.png");
    assert_eq!(std::fs::read(&first).unwrap(), b"\x89PNG one");
    until("the harness got the message", || {
        exec.got.lock().unwrap().len() == 1
    })
    .await;
    assert_eq!(
        exec.got.lock().unwrap()[0],
        format!("look\n\n@{}", first.display())
    );

    // A pending message (its harness was restarted): the supervisor ships its attachments too.
    attach(&core, &s, "at_shot2", "two.png", b"two").await;
    sqlx::query("UPDATE core_agent_attachments SET pending = 1 WHERE id = 'at_shot2'")
        .execute(&core.app.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE core_agent_sessions SET pending = 'again' WHERE id = ?")
        .bind(&s.id)
        .execute(&core.app.pool)
        .await
        .unwrap();
    until("the pending message was delivered", || {
        exec.got.lock().unwrap().len() == 2
    })
    .await;
    let second = landed.join("at_shot2-two.png");
    assert_eq!(std::fs::read(&second).unwrap(), b"two");
    assert_eq!(
        exec.got.lock().unwrap()[1],
        format!("again\n\n@{}", second.display())
    );
    // The supervisor clears the flag just after the harness has the message.
    let mut cleared = false;
    for _ in 0..250 {
        if attachments::pending(&core.app.pool, &s.id)
            .await
            .unwrap()
            .is_empty()
        {
            cleared = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(cleared, "delivered once");

    // Another session's attachment is not this session's: nothing is sent.
    let other = session(&core, &r.id).await;
    attach(&core, &other, "at_theirs", "x.png", b"x").await;
    let proof = Some(ainkrad_core_server::hub::Elevated::for_tests());
    let refused =
        service::attach::send_with(&core.app, &s, "x".into(), &["at_theirs".into()], proof).await;
    assert!(refused.is_err());
    assert!(!landed.join("at_theirs-x.png").exists());
    assert_eq!(exec.got.lock().unwrap().len(), 2);

    exec.stop.notify_waiters();
    r.halt().await;
    let _ = std::fs::remove_dir_all(&st.0);
    let _ = std::fs::remove_dir_all(&dir);
}
