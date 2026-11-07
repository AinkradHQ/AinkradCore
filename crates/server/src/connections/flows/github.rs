//! The GitHub device flow as a flow: `start` asks GitHub for a code and hands the screen what to
//! show; a task owns the device code and polls on GitHub's own interval until the person
//! approves, denies or the code ends, then stores the token. The task stops when the flow is
//! cancelled, when it ends, or when the Core stops.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{Flow, Start, StartError, View, blank, finish, new_flow};
use crate::api::App;
use crate::connections::github::device::{self, DeviceError, Pending, Step};

pub(super) async fn start(app: &App, s: Start<'_>) -> Result<View, StartError> {
    let Some(client_id) = app.conn_apps.github_client_id() else {
        return Err(StartError::NotConfigured(
            "Sign in with GitHub is not set up on this Core yet: an admin enters Ainkrad's GitHub \
             client id first",
        ));
    };
    if !app.conn_flows.room(s.user) {
        return Err(StartError::TooMany);
    }
    let transport = app.connections.github().transport();
    let (prompt, pending) = device::start(transport, &client_id, Instant::now())
        .await
        .map_err(StartError::Device)?;
    let mut view = blank("github");
    view.prompt = Some(prompt.clone());
    let life = Duration::from_secs(prompt.expires_in);
    let flow = app
        .conn_flows
        .admit(new_flow(&s, "github", life, view, None))?;
    let first = flow.view();
    tokio::spawn(run(app.clone(), flow, pending, client_id));
    Ok(first)
}

async fn run(app: App, flow: Arc<Flow>, pending: Pending, client_id: String) {
    let mut closing = app.closing.subscribe();
    tokio::select! {
        () = poll(&app, &flow, pending, &client_id) => {}
        () = crate::api::stopping(&mut closing) => {}
    }
}

async fn poll(app: &App, flow: &Arc<Flow>, mut pending: Pending, client_id: &str) {
    let transport = app.connections.github().transport();
    loop {
        if flow.cancelled() {
            return;
        }
        match pending.poll(transport, client_id, Instant::now()).await {
            Step::Wait { secs } => tokio::time::sleep(Duration::from_secs(secs.clamp(1, 60))).await,
            Step::Granted(g) => {
                flow.set(|v| v.step = "approved");
                let done = finish::store(app, flow, &g.material, "GitHub").await;
                finish::conclude(flow, done);
                return;
            }
            Step::Expired => return flow.set(|v| v.step = "expired"),
            Step::Denied => return flow.set(|v| v.step = "denied"),
            Step::Closed => return,
            Step::Failed(e) if e.transient() => {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Step::Failed(e) => return flow.fail(e.code(), &message(&e)),
        }
    }
}

fn message(e: &DeviceError) -> String {
    e.to_string()
}
