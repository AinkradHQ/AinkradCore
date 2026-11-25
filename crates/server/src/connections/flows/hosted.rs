//! A sign-in whose redirect is Ainkrad's hosted callback (`https://signin.ainkrad.io/callback`):
//! the browser lands on the sign-in service, not on this Mac, so no client hands the code over.
//! A task asks the service for it (`Jira::collect`, signed, by the flow's `state`) every few
//! seconds while the flow waits, and finishes the flow through the same [`super::callback`] a
//! client's delivery uses. A client that still delivers the redirect itself (ctl
//! `--callback-url`) keeps working: whichever comes first finishes, the other finds the flow
//! no longer waiting. The task stops when the flow ends, is cancelled, or the Core stops.

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use super::Flow;
use crate::api::App;

const EVERY: Duration = if cfg!(test) {
    Duration::from_millis(20)
} else {
    Duration::from_secs(3)
};

/// Starts the task when `redirect` is the hosted callback; a loopback redirect is the client's.
pub(super) fn watch(app: &App, flow: &Arc<Flow>, redirect: &str) {
    if redirect != crate::connections::jira::service::callback_url() {
        return;
    }
    // Weak: a cancelled or evicted flow is dropped at once (and its pending sign-in with it).
    let (app, flow) = (app.clone(), Arc::downgrade(flow));
    tokio::spawn(async move {
        let mut closing = app.closing.subscribe();
        tokio::select! {
            () = poll(&app, &flow) => {}
            () = crate::api::stopping(&mut closing) => {}
        }
    });
}

fn waiting(flow: &Flow) -> bool {
    !flow.cancelled() && Instant::now() < flow.expires && flow.step() == "waiting"
}

async fn poll(app: &App, flow: &Weak<Flow>) {
    let jira = app.connections.jira();
    loop {
        tokio::time::sleep(EVERY).await;
        let Some(flow) = flow.upgrade().filter(|f| waiting(f)) else {
            return;
        };
        let Some(state) = flow.jira_state.as_ref().map(|s| s.to_string()) else {
            return;
        };
        let flow = &*flow;
        // Not yet (404), busy (429), down, a clock problem: asked again until the flow ends.
        let Ok(r) = jira.collect(&state, &app.clock.now()).await else {
            continue;
        };
        match r.status {
            200 => {
                if let Some(code) = r.body["code"].as_str() {
                    let _ = super::callback(app, flow, code, &state).await;
                } else if !waiting(flow) {
                    // A client's delivery finished it meanwhile.
                } else if r.body["error"] == "access_denied" {
                    flow.set(|v| v.step = "denied");
                } else {
                    flow.fail("sign_in_failed", "the service did not complete the sign-in");
                }
                return;
            }
            410 => {
                return flow.fail(
                    "already_collected",
                    "that sign-in's answer was already taken; start again",
                );
            }
            _ => {}
        }
    }
}
