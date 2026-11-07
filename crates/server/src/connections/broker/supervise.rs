//! The Core's side of the `agent.tools` channel for one live session that has connection access:
//! a long poll of the runner (calls in, the tool list out when it changes), one task per call
//! (the call runs and its result goes back in a short poll of its own), and the cursor in the
//! store so a call the runner resends is never run twice.
//!
//! A session with no `core_session_connections` row has no supervisor here: its access is given
//! when the Core makes it, before it starts. A runner that does not list `connection-tools`
//! (an older one) is polled slowly and never sent a tool.

use std::time::Duration;

use ainkrad_proto::v2::{
    AGENT_DRIVER, Body, CAP_TOOLS, Command, ErrorCode, MAX_BATCH, Reply, StreamError, ToolBatch,
    ToolResult, ToolsPoll, valid_call_id,
};
use futures_util::future::{BoxFuture, FutureExt};

use super::Env;
use crate::api::App;
use crate::store::connections::access;

/// How many times a result is offered to the runner before it is let go (its call times out there).
const DELIVER_TRIES: usize = 3;

/// Supervises session `id`'s tool channel, unless this process already does.
pub fn supervise(app: &App, id: &str) {
    let broker = &app.connections;
    let first = broker
        .supervised
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.to_owned());
    if !first {
        return;
    }
    let (app, id) = (app.clone(), id.to_owned());
    tokio::spawn(async move {
        let mut closing = app.closing.subscribe();
        tokio::select! {
            () = run(&app, &id) => {}
            () = crate::api::stopping(&mut closing) => {}
        }
        let mut held = app
            .connections
            .supervised
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        held.remove(&id);
    });
}

fn offers_tools(app: &App, runner: &str) -> bool {
    app.hub.runners().get(runner).is_some_and(|r| {
        r.online
            && r.drivers
                .iter()
                .any(|d| d.name == AGENT_DRIVER && d.commands.iter().any(|c| c == CAP_TOOLS))
    })
}

async fn ask(
    app: &App,
    runner: &str,
    poll: ToolsPoll,
    wait: Duration,
) -> Result<ToolBatch, StreamError> {
    let sent = app
        .hub
        .dispatch_agent_read(runner, Command::AgentTools(poll))?;
    let answer = tokio::time::timeout(wait, sent.outcome())
        .await
        .map_err(|_| StreamError::new(ErrorCode::Lost, "the runner did not answer in time"))??;
    match answer {
        Body::Result(Reply::AgentTools(batch)) => Ok(batch),
        _ => Err(StreamError::new(
            ErrorCode::BadFrame,
            "an answer of another op",
        )),
    }
}

async fn run(app: &App, id: &str) {
    let cfg = app.agents.config.clone();
    let wait_ms = u64::try_from(cfg.read_wait.as_millis()).unwrap_or(u64::MAX);
    let mut sent = None;
    loop {
        let acc = match access::load(&app.pool, id).await {
            Ok(Some(a)) if a.live && a.grant.is_some() => a,
            Ok(_) => return,
            Err(e) => {
                tracing::error!(session = id, error = %e, "reading a session's tool access failed");
                tokio::time::sleep(cfg.retry).await;
                continue;
            }
        };
        if !offers_tools(app, &acc.runner) {
            tokio::time::sleep(cfg.retry * 5).await;
            continue;
        }
        let now = app.clock.now();
        let env = Env {
            pool: &app.pool,
            sealer: app.secrets.as_ref(),
            now: &now,
        };
        let want = match app.connections.tools(&env, id).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(session = id, error = %e, "listing a session's tools failed");
                tokio::time::sleep(cfg.retry).await;
                continue;
            }
        };
        let changed = sent.as_ref() != Some(&want);
        let poll = ToolsPoll {
            session: id.to_owned(),
            after: acc.grant.as_ref().map_or(0, |g| g.tc_seq),
            wait_ms: Some(wait_ms),
            results: Vec::new(),
            tools: changed.then(|| want.clone()),
        };
        match ask(app, &acc.runner, poll, cfg.read_wait + cfg.answer).await {
            Ok(batch) => {
                if changed {
                    sent = Some(want);
                }
                intake(app.clone(), acc.runner.clone(), id.to_owned(), batch).await;
            }
            Err(e) => {
                tracing::debug!(session = id, code = ?e.code, "a tools poll did not get through");
                // What the runner now holds is unknown: send the list again with the next poll.
                sent = None;
                tokio::time::sleep(cfg.retry).await;
            }
        }
    }
}

/// Takes the calls of `batch` the cursor has not seen (each exactly once, in order) and runs each
/// in a task of its own.
fn intake(app: App, runner: String, session: String, batch: ToolBatch) -> BoxFuture<'static, ()> {
    async move {
        if batch.session != session {
            return;
        }
        let mut calls = batch.calls;
        calls.truncate(MAX_BATCH);
        calls.sort_by_key(|c| c.tc_seq);
        let mut take = Vec::new();
        {
            // The cursor moves before anything runs: a resend is then a no-op.
            let _one_at_a_time = app.connections.intake.lock().await;
            for c in calls {
                match access::advance(&app.pool, &session, c.tc_seq).await {
                    Ok(true) => take.push(c),
                    Ok(false) => {}
                    Err(e) => {
                        tracing::error!(session, error = %e, "moving a tool-call cursor failed");
                        break;
                    }
                }
            }
        }
        for call in take {
            if !valid_call_id(&call.id) {
                tracing::warn!(session, "a tool call with a malformed id was dropped");
                continue;
            }
            let (app, runner, session) = (app.clone(), runner.clone(), session.clone());
            tokio::spawn(async move {
                let now = app.clock.now();
                let env = Env {
                    pool: &app.pool,
                    sealer: app.secrets.as_ref(),
                    now: &now,
                };
                let result = app.connections.handle(&env, &runner, &session, &call).await;
                deliver(app.clone(), runner, session, result).await;
            });
        }
    }
    .boxed()
}

/// Gives the runner one finished call's result in a short poll, and takes any calls it answers
/// with. A few tries; then the runner's own timeout ends the call for the harness.
async fn deliver(app: App, runner: String, session: String, result: ToolResult) {
    let retry = app.agents.config.retry;
    for _ in 0..DELIVER_TRIES {
        let after = match access::load(&app.pool, &session).await {
            Ok(Some(a)) if a.live => a.grant.map_or(0, |g| g.tc_seq),
            _ => return,
        };
        let poll = ToolsPoll {
            session: session.clone(),
            after,
            wait_ms: None,
            results: vec![result.clone()],
            tools: None,
        };
        match ask(&app, &runner, poll, app.agents.config.answer).await {
            Ok(batch) => {
                intake(app.clone(), runner.clone(), session.clone(), batch).await;
                return;
            }
            Err(_) => tokio::time::sleep(retry).await,
        }
    }
    tracing::warn!(session, "a tool result could not be delivered");
}
