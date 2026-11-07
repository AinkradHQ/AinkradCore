//! The Core's side of the `agent.tools` channel for one live session that has connection access:
//! a long poll of the runner (calls in, the tool list out when it changes), one task per call
//! (the call runs and its result goes back in a short poll of its own), and the cursor in the
//! store so a call the runner resends is never run twice.
//!
//! Every live session is polled (its access needs no row, see `store::connections::access`).
//! A runner that does not list `connection-tools`
//! (an older one) is polled slowly and never sent a tool.

use std::time::Duration;

use ainkrad_proto::v2::{
    AGENT_DRIVER, Body, CAP_TOOLS, Command, ErrorCode, MAX_BATCH, Reply, StreamError, ToolBatch,
    ToolResult, ToolsPoll, valid_call_id,
};
use futures_util::future::{BoxFuture, FutureExt};

use super::Env;
use crate::api::App;
use crate::store::connections::access::{self, Step};

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

/// Narrows session `session` to `allowlist` and makes sure its tool channel is being supervised
/// (the hook C5's allowlist API calls; the session's own create path writes the row in its own
/// transaction before the session starts).
pub async fn set_access(
    app: &App,
    session: &str,
    allowlist: &[String],
) -> Result<(), crate::store::secrets::Error> {
    access::set(&app.pool, session, allowlist).await?;
    supervise(app, session);
    Ok(())
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
            Ok(Some(a)) if a.live => a,
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
            after: acc.grant.tc_seq,
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

/// Takes the calls of `batch` the cursor has not seen (each exactly once, in order, each exactly
/// the next number) and runs each in a task of its own. A resend is skipped; a call past the next
/// number means one was lost: the cursor moves to it and it is answered `out_of_order`, not run.
fn intake(app: App, runner: String, session: String, batch: ToolBatch) -> BoxFuture<'static, ()> {
    async move {
        if batch.session != session {
            return;
        }
        let mut calls = batch.calls;
        calls.sort_by_key(|c| c.tc_seq);
        calls.truncate(MAX_BATCH);
        let mut take = Vec::new();
        let mut skipped = Vec::new();
        {
            // The cursor moves before anything runs: a resend is then a no-op.
            let _one_at_a_time = app.connections.intake.lock().await;
            for c in calls {
                match access::advance(&app.pool, &session, c.tc_seq).await {
                    Ok(Step::Take) => take.push(c),
                    Ok(Step::Gap) => skipped.push(c),
                    Ok(Step::Stale) => {}
                    Err(e) => {
                        tracing::error!(session, error = %e, "moving a tool-call cursor failed");
                        break;
                    }
                }
            }
        }
        for c in skipped {
            let refusal = ToolResult {
                id: c.id,
                ok: false,
                result: None,
                code: Some("out_of_order".to_owned()),
                message: Some("a call before this one was lost; send it again".to_owned()),
            };
            push_result(&app, &runner, &session, refusal);
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
                push_result(&app, &runner, &session, result);
            });
        }
    }
    .boxed()
}

/// Queues one finished call's result for its session. At most ONE delivery stream per session is
/// ever open: a drainer sends everything queued in one short poll (up to a batch), then again while
/// more has come. So a burst of finished calls costs one stream, never one each, and cannot starve
/// the runner's other commands (the agent driver's stream budget is three per session: its read,
/// its tools poll, this).
fn push_result(app: &App, runner: &str, session: &str, result: ToolResult) {
    let broker = &app.connections;
    broker
        .outbox
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(session.to_owned())
        .or_default()
        .push(result);
    let first = broker
        .delivering
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(session.to_owned());
    if first {
        tokio::spawn(drain(app.clone(), runner.to_owned(), session.to_owned()));
    }
}

async fn drain(app: App, runner: String, session: String) {
    let retry = app.agents.config.retry;
    loop {
        let batch: Vec<ToolResult> = {
            let mut outbox = app
                .connections
                .outbox
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let queued = outbox.get_mut(&session).filter(|q| !q.is_empty());
            let Some(queued) = queued else {
                // Checked and released under the outbox lock: a result pushed after this is
                // seen by its pusher as "nobody delivering" and starts a new drainer.
                outbox.remove(&session);
                let mut d = app
                    .connections
                    .delivering
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                d.remove(&session);
                return;
            };
            let n = queued.len().min(MAX_BATCH);
            queued.drain(..n).collect()
        };
        let mut delivered = false;
        for _ in 0..DELIVER_TRIES {
            let after = match access::load(&app.pool, &session).await {
                Ok(Some(a)) if a.live => a.grant.tc_seq,
                _ => break,
            };
            let poll = ToolsPoll {
                session: session.clone(),
                after,
                wait_ms: None,
                results: batch.clone(),
                tools: None,
            };
            match ask(&app, &runner, poll, app.agents.config.answer).await {
                Ok(answer) => {
                    intake(app.clone(), runner.clone(), session.clone(), answer).await;
                    delivered = true;
                    break;
                }
                Err(_) => tokio::time::sleep(retry).await,
            }
        }
        if !delivered {
            tracing::warn!(session, "tool results could not be delivered");
        }
    }
}
