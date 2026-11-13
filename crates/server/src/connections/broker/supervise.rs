//! The Core's side of the `agent.tools` channel for one live session that has connection access:
//! a long poll of the runner (calls in, the tool list out when it changes), one task per call
//! (the call runs and its result goes back in a short poll of its own), and the cursor in the
//! store so a call the runner resends is never run twice.
//!
//! Every live session is polled: its access needs no row (`store::connections::access`), but what
//! it may CALL is read-class operations only until an explicit allowlist row says more. A runner
//! that does not list `connection-tools` (an older one) is polled slowly and never sent a tool.
//!
//! **Results are kept until the runner has them.** A finished call's result waits in a bounded
//! per-session outbox and is offered again (one delivery stream per session, see
//! [`push_result`]) until a poll is answered, for at most [`KEEP`]; one that expires, or whose
//! session ended, is audited as `result_undelivered`. A small cache of the last results answers a
//! call the runner sends again after the Core already took it, instead of running it twice.

use std::time::{Duration, Instant};

use ainkrad_proto::v2::{
    AGENT_DRIVER, Body, CAP_TOOLS, Command, ErrorCode, MAX_BATCH, Reply, StreamError, ToolBatch,
    ToolResult, ToolsPoll, valid_call_id,
};
use futures_util::future::{BoxFuture, FutureExt};

use super::Env;
use crate::api::App;
use crate::store::connections::access::{self, Step};

/// How long a result is kept for a runner that is away.
const KEEP: Duration = Duration::from_secs(600);
/// Results kept per session waiting for delivery, and finished results remembered per session.
const MAX_WAITING: usize = 128;
const MAX_DONE: usize = 64;

/// A finished call's result, waiting to reach its runner. `op` is a registered operation name
/// (what the audit row of a lost one may name).
pub(super) struct Pending {
    at: Instant,
    op: Option<String>,
    result: ToolResult,
}

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
            Ok(mut t) => {
                // Code Mode (E1): every session can search the operation catalogue.
                t.push(crate::ops_catalog::search_tool());
                t.push(crate::ops_catalog::call_tool());
                t
            }
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
/// the next number) and runs each in a task of its own. A resend of a call already taken is
/// answered from its stored result (never run again); a call past the next number means one was
/// lost: the cursor moves to it and it is answered `out_of_order`, not run.
fn intake(app: App, runner: String, session: String, batch: ToolBatch) -> BoxFuture<'static, ()> {
    async move {
        if batch.session != session {
            return;
        }
        let mut calls = batch.calls;
        calls.sort_by_key(|c| c.tc_seq);
        calls.truncate(MAX_BATCH);
        let (mut take, mut skipped, mut again) = (Vec::new(), Vec::new(), Vec::new());
        {
            // The cursor moves before anything runs: a resend is then a no-op.
            let _one_at_a_time = app.connections.intake.lock().await;
            for c in calls {
                match access::advance(&app.pool, &session, c.tc_seq).await {
                    Ok(Step::Take) => take.push(c),
                    Ok(Step::Gap) => skipped.push(c),
                    Ok(Step::Stale) => again.push(c),
                    Err(e) => {
                        tracing::error!(session, error = %e, "moving a tool-call cursor failed");
                        break;
                    }
                }
            }
        }
        for c in again {
            let stored = app.connections.stored(&session, &c.id);
            if let Some(result) = stored {
                push_result(&app, &runner, &session, (result, None), false);
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
            push_result(&app, &runner, &session, (refusal, None), true);
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
                if call.tool == crate::ops_catalog::SEARCH {
                    let r = crate::ops_catalog::search_call(&app, &runner, &session, &call).await;
                    push_result(&app, &runner, &session, (r, None), true);
                    return;
                }
                if call.tool == crate::ops_catalog::CALL {
                    let r = crate::ops_catalog::call_call(&app, &runner, &session, &call).await;
                    push_result(&app, &runner, &session, (r, None), true);
                    return;
                }
                let result = app.connections.handle(&env, &runner, &session, &call).await;
                let op = app
                    .connections
                    .is_registered(&call.tool)
                    .then(|| call.tool.clone());
                push_result(&app, &runner, &session, (result, op), true);
            });
        }
    }
    .boxed()
}

impl super::Broker {
    /// The stored result of call `id` of `session`, if it is among the last ones.
    fn stored(&self, session: &str, id: &str) -> Option<ToolResult> {
        let done = self.done.lock().unwrap_or_else(|e| e.into_inner());
        let found = done.get(session)?.iter().find(|(_, r)| r.id == id);
        found.map(|(_, r)| r.clone())
    }

    /// Whether `tool` is a registered operation.
    pub(super) fn is_registered(&self, tool: &str) -> bool {
        let kind = tool.split_once('.').map(|(k, _)| k);
        let adapter = kind.and_then(|k| self.reg.get(k));
        adapter.is_some_and(|a| a.descriptor().capability_of(tool).is_some())
    }
}

/// Queues one finished call's result for its session (`remember`: also keep it for a resend of the
/// call). At most ONE delivery stream per session is ever open: a drainer sends everything queued
/// in one short poll (up to a batch), again while more has come, and keeps what it could not
/// deliver. So a burst of finished calls costs one stream, never one each, and cannot starve the
/// runner's other commands (the agent driver's stream budget is three per session: its read, its
/// tools poll, this).
fn push_result(
    app: &App,
    runner: &str,
    session: &str,
    (result, op): (ToolResult, Option<String>),
    remember: bool,
) {
    let broker = &app.connections;
    if remember {
        let mut done = broker.done.lock().unwrap_or_else(|e| e.into_inner());
        let d = done.entry(session.to_owned()).or_default();
        d.push_back((Instant::now(), result.clone()));
        while d.len() > MAX_DONE {
            d.pop_front();
        }
    }
    let mut lost = None;
    {
        let mut outbox = broker.outbox.lock().unwrap_or_else(|e| e.into_inner());
        let q = outbox.entry(session.to_owned()).or_default();
        // A result already waiting is not queued twice.
        if !q.iter().any(|p| p.result.id == result.id) {
            q.push_back(Pending {
                at: Instant::now(),
                op,
                result,
            });
        }
        if q.len() > MAX_WAITING {
            lost = q.pop_front();
        }
    }
    if let Some(p) = lost {
        tokio::spawn(undelivered(app.clone(), session.to_owned(), vec![p]));
    }
    let first = broker
        .delivering
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(session.to_owned());
    if first {
        tokio::spawn(drain(app.clone(), runner.to_owned(), session.to_owned()));
    }
}

/// Audits results that never reached their runner, so the audit and the agent do not disagree.
async fn undelivered(app: App, session: String, lost: Vec<Pending>) {
    let user = match access::load(&app.pool, &session).await {
        Ok(Some(a)) => a.user,
        _ => 0,
    };
    for p in lost {
        let row = access::audit_undelivered(&app.pool, user, &session, p.op.as_deref()).await;
        if let Err(e) = row {
            tracing::error!(error = ?e, "auditing an undelivered tool result failed");
        }
    }
}

async fn drain(app: App, runner: String, session: String) {
    let retry = app.agents.config.retry;
    loop {
        // What expired, and what is next to send; an empty outbox ends the drainer under the lock,
        // so a result pushed after that sees "nobody delivering" and starts a new one.
        let (expired, batch) = {
            let mut outbox = app
                .connections
                .outbox
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut expired = Vec::new();
            if let Some(q) = outbox.get_mut(&session) {
                while q.front().is_some_and(|p| p.at.elapsed() >= KEEP) {
                    expired.extend(q.pop_front());
                }
            }
            let batch: Vec<ToolResult> = outbox
                .get(&session)
                .map(|q| q.iter().take(MAX_BATCH).map(|p| p.result.clone()).collect())
                .unwrap_or_default();
            if batch.is_empty() {
                outbox.remove(&session);
                let mut d = app
                    .connections
                    .delivering
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                d.remove(&session);
            }
            (expired, batch)
        };
        if !expired.is_empty() {
            undelivered(app.clone(), session.clone(), expired).await;
        }
        if batch.is_empty() {
            return;
        }
        let after = match access::load(&app.pool, &session).await {
            Ok(Some(a)) if a.live => a.grant.tc_seq,
            Ok(_) => {
                // The session is over: nobody will take these.
                let gone = take_all(&app, &session);
                undelivered(app.clone(), session.clone(), gone).await;
                continue;
            }
            Err(_) => {
                tokio::time::sleep(retry).await;
                continue;
            }
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
                // An answered poll is an acknowledgement: the runner has them.
                {
                    let ids: Vec<&str> = batch.iter().map(|r| r.id.as_str()).collect();
                    let mut outbox = app
                        .connections
                        .outbox
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if let Some(q) = outbox.get_mut(&session) {
                        q.retain(|p| !ids.contains(&p.result.id.as_str()));
                    }
                }
                intake(app.clone(), runner.clone(), session.clone(), answer).await;
            }
            // The runner is away or busy: keep them and try again (until they expire).
            Err(_) => tokio::time::sleep(retry).await,
        }
    }
}

fn take_all(app: &App, session: &str) -> Vec<Pending> {
    let mut outbox = app
        .connections
        .outbox
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    outbox
        .get_mut(session)
        .map(|q| q.drain(..).collect())
        .unwrap_or_default()
}
