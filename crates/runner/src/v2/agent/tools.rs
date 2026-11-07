//! Connection tools on the runner (C4): the harness's tool calls wait here for the Core, and the
//! Core's results come back here. The runner NEVER receives, stores or forwards a connection
//! credential: a call is a tool name and arguments, a result is plain data or a plain refusal.
//!
//! - [`Tools::call`] is what the harness-facing side (the MCP front, see [`mcp`]) calls: the tool
//!   must be in the list the Core last sent for the session, the arguments are bounded, at most
//!   [`MAX_PENDING`] calls wait per session, and a call the Core never answers ends `timed_out`.
//! - [`Tools::poll`] answers the Core's `agent.tools`: it takes the tool list and the results,
//!   acknowledges the calls the Core holds, and waits for calls after `after`.
//! - Calls are numbered when first sent (`tc_seq`), starting above the Core's cursor, so a runner
//!   that restarted never reuses a number the Core has already taken.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use ainkrad_proto::v2::{
    ConnTool, MAX_ARGS_BYTES, MAX_BATCH, MAX_PENDING, MAX_RESULT_BYTES, ToolBatch, ToolCall,
    ToolResult, ToolsPoll,
};
use serde_json::Value;
use tokio::sync::{Notify, oneshot};

pub mod mcp;

/// A call the Core never answers ends here.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Default)]
struct One {
    tools: Vec<ConnTool>,
    pending: HashMap<String, oneshot::Sender<ToolResult>>,
    /// Not yet numbered or sent.
    queued: VecDeque<(String, String, Value)>,
    /// Sent (numbered) and not yet acknowledged.
    sent: Vec<ToolCall>,
    next: u64,
    n: u64,
}

#[derive(Default)]
pub struct Tools {
    sessions: Mutex<HashMap<String, One>>,
    changed: Notify,
}

fn refusal(id: &str, code: &str, message: &str) -> ToolResult {
    ToolResult {
        id: id.to_owned(),
        ok: false,
        result: None,
        code: Some(code.to_owned()),
        message: Some(message.to_owned()),
    }
}

impl Tools {
    /// The tools the Core last listed for `session`.
    pub fn list(&self, session: &str) -> Vec<ConnTool> {
        let all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        all.get(session)
            .map(|o| o.tools.clone())
            .unwrap_or_default()
    }

    /// Calls `tool` for `session` and waits for the Core's answer (at most `wait`).
    pub async fn call_within(
        &self,
        session: &str,
        tool: &str,
        args: Value,
        wait: Duration,
    ) -> ToolResult {
        let (id, rx) = {
            let mut all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            let one = all.entry(session.to_owned()).or_default();
            if !one.tools.iter().any(|t| t.name == tool) {
                return refusal("", "unknown_tool", "no such tool in this session");
            }
            if serde_json::to_string(&args).map_or(usize::MAX, |s| s.len()) > MAX_ARGS_BYTES {
                return refusal("", "bad_args", "the arguments are too large");
            }
            if one.pending.len() >= MAX_PENDING {
                return refusal("", "rate_limited", "too many calls are waiting");
            }
            one.n += 1;
            let id = format!("c{}", one.n);
            let (tx, rx) = oneshot::channel();
            one.pending.insert(id.clone(), tx);
            one.queued.push_back((id.clone(), tool.to_owned(), args));
            (id, rx)
        };
        self.changed.notify_waiters();
        let answer = tokio::time::timeout(wait, rx).await;
        // Whatever the end, the call is no longer waiting.
        let mut all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(one) = all.get_mut(session) {
            one.pending.remove(&id);
        }
        match answer {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => refusal(&id, "session_over", "the session ended"),
            Err(_) => refusal(&id, "timed_out", "the Core did not answer in time"),
        }
    }

    pub async fn call(&self, session: &str, tool: &str, args: Value) -> ToolResult {
        self.call_within(session, tool, args, CALL_TIMEOUT).await
    }

    /// The Core's `agent.tools` poll (see the module docs).
    pub async fn poll(&self, req: &ToolsPoll, max_wait: Duration) -> ToolBatch {
        let wait = Duration::from_millis(req.wait_ms.unwrap_or(0)).min(max_wait);
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let notified = self.changed.notified();
            {
                let mut all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
                let one = all.entry(req.session.clone()).or_default();
                if let Some(list) = &req.tools {
                    one.tools = list.iter().take(MAX_BATCH.max(64)).cloned().collect();
                }
                for r in &req.results {
                    // A result for a call that is not waiting is dropped.
                    if let Some(tx) = one.pending.remove(&r.id) {
                        let mut r = r.clone();
                        if r.result
                            .as_ref()
                            .is_some_and(|v| v.to_string().len() > MAX_RESULT_BYTES)
                        {
                            r = refusal(&r.id, "too_large", "the result is too large");
                        }
                        let _ = tx.send(r);
                    }
                }
                one.sent.retain(|c| c.tc_seq > req.after);
                one.next = one.next.max(req.after + 1);
                while let Some((id, tool, args)) = one.queued.pop_front() {
                    let tc_seq = one.next;
                    one.next += 1;
                    one.sent.push(ToolCall {
                        tc_seq,
                        id,
                        tool,
                        args,
                    });
                }
                if !one.sent.is_empty() || tokio::time::Instant::now() >= deadline {
                    let calls = one.sent.iter().take(MAX_BATCH).cloned().collect();
                    return ToolBatch {
                        session: req.session.clone(),
                        calls,
                    };
                }
            }
            let _ = tokio::time::timeout_at(deadline, notified).await;
        }
    }

    /// Drops everything of `session` (it ended): waiting calls end as `session_over`.
    pub fn forget(&self, session: &str) {
        let mut all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        all.remove(session);
    }
}

#[cfg(test)]
mod tests;
