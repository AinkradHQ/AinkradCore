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
    ConnTool, MAX_ARGS_BYTES, MAX_BATCH, MAX_PENDING, MAX_RESULT_BYTES, MAX_SCHEMA_BYTES,
    ToolBatch, ToolCall, ToolResult, ToolsPoll, valid_tool_name,
};
use serde_json::Value;
use tokio::sync::{Notify, oneshot, watch};

pub mod mcp;
pub mod selftest;
pub mod sock;

/// A call the Core never answers ends here.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(120);

struct One {
    tools: Vec<ConnTool>,
    pending: HashMap<String, oneshot::Sender<ToolResult>>,
    /// Not yet numbered or sent.
    queued: VecDeque<(String, String, Value)>,
    /// Sent (numbered) and not yet acknowledged.
    sent: Vec<ToolCall>,
    next: u64,
    n: u64,
    /// Random per session state (so per runner start): a call id carries it, and a result for an
    /// id of an older epoch (a call of before a restart) can never match a new call.
    epoch: String,
}

impl One {
    fn new() -> Self {
        use std::hash::{BuildHasher, Hasher};
        let epoch = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        Self {
            tools: Vec::new(),
            pending: HashMap::new(),
            queued: VecDeque::new(),
            sent: Vec::new(),
            next: 0,
            n: 0,
            epoch: format!("{:08x}", epoch & 0xffff_ffff),
        }
    }
}

pub struct Tools {
    sessions: Mutex<HashMap<String, One>>,
    changed: Notify,
    /// Counts the polls that changed some session's tool list: an open connection looks again at
    /// its own session's list when it ticks (`sock`'s list-changed notification).
    listed: watch::Sender<u64>,
}

impl Default for Tools {
    fn default() -> Self {
        Self {
            sessions: Mutex::default(),
            changed: Notify::new(),
            listed: watch::channel(0).0,
        }
    }
}

/// Ends a waiting call however its future ends, a dropped one (the connection closed) included.
struct Waiting<'a> {
    tools: &'a Tools,
    session: &'a str,
    id: String,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        let mut all = self
            .tools
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(one) = all.get_mut(self.session) {
            one.pending.remove(&self.id);
        }
    }
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

/// A tool whose schema is too large to list is listed with an open object instead.
fn bounded(mut t: ConnTool) -> ConnTool {
    if t.input_schema
        .as_ref()
        .is_some_and(|s| s.to_string().len() > MAX_SCHEMA_BYTES)
    {
        t.input_schema = None;
    }
    t
}

impl Tools {
    /// The tools the Core last listed for `session`.
    pub fn list(&self, session: &str) -> Vec<ConnTool> {
        let all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        all.get(session)
            .map(|o| o.tools.clone())
            .unwrap_or_default()
    }

    /// Ticks whenever a poll changes some session's tool list.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.listed.subscribe()
    }

    /// Whether any state is held for `session` (a test's way to see that none was made).
    #[cfg(test)]
    pub(crate) fn holds(&self, session: &str) -> bool {
        let all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        all.contains_key(session)
    }

    /// Calls `tool` for `session` and waits for the Core's answer (at most `wait`).
    pub async fn call_within(
        &self,
        session: &str,
        tool: &str,
        args: Value,
        wait: Duration,
    ) -> ToolResult {
        let (id, rx, write) = {
            let mut all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            // No state is made for a session string nobody started: the Core's first poll does.
            let Some(one) = all.get_mut(session) else {
                return refusal("", "unknown_tool", "no such tool in this session");
            };
            let Some(listed) = one.tools.iter().find(|t| t.name == tool) else {
                return refusal("", "unknown_tool", "no such tool in this session");
            };
            let write = listed.write;
            if serde_json::to_string(&args).map_or(usize::MAX, |s| s.len()) > MAX_ARGS_BYTES {
                return refusal("", "bad_args", "the arguments are too large");
            }
            if one.pending.len() >= MAX_PENDING {
                return refusal("", "rate_limited", "too many calls are waiting");
            }
            one.n += 1;
            let id = format!("{}-{}", one.epoch, one.n);
            let (tx, rx) = oneshot::channel();
            one.pending.insert(id.clone(), tx);
            one.queued.push_back((id.clone(), tool.to_owned(), args));
            (id, rx, write)
        };
        self.changed.notify_waiters();
        // Whatever the end, the call is no longer waiting.
        let _waiting = Waiting {
            tools: self,
            session,
            id: id.clone(),
        };
        let answer = tokio::time::timeout(wait, rx).await;
        match answer {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => refusal(&id, "session_over", "the session ended"),
            // A write the Core may still have made: the same words as the Core's own (a retry of
            // it could repeat it). A read simply timed out.
            Err(_) if write => refusal(
                &id,
                "outcome_unknown",
                "the call may have been applied; check before retrying",
            ),
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
                let one = all.entry(req.session.clone()).or_insert_with(One::new);
                if let Some(list) = &req.tools {
                    let list: Vec<ConnTool> = list
                        .iter()
                        .filter(|t| valid_tool_name(&t.name))
                        .take(MAX_BATCH.max(64))
                        .cloned()
                        .map(bounded)
                        .collect();
                    if list != one.tools {
                        one.tools = list;
                        self.listed.send_modify(|n| *n += 1);
                    }
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
