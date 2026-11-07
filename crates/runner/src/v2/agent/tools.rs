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
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// What a session may hold queued or sent-and-unacknowledged, in calls (waiting or abandoned) and in
/// bytes of arguments, and what the whole runner may: past these a call is refused `busy` before it
/// is queued. A call whose caller went away is taken out of the queue; one already numbered stays
/// until the Core acknowledges it (a gap in the numbering would be refused), so these bound it.
pub const MAX_HELD_CALLS: usize = MAX_PENDING;
pub const MAX_HELD_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_HELD_TOTAL: usize = 16 * 1024 * 1024;

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
    /// Bytes of arguments of each call that is queued or sent and not acknowledged, by id, and
    /// their sum.
    sizes: HashMap<String, usize>,
    held: usize,
}

impl One {
    /// The call `id` no longer holds its arguments (it was acknowledged or taken out of the queue).
    fn release(&mut self, id: &str, total: &AtomicUsize) {
        if let Some(n) = self.sizes.remove(id) {
            self.held -= n;
            total.fetch_sub(n, Ordering::SeqCst);
        }
    }
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
            sizes: HashMap::new(),
            held: 0,
        }
    }
}

pub struct Tools {
    sessions: Mutex<HashMap<String, One>>,
    changed: Notify,
    /// Counts the polls that changed some session's tool list: an open connection looks again at
    /// its own session's list when it ticks (`sock`'s list-changed notification).
    listed: watch::Sender<u64>,
    /// Bytes of arguments held by every session (see [`MAX_HELD_TOTAL`]).
    total: AtomicUsize,
}

impl Default for Tools {
    fn default() -> Self {
        Self {
            sessions: Mutex::default(),
            changed: Notify::new(),
            listed: watch::channel(0).0,
            total: AtomicUsize::new(0),
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
            // Nobody waits for it: a call not yet numbered is not sent to the Core at all.
            if let Some(at) = one.queued.iter().position(|(id, ..)| *id == self.id) {
                one.queued.remove(at);
                one.release(&self.id, &self.tools.total);
            }
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

/// A tool whose schema is too large, or not an object schema, is listed with an open object instead.
fn bounded(mut t: ConnTool) -> ConnTool {
    // Size first, then shape: only an object schema (`"type": "object"`) is passed on.
    let ok = |s: &Value| {
        s.to_string().len() <= MAX_SCHEMA_BYTES
            && s.get("type").and_then(Value::as_str) == Some("object")
    };
    if t.input_schema.as_ref().is_some_and(|s| !ok(s)) {
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

    /// Takes every tool away from `session` (its socket was given up): a harness that asks sees none.
    pub fn unlist(&self, session: &str) {
        let mut all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(one) = all.get_mut(session)
            && !one.tools.is_empty()
        {
            one.tools.clear();
            self.listed.send_modify(|n| *n += 1);
        }
    }

    /// Whether `name` (as a harness names it: the operation with `.` as `_`) is one of the tools the
    /// Core last listed for `session`.
    pub fn knows(&self, session: &str, name: &str) -> bool {
        let all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        all.get(session)
            .is_some_and(|o| o.tools.iter().any(|t| t.name.replace('.', "_") == name))
    }

    /// Calls queued or sent and not acknowledged for `session`, and the bytes the runner holds in all
    /// (a test's way to see that nothing grows).
    #[cfg(test)]
    pub(crate) fn held(&self, session: &str) -> (usize, usize) {
        let all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let n = all
            .get(session)
            .map_or(0, |o| o.queued.len() + o.sent.len());
        (n, self.total.load(Ordering::SeqCst))
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
            let len = serde_json::to_string(&args).map_or(usize::MAX, |s| s.len());
            if len > MAX_ARGS_BYTES {
                return refusal("", "bad_args", "the arguments are too large");
            }
            if one.pending.len() >= MAX_PENDING {
                return refusal("", "rate_limited", "too many calls are waiting");
            }
            // What is queued or sent and not acknowledged is bounded, abandoned calls included.
            if one.queued.len() + one.sent.len() >= MAX_HELD_CALLS
                || one.held + len > MAX_HELD_BYTES
                || self.total.load(Ordering::SeqCst) + len > MAX_HELD_TOTAL
            {
                return refusal("", "busy", "too many calls are waiting for the Core");
            }
            one.n += 1;
            let id = format!("{}-{}", one.epoch, one.n);
            let (tx, rx) = oneshot::channel();
            one.pending.insert(id.clone(), tx);
            one.sizes.insert(id.clone(), len);
            one.held += len;
            self.total.fetch_add(len, Ordering::SeqCst);
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

    /// Makes the state of `session` (its socket is open): the Core's polls find it from now on.
    pub fn open(&self, session: &str) {
        let mut all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        all.entry(session.to_owned()).or_insert_with(One::new);
    }

    /// The Core's `agent.tools` poll for a session that was opened (see the module docs). It never
    /// makes state. `None` when the session is not open (yet): the poll, tool list included, is
    /// not taken, and the caller says so, so the Core sends it again. One forgotten while the poll
    /// waited gets an empty answer at once.
    pub async fn poll_live(&self, req: &ToolsPoll, max_wait: Duration) -> Option<ToolBatch> {
        let open = {
            let all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            all.contains_key(&req.session)
        };
        if !open {
            return None;
        }
        Some(self.poll_with(req, max_wait, false).await)
    }

    /// `poll_live`, but the first pass makes the session's state if there is none (the Core's first
    /// poll starting a session; what the module's own tests and the self-test use).
    pub async fn poll(&self, req: &ToolsPoll, max_wait: Duration) -> ToolBatch {
        self.poll_with(req, max_wait, true).await
    }

    async fn poll_with(&self, req: &ToolsPoll, max_wait: Duration, create: bool) -> ToolBatch {
        let wait = Duration::from_millis(req.wait_ms.unwrap_or(0)).min(max_wait);
        let deadline = tokio::time::Instant::now() + wait;
        let empty = || ToolBatch {
            session: req.session.clone(),
            calls: Vec::new(),
        };
        let mut existed = false;
        loop {
            let notified = self.changed.notified();
            let done = {
                let mut all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
                if create && !existed {
                    all.entry(req.session.clone()).or_insert_with(One::new);
                }
                match all.get_mut(&req.session) {
                    None if existed || tokio::time::Instant::now() >= deadline => Some(empty()),
                    None => None,
                    Some(one) => {
                        existed = true;
                        self.apply(one, req);
                        (!one.sent.is_empty() || tokio::time::Instant::now() >= deadline).then(
                            || ToolBatch {
                                session: req.session.clone(),
                                calls: one.sent.iter().take(MAX_BATCH).cloned().collect(),
                            },
                        )
                    }
                }
            };
            if let Some(batch) = done {
                return batch;
            }
            let _ = tokio::time::timeout_at(deadline, notified).await;
        }
    }

    /// One poll's effect on a session: its tool list, the results, the acknowledgement, and the
    /// numbering of what was queued.
    fn apply(&self, one: &mut One, req: &ToolsPoll) {
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
        let acked: Vec<String> = one
            .sent
            .iter()
            .filter(|c| c.tc_seq <= req.after)
            .map(|c| c.id.clone())
            .collect();
        for id in acked {
            one.release(&id, &self.total);
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
    }

    /// Drops everything of `session` (it ended): waiting calls end as `session_over`.
    pub fn forget(&self, session: &str) {
        let mut all = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(one) = all.remove(session) {
            self.total.fetch_sub(one.held, Ordering::SeqCst);
        }
        drop(all);
        // A poll waiting on it ends now (and finds nothing to make).
        self.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests;
