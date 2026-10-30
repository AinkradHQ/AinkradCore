//! Codex over `codex app-server`: JSON-RPC 2.0, one message per line on stdio (E0.3; Grimoire
//! `CodexProtocol.swift`; schema from `codex app-server generate-json-schema`, 0.154.0).
//!
//! Config isolation: `CODEX_HOME` is the spec's `config_dir`, so the user's `~/.codex`
//! (`config.toml`, `hooks.json`, `AGENTS.md`, skills, MCP servers, sessions) is never read. One
//! home per runner, not per run: a thread must outlive its process for `thread/resume`, and the
//! login lives there. Log it in once with `CODEX_HOME=<dir> codex login` (or non-interactively,
//! `codex login --with-api-key` with the key on stdin).
//!
//! Instructions go by protocol (`developerInstructions`, read from the spec's file), never
//! argv. Approvals: `approvalPolicy: untrusted` asks before anything not known-safe, routed to
//! us (`approvalsReviewer: user`), not to Codex's auto-reviewer. Codex reports tokens, no cost.
//!
//! Long-lived (E15.6): every thread param is per thread, so a later run starts a new thread on
//! the same app-server (`renew`).

use std::collections::{HashMap, VecDeque};
use std::io;

use serde_json::{Value, json};
use tokio::process::Command;

use crate::proc::{self, Proc};
use crate::{Decision, Harness, HarnessEvent, Spec, TurnOutcome, Usage};

/// The Codex CLI version this adapter was written and recorded against (E3.6 probes it).
pub const VERSION: &str = "0.154.0";

/// The process to spawn: cleared env + allowlist, `CODEX_HOME` set to the spec's config dir.
pub fn command(spec: &Spec) -> Command {
    let program = spec.program.as_deref().unwrap_or("codex".as_ref());
    proc::command(
        program.as_os_str(),
        &["app-server".to_owned()],
        spec,
        &[("CODEX_HOME", spec.config_dir.as_os_str())],
    )
}

/// The spec's MCP file for the Citadel MCP server at `url`: the `mcp_servers` table of a
/// Codex config, which `thread_params` sends as the thread's `config`, over stdin.
pub fn mcp_config(url: &str, token: &str) -> Value {
    json!({"citadel": {"url": url,
        "http_headers": {"Authorization": format!("Bearer {token}")}}})
}

/// `thread/start` (or, with `resume`, `thread/resume`) params. The spec's instructions and MCP
/// servers are read from their files and sent in the params, never in argv.
pub fn thread_params(spec: &Spec, resume: Option<&str>) -> io::Result<Value> {
    // A sandboxed run acts without asking inside Codex's own workspace sandbox; any other
    // asks before anything not known-safe. Edits are approved by the runner (E3.10).
    let approvals = if spec.sandboxed { "never" } else { "untrusted" };
    let mut params = json!({
        "cwd": spec.cwd, "model": spec.model,
        "approvalPolicy": approvals, "approvalsReviewer": "user", "sandbox": "workspace-write",
    });
    if let Some(file) = &spec.instructions {
        params["developerInstructions"] = std::fs::read_to_string(file)?.into();
    }
    if let Some(file) = &spec.mcp_config {
        let servers: Value = serde_json::from_slice(&std::fs::read(file)?)?;
        params["config"] = json!({"mcp_servers": servers});
    }
    if let Some(thread) = resume {
        params["threadId"] = thread.into();
        // Full-history hydration on resume is deprecated (E0.3).
        params["excludeTurns"] = true.into();
    }
    Ok(params)
}

pub struct Codex {
    proc: Proc,
    thread: String,
    /// Decodes stdout; separate so fixtures can drive it without a process.
    decoder: Decoder,
    queued: VecDeque<HarnessEvent>,
    next_id: u64,
    exited: bool,
}

/// Turns Codex's stdout messages into events, tracking what the protocol needs.
#[derive(Default)]
pub struct Decoder {
    /// The running turn, for `turn/interrupt`.
    turn: Option<String>,
    /// Ids of our `turn/start` requests, so a refused one ends its turn.
    turn_starts: Vec<u64>,
    /// Approval id → the JSON-RPC id as sent, echoed back with its JSON type.
    pending: HashMap<String, Value>,
    /// `fileChange` items by id: an approval names only the item, the item names the paths.
    changes: HashMap<String, Value>,
    /// The thread's token totals at the last turn end, and now. Codex reports cumulative
    /// totals (across resume too), so a turn's use is the difference.
    base: Usage,
    latest: Usage,
    totals: Usage,
    /// Messages owed to the CLI, e.g. refusals of server requests we do not serve.
    replies: Vec<Value>,
    /// The server request refused since the last turn ended: the protocol failure when the
    /// process then ends without completing the turn.
    refused: Option<String>,
}

fn text(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

fn count(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

/// Codex's `inputTokens` includes the cached ones; `Usage::input` does not.
fn usage(t: &Value) -> Usage {
    let cached = count(&t["cachedInputTokens"]);
    Usage {
        input: count(&t["inputTokens"]).saturating_sub(cached),
        output: count(&t["outputTokens"]),
        cache_read: cached,
        cache_write: count(&t["cacheWriteInputTokens"]),
        cost_usd: None,
    }
}

fn minus(a: Usage, b: Usage) -> Usage {
    Usage {
        input: a.input.saturating_sub(b.input),
        output: a.output.saturating_sub(b.output),
        cache_read: a.cache_read.saturating_sub(b.cache_read),
        cache_write: a.cache_write.saturating_sub(b.cache_write),
        cost_usd: None,
    }
}

/// The items that are tool calls: a `ToolUse` when they start, a `ToolResult` when they end.
const TOOL_ITEMS: &[&str] = &["commandExecution", "fileChange", "mcpToolCall", "webSearch"];

/// A completed tool item. A command's output is `aggregatedOutput`; an MCP call's, its result's
/// text or its error; a file change's, the paths it touched. Not `completed` (`failed`,
/// `declined`), or a non-zero exit, is a failure.
fn tool_result(item: &Value) -> HarnessEvent {
    let exit_code = item["exitCode"].as_i64();
    let output = match item["type"].as_str() {
        Some("commandExecution") => text_or_empty(&item["aggregatedOutput"]),
        Some("mcpToolCall") => match item["error"]["message"].as_str() {
            Some(e) => e.to_owned(),
            None => item["result"]["content"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        },
        Some("fileChange") => item["changes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| c["path"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    };
    HarnessEvent::ToolResult {
        id: text(&item["id"]),
        ok: item["status"] == "completed" && exit_code.is_none_or(|c| c == 0),
        exit_code,
        output,
    }
}

fn text_or_empty(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_owned()
}

impl Decoder {
    pub fn decode(&mut self, m: &Value) -> Vec<HarnessEvent> {
        match (m["method"].as_str(), m.get("id")) {
            (Some(method), Some(id)) => self.server_request(method, id, &m["params"]),
            (Some(method), None) => self.notification(method, &m["params"]),
            (None, Some(id)) => self.response(id, m),
            (None, None) => vec![],
        }
    }

    fn server_request(&mut self, method: &str, id: &Value, params: &Value) -> Vec<HarnessEvent> {
        let (tool, input) = match method {
            "item/commandExecution/requestApproval" => ("commandExecution", params.clone()),
            "item/fileChange/requestApproval" => (
                "fileChange",
                self.changes
                    .get(&text(&params["itemId"]))
                    .cloned()
                    .unwrap_or_else(|| params.clone()),
            ),
            // Unserved requests (permission grants, user input, elicitation, dynamic tools)
            // are refused, or the turn hangs; a refused grant is a denial.
            _ => {
                tracing::debug!(harness = "codex", method, "refused an unserved request");
                self.refused = Some(method.to_owned());
                self.replies
                    .push(json!({"jsonrpc": "2.0", "id": id, "error": {
                    "code": -32601, "message": format!("citadel does not serve {method}")}}));
                return vec![];
            }
        };
        let key = id.to_string();
        self.pending.insert(key.clone(), id.clone());
        vec![HarnessEvent::ApprovalRequested {
            id: key,
            tool: tool.to_owned(),
            input,
        }]
    }

    fn notification(&mut self, method: &str, p: &Value) -> Vec<HarnessEvent> {
        match method {
            "turn/started" => {
                self.turn = p["turn"]["id"].as_str().map(str::to_owned);
                vec![]
            }
            "item/started" => {
                let item = &p["item"];
                let kind = item["type"].as_str().unwrap_or("");
                if !TOOL_ITEMS.contains(&kind) {
                    return vec![];
                }
                let id = text(&item["id"]);
                if kind == "fileChange" {
                    self.changes.insert(id.clone(), item.clone());
                }
                vec![HarnessEvent::ToolUse {
                    id,
                    name: kind.to_owned(),
                    input: item.clone(),
                }]
            }
            "item/completed" => match &p["item"] {
                item if item["type"] == "agentMessage" => match item["text"].as_str() {
                    Some(t) if !t.is_empty() => {
                        vec![HarnessEvent::AssistantText { text: t.to_owned() }]
                    }
                    _ => vec![],
                },
                item if TOOL_ITEMS.contains(&item["type"].as_str().unwrap_or("")) => {
                    vec![tool_result(item)]
                }
                _ => vec![],
            },
            "thread/tokenUsage/updated" => {
                let total = usage(&p["tokenUsage"]["total"]);
                // Another turn's totals (a resumed thread replays its last) are the baseline.
                if p["turnId"].as_str() != self.turn.as_deref() {
                    self.base = total;
                }
                self.latest = total;
                if self.turn.is_none() || p["turnId"].as_str() != self.turn.as_deref() {
                    return vec![];
                }
                vec![HarnessEvent::UsageSoFar(minus(self.latest, self.base))]
            }
            "turn/completed" => self.turn_completed(&p["turn"]),
            other => {
                tracing::debug!(harness = "codex", method = other, "ignored a notification");
                vec![]
            }
        }
    }

    /// The turn's failure when the process ended without completing it after a refused
    /// request.
    pub fn ended_early(&mut self) -> Option<HarnessEvent> {
        let method = self.refused.take()?;
        Some(HarnessEvent::TurnEnded {
            outcome: TurnOutcome::Failed {
                reason: format!("exited after Citadel refused its request {method}"),
                code: crate::PROTOCOL.to_owned(),
            },
        })
    }

    fn turn_completed(&mut self, turn: &Value) -> Vec<HarnessEvent> {
        self.turn = None;
        self.refused = None;
        let delta = minus(self.latest, self.base);
        self.base = self.latest;
        self.totals.input += delta.input;
        self.totals.output += delta.output;
        self.totals.cache_read += delta.cache_read;
        self.totals.cache_write += delta.cache_write;
        let outcome = match turn["status"].as_str().unwrap_or("") {
            "completed" => TurnOutcome::Success,
            "interrupted" => TurnOutcome::Interrupted,
            status => {
                let error = &turn["error"];
                let mut reason = error["message"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(status)
                    .to_owned();
                reason.truncate(reason.floor_char_boundary(500));
                let code = match &error["codexErrorInfo"] {
                    Value::Null => status.to_owned(),
                    // An enum: a bare string, or `{variant: {…}}`.
                    Value::Object(o) => o.keys().next().cloned().unwrap_or_default(),
                    info => text(info),
                };
                TurnOutcome::Failed { reason, code }
            }
        };
        vec![
            HarnessEvent::Usage(delta),
            HarnessEvent::TurnEnded { outcome },
        ]
    }

    fn response(&mut self, id: &Value, m: &Value) -> Vec<HarnessEvent> {
        if let Some(turn) = m["result"]["turn"]["id"].as_str() {
            self.turn = Some(turn.to_owned());
        }
        let Some(at) = self.turn_starts.iter().position(|t| id == t) else {
            return vec![];
        };
        self.turn_starts.remove(at);
        if m["error"].is_null() {
            return vec![];
        }
        vec![HarnessEvent::TurnEnded {
            outcome: TurnOutcome::Failed {
                reason: text(&m["error"]["message"]),
                code: "turn_start".to_owned(),
            },
        }]
    }
}

impl Codex {
    async fn spawn(spec: &Spec, resume: Option<&str>) -> io::Result<Self> {
        let params = thread_params(spec, resume)?;
        let mut codex = Self {
            proc: Proc::spawn_with_pgid_file(command(spec), proc::sandbox_pgid_file(spec))?,
            thread: String::new(),
            decoder: Decoder::default(),
            queued: VecDeque::new(),
            next_id: 0,
            exited: false,
        };
        let client = json!({"clientInfo": {"name": "citadel", "version": env!("CARGO_PKG_VERSION")},
                            "capabilities": null});
        let id = codex.request("initialize", client).await?;
        codex.response(id).await?;
        codex
            .proc
            .write(&json!({"jsonrpc": "2.0", "method": "initialized"}))
            .await?;
        let method = if resume.is_some() {
            "thread/resume"
        } else {
            "thread/start"
        };
        let id = codex.request(method, params).await?;
        codex.thread = text(&codex.response(id).await?["thread"]["id"]);
        let id = codex.thread.clone();
        codex.queued.push_front(HarnessEvent::SessionStarted { id });
        Ok(codex)
    }

    async fn request(&mut self, method: &str, params: Value) -> io::Result<u64> {
        self.next_id += 1;
        let id = self.next_id;
        self.proc
            .write(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await?;
        Ok(id)
    }

    /// Reads one message into the queue; `false` at EOF.
    async fn pump(&mut self) -> bool {
        let Some(message) = self.proc.next().await else {
            return false;
        };
        self.handle(&message).await;
        true
    }

    async fn handle(&mut self, message: &Value) {
        let events = self.decoder.decode(message);
        for reply in std::mem::take(&mut self.decoder.replies) {
            let _ = self.proc.write(&reply).await;
        }
        self.queued.extend(events);
    }

    /// Queues messages until the response to `id`: its result, or its error.
    async fn response(&mut self, id: u64) -> io::Result<Value> {
        loop {
            let Some(m) = self.proc.next().await else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "codex exited during startup",
                ));
            };
            if m["id"] == id && m.get("method").is_none() {
                if !m["error"].is_null() {
                    return Err(io::Error::other(format!("codex: {}", m["error"])));
                }
                return Ok(m["result"].clone());
            }
            self.handle(&m).await;
        }
    }
}

impl Harness for Codex {
    const LONG_LIVED: bool = true;

    async fn start(spec: &Spec) -> io::Result<Self> {
        Self::spawn(spec, None).await
    }

    /// A new thread with the spec's cwd, model, instructions and MCP servers (all thread
    /// params) on this app-server; the process's `CODEX_HOME` and environment are the ones it
    /// started with, which the caller keys its reuse on.
    async fn renew(&mut self, spec: &Spec) -> io::Result<()> {
        if self.exited {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "codex exited"));
        }
        let params = thread_params(spec, None)?;
        self.decoder = Decoder::default();
        self.queued.clear();
        let id = self.request("thread/start", params).await?;
        self.thread = text(&self.response(id).await?["thread"]["id"]);
        let id = self.thread.clone();
        self.queued.push_front(HarnessEvent::SessionStarted { id });
        Ok(())
    }

    async fn resume(spec: &Spec, session: &str) -> io::Result<Self> {
        Self::spawn(spec, Some(session)).await
    }

    async fn send(&mut self, prompt: &str) -> io::Result<()> {
        let params = json!({"threadId": self.thread,
            "input": [{"type": "text", "text": prompt, "text_elements": []}]});
        let id = self.request("turn/start", params).await?;
        self.decoder.turn_starts.push(id);
        Ok(())
    }

    async fn interrupt(&mut self) -> io::Result<()> {
        // The turn id comes with the `turn/start` response; read until it is here.
        while self.decoder.turn.is_none() {
            if !self.pump().await {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "codex exited"));
            }
        }
        let params = json!({"threadId": self.thread, "turnId": self.decoder.turn});
        self.request("turn/interrupt", params).await.map(drop)
    }

    async fn approve(&mut self, id: &str, decision: Decision) -> io::Result<()> {
        let rpc_id =
            self.decoder.pending.remove(id).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("no approval {id}"))
            })?;
        let (decision, reason) = match decision {
            Decision::Allow => ("accept", None),
            Decision::Deny { reason } => ("decline", Some(reason)),
        };
        self.proc
            .write(&json!({"jsonrpc": "2.0", "id": rpc_id, "result": {"decision": decision}}))
            .await?;
        // `decline` carries no reason: it reaches the agent as a steer of the running turn.
        match (reason, &self.decoder.turn) {
            (Some(reason), Some(turn)) if !reason.is_empty() => {
                let text = format!("Your {id} request was denied: {reason}");
                let params = json!({"threadId": self.thread, "expectedTurnId": turn,
                    "input": [{"type": "text", "text": text, "text_elements": []}]});
                self.request("turn/steer", params).await.map(drop)
            }
            _ => Ok(()),
        }
    }

    async fn next(&mut self) -> Option<HarnessEvent> {
        loop {
            if let Some(event) = self.queued.pop_front() {
                return Some(event);
            }
            if self.exited {
                return None;
            }
            if !self.pump().await {
                self.exited = true;
                let exited = HarnessEvent::Exited {
                    code: self.proc.wait().await,
                };
                let Some(failed) = self.decoder.ended_early() else {
                    return Some(exited);
                };
                self.queued.push_back(exited);
                return Some(failed);
            }
        }
    }

    fn usage(&self) -> Usage {
        self.decoder.totals
    }

    fn stderr_tail(&self) -> String {
        self.proc.stderr_tail()
    }

    async fn stop(self) -> Option<i32> {
        self.proc.stop().await
    }
}

#[cfg(test)]
mod tests;
