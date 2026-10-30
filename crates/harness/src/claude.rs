//! Claude Code over `claude -p` stream-json (E0.3; Grimoire `ClaudeProtocol.swift`).
//!
//! Config isolation: `CLAUDE_CONFIG_DIR` is the spec's `config_dir`, so the user's
//! `~/.claude` (settings, hooks, plugins, skills, MCP servers, `CLAUDE.md`, sessions) is never
//! read; `--setting-sources local --strict-mcp-config` also keeps project/user settings and any
//! MCP server not in `--mcp-config` out. One config dir per runner, not per run: a run's
//! session must outlive its process for `--resume`, and a subscription login lives per config
//! dir (macOS keychain item `Claude Code-credentials-<hash of dir>`). Auth is that login, or
//! `CLAUDE_CODE_OAUTH_TOKEN` (`claude setup-token`) / `ANTHROPIC_API_KEY` passed through the
//! env allowlist. `--bare` is not used: it drops subscription auth.
//!
//! Plan limits: `rate_limit_event` becomes `RateLimit` (E15.2), the account's five-hour and
//! seven-day windows as Claude reports them.
//!
//! `CLAUDE.md` discovery still walks up from the working directory, so a runner's work root
//! must not sit under a directory holding one (e.g. a home with `~/CLAUDE.md`).

use std::collections::{HashMap, VecDeque};
use std::io;

use serde_json::{Value, json};
use tokio::process::Command;

use crate::proc::{self, Proc};
use crate::{Decision, Harness, HarnessEvent, RateWindow, Spec, TurnOutcome, Usage, sum_tokens};

/// The Claude Code version this adapter was written and recorded against (E3.6 probes it).
pub const VERSION: &str = "2.1.306";

/// Variables Claude authenticates with, for a runner's env allowlist.
pub const AUTH_ENV: &[&str] = &["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"];

/// Claude Code adds `Co-Authored-By` and "Generated with" lines to commits and PRs by default,
/// and `--setting-sources local` skips the settings file that could turn them off. An empty
/// string hides each one; `--settings` is read even with local-only setting sources.
const ATTRIBUTION_OFF: &str = r#"{"attribution":{"commit":"","pr":""}}"#;

/// A random v4 UUID, for `Spec::session_id`.
pub fn new_session_id() -> io::Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| io::Error::other(e.to_string()))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// The `--mcp-config` file for the Citadel MCP server at `url`: the run token rides in a
/// header, so it is in this file (the runner keeps it private) and never in argv.
pub fn mcp_config(url: &str, token: &str) -> Value {
    json!({"mcpServers": {"citadel": {"type": "http", "url": url,
        "headers": {"Authorization": format!("Bearer {token}")}}}})
}

/// The argv: flags and file paths only, never a prompt.
pub fn args(spec: &Spec, resume: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = [
        "-p",
        "--input-format",
        "stream-json",
        "--output-format",
        "stream-json",
        "--verbose",
        "--permission-prompt-tool",
        "stdio",
        "--permission-mode",
        if spec.accept_edits {
            "acceptEdits"
        } else {
            "default"
        },
        "--setting-sources",
        "local",
        "--settings",
        ATTRIBUTION_OFF,
        "--strict-mcp-config",
        // The Citadel MCP tools are scoped by the run token: Claude never asks for them.
        "--allowedTools",
        "mcp__citadel",
        "--model",
    ]
    .map(str::to_owned)
    .into();
    args.push(spec.model.clone());
    let mut flag = |name: &str, value: String| args.extend([name.to_owned(), value]);
    if let Some(file) = &spec.instructions {
        flag("--append-system-prompt-file", file.display().to_string());
    }
    if let Some(file) = &spec.mcp_config {
        flag("--mcp-config", file.display().to_string());
    }
    match (resume, &spec.session_id) {
        (Some(id), _) => flag("--resume", id.to_owned()),
        (None, Some(id)) => flag("--session-id", id.clone()),
        (None, None) => {}
    }
    args
}

/// The process to spawn: cleared env + allowlist, `CLAUDE_CONFIG_DIR` set to the spec's.
pub fn command(spec: &Spec, resume: Option<&str>) -> Command {
    let program = spec.program.as_deref().unwrap_or("claude".as_ref());
    proc::command(
        program.as_os_str(),
        &args(spec, resume),
        spec,
        &[("CLAUDE_CONFIG_DIR", spec.config_dir.as_os_str())],
    )
}

pub struct Claude {
    proc: Proc,
    /// Decodes stdout; separate so fixtures can drive it without a process.
    decoder: Decoder,
    queued: VecDeque<HarnessEvent>,
    next_id: u32,
    exited: bool,
}

/// Turns Claude's stdout messages into events, tracking what the protocol needs.
#[derive(Default)]
pub struct Decoder {
    session: Option<String>,
    /// Approval id → the tool input, echoed back as `updatedInput` on allow.
    pending: HashMap<String, Value>,
    interrupting: bool,
    /// This turn's assistant messages → their use, for `UsageSoFar`. A message repeats on
    /// the wire, so it is keyed. Its `output_tokens` is the count when it started, so output
    /// is undercounted until the turn's `result`.
    messages: HashMap<String, Usage>,
    totals: Usage,
    /// Messages owed to the CLI, e.g. refusals of control requests we do not serve.
    replies: Vec<Value>,
    /// The control request refused since the last turn ended: a newer CLI's, the protocol
    /// failure when the process then ends without a result.
    refused: Option<String>,
}

fn text(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

fn count(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

/// `rate_limit_info`: its status and every `unifiedWindows` entry with a utilization.
fn rate_limit(info: &Value) -> Option<HarnessEvent> {
    let windows = info["unifiedWindows"]
        .as_object()?
        .iter()
        .filter_map(|(name, w)| {
            Some(RateWindow {
                name: name.clone(),
                utilization: w["utilization"].as_f64()?,
                resets_at: w["resetsAt"].as_i64(),
            })
        })
        .collect();
    Some(HarnessEvent::RateLimit {
        status: text(&info["status"]),
        windows,
    })
}

/// One `tool_result` block. Its content is a string or text blocks; a failed Bash call's reads
/// `Error: Exit code N…`, the only place Claude gives the exit code.
fn tool_result(b: &Value) -> HarnessEvent {
    let output = match &b["content"] {
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Null => String::new(),
        v => text(v),
    };
    let ok = b["is_error"] != true;
    let exit_code = output.strip_prefix("Error: Exit code ").and_then(|rest| {
        rest.split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()
    });
    HarnessEvent::ToolResult {
        id: text(&b["tool_use_id"]),
        ok,
        exit_code,
        output,
    }
}

impl Decoder {
    pub fn decode(&mut self, m: &Value) -> Vec<HarnessEvent> {
        match m["type"].as_str().unwrap_or("") {
            // `system/init` repeats at every turn start; the session is announced once.
            "system" if m["subtype"] == "init" => {
                let id = text(&m["session_id"]);
                if self.session.as_ref() == Some(&id) {
                    return vec![];
                }
                self.session = Some(id.clone());
                vec![HarnessEvent::SessionStarted { id }]
            }
            "assistant" => {
                let mut events: Vec<HarnessEvent> = m["message"]["content"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|b| match b["type"].as_str()? {
                        "text" => Some(HarnessEvent::AssistantText {
                            text: text(&b["text"]),
                        }),
                        "tool_use" => Some(HarnessEvent::ToolUse {
                            id: text(&b["id"]),
                            name: text(&b["name"]),
                            input: b["input"].clone(),
                        }),
                        _ => None,
                    })
                    .collect();
                events.extend(self.progress(&m["message"]));
                events
            }
            // Tool results come back as a user message of `tool_result` blocks.
            "user" => m["message"]["content"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|b| b["type"] == "tool_result")
                .map(tool_result)
                .collect(),
            "control_request" => self.control_request(m),
            "rate_limit_event" => rate_limit(&m["rate_limit_info"]).into_iter().collect(),
            "result" => self.result(m),
            other => {
                tracing::debug!(
                    harness = "claude",
                    kind = other,
                    "ignored an unknown message"
                );
                vec![]
            }
        }
    }

    /// The turn's failure when the process ended without a result after a refused request.
    pub fn ended_early(&mut self) -> Option<HarnessEvent> {
        let why = self.refused.take()?;
        Some(HarnessEvent::TurnEnded {
            outcome: TurnOutcome::Failed {
                reason: format!("exited after an unrecognised control request ({why})"),
                code: crate::PROTOCOL.to_owned(),
            },
        })
    }

    fn control_request(&mut self, m: &Value) -> Vec<HarnessEvent> {
        let id = text(&m["request_id"]);
        let request = &m["request"];
        if request["subtype"] != "can_use_tool" {
            let subtype = text(&request["subtype"]);
            tracing::debug!(harness = "claude", %subtype, "refused an unknown control request");
            self.refused = Some(subtype);
            self.replies
                .push(json!({"type": "control_response", "response": {
                "subtype": "error", "request_id": id,
                "error": format!("unsupported control request: {}", request["subtype"])}}));
            return vec![];
        }
        self.pending.insert(id.clone(), request["input"].clone());
        vec![HarnessEvent::ApprovalRequested {
            id,
            tool: text(&request["tool_name"]),
            input: request["input"].clone(),
        }]
    }

    /// The turn's use so far, when this message changes it.
    fn progress(&mut self, message: &Value) -> Option<HarnessEvent> {
        // Indexed as a `Value`: a missing count is 0, never a panic.
        let u = &message["usage"];
        u.as_object()?;
        let step = Usage {
            input: count(&u["input_tokens"]),
            output: count(&u["output_tokens"]),
            cache_read: count(&u["cache_read_input_tokens"]),
            cache_write: count(&u["cache_creation_input_tokens"]),
            cost_usd: None,
        };
        let id = text(&message["id"]);
        if self.messages.insert(id, step) == Some(step) {
            return None;
        }
        Some(HarnessEvent::UsageSoFar(sum_tokens(self.messages.values())))
    }

    fn result(&mut self, m: &Value) -> Vec<HarnessEvent> {
        self.messages.clear();
        self.refused = None;
        let u = &m["usage"];
        let usage = Usage {
            input: count(&u["input_tokens"]),
            output: count(&u["output_tokens"]),
            cache_read: count(&u["cache_read_input_tokens"]),
            cache_write: count(&u["cache_creation_input_tokens"]),
            cost_usd: m["total_cost_usd"].as_f64(),
        };
        self.totals.input += usage.input;
        self.totals.output += usage.output;
        self.totals.cache_read += usage.cache_read;
        self.totals.cache_write += usage.cache_write;
        // Claude's cost is cumulative for the session, across `--resume` too.
        self.totals.cost_usd = usage.cost_usd.or(self.totals.cost_usd);
        let interrupted = std::mem::take(&mut self.interrupting);
        // The provider's HTTP status, when the API refused the turn (E15.3, `classify`).
        let code = match m["api_error_status"].as_u64() {
            Some(status) if m["is_error"] == true => format!("{}:{status}", text(&m["subtype"])),
            _ => text(&m["subtype"]),
        };
        let outcome = match (m["is_error"].as_bool().unwrap_or(false), code.as_str()) {
            (false, "success") => TurnOutcome::Success,
            (_, c) if interrupted && c.starts_with("error_during_execution") => {
                TurnOutcome::Interrupted
            }
            _ => {
                let mut reason = match &m["result"] {
                    Value::String(s) if !s.is_empty() => s.clone(),
                    _ => m["errors"]
                        .as_array()
                        .map(|e| e.iter().map(text).collect::<Vec<_>>().join("; "))
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| code.clone()),
                };
                reason.truncate(reason.floor_char_boundary(500));
                TurnOutcome::Failed { reason, code }
            }
        };
        vec![
            HarnessEvent::Usage(usage),
            HarnessEvent::TurnEnded { outcome },
        ]
    }
}

impl Claude {
    async fn spawn(spec: &Spec, resume: Option<&str>) -> io::Result<Self> {
        let mut claude = Self {
            proc: Proc::spawn_with_pgid_file(command(spec, resume), proc::sandbox_pgid_file(spec))?,
            decoder: Decoder::default(),
            queued: VecDeque::new(),
            next_id: 0,
            exited: false,
        };
        // A child that already exited is not a start failure: its `Exited` event carries the
        // exit code and the stderr tail, and a write to its pipe is EPIPE only by timing.
        match claude.control(json!({"subtype": "initialize"})).await {
            Err(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(e),
            _ => Ok(claude),
        }
    }

    async fn control(&mut self, request: Value) -> io::Result<()> {
        self.next_id += 1;
        let id = format!("citadel-{}", self.next_id);
        self.proc
            .write(&json!({"type": "control_request", "request_id": id, "request": request}))
            .await
    }
}

impl Harness for Claude {
    async fn start(spec: &Spec) -> io::Result<Self> {
        Self::spawn(spec, None).await
    }

    async fn resume(spec: &Spec, session: &str) -> io::Result<Self> {
        Self::spawn(spec, Some(session)).await
    }

    async fn send(&mut self, prompt: &str) -> io::Result<()> {
        let message = json!({"type": "user", "message": {"role": "user", "content": prompt}});
        self.proc.write(&message).await
    }

    async fn interrupt(&mut self) -> io::Result<()> {
        self.decoder.interrupting = true;
        self.control(json!({"subtype": "interrupt"})).await
    }

    async fn approve(&mut self, id: &str, decision: Decision) -> io::Result<()> {
        let input =
            self.decoder.pending.remove(id).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("no approval {id}"))
            })?;
        let response = match decision {
            Decision::Allow => json!({"behavior": "allow", "updatedInput": input}),
            Decision::Deny { reason } => json!({"behavior": "deny", "message": reason}),
        };
        self.proc
            .write(&json!({"type": "control_response", "response": {
                "subtype": "success", "request_id": id, "response": response}}))
            .await
    }

    async fn next(&mut self) -> Option<HarnessEvent> {
        loop {
            if let Some(event) = self.queued.pop_front() {
                return Some(event);
            }
            if self.exited {
                return None;
            }
            let Some(message) = self.proc.next().await else {
                self.exited = true;
                let code = self.proc.wait().await;
                let exited = HarnessEvent::Exited { code };
                let Some(failed) = self.decoder.ended_early() else {
                    return Some(exited);
                };
                self.queued.push_back(exited);
                return Some(failed);
            };
            let events = self.decoder.decode(&message);
            for reply in std::mem::take(&mut self.decoder.replies) {
                let _ = self.proc.write(&reply).await;
            }
            self.queued.extend(events);
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
