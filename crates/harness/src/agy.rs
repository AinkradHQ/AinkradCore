//! agy (Antigravity CLI) in print mode, stream-json both ways (E0.3; Grimoire `AgyProtocol.swift`,
//! `AgyEngine.swift`). One process per conversation; each stdin line runs one turn.
//!
//! **Sandboxed only.** agy has no approval channel: what a tool may do is decided by its
//! settings file, not by anything on the stream. So the adapter refuses to start unless the
//! spec says the workspace is a sandbox, writes its own settings (every tool proceeds), and runs
//! with `--sandbox` (terminal restrictions) and `--mode accept-edits`.
//!
//! Config isolation: `HOME` is the spec's `config_dir`. agy has no config-dir variable and reads
//! `~/.gemini/antigravity-cli/settings.json`, so a private home is the only way to own that file
//! and keep the user's settings, `GEMINI.md`, `AGENTS.md`, hooks, plugins and MCP servers out.
//! The login lives there too: log the runner's home in once (`HOME=<dir> agy`, interactive).
//! The prompt goes over stdin, never argv.
//!
//! Interrupt is SIGINT: the turn ends with `error: interrupted`, then the process exits; resume
//! continues the conversation in a new one. The conversation id arrives only with the first
//! prompt. agy reports tokens, no cost.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;

use serde_json::{Value, json};
use tokio::process::Command;

use crate::proc::{self, Proc};
use crate::{Decision, Harness, HarnessEvent, Spec, TurnOutcome, Usage};

/// The agy version this adapter was written and recorded against (E3.6 probes it). Tool names
/// change between versions (`write_file` here, `write_to_file` in Grimoire's).
pub const VERSION: &str = "1.4.4";

/// The runner-owned settings: there is no one to ask, so every tool proceeds.
pub const SETTINGS: &str = r#"{"toolPermission": "always-proceed"}"#;

/// The argv: flags only, `-p=` last (`-p` takes the next argument as its prompt).
pub fn args(spec: &Spec, resume: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = [
        "--input-format",
        "stream-json",
        "--output-format",
        "stream-json",
        "--sandbox",
        "--mode",
        "accept-edits",
        "--disable-slash-commands",
        "--model",
    ]
    .map(str::to_owned)
    .into();
    args.push(spec.model.clone());
    if let Some(id) = resume {
        args.extend(["--conversation".to_owned(), id.to_owned()]);
    }
    args.push("-p=".to_owned());
    args
}

/// The process to spawn: cleared env + allowlist, `HOME` set to the spec's config dir.
pub fn command(spec: &Spec, resume: Option<&str>) -> Command {
    let program = spec.program.as_deref().unwrap_or("agy".as_ref());
    proc::command(
        program.as_os_str(),
        &args(spec, resume),
        spec,
        &[("HOME", spec.config_dir.as_os_str())],
    )
}

/// The spec's MCP file for the Citadel MCP server at `url`, in agy's `mcp_config.json` form
/// (what `agy mcp add --header` writes).
pub fn mcp_config(url: &str, token: &str) -> Value {
    json!({"mcpServers": {"citadel": {"serverUrl": url, "disabled": false,
        "headers": {"Authorization": format!("Bearer {token}")}}}})
}

/// agy takes neither instructions nor MCP servers by flag: it reads them from its home. So
/// the spec's files are linked there, MCP servers as `.gemini/config/mcp_config.json` and
/// instructions as `.gemini/GEMINI.md`; a file the spec lacks removes a stale link. Links,
/// not copies: the run token stays only in the runner's per-run file, and dies with it.
// ponytail: one home per runner, so two agy runs at once would share these links; the runner
// works one run at a time. A home per run is the upgrade if that changes.
fn link_files(spec: &Spec) -> io::Result<()> {
    let gemini = spec.config_dir.join(".gemini");
    let links = [
        (&spec.mcp_config, gemini.join("config/mcp_config.json")),
        (&spec.instructions, gemini.join("GEMINI.md")),
    ];
    for (file, at) in links {
        std::fs::create_dir_all(at.parent().expect("a parent"))?;
        match std::fs::remove_file(&at) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        if let Some(file) = file {
            std::os::unix::fs::symlink(file, &at)?;
        }
    }
    Ok(())
}

pub struct Agy {
    proc: Proc,
    /// Decodes stdout; separate so fixtures can drive it without a process.
    decoder: Decoder,
    queued: VecDeque<HarnessEvent>,
    exited: bool,
}

/// Turns agy's stdout messages into events.
#[derive(Default)]
pub struct Decoder {
    session: Option<String>,
    /// The process continues an earlier conversation, so its first cumulative total is not
    /// all its own.
    resumed: bool,
    /// Text so far per streaming step; tool steps already announced.
    texts: HashMap<i64, String>,
    tools: HashSet<i64>,
    /// Tool steps whose end was announced.
    finished: HashSet<i64>,
    /// This turn's per-step use, and the conversation's cumulative total at the last turn end.
    steps: Usage,
    last: Option<Usage>,
    totals: Usage,
}

fn text(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

fn count(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

/// Assumed to count cached input in `input_tokens`, as Gemini does; `Usage::input` does not.
fn usage(u: &Value) -> Usage {
    let cached = count(&u["cache_read_tokens"]);
    Usage {
        input: count(&u["input_tokens"]).saturating_sub(cached),
        // Thinking is billed as output.
        output: count(&u["output_tokens"]) + count(&u["thinking_tokens"]),
        cache_read: cached,
        cache_write: 0,
        cost_usd: None,
    }
}

fn add(a: Usage, b: Usage) -> Usage {
    Usage {
        input: a.input + b.input,
        output: a.output + b.output,
        cache_read: a.cache_read + b.cache_read,
        cache_write: a.cache_write + b.cache_write,
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

impl Decoder {
    pub fn decode(&mut self, m: &Value) -> Vec<HarnessEvent> {
        match m["event"].as_str().unwrap_or("") {
            "init" => {
                let id = text(&m["conversation_id"]);
                if self.session.as_ref() == Some(&id) {
                    return vec![];
                }
                self.session = Some(id.clone());
                vec![HarnessEvent::SessionStarted { id }]
            }
            "step_update" => self.step(&m["step_update"]),
            "result" => self.result(&m["result"]),
            other => {
                tracing::debug!(harness = "agy", kind = other, "ignored an event");
                vec![]
            }
        }
    }

    fn step(&mut self, s: &Value) -> Vec<HarnessEvent> {
        let index = s["step_index"].as_i64().unwrap_or(-1);
        let done = s["state"] == "DONE";
        match s["step_type"].as_str().unwrap_or("") {
            "agent_response" => {
                let so_far = self.texts.entry(index).or_default();
                so_far.push_str(s["text_delta"].as_str().unwrap_or(""));
                if !done {
                    return vec![];
                }
                self.steps = add(self.steps, usage(&s["usage"]));
                let full = self.texts.remove(&index).unwrap_or_default();
                let mut events = match full.trim_end() {
                    "" => vec![],
                    t => vec![HarnessEvent::AssistantText { text: t.to_owned() }],
                };
                events.push(HarnessEvent::UsageSoFar(self.steps));
                events
            }
            "tool" => {
                let mut events = vec![];
                if self.tools.insert(index) {
                    events.push(HarnessEvent::ToolUse {
                        id: index.to_string(),
                        name: text(&s["tool_info"]["name"]),
                        input: s["tool_info"]["parameters"].clone(),
                    });
                }
                // agy reports no output, only the step's end: `DONE`, else a failure.
                let state = s["state"].as_str().unwrap_or("");
                if !matches!(state, "" | "ACTIVE" | "PENDING") && self.finished.insert(index) {
                    events.push(HarnessEvent::ToolResult {
                        id: index.to_string(),
                        ok: done,
                        exit_code: None,
                        output: s["error"].as_str().unwrap_or_default().to_owned(),
                    });
                }
                events
            }
            _ => vec![],
        }
    }

    fn result(&mut self, r: &Value) -> Vec<HarnessEvent> {
        // `result.usage` is the conversation's, across processes. A resumed process has no
        // earlier total, so its first turn is the sum of its steps (an interrupted step has
        // none, which only the totals show).
        let total = usage(&r["usage"]);
        let turn = match self.last {
            Some(last) => minus(total, last),
            None if self.resumed => self.steps,
            None => total,
        };
        self.last = Some(total);
        self.steps = Usage::default();
        self.texts.clear();
        self.totals = add(self.totals, turn);
        let status = text(&r["status"]);
        let outcome = match (status.as_str(), r["error"].as_str()) {
            ("SUCCESS", _) => TurnOutcome::Success,
            (_, Some("interrupted")) => TurnOutcome::Interrupted,
            (_, error) => {
                let mut reason = error
                    .filter(|e| !e.is_empty())
                    .unwrap_or(&status)
                    .to_owned();
                reason.truncate(reason.floor_char_boundary(500));
                TurnOutcome::Failed {
                    reason,
                    code: status.to_lowercase(),
                }
            }
        };
        vec![
            HarnessEvent::Usage(turn),
            HarnessEvent::TurnEnded { outcome },
        ]
    }
}

impl Agy {
    async fn spawn(spec: &Spec, resume: Option<&str>) -> io::Result<Self> {
        if !spec.sandboxed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "agy has no approval channel; it only runs in a sandboxed workspace",
            ));
        }
        link_files(spec)?;
        let settings = spec.config_dir.join(".gemini/antigravity-cli");
        std::fs::create_dir_all(&settings)?;
        std::fs::write(settings.join("settings.json"), SETTINGS)?;
        Ok(Self {
            proc: Proc::spawn_with_pgid_file(command(spec, resume), proc::sandbox_pgid_file(spec))?,
            decoder: Decoder {
                resumed: resume.is_some(),
                ..Decoder::default()
            },
            queued: VecDeque::new(),
            exited: false,
        })
    }
}

impl Harness for Agy {
    async fn start(spec: &Spec) -> io::Result<Self> {
        Self::spawn(spec, None).await
    }

    async fn resume(spec: &Spec, session: &str) -> io::Result<Self> {
        Self::spawn(spec, Some(session)).await
    }

    async fn send(&mut self, prompt: &str) -> io::Result<()> {
        let message = json!({"event": "user", "message": {"role": "user", "content": prompt}});
        self.proc.write(&message).await
    }

    /// SIGINT: the turn ends as interrupted, then the process exits.
    async fn interrupt(&mut self) -> io::Result<()> {
        self.proc.interrupt().await
    }

    async fn approve(&mut self, id: &str, _: Decision) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("agy has no approvals to answer ({id})"),
        ))
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
                return Some(HarnessEvent::Exited { code });
            };
            self.queued.extend(self.decoder.decode(&message));
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
