//! OpenCode over `opencode serve`: HTTP requests, one SSE `/event` stream back (E0.3; Grimoire
//! `OpenCodeServer.swift`, `OpenCodeProtocol.swift`, `OpenCodeEngine.swift`).
//!
//! Config isolation: the server's XDG config, data, cache and state dirs are under the spec's
//! `config_dir`, so the user's `~/.config/opencode` (global `AGENTS.md`, plugins, agents, MCP
//! servers) and `~/.local/share/opencode` (logins, sessions) are never read;
//! `OPENCODE_DISABLE_CLAUDE_CODE` keeps `~/.claude` (CLAUDE.md, skills) out too. One config dir
//! per runner, not per run: a session must outlive its server for resume, and logins live in it
//! (`XDG_DATA_HOME=<dir>/data opencode auth login`). The free `opencode/*` models need none.
//!
//! One server per adapter, on loopback with a random password (`OPENCODE_SERVER_PASSWORD`), so
//! other local users cannot drive it. Instructions and MCP servers go by file path; the prompt
//! goes in the request body, never argv. The spec's model is `provider/model`.
//!
//! Long-lived (E15.6): a later run opens a new session on the same server (`renew`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::io;
use std::time::Duration;

use reqwest::Method;
use serde_json::{Value, json};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::proc::{self, Proc};
use crate::{Decision, Harness, HarnessEvent, Spec, TurnOutcome, Usage, sum_tokens};

/// The OpenCode version this adapter was written and recorded against (E3.6 probes it).
pub const VERSION: &str = "1.18.34";

/// `opencode serve`'s basic-auth user.
const USER: &str = "opencode";

/// The variables that isolate the server, plus its password.
pub fn env(spec: &Spec, password: &str) -> Vec<(&'static str, OsString)> {
    let dir = |name: &str| spec.config_dir.join(name).into_os_string();
    let mut env = vec![
        ("XDG_CONFIG_HOME", dir("config")),
        ("XDG_DATA_HOME", dir("data")),
        ("XDG_CACHE_HOME", dir("cache")),
        ("XDG_STATE_HOME", dir("state")),
        ("OPENCODE_DISABLE_CLAUDE_CODE", "1".into()),
        ("OPENCODE_DISABLE_EXTERNAL_SKILLS", "1".into()),
        ("OPENCODE_DISABLE_AUTOUPDATE", "1".into()),
        ("OPENCODE_SERVER_PASSWORD", password.into()),
    ];
    if let Some(file) = &spec.instructions {
        let config = json!({"instructions": [file]});
        env.push(("OPENCODE_CONFIG_CONTENT", config.to_string().into()));
    }
    if let Some(file) = &spec.mcp_config {
        env.push(("OPENCODE_CONFIG", file.into()));
    }
    env
}

/// The spec's MCP file for the Citadel MCP server at `url`: an OpenCode config holding only
/// that server, loaded by path (`OPENCODE_CONFIG`), so the run token is in neither argv nor
/// the environment. `oauth: false`: the token is the only auth, never a login flow.
pub fn mcp_config(url: &str, token: &str) -> Value {
    json!({"mcp": {"citadel": {"type": "remote", "url": url, "enabled": true, "oauth": false,
        "headers": {"Authorization": format!("Bearer {token}")}}}})
}

/// The server to spawn: cleared env + allowlist + `env`.
pub fn command(spec: &Spec, password: &str) -> Command {
    let program = spec.program.as_deref().unwrap_or("opencode".as_ref());
    let env = env(spec, password);
    let set: Vec<_> = env.iter().map(|(k, v)| (*k, v.as_os_str())).collect();
    let args = ["serve", "--port", "0", "--hostname", "127.0.0.1"].map(str::to_owned);
    proc::command(program.as_os_str(), &args, spec, &set)
}

/// The session's permission rules (E3.10): edits, shell and fetches ask (Grimoire's Ask
/// mode); edits go ahead when the spec accepts them, and everything when it is sandboxed.
pub fn permissions(spec: &Spec) -> Value {
    let rule = |p: &str, allow: bool| {
        let action = if allow || spec.sandboxed {
            "allow"
        } else {
            "ask"
        };
        json!({"permission": p, "pattern": "*", "action": action})
    };
    json!({"permission": [rule("edit", spec.accept_edits), rule("bash", false),
                          rule("webfetch", false)]})
}

pub struct OpenCode {
    proc: Proc,
    http: reqwest::Client,
    base: String,
    password: String,
    dir: String,
    session: String,
    /// `{providerID, modelID}`.
    model: Value,
    events: mpsc::UnboundedReceiver<Value>,
    /// Decodes the event stream; separate so fixtures can drive it without a server.
    decoder: Decoder,
    queued: VecDeque<HarnessEvent>,
    exited: bool,
}

/// Turns OpenCode's events for one session into harness events.
#[derive(Default)]
pub struct Decoder {
    session: String,
    user_messages: HashSet<String>,
    /// Tool call ids and text part ids already announced.
    seen: HashSet<String>,
    /// This turn's completed assistant messages → their use. A message completes more than
    /// once on the wire, so it is keyed, not summed.
    steps: HashMap<String, Usage>,
    /// A turn is running: `session.idle` repeats after an abort, and only the first ends it.
    busy: bool,
    /// A `session.error` waiting for the turn's `session.idle`.
    error: Option<Value>,
    /// The session's cost so far, across servers.
    cost: f64,
    totals: Usage,
}

fn text(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

fn count(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

impl Decoder {
    pub fn decode(&mut self, e: &Value) -> Vec<HarnessEvent> {
        let p = &e["properties"];
        let session = [
            &p["sessionID"],
            &p["info"]["sessionID"],
            &p["part"]["sessionID"],
        ]
        .into_iter()
        .find_map(Value::as_str);
        if session != Some(self.session.as_str()) {
            return vec![];
        }
        match e["type"].as_str().unwrap_or("") {
            "message.updated" => {
                let info = &p["info"];
                let id = text(&info["id"]);
                if info["role"] == "user" {
                    self.user_messages.insert(id);
                } else if info["role"] == "assistant" && !info["time"]["completed"].is_null() {
                    let t = &info["tokens"];
                    let step = Usage {
                        input: count(&t["input"]),
                        // Reasoning is billed as output.
                        output: count(&t["output"]) + count(&t["reasoning"]),
                        cache_read: count(&t["cache"]["read"]),
                        cache_write: count(&t["cache"]["write"]),
                        cost_usd: info["cost"].as_f64(),
                    };
                    if self.steps.insert(id, step) != Some(step) {
                        return vec![HarnessEvent::UsageSoFar(sum_tokens(self.steps.values()))];
                    }
                }
                vec![]
            }
            "message.part.updated" => self.part(&p["part"]),
            "permission.asked" => {
                let mut input = p["metadata"].clone();
                if let Some(o) = input.as_object_mut() {
                    o.insert("patterns".to_owned(), p["patterns"].clone());
                }
                vec![HarnessEvent::ApprovalRequested {
                    id: text(&p["id"]),
                    tool: text(&p["permission"]),
                    input,
                }]
            }
            // A new turn: an error from an earlier one must not end it (Grimoire GD8).
            "session.status" if p["status"]["type"] == "busy" => {
                self.busy = true;
                self.error = None;
                vec![]
            }
            "session.error" => {
                self.error = Some(p["error"].clone());
                vec![]
            }
            "session.idle" if std::mem::take(&mut self.busy) => self.idle(),
            other => {
                tracing::debug!(harness = "opencode", kind = other, "ignored an event");
                vec![]
            }
        }
    }

    fn part(&mut self, part: &Value) -> Vec<HarnessEvent> {
        if self.user_messages.contains(&text(&part["messageID"])) {
            return vec![];
        }
        match part["type"].as_str() {
            Some("tool") => {
                let (id, state) = (text(&part["callID"]), &part["state"]);
                let mut events = vec![];
                if state["status"] != "pending" && self.seen.insert(id.clone()) {
                    events.push(HarnessEvent::ToolUse {
                        id: id.clone(),
                        name: text(&part["tool"]),
                        input: state["input"].clone(),
                    });
                }
                // A finished call: `completed` with its output, or `error` with the error.
                let ok = state["status"] == "completed";
                if (ok || state["status"] == "error") && self.seen.insert(format!("result:{id}")) {
                    let output = state[if ok { "output" } else { "error" }].as_str();
                    events.push(HarnessEvent::ToolResult {
                        id,
                        ok,
                        exit_code: state["metadata"]["exit"].as_i64(),
                        output: output.unwrap_or_default().to_owned(),
                    });
                }
                events
            }
            // A text part is final once it has an end time.
            Some("text")
                if !part["time"]["end"].is_null()
                    && part["text"].as_str().is_some_and(|t| !t.is_empty())
                    && self.seen.insert(text(&part["id"])) =>
            {
                vec![HarnessEvent::AssistantText {
                    text: text(&part["text"]),
                }]
            }
            _ => vec![],
        }
    }

    fn idle(&mut self) -> Vec<HarnessEvent> {
        let mut turn = Usage::default();
        let mut cost = 0.0;
        for step in std::mem::take(&mut self.steps).into_values() {
            turn.input += step.input;
            turn.output += step.output;
            turn.cache_read += step.cache_read;
            turn.cache_write += step.cache_write;
            cost += step.cost_usd.unwrap_or(0.0);
        }
        self.cost += cost;
        turn.cost_usd = Some(self.cost);
        self.totals.input += turn.input;
        self.totals.output += turn.output;
        self.totals.cache_read += turn.cache_read;
        self.totals.cache_write += turn.cache_write;
        self.totals.cost_usd = Some(self.cost);
        let outcome = match self.error.take() {
            None => TurnOutcome::Success,
            Some(e) if e["name"] == "MessageAbortedError" => TurnOutcome::Interrupted,
            Some(e) => {
                // An `APIError` carries the provider's HTTP status (E15.3, `classify`).
                let code = match e["data"]["statusCode"].as_u64() {
                    Some(status) => format!("{}:{status}", text(&e["name"])),
                    None => text(&e["name"]),
                };
                let mut reason = e["data"]["message"]
                    .as_str()
                    .map_or_else(|| code.clone(), str::to_owned);
                reason.truncate(reason.floor_char_boundary(500));
                TurnOutcome::Failed { reason, code }
            }
        };
        vec![
            HarnessEvent::Usage(turn),
            HarnessEvent::TurnEnded { outcome },
        ]
    }
}

/// Forwards each SSE `data:` JSON of `response` into a channel, until either side ends.
fn forward(mut response: reqwest::Response) -> mpsc::UnboundedReceiver<Value> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buffer = Vec::new();
        while let Ok(Some(chunk)) = response.chunk().await {
            buffer.extend_from_slice(&chunk);
            while let Some(end) = buffer.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buffer.drain(..=end).collect();
                let Some(data) = line.strip_prefix(b"data: ") else {
                    continue;
                };
                if let Ok(event) = serde_json::from_slice(data)
                    && tx.send(event).is_err()
                {
                    return;
                }
            }
        }
    });
    rx
}

impl OpenCode {
    async fn spawn(spec: &Spec, resume: Option<&str>) -> io::Result<Self> {
        let invalid = |m: String| io::Error::new(io::ErrorKind::InvalidInput, m);
        let (provider, model) = spec.model.split_once('/').ok_or_else(|| {
            invalid(format!(
                "opencode model {:?} is not provider/model",
                spec.model
            ))
        })?;
        let password = crate::claude::new_session_id()?;
        let mut proc =
            Proc::spawn_with_pgid_file(command(spec, &password), proc::sandbox_pgid_file(spec))?;
        let listening = async {
            while let Some(line) = proc.line().await {
                if let Some((_, url)) = line.split_once("listening on ") {
                    return Ok(url.trim().to_owned());
                }
            }
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "opencode serve exited before listening",
            ))
        };
        let base = tokio::time::timeout(Duration::from_secs(60), listening)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "opencode serve did not listen")
            })??;
        proc.drain();
        let mut opencode = Self {
            proc,
            http: reqwest::Client::builder()
                .no_proxy()
                .build()
                .map_err(io::Error::other)?,
            base,
            password,
            // Every call is scoped by directory; one spelling of it (`/var` is a symlink on
            // macOS).
            dir: std::fs::canonicalize(&spec.cwd)?.display().to_string(),
            session: String::new(),
            model: json!({"providerID": provider, "modelID": model}),
            events: mpsc::unbounded_channel().1,
            decoder: Decoder::default(),
            queued: VecDeque::new(),
            exited: false,
        };
        opencode.open(spec, resume).await?;
        Ok(opencode)
    }

    /// Subscribes to the directory's events, then opens the session (a new one, or `resume`d).
    async fn open(&mut self, spec: &Spec, resume: Option<&str>) -> io::Result<()> {
        // Subscribe before the session exists, so nothing is missed.
        let response = self
            .request(Method::GET, "/event")
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(io::Error::other)?;
        self.events = forward(response);
        let session = match resume {
            Some(id) => {
                let path = format!("/session/{id}");
                self.call(Method::PATCH, &path, Some(permissions(spec)))
                    .await?
            }
            None => {
                self.call(Method::POST, "/session", Some(permissions(spec)))
                    .await?
            }
        };
        self.session = text(&session["id"]);
        self.decoder.session = self.session.clone();
        self.decoder.cost = session["cost"].as_f64().unwrap_or(0.0);
        let id = self.session.clone();
        self.queued.push_back(HarnessEvent::SessionStarted { id });
        Ok(())
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.request_in(&self.dir, method, path)
    }

    fn request_in(&self, dir: &str, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.base))
            .query(&[("directory", dir)])
            .basic_auth(USER, Some(&self.password))
    }

    /// The JSON reply (`null` when empty), or the HTTP error with its body.
    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> io::Result<Value> {
        let mut request = self.request(method, path);
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.map_err(io::Error::other)?;
        let status = response.status();
        let body = response.text().await.map_err(io::Error::other)?;
        if !status.is_success() {
            return Err(io::Error::other(format!(
                "opencode {path}: {status}: {body}"
            )));
        }
        Ok(serde_json::from_str(&body).unwrap_or(Value::Null))
    }
}

impl Harness for OpenCode {
    const LONG_LIVED: bool = true;

    async fn start(spec: &Spec) -> io::Result<Self> {
        Self::spawn(spec, None).await
    }

    /// A new session in the spec's directory with its model and permissions. The server's
    /// MCP config and instructions are the files it started with, which the caller rewrites
    /// for each run at the same paths; disposing the directories' instances makes OpenCode
    /// read them again (it caches them per instance), so the old run's token is never used.
    async fn renew(&mut self, spec: &Spec) -> io::Result<()> {
        if self.exited {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "opencode exited"));
        }
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "model is not provider/model");
        let (provider, model) = spec.model.split_once('/').ok_or_else(invalid)?;
        let dir = std::fs::canonicalize(&spec.cwd)?.display().to_string();
        let old = std::mem::replace(&mut self.dir, dir);
        for dir in [old.as_str(), self.dir.as_str()] {
            let disposed = self
                .request_in(dir, Method::POST, "/instance/dispose")
                .send()
                .await
                .and_then(reqwest::Response::error_for_status);
            disposed.map_err(io::Error::other)?;
        }
        self.model = json!({"providerID": provider, "modelID": model});
        self.decoder = Decoder::default();
        self.queued.clear();
        self.open(spec, None).await
    }

    async fn resume(spec: &Spec, session: &str) -> io::Result<Self> {
        Self::spawn(spec, Some(session)).await
    }

    async fn send(&mut self, prompt: &str) -> io::Result<()> {
        let body = json!({"parts": [{"type": "text", "text": prompt}], "agent": "build",
                          "model": self.model});
        let path = format!("/session/{}/prompt_async", self.session);
        self.call(Method::POST, &path, Some(body)).await.map(drop)
    }

    async fn interrupt(&mut self) -> io::Result<()> {
        let path = format!("/session/{}/abort", self.session);
        self.call(Method::POST, &path, None).await.map(drop)
    }

    async fn approve(&mut self, id: &str, decision: Decision) -> io::Result<()> {
        let body = match decision {
            Decision::Allow => json!({"reply": "once"}),
            Decision::Deny { reason } => json!({"reply": "reject", "message": reason}),
        };
        let path = format!("/permission/{id}/reply");
        self.call(Method::POST, &path, Some(body)).await.map(drop)
    }

    async fn next(&mut self) -> Option<HarnessEvent> {
        loop {
            if let Some(event) = self.queued.pop_front() {
                return Some(event);
            }
            if self.exited {
                return None;
            }
            // The stream ends only with the server.
            let Some(event) = self.events.recv().await else {
                self.exited = true;
                let code = self.proc.wait().await;
                return Some(HarnessEvent::Exited { code });
            };
            self.queued.extend(self.decoder.decode(&event));
        }
    }

    fn usage(&self) -> Usage {
        self.decoder.totals
    }

    fn stderr_tail(&self) -> String {
        self.proc.stderr_tail()
    }

    async fn stop(self) -> Option<i32> {
        self.proc.kill().await
    }
}

#[cfg(test)]
mod tests;
