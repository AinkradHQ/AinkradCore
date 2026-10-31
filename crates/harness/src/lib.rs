//! Harness adapters (E3.2+): one trait every coding-agent CLI is driven through, the shape
//! the E0.3 spike proved for Claude, Codex, OpenCode and agy
//! (`Docs/Topics/ainkrad-harness-protocols.md`).
//!
//! Context never travels in argv: prompts go over stdin or the harness protocol, and
//! instructions and MCP config go by file path. The child starts from an empty environment
//! plus an allowlist, so the runner's own variables (and secrets) stay out.

use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::path::PathBuf;

use serde::Serialize;
use serde_json::Value;

pub mod agy;
mod classify;
pub mod claude;
pub mod codex;
pub mod compat;
mod meter;
pub mod opencode;
mod proc;
mod sandbox;
pub use sandbox::identity as process_identity;
pub use sandbox::reap_group;

/// The sandboxed command for `program` (test support for the runner's network-isolation test).
#[doc(hidden)]
pub fn sandbox_command(
    program: &std::ffi::OsStr,
    args: &[String],
    spec: &Spec,
) -> tokio::process::Command {
    sandbox::command(program, args, spec)
}

pub use classify::{DROPPED, ErrorClass, PROTOCOL, classify};
pub use meter::{Meter, tokens, weighted_tokens};

/// The variables `harness` authenticates with, which an account's token may be put in (E15.1).
/// Codex and OpenCode also log in per config dir (`CODEX_HOME`, OpenCode's config dir); agy
/// takes a Gemini key.
pub fn auth_env(harness: &str) -> &'static [&'static str] {
    match harness {
        "claude" => claude::AUTH_ENV,
        "codex" => &["CODEX_API_KEY", "OPENAI_API_KEY"],
        "agy" => &["GEMINI_API_KEY"],
        _ => &[],
    }
}

/// What a harness session is started with.
#[derive(Debug, Clone, Default)]
pub struct Spec {
    /// The harness executable; `None` is the harness's own name looked up on `PATH`.
    pub program: Option<PathBuf>,
    /// The working directory the agent works in.
    pub cwd: PathBuf,
    /// The process's own working dir when it is not `cwd`: a long-lived server's (E15.9), whose
    /// later sessions work in other dirs and whose first one's may be removed meanwhile.
    pub process_dir: Option<PathBuf>,
    pub model: String,
    /// Instructions appended to the harness's system prompt, by file.
    pub instructions: Option<PathBuf>,
    /// MCP servers, by file, in the harness's own format (each adapter's `mcp_config`); no
    /// other MCP server is loaded (E4.2). It may hold a run token: never argv, never logged.
    pub mcp_config: Option<PathBuf>,
    /// The harness's private config/home dir, never the user's own.
    pub config_dir: PathBuf,
    /// Names of the runner's environment variables the child may see; everything else is
    /// cleared.
    pub env_allow: Vec<String>,
    /// Variables set for the child, e.g. the runner's git config (E3.7).
    pub env: Vec<(String, OsString)>,
    /// The id a new session gets, where the harness lets the caller choose it (Claude). The
    /// `SessionStarted` event is still the truth.
    pub session_id: Option<String>,
    /// The workspace is disposable and contained (a container or VM) and the project lets
    /// the harness act without asking there (E3.10). Harnesses with no approval channel (agy)
    /// refuse to start without it.
    pub sandboxed: bool,
    /// The project lets file edits inside `cwd` go ahead without asking (E3.10).
    pub accept_edits: bool,
}

/// One normalised harness event. Serialised as a `run_event` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HarnessEvent {
    /// The resumable session id, once per session.
    SessionStarted {
        id: String,
    },
    AssistantText {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    /// The result of the `ToolUse` with this `id`: whether it worked, the command's exit code
    /// when the harness reports one, and its output as the harness gave it (unredacted, whole:
    /// the runner summarises and redacts it before it goes anywhere).
    ToolResult {
        id: String,
        ok: bool,
        exit_code: Option<i64>,
        output: String,
    },
    /// The harness waits for `approve(id, …)`.
    ApprovalRequested {
        id: String,
        tool: String,
        input: Value,
    },
    Usage(Usage),
    /// The running turn's tokens so far, from the harness's mid-turn reports (a running
    /// total for the turn: a later one replaces it). The turn's `Usage` closes the turn; a
    /// runner capping tokens counts the larger of the two, as an interrupted turn may report
    /// less than it spent (Claude reports zero).
    UsageSoFar(Usage),
    /// The provider account's plan limits, as the harness reports them (E15.2; Claude's
    /// `rate_limit_event`): `status` is the harness's own word (`allowed`, `allowed_warning`,
    /// `rejected`), each window's `utilization` a fraction of its limit.
    RateLimit {
        status: String,
        windows: Vec<RateWindow>,
    },
    TurnEnded {
        outcome: TurnOutcome,
    },
    /// The process is gone; the stream ends after this.
    Exited {
        code: Option<i32>,
    },
}

/// One plan window of a `RateLimit`, e.g. Claude's `five_hour` and `seven_day`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RateWindow {
    pub name: String,
    /// 0.0 to 1.0 (and past it, at the limit).
    pub utilization: f64,
    /// When the window resets, in seconds since the epoch.
    pub resets_at: Option<i64>,
}

/// Token use. In a `Usage` event: this turn's tokens, and the session's cost so far if the
/// harness reports one. From `Harness::usage`: the totals since the adapter started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Usage {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub cost_usd: Option<f64>,
}

/// The tokens of `steps` added up; no cost.
pub(crate) fn sum_tokens<'a>(steps: impl IntoIterator<Item = &'a Usage>) -> Usage {
    steps.into_iter().fold(Usage::default(), |a, b| Usage {
        input: a.input + b.input,
        output: a.output + b.output,
        cache_read: a.cache_read + b.cache_read,
        cache_write: a.cache_write + b.cache_write,
        cost_usd: None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TurnOutcome {
    Success,
    /// Ended by `interrupt`.
    Interrupted,
    /// `code` is the harness's error class, for the loop-breaker fingerprint.
    Failed {
        reason: String,
        code: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { reason: String },
}

/// A live harness session. Events come from `next`; requests go in through the rest.
pub trait Harness: Sized + Send + 'static {
    /// The harness is a long-lived server that can take another session (`renew`) after a
    /// turn ends: OpenCode's `serve`, Codex's `app-server` (E15.6).
    const LONG_LIVED: bool = false;
    /// Spawns a new session.
    fn start(spec: &Spec) -> impl Future<Output = io::Result<Self>> + Send;
    /// Starts a new session for `spec` (a later run: its working dir, model, instructions and
    /// MCP config) on this already running process, so the next run skips its start-up (E15.6).
    /// Nothing of the old session carries over. `Unsupported` unless `LONG_LIVED`.
    fn renew(&mut self, spec: &Spec) -> impl Future<Output = io::Result<()>> + Send {
        let _ = spec;
        async { Err(io::Error::from(io::ErrorKind::Unsupported)) }
    }
    /// Spawns a process that continues `session`.
    fn resume(spec: &Spec, session: &str) -> impl Future<Output = io::Result<Self>> + Send;
    /// Starts a turn with `prompt`.
    fn send(&mut self, prompt: &str) -> impl Future<Output = io::Result<()>> + Send;
    /// Ends the running turn; the process stays up for the next `send`, except agy's, which
    /// exits after the turn ends (`resume` continues it).
    fn interrupt(&mut self) -> impl Future<Output = io::Result<()>> + Send;
    /// Answers an `ApprovalRequested`.
    fn approve(
        &mut self,
        id: &str,
        decision: Decision,
    ) -> impl Future<Output = io::Result<()>> + Send;
    /// The next event; `None` after `Exited`.
    fn next(&mut self) -> impl Future<Output = Option<HarnessEvent>> + Send;
    /// Totals since this adapter started.
    fn usage(&self) -> Usage;
    /// The end of the process's stderr so far, for a failure reason. Unredacted: the caller
    /// redacts it before it goes anywhere.
    fn stderr_tail(&self) -> String;
    /// Closes stdin, waits briefly, then kills: the exit code, if it exited.
    fn stop(self) -> impl Future<Output = Option<i32>> + Send;
}

/// A recorded fixture as a newer CLI might send it: an unknown field on every message, and the
/// `unknown` messages (new event types, new nested shapes) after each line.
#[cfg(test)]
pub(crate) fn newer_cli(fixture: &str, unknown: &[Value]) -> String {
    let mut out = String::new();
    for line in fixture.lines() {
        let mut m: Value = serde_json::from_str(line).unwrap();
        m["citadelFuture"] = serde_json::json!({"added": "in a newer CLI"});
        out.push_str(&format!("{m}\n"));
        for u in unknown {
            out.push_str(&format!("{u}\n"));
        }
    }
    out
}
