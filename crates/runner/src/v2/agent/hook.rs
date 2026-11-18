//! `ainkrad-runner hook prompt|checkpoint <socket>`: the Brain's Claude Code hooks (B8-03), run by
//! Claude inside the sandbox with the hook's JSON on stdin.
//!
//! SECURITY MODEL (read before changing anything here)
//! 1. Authentication is the session's own tools socket, given as an argument (like `mcp-stdio`).
//!    No new credential type; nothing secret on the command line or in the environment. The ops
//!    are the Core's allow-listed `brainAiContext` and `brainAiCheckpoint`, which act for that
//!    session only; nothing in the request names a session.
//! 2. Fail open, always: whatever goes wrong (no socket, a refusal, a timeout, bad input, a reply
//!    that is too large) the shim prints NOTHING and exits 0, so a Core fault never blocks a prompt.
//!    Stdout is one JSON object or empty; stderr is never written; no prompt text is logged.
//! 3. Hard deadline [`DEADLINE`] (1.5 s) for the whole run, kept by a watchdog around a worker thread, not
//!    by the socket alone.
//! 4. `prompt` hands the model the bundle ONLY as `additionalContext`, verbatim: it is already the
//!    outside-data envelope `brainAiContext` wrapped, so it is neither re-wrapped nor edited, and a
//!    bundle over [`MAX_CONTEXT_CHARS`] is dropped whole, never cut (a cut would lose the closing marker).
//!    Text that does not start and end as the envelope does is never printed.
//!    The prompt is only the lookup key: it is sent to the Core and not kept.
//! 5. `checkpoint` is a request: it prints nothing (PreCompact's stdout would become instructions
//!    for the compaction summary) and the Core's caps decide whether it distils.
//! 6. Nothing here reads a file, the network or the environment: stdin and one socket.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

/// The whole run: reading stdin, the call and the answer.
pub const DEADLINE: Duration = Duration::from_millis(1500);
/// Claude's `additionalContext` limit.
pub const MAX_CONTEXT_CHARS: usize = 10_000;
/// The most stdin read (a prompt can be long; the Core cuts it again).
const MAX_STDIN: u64 = 1 << 20;
/// The most bytes of one reply line.
const MAX_REPLY: u64 = 256 * 1024;
/// The envelope markers of `ainkrad_core::untrusted` (this crate does not depend on the Core). The
/// shim prints only text that starts and ends as an envelope does, so nothing else can reach a prompt.
const ENVELOPE_OPEN: &str = "<<<OUTSIDE TEXT";
const ENVELOPE_CLOSE: &str = "<<<END OUTSIDE TEXT>>>";
/// The Core's channel for any allow-listed op (the same one the `ainkrad` CLI uses).
const CALL: &str = "ainkrad_call";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Prompt,
    Checkpoint,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "prompt" => Some(Self::Prompt),
            "checkpoint" => Some(Self::Checkpoint),
            _ => None,
        }
    }
}

/// The `ainkrad_call` arguments for the hook's stdin; `None` when there is nothing to ask.
fn request(kind: Kind, stdin: &str) -> Option<Value> {
    match kind {
        Kind::Checkpoint => Some(json!({"op": "brainAiCheckpoint", "args": {}})),
        Kind::Prompt => {
            let input: Value = serde_json::from_str(stdin).ok()?;
            let prompt = input["prompt"].as_str().filter(|p| !p.trim().is_empty())?;
            Some(json!({"op": "brainAiContext", "args": {"mode": "prompt", "prompt": prompt}}))
        }
    }
}

/// What the hook prints for the Core's answer: one JSON object, or nothing.
fn output(kind: Kind, answer: &Value) -> String {
    if kind == Kind::Checkpoint {
        return String::new();
    }
    let text = answer["text"].as_str().unwrap_or_default();
    let text = text.trim();
    if text.is_empty()
        || text.chars().count() > MAX_CONTEXT_CHARS
        || !text.starts_with(ENVELOPE_OPEN)
        || !text.ends_with(ENVELOPE_CLOSE)
    {
        return String::new();
    }
    json!({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": text}})
        .to_string()
}

/// One `tools/call` on the socket and its answer's body; `None` on any failure or refusal.
fn call(sock: &str, args: &Value, wait: Duration) -> Option<Value> {
    let stream = UnixStream::connect(sock).ok()?;
    stream.set_write_timeout(Some(wait)).ok()?;
    stream.set_read_timeout(Some(wait)).ok()?;
    let mut line = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": CALL, "arguments": args}})
    .to_string();
    line.push('\n');
    (&stream).write_all(line.as_bytes()).ok()?;
    let mut reader = BufReader::new(&stream).take(MAX_REPLY);
    // Notifications may come first; the answer is the line with our id.
    for _ in 0..8 {
        let mut buf = String::new();
        if reader.read_line(&mut buf).ok()? == 0 {
            return None;
        }
        let v: Value = serde_json::from_str(&buf).ok()?;
        if v["id"] != json!(1) {
            continue;
        }
        let r = &v["result"];
        if r["isError"] != false {
            return None;
        }
        return serde_json::from_str(r["content"][0]["text"].as_str()?).ok();
    }
    None
}

/// The text to print for one hook run: empty on any problem. `stdin` is read inside the deadline.
pub fn run(
    kind: Kind,
    sock: &str,
    mut stdin: impl Read + Send + 'static,
    wait: Duration,
) -> String {
    let sock = sock.to_owned();
    let (tx, rx) = mpsc::channel();
    // A watchdog on a worker: a stuck read or write cannot hold the user's prompt past `wait`.
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = (&mut stdin).take(MAX_STDIN).read_to_string(&mut text);
        let out = request(kind, &text)
            .and_then(|args| call(&sock, &args, wait))
            .map(|answer| output(kind, &answer))
            .unwrap_or_default();
        let _ = tx.send(out);
    });
    rx.recv_timeout(wait).unwrap_or_default()
}

/// `hook <kind> <sock>`: always exit 0.
pub fn main(kind: &str, sock: &str) -> ExitCode {
    if let Some(kind) = Kind::parse(kind) {
        let out = run(kind, sock, std::io::stdin(), DEADLINE);
        if !out.is_empty() {
            let _ = writeln!(std::io::stdout(), "{out}");
            let _ = std::io::stdout().flush();
        }
    }
    // Not a return: the runtime would wait for a worker still blocked on stdin.
    std::process::exit(0)
}

#[cfg(test)]
mod tests;
